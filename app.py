import os
from flask import (
    Flask,
    request,
    jsonify,
    render_template,
    Response,
    make_response,
    redirect,
    url_for,
    g,
)
from config import Config
from database import (
    init_db,
    get_user_by_username,
    create_user,
    log_auth_event,
    get_recent_auth_logs,
    get_all_users,
    unlock_user_account,
    get_recent_challenges,
    get_system_stats,
)
from auth.security import (
    validate_username,
    validate_password_policy,
    generate_salt,
)
from auth.authentication import (
    issue_challenge,
    verify_challenge_proof,
)
from auth.protocol import (
    compute_verifiers_from_password,
)
from auth.verifier import (
    seal_verifier_with_argon2id,
)
from auth.sessions import (
    create_user_session,
    validate_session_request,
    terminate_session,
    login_required,
    require_role,
    validate_csrf_token,
    generate_csrf_token,
)


def create_app(test_config=None) -> Flask:
    """Application factory for the Secure Authentication Protocol server."""
    app = Flask(__name__)
    app.config.from_object(Config)

    if test_config:
        app.config.update(test_config)

    # Validate production secrets (fails closed if production is missing required keys)
    Config.validate_secrets(env_override=app.config.get("FLASK_ENV"))

    # Ensure database is initialized
    init_db(app.config["DATABASE_PATH"])

    # --------------------------------------------------------------------------
    # CSRF PROTECTION MIDDLEWARE
    # --------------------------------------------------------------------------
    @app.before_request
    def enforce_csrf():
        """
        Enforce synchronizer CSRF tokens on authenticated state-changing requests.
        Protocol handshakes (/api/auth/*, /api/register/*) are exempt as they are
        already bound to fresh 128-bit nonces and HMAC proofs.
        """
        if request.method in ("POST", "PUT", "PATCH", "DELETE"):
            exempt_paths = (
                "/api/register/initiate",
                "/api/register/finalize",
                "/api/register",
                "/api/auth/challenge",
                "/api/auth/verify",
                "/api/auth/logout",
            )
            if request.path not in exempt_paths:
                is_valid, user, _ = validate_session_request(request, db_path=app.config["DATABASE_PATH"])
                if is_valid and user:
                    if not validate_csrf_token(request):
                        return jsonify({
                            "status": "error",
                            "message": "CSRF validation failed: Invalid or missing CSRF token."
                        }), 403

    # --------------------------------------------------------------------------
    # SECURITY HEADERS MIDDLEWARE
    # --------------------------------------------------------------------------
    @app.after_request
    def set_security_headers(response: Response) -> Response:
        """Enforce standard HTTP security headers and CSP on all responses."""
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "script-src 'self'; "
            "style-src 'self'; "
            "img-src 'self' data:; "
            "font-src 'self'; "
            "connect-src 'self'; "
            "object-src 'none'; "
            "base-uri 'self'; "
            "frame-ancestors 'none'; "
            "form-action 'self';"
        )
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
        response.headers["Pragma"] = "no-cache"

        if request.is_secure:
            response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"

        # Provide synchronizer CSRF cookie for authenticated clients if not set
        if "csrf_token" not in request.cookies:
            response.set_cookie(
                "csrf_token",
                generate_csrf_token(),
                httponly=False,
                secure=Config.SESSION_COOKIE_SECURE if request.is_secure else False,
                samesite="Lax",
                path="/",
            )

        return response

    # --------------------------------------------------------------------------
    # FRONTEND HTML VIEW ROUTES
    # --------------------------------------------------------------------------
    @app.route("/", methods=["GET"])
    def index():
        is_valid, user, _ = validate_session_request(request, db_path=app.config["DATABASE_PATH"])
        if is_valid:
            return redirect(url_for("dashboard_view"))
        return redirect(url_for("login_view"))

    @app.route("/login", methods=["GET"])
    def login_view():
        is_valid, user, _ = validate_session_request(request, db_path=app.config["DATABASE_PATH"])
        if is_valid:
            return redirect(url_for("dashboard_view"))
        return render_template("login.html", current_user=None)

    @app.route("/register", methods=["GET"])
    def register_view():
        is_valid, user, _ = validate_session_request(request, db_path=app.config["DATABASE_PATH"])
        if is_valid:
            return redirect(url_for("dashboard_view"))
        return render_template("register.html", current_user=None)

    @app.route("/dashboard", methods=["GET"])
    def dashboard_view():
        is_valid, user, _ = validate_session_request(request, db_path=app.config["DATABASE_PATH"])
        if not is_valid:
            return redirect(url_for("login_view"))
        return render_template("dashboard.html", current_user=user)

    @app.route("/logs", methods=["GET"])
    def logs_view():
        is_valid, user, _ = validate_session_request(request, db_path=app.config["DATABASE_PATH"])
        if not is_valid:
            return redirect(url_for("login_view"))
        return render_template("logs.html", current_user=user)

    @app.route("/admin", methods=["GET"])
    @require_role("admin")
    def admin_view():
        """Server-side administrative and threat intelligence console (Admin Only)."""
        users = get_all_users(db_path=app.config["DATABASE_PATH"])
        challenges = get_recent_challenges(limit=25, db_path=app.config["DATABASE_PATH"])
        stats = get_system_stats(db_path=app.config["DATABASE_PATH"])
        log_auth_event(
            username=g.current_user["username"],
            event="ADMIN_CONSOLE_ACCESSED",
            success=True,
            ip_address=request.remote_addr or "127.0.0.1",
            user_id=g.current_user["id"],
            db_path=app.config["DATABASE_PATH"],
        )
        return render_template(
            "admin.html",
            current_user=g.current_user,
            users=users,
            challenges=challenges,
            stats=stats,
        )

    @app.route("/api/admin/unlock/<int:user_id>", methods=["POST"])
    @require_role("admin")
    def admin_unlock_user(user_id: int):
        """Administratively unlock a locked user account (Admin Only)."""
        success = unlock_user_account(user_id, db_path=app.config["DATABASE_PATH"])
        if success:
            log_auth_event(
                username=g.current_user["username"],
                event="ACCOUNT_UNLOCKED_BY_ADMIN",
                success=True,
                ip_address=request.remote_addr or "127.0.0.1",
                user_id=user_id,
                db_path=app.config["DATABASE_PATH"],
            )
            return jsonify({"status": "success", "message": "Account unlocked successfully."}), 200
        return jsonify({"status": "error", "message": "Failed to unlock account or user not found."}), 404

    # --------------------------------------------------------------------------
    # CHALLENGE-RESPONSE AUTHENTICATION ROUTES
    # --------------------------------------------------------------------------
    @app.route("/api/auth/challenge", methods=["POST"])
    def auth_challenge():
        """
        Step 1 & 2: Client requests challenge with username and client_nonce.
        Server generates random server_nonce, binds challenge, sets 60s TTL,
        and returns challenge payload (with synthetic salt if user is unknown).
        """
        data = request.get_json(silent=True) or {}
        username = data.get("username", "")
        client_nonce = data.get("client_nonce", "")
        client_ip = request.remote_addr or "127.0.0.1"

        success, payload, status_code = issue_challenge(
            username=username,
            client_nonce=client_nonce,
            client_ip=client_ip,
            db_path=app.config["DATABASE_PATH"],
        )
        return jsonify(payload), status_code

    @app.route("/api/auth/verify", methods=["POST"])
    def auth_verify():
        """
        Step 5 & 6: Client submits authentication proof.
        Server verifies challenge binding, single-use, unexpired status,
        reconstructs AuthMessage, and constant-time checks client proof.
        """
        data = request.get_json(silent=True) or {}
        client_ip = request.remote_addr or "127.0.0.1"

        success, message, user_id, status_code, server_proof = verify_challenge_proof(
            data=data,
            client_ip=client_ip,
            db_path=app.config["DATABASE_PATH"],
        )

        response_payload = {
            "status": "success" if success else "error",
            "message": message,
        }
        if success and user_id:
            response_payload["user_id"] = user_id
            if server_proof:
                response_payload["server_proof"] = server_proof
            resp = make_response(jsonify(response_payload), status_code)
            # Create session, hash token into DB, attach HttpOnly Secure SameSite cookie
            create_user_session(user_id=user_id, response=resp, db_path=app.config["DATABASE_PATH"])
            return resp

        return jsonify(response_payload), status_code

    @app.route("/api/auth/logout", methods=["POST"])
    def auth_logout():
        """
        Logout: Revokes session in database, clears cookie, and logs event.
        """
        client_ip = request.remote_addr or "127.0.0.1"
        is_valid, user, _ = validate_session_request(request, db_path=app.config["DATABASE_PATH"])
        username = user["username"] if user else "anonymous"
        user_id = user["id"] if user else None

        response = make_response(jsonify({"status": "success", "message": "Logged out successfully."}), 200)
        terminate_session(request, response, db_path=app.config["DATABASE_PATH"])

        log_auth_event(
            username=username,
            event="LOGOUT_SUCCESS",
            success=True,
            ip_address=client_ip,
            user_id=user_id,
            db_path=app.config["DATABASE_PATH"],
        )
        return response

    @app.route("/api/user/me", methods=["GET"])
    def get_current_user_profile():
        """Retrieve authenticated user identity (requires valid session cookie)."""
        is_valid, user, err = validate_session_request(request, db_path=app.config["DATABASE_PATH"])
        if not is_valid:
            return jsonify({"status": "error", "message": f"Authentication required: {err}"}), 401
        return jsonify({
            "status": "success",
            "user": {
                "id": user["id"],
                "username": user["username"],
                "created_at": user["created_at"],
            }
        }), 200

    @app.route("/api/auth/logs", methods=["GET"])
    def get_security_audit_logs():
        """Retrieve recent security audit logs for authenticated users."""
        is_valid, user, err = validate_session_request(request, db_path=app.config["DATABASE_PATH"])
        if not is_valid:
            return jsonify({"status": "error", "message": f"Authentication required: {err}"}), 401

        raw_logs = get_recent_auth_logs(limit=50, db_path=app.config["DATABASE_PATH"])
        logs = [
            {
                "id": log["id"],
                "username_attempted": log["username_attempted"],
                "event": log["event"],
                "success": bool(log["success"]),
                "ip_address": log["ip_address"],
                "timestamp": log["timestamp"],
            }
            for log in raw_logs
        ]
        return jsonify({"status": "success", "logs": logs}), 200

    # --------------------------------------------------------------------------
    # REGISTRATION PROTOCOL ROUTES
    # --------------------------------------------------------------------------
    @app.route("/api/register/initiate", methods=["POST"])
    def register_initiate():
        """
        Step 1 of Client-Derived Verifier Registration:
        Client submits requested username.
        Server validates format, checks uniqueness, and issues fresh 16-byte random salt.
        """
        data = request.get_json(silent=True) or {}
        username = data.get("username", "").strip()

        is_valid_user, user_err = validate_username(username)
        if not is_valid_user:
            return jsonify({"status": "error", "message": user_err}), 400

        # Check if username is already registered
        existing = get_user_by_username(username, db_path=app.config["DATABASE_PATH"])
        if existing:
            return jsonify({"status": "error", "message": "Username is already registered."}), 409

        salt = generate_salt(Config.SALT_BYTES)
        return jsonify({
            "status": "success",
            "username": username,
            "salt": salt,
            "iterations": Config.PBKDF2_ITERATIONS,
            "protocol_version": Config.PROTOCOL_VERSION,
        }), 200

    @app.route("/api/register/finalize", methods=["POST"])
    def register_finalize():
        """
        Step 2 of Client-Derived Verifier Registration:
        Client computes PBKDF2 locally and submits stored_key and server_key.
        Server verifies inputs and stores verifiers without ever receiving the plaintext password.
        """
        data = request.get_json(silent=True) or {}
        username = data.get("username", "").strip()
        salt = data.get("salt", "").strip()
        iterations = data.get("iterations")
        stored_key = data.get("stored_key", "").strip()
        server_key = data.get("server_key", "").strip()
        client_ip = request.remote_addr or "127.0.0.1"

        # Validate username
        is_valid_user, user_err = validate_username(username)
        if not is_valid_user:
            return jsonify({"status": "error", "message": user_err}), 400

        # Validate cryptographic parameter formats
        try:
            salt_bytes = bytes.fromhex(salt)
            if len(salt_bytes) != Config.SALT_BYTES:
                return jsonify({"status": "error", "message": "Invalid salt length."}), 400
        except ValueError:
            return jsonify({"status": "error", "message": "Salt must be a valid hex string."}), 400

        if iterations != Config.PBKDF2_ITERATIONS:
            return jsonify({"status": "error", "message": f"Iterations must be {Config.PBKDF2_ITERATIONS}."}), 400

        try:
            sk_bytes = bytes.fromhex(stored_key)
            if len(sk_bytes) != 32:
                return jsonify({"status": "error", "message": "Invalid verifier key length."}), 400
            if server_key:
                srv_bytes = bytes.fromhex(server_key)
                if len(srv_bytes) != 32:
                    return jsonify({"status": "error", "message": "Invalid server key length."}), 400
        except ValueError:
            return jsonify({"status": "error", "message": "Verifier keys must be valid 32-byte hex strings."}), 400

        # Check duplicate
        if get_user_by_username(username, db_path=app.config["DATABASE_PATH"]):
            return jsonify({"status": "error", "message": "Username is already registered."}), 409

        # Compute Argon2id verifier seal
        seal = seal_verifier_with_argon2id(stored_key)

        # Store user verifiers
        create_user(
            username=username,
            salt=salt,
            iterations=iterations,
            stored_key=stored_key,
            server_key=server_key or None,
            role="user",
            is_admin=0,
            verifier_seal=seal,
            db_path=app.config["DATABASE_PATH"],
        )

        log_auth_event(
            username=username,
            event="REGISTER_SUCCESS",
            success=True,
            ip_address=client_ip,
            db_path=app.config["DATABASE_PATH"],
        )

        return jsonify({
            "status": "success",
            "message": "User registered successfully.",
            "username": username,
        }), 201

    @app.route("/api/register", methods=["POST"])
    def register_direct():
        """
        Direct registration route: enforces password policy and derives verifiers on server.
        Used for automated test suites and direct evaluation clients.
        Plaintext password is used solely for PBKDF2 calculation and immediately discarded.
        """
        data = request.get_json(silent=True) or {}
        username = data.get("username", "").strip()
        password = data.get("password", "")
        client_ip = request.remote_addr or "127.0.0.1"

        # Validate username
        is_valid_user, user_err = validate_username(username)
        if not is_valid_user:
            return jsonify({"status": "error", "message": user_err}), 400

        # Validate password policy
        is_valid_pwd, pwd_err = validate_password_policy(password)
        if not is_valid_pwd:
            return jsonify({"status": "error", "message": pwd_err}), 400

        # Check duplicate username
        if get_user_by_username(username, db_path=app.config["DATABASE_PATH"]):
            return jsonify({"status": "error", "message": "Username is already registered."}), 409

        # Generate fresh salt and compute verifiers
        salt = generate_salt(Config.SALT_BYTES)
        verifiers = compute_verifiers_from_password(password, salt, Config.PBKDF2_ITERATIONS)

        # Clear password reference from local scope
        del password

        # Compute Argon2id verifier integrity seal
        seal = seal_verifier_with_argon2id(verifiers["stored_key"])

        create_user(
            username=username,
            salt=verifiers["salt"],
            iterations=int(verifiers["iterations"]),
            stored_key=verifiers["stored_key"],
            server_key=verifiers["server_key"],
            role="user",
            is_admin=0,
            verifier_seal=seal,
            db_path=app.config["DATABASE_PATH"],
        )

        log_auth_event(
            username=username,
            event="REGISTER_SUCCESS",
            success=True,
            ip_address=client_ip,
            db_path=app.config["DATABASE_PATH"],
        )

        return jsonify({
            "status": "success",
            "message": "User registered successfully.",
            "username": username,
        }), 201

    @app.route("/health", methods=["GET"])
    def health():
        """Basic health check endpoint."""
        return jsonify({"status": "healthy", "protocol": Config.PROTOCOL_VERSION}), 200

    return app


if __name__ == "__main__":
    app = create_app()
    app.run(host=Config.HOST, port=Config.PORT, debug=Config.DEBUG)

