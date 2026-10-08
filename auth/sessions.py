"""Secure session management: token hashing, cookie policies, timeouts, and revocation."""

import time
import secrets
import hashlib
import hmac
from functools import wraps
from typing import Tuple, Optional
from flask import Request, Response, request, jsonify, g
from config import Config
from database import (
    create_session,
    get_session,
    update_session_activity,
    revoke_session,
    get_user_by_id,
    log_auth_event,
)


def hash_session_token(token: str) -> str:
    """Compute SHA-256 hex digest of raw session token for secure database storage."""
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def create_user_session(
    user_id: int,
    response: Response,
    db_path: Optional[str] = None,
) -> str:
    """
    Issue a new session identifier:
    1. Generates 256-bit high-entropy random token via secrets.token_hex(32).
    2. Stores only SHA256(token) in database (mitigating database token theft).
    3. Attaches secure cookie with HttpOnly, Secure, and SameSite=Lax attributes.
    4. Regenerates session ID, preventing session fixation attacks.
    """
    raw_token = secrets.token_hex(32)
    token_hash = hash_session_token(raw_token)

    # Store hashed session in database
    create_session(
        session_id_hash=token_hash,
        user_id=user_id,
        absolute_ttl=Config.SESSION_ABSOLUTE_TIMEOUT_SECONDS,
        db_path=db_path,
    )

    # Configure secure cookie
    response.set_cookie(
        key=Config.SESSION_COOKIE_NAME,
        value=raw_token,
        max_age=Config.SESSION_ABSOLUTE_TIMEOUT_SECONDS,
        httponly=Config.SESSION_COOKIE_HTTPONLY,
        secure=Config.SESSION_COOKIE_SECURE,
        samesite=Config.SESSION_COOKIE_SAMESITE,
        path="/",
    )

    return raw_token


def validate_session_request(
    req: Request,
    db_path: Optional[str] = None,
) -> Tuple[bool, Optional[dict], str]:
    """
    Validate the incoming session cookie:
    1. Extracts cookie from HTTP request.
    2. Hashes token and looks up session in DB.
    3. Enforces revocation check.
    4. Enforces absolute timeout (8 hours).
    5. Enforces idle timeout (15 minutes of inactivity).
    6. Updates last_seen timestamp on active sessions.
    """
    raw_token = req.cookies.get(Config.SESSION_COOKIE_NAME)
    if not raw_token:
        return False, None, "No session token provided."

    token_hash = hash_session_token(raw_token)
    session = get_session(token_hash, db_path=db_path)
    if not session:
        return False, None, "Invalid or non-existent session."

    # 1. Check if session was revoked (e.g., via logout)
    if session["revoked"] == 1:
        return False, None, "Session has been revoked."

    now = int(time.time())

    # 2. Enforce Absolute Timeout
    if now > session["expires_at"]:
        revoke_session(token_hash, db_path=db_path)
        return False, None, "Session expired (absolute lifetime exceeded)."

    # 3. Enforce Idle Timeout
    if (now - session["last_seen"]) > Config.SESSION_IDLE_TIMEOUT_SECONDS:
        revoke_session(token_hash, db_path=db_path)
        return False, None, "Session expired due to inactivity (idle timeout)."

    # 4. Refresh idle timer on active request
    update_session_activity(token_hash, db_path=db_path)

    # 5. Fetch authenticated user record
    user = get_user_by_id(session["user_id"], db_path=db_path)
    if not user:
        return False, None, "Associated user account no longer exists."

    return True, dict(user), ""


def terminate_session(
    req: Request,
    response: Response,
    db_path: Optional[str] = None,
) -> None:
    """
    Revoke session in database and delete the cookie on client.
    """
    raw_token = req.cookies.get(Config.SESSION_COOKIE_NAME)
    if raw_token:
        token_hash = hash_session_token(raw_token)
        revoke_session(token_hash, db_path=db_path)

    # Overwrite cookie with expired timestamp
    response.delete_cookie(
        key=Config.SESSION_COOKIE_NAME,
        path="/",
        secure=Config.SESSION_COOKIE_SECURE,
        httponly=Config.SESSION_COOKIE_HTTPONLY,
        samesite=Config.SESSION_COOKIE_SAMESITE,
    )


def login_required(f):
    """Decorator protecting routes requiring an active authenticated session."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        from flask import current_app
        db_path = current_app.config.get("DATABASE_PATH") if current_app else None
        is_valid, user, err_msg = validate_session_request(request, db_path=db_path)
        if not is_valid:
            return jsonify({
                "status": "error",
                "message": f"Authentication required: {err_msg}",
            }), 401
        # Store user in Flask request context
        g.user = user
        return f(*args, **kwargs)
    return decorated_function


def generate_csrf_token() -> str:
    """Generate cryptographically secure 256-bit CSRF token."""
    return secrets.token_hex(32)


def validate_csrf_token(req: Request) -> bool:
    """
    Validate CSRF token via synchronizer pattern:
    Checks X-CSRF-Token header or csrf_token body/form field against cookie.
    """
    token_cookie = req.cookies.get("csrf_token")
    if not token_cookie:
        return False

    token_header = req.headers.get("X-CSRF-Token")
    token_body = None
    if req.is_json:
        token_body = (req.get_json(silent=True) or {}).get("csrf_token")
    elif req.form:
        token_body = req.form.get("csrf_token")

    submitted = token_header or token_body
    if not submitted:
        return False

    return hmac.compare_digest(submitted, token_cookie)


def require_role(required_role: str):
    """
    Server-side Role-Based Access Control (RBAC) decorator.
    - If unauthenticated: returns 401 Unauthorized for API, redirects to /login for UI.
    - If authenticated but unauthorized: returns 403 Forbidden.
    """
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            from flask import render_template, current_app
            db_path = current_app.config.get("DATABASE_PATH") if current_app else None
            is_valid, user, _ = validate_session_request(request, db_path=db_path)
            if not is_valid or not user:
                if request.path.startswith("/api/"):
                    return jsonify({
                        "status": "error",
                        "message": "Authentication required. Active session required."
                    }), 401
                return render_template(
                    "login.html",
                    current_user=None,
                    error="Authentication required. Please log in.",
                ), 401

            user_role = user.get("role") or ("admin" if user.get("is_admin") else "user")
            if user_role != required_role:
                log_auth_event(
                    username=user.get("username", "unknown"),
                    event="ACCESS_DENIED_UNAUTHORIZED_ROLE",
                    success=False,
                    ip_address=request.remote_addr or "127.0.0.1",
                    user_id=user.get("id"),
                    db_path=db_path,
                )
                if request.path.startswith("/api/"):
                    return jsonify({
                        "status": "error",
                        "message": "Access Denied: Administrative privileges required."
                    }), 403
                return render_template(
                    "dashboard.html",
                    current_user=user,
                    error="Access Denied: Insufficient administrative privileges.",
                ), 403

            g.current_user = user
            g.user = user
            return f(*args, **kwargs)
        return decorated_function
    return decorator

