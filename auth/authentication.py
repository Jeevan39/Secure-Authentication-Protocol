"""Challenge-response authentication engine: nonce handling, challenge lifecycle, and proof verification."""

import time
import uuid
from typing import Dict, Any, Tuple, Optional
from config import Config
from database import (
    get_user_by_username,
    create_challenge,
    get_challenge,
    consume_challenge_atomically,
    record_failed_login,
    reset_failed_login,
    log_auth_event,
)
from auth.security import validate_username
from auth.protocol import (
    build_auth_message,
    verify_client_proof,
    generate_synthetic_salt,
    compute_server_signature,
)
import secrets
import hashlib
import hmac


def issue_challenge(
    username: str,
    client_nonce: str,
    client_ip: str,
    db_path: Optional[str] = None,
) -> Tuple[bool, Dict[str, Any], int]:
    """
    Step 2 of Authentication Protocol:
    1. Validates username and client_nonce.
    2. Looks up user account.
    3. If user exists: retrieves salt and iterations.
    4. If user does NOT exist: derives deterministic synthetic salt (mitigating enumeration).
    5. Generates fresh random server_nonce.
    6. Stores challenge in DB with 60s expiration.
    7. Returns challenge parameters to client.
    """
    # 1. Validate inputs
    is_valid_user, user_err = validate_username(username)
    if not is_valid_user:
        return False, {"status": "error", "message": user_err}, 400

    if not client_nonce or not isinstance(client_nonce, str):
        return False, {"status": "error", "message": "Client nonce is required."}, 400

    try:
        cn_bytes = bytes.fromhex(client_nonce.strip())
        if len(cn_bytes) != Config.NONCE_BYTES:
            return False, {"status": "error", "message": "Client nonce must be 16 bytes (32 hex characters)."}, 400
    except ValueError:
        return False, {"status": "error", "message": "Client nonce must be a valid hex string."}, 400

    # 2. Check user account
    user = get_user_by_username(username, db_path=db_path)
    now = int(time.time())

    if user:
        salt = user["salt"]
        iterations = user["iterations"]
    else:
        # Unknown user: Generate deterministic synthetic salt
        salt = generate_synthetic_salt(username)
        iterations = Config.PBKDF2_ITERATIONS

    # 3. Generate fresh server nonce and challenge identifier
    server_nonce = secrets.token_hex(Config.NONCE_BYTES)
    challenge_id = str(uuid.uuid4())

    # 4. Store ephemeral challenge record
    create_challenge(
        challenge_id=challenge_id,
        username=username,
        client_nonce=client_nonce.strip(),
        server_nonce=server_nonce,
        context=Config.AUTH_CONTEXT,
        ttl_seconds=Config.CHALLENGE_TTL_SECONDS,
        db_path=db_path,
    )

    event_name = (
        "CHALLENGE_ISSUED_LOCKED"
        if (user and user["locked_until"] and now < user["locked_until"])
        else "CHALLENGE_ISSUED"
    )
    log_auth_event(
        username=username,
        event=event_name,
        success=True,
        ip_address=client_ip,
        user_id=user["id"] if user else None,
        db_path=db_path,
    )

    # 5. Return challenge response
    return True, {
        "status": "success",
        "challenge_id": challenge_id,
        "username": username,
        "salt": salt,
        "iterations": iterations,
        "server_nonce": server_nonce,
        "protocol_version": Config.PROTOCOL_VERSION,
        "context": Config.AUTH_CONTEXT,
    }, 200


def verify_challenge_proof(
    data: Dict[str, Any],
    client_ip: str,
    db_path: Optional[str] = None,
) -> Tuple[bool, str, Optional[int], int, Optional[str]]:
    """
    Step 6 of Authentication Protocol:
    1. Validates challenge existence, binding, expiration, and unused status.
    2. Atomically marks challenge as used (preventing replay and concurrency attacks).
    3. Reconstructs canonical AuthMessage.
    4. Verifies HMAC proof against stored verifier using constant-time comparison.
    5. Updates lockout/failed attempt counters.
    6. Mitigates username enumeration with identical generic error messages.
    7. Computes and returns ServerProof for mutual client-server verification using SERVER_PROOF_SECRET.
    """
    generic_error = "Authentication failed. Please verify your credentials and try again."
    
    username = str(data.get("username", "")).strip()
    client_nonce = str(data.get("client_nonce", "")).strip()
    server_nonce = str(data.get("server_nonce", "")).strip()
    challenge_id = str(data.get("challenge_id", "")).strip()
    proof = str(data.get("proof", "")).strip()

    if not all([username, client_nonce, server_nonce, challenge_id, proof]):
        return False, "Missing required authentication parameters.", None, 400, None

    now = int(time.time())

    # 1. Look up challenge record
    challenge = get_challenge(challenge_id, db_path=db_path)
    if not challenge:
        log_auth_event(username, "CHALLENGE_NOT_FOUND", False, client_ip, db_path=db_path)
        return False, generic_error, None, 401, None

    # 2. Check expiration (60 seconds TTL)
    if now > challenge["expires_at"]:
        log_auth_event(username, "CHALLENGE_EXPIRED", False, client_ip, db_path=db_path)
        return False, generic_error, None, 401, None

    # 3. Check if challenge was already consumed
    if challenge["used"] == 1:
        log_auth_event(username, "REPLAY_ATTEMPT_CHALLENGE_USED", False, client_ip, db_path=db_path)
        return False, generic_error, None, 401, None

    # 4. Check binding to nonces and username
    if (
        challenge["username"] != username
        or challenge["client_nonce"] != client_nonce
        or challenge["server_nonce"] != server_nonce
    ):
        log_auth_event(username, "CHALLENGE_BINDING_MISMATCH", False, client_ip, db_path=db_path)
        return False, generic_error, None, 401, None

    # 5. Look up user account
    user = get_user_by_username(username, db_path=db_path)
    if not user:
        # Atomic consumption of challenge even for unknown users to prevent challenge hoarding
        consume_challenge_atomically(challenge_id, db_path=db_path)
        # Dummy computation to normalize execution timing
        dummy_key = hashlib.sha256(b"dummy-timing-equalizer").digest()
        dummy_msg = b"dummy-canonical-timing-auth-message"
        _ = hmac.new(dummy_key, dummy_msg, hashlib.sha256).digest()
        log_auth_event(username, "UNKNOWN_USER_AUTH_FAILED", False, client_ip, db_path=db_path)
        return False, generic_error, None, 401, None

    # 6. Check account lockout status (mitigate enumeration via identical 401 response)
    if user["locked_until"] and now < user["locked_until"]:
        consume_challenge_atomically(challenge_id, db_path=db_path)
        dummy_key = hashlib.sha256(b"dummy-timing-equalizer-locked").digest()
        dummy_msg = b"dummy-canonical-timing-locked-message"
        _ = hmac.new(dummy_key, dummy_msg, hashlib.sha256).digest()
        log_auth_event(username, "ACCOUNT_LOCKED", False, client_ip, user_id=user["id"], db_path=db_path)
        return False, generic_error, None, 401, None

    # 7. Construct canonical transcript message
    auth_message = build_auth_message(
        protocol_version=Config.PROTOCOL_VERSION,
        context=challenge["context"],
        username=username,
        client_nonce=client_nonce,
        server_nonce=server_nonce,
    )

    # 8. Check Argon2id at-rest verifier integrity seal if present
    has_seal = "verifier_seal" in user.keys() and user["verifier_seal"]
    if has_seal:
        from auth.verifier import verify_sealed_verifier
        is_seal_valid = verify_sealed_verifier(user["stored_key"], user["verifier_seal"])
        if not is_seal_valid:
            log_auth_event(username, "VERIFIER_SEAL_INTEGRITY_COMPROMISED", False, client_ip, user_id=user["id"], db_path=db_path)
            return False, generic_error, None, 401, None

    # Verify client proof against stored_key
    stored_key_bytes = bytes.fromhex(user["stored_key"])
    is_valid_proof, recovered_key = verify_client_proof(proof, stored_key_bytes, auth_message)

    # 9. Atomically consume the challenge
    consumed_ok = consume_challenge_atomically(challenge_id, db_path=db_path)
    if not consumed_ok:
        # Concurrency race-condition detected: another request consumed this challenge in parallel
        log_auth_event(username, "CHALLENGE_RACE_CONDITION_PREVENTED", False, client_ip, user_id=user["id"], db_path=db_path)
        return False, generic_error, None, 401, None

    # 10. Handle verification outcome
    if is_valid_proof:
        # ServerProof is generated using the application-level secret SERVER_PROOF_SECRET
        # decoupled from user database rows, ensuring database compromise does not leak server proof capability.
        server_proof = compute_server_signature(Config.SERVER_PROOF_SECRET, auth_message)
        reset_failed_login(user["id"], db_path=db_path)
        log_auth_event(username, "LOGIN_SUCCESS", True, client_ip, user_id=user["id"], db_path=db_path)
        return True, "Authentication successful.", user["id"], 200, server_proof
    else:
        new_attempts = record_failed_login(user["id"], db_path=db_path)
        log_auth_event(username, f"INVALID_PROOF_ATTEMPT_{new_attempts}", False, client_ip, user_id=user["id"], db_path=db_path)
        return False, generic_error, user["id"], 401, None

