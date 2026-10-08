"""
Administrative Account Provisioning Utility
Creates or promotes an administrative account for local demonstration.
This script executes strictly offline and is never exposed as an HTTP endpoint.
"""

import sys
from auth.security import validate_username, validate_password_policy, generate_salt
from auth.protocol import compute_verifiers_from_password
from auth.verifier import seal_verifier_with_argon2id
from database import create_user, get_user_by_username, get_db_connection, init_db
from config import Config


def provision_admin(username: str = "admin", password: str = "Admin@123456", db_path: str = None) -> bool:  # nosec B107
    """Provision or promote an administrator account offline."""
    init_db(db_path)

    is_valid_u, err_u = validate_username(username)
    if not is_valid_u:
        print(f"[-] Validation Error: {err_u}")
        return False

    is_valid_p, err_p = validate_password_policy(password)
    if not is_valid_p:
        print(f"[-] Validation Error: {err_p}")
        return False

    conn = get_db_connection(db_path)
    existing = get_user_by_username(username, db_path=db_path)

    if existing:
        conn.execute(
            "UPDATE users SET role = 'admin', is_admin = 1 WHERE username = ?;",
            (username,),
        )
        conn.commit()
        conn.close()
        print(f"[+] Existing user '{username}' promoted to 'admin' role successfully.")
        return True
    conn.close()

    salt = generate_salt(Config.SALT_BYTES)
    verifiers = compute_verifiers_from_password(password, salt, Config.PBKDF2_ITERATIONS)
    # At-rest verifier hardening via Argon2id
    sealed_stored_key = seal_verifier_with_argon2id(verifiers["stored_key"])

    create_user(
        username=username,
        salt=salt,
        iterations=Config.PBKDF2_ITERATIONS,
        stored_key=verifiers["stored_key"],
        server_key=verifiers["server_key"],
        role="admin",
        is_admin=1,
        verifier_seal=sealed_stored_key,
        db_path=db_path,
    )
    print(f"[+] Administrator account '{username}' provisioned successfully.")
    return True


if __name__ == "__main__":
    admin_user = sys.argv[1] if len(sys.argv) > 1 else "admin"
    admin_pass = sys.argv[2] if len(sys.argv) > 2 else "Admin@123456"
    provision_admin(admin_user, admin_pass)
