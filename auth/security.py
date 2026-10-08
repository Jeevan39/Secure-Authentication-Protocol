"""Security validation routines: password policy, username constraints, and CSPRNG salt generation."""

import re
import secrets
from typing import Tuple
from config import Config

# Common weak passwords blacklist for educational defense demonstration
COMMON_WEAK_PASSWORDS = {
    "password123",
    "password1234",
    "admin123456",
    "qwerty12345",
    "welcome1234",
    "letmein1234",
    "changeme123",
    "p@ssword123",
    "p@ssw0rd123",
    "iloveyou123",
}

USERNAME_REGEX = re.compile(r"^[a-zA-Z0-9_]{3,32}$")


def validate_username(username: str) -> Tuple[bool, str]:
    """
    Validate username against security constraints:
    - 3 to 32 characters
    - Alphanumeric and underscores only
    - Strictly forbids delimiters like '|' to prevent canonical transcript injection
    """
    if not username or not isinstance(username, str):
        return False, "Username is required."

    username_trimmed = username.strip()
    if len(username_trimmed) < 3:
        return False, "Username must be at least 3 characters long."
    if len(username_trimmed) > 32:
        return False, "Username must not exceed 32 characters."
    if not USERNAME_REGEX.match(username_trimmed):
        return False, "Username may only contain letters, numbers, and underscores."

    return True, ""


def validate_password_policy(password: str) -> Tuple[bool, str]:
    """
    Enforce sound password policy:
    - Length between 10 and 128 characters
    - At least one uppercase letter
    - At least one lowercase letter
    - At least one digit
    - At least one special character
    - Protection against commonly used weak passwords
    """
    if not password or not isinstance(password, str):
        return False, "Password is required."

    if len(password) < 10:
        return False, "Password must be at least 10 characters long."
    if len(password) > 128:
        return False, "Password exceeds maximum allowable length (128 characters)."

    if not any(c.isupper() for c in password):
        return False, "Password must contain at least one uppercase letter."
    if not any(c.islower() for c in password):
        return False, "Password must contain at least one lowercase letter."
    if not any(c.isdigit() for c in password):
        return False, "Password must contain at least one numerical digit."
    if not any(c in "!@#$%^&*()-_=+[]{}|;:,.<>?/~`" for c in password):
        return False, "Password must contain at least one special character."

    # Check weak password blacklist (case-insensitive check)
    cleaned = password.lower().strip()
    for weak in COMMON_WEAK_PASSWORDS:
        if weak in cleaned:
            return False, "Password contains an easily guessable dictionary pattern."

    return True, ""


def generate_salt(num_bytes: int = Config.SALT_BYTES) -> str:
    """Generate a cryptographically secure random salt in hex format."""
    return secrets.token_hex(num_bytes)

