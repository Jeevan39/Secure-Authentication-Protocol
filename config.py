"""Central configuration and cryptographic security policies."""

import os
from pathlib import Path
from dotenv import load_dotenv

# Base directory of the project
BASE_DIR = Path(__file__).resolve().parent

# Load environment variables from .env if present
env_path = BASE_DIR / ".env"
if env_path.exists():
    load_dotenv(env_path)

# Known development fallback secrets (strictly rejected in production by Config.validate_secrets)
DEV_FALLBACK_SECRET_KEY = "dev-secret-key-4a9b2c8f1e3d7a6b5c0e2f4a6b8c0d2e4f6a8b0c2d4e6f8a0b2c4d6e8f0a2b4c"  # nosec B105
DEV_FALLBACK_SERVER_PEPPER = "dev-pepper-7f8e9d0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e"
DEV_FALLBACK_SERVER_PROOF_SECRET = "dev-proof-secret-9e8d7c6b5a4f3e2d1c0b9a8f7e6d5c4b3a2f1e0d9c8b7a6f5e4d3c2b1a0f9e8d"  # nosec B105


class Config:
    """Security and application configuration parameters."""

    # Application settings
    FLASK_ENV = os.getenv("FLASK_ENV", "development")
    DEBUG = os.getenv("FLASK_DEBUG", "False").lower() in ("true", "1")
    HOST = os.getenv("HOST", "127.0.0.1")
    PORT = int(os.getenv("PORT", "5000"))

    # Cryptographic keys
    # In development, stable fallbacks are provided for local testing convenience.
    # In production, unpredictable secrets must be loaded from the environment.
    SECRET_KEY = os.getenv("SECRET_KEY", DEV_FALLBACK_SECRET_KEY)

    # Server pepper used for generating deterministic synthetic salts for unknown usernames
    SERVER_PEPPER = os.getenv("SERVER_PEPPER", DEV_FALLBACK_SERVER_PEPPER).encode("utf-8")

    # Server authentication secret used for ServerProof generation
    # Kept independent of user database records so database compromise does not leak server proof signing capability
    SERVER_PROOF_SECRET = os.getenv("SERVER_PROOF_SECRET", DEV_FALLBACK_SERVER_PROOF_SECRET).encode("utf-8")

    # Database
    DATABASE_PATH = os.getenv("DATABASE_PATH", str(BASE_DIR / "database" / "auth.db"))

    # Cryptographic Protocol Parameters
    PROTOCOL_VERSION = "SAP-v1.0"
    AUTH_CONTEXT = "secure-authentication-protocol-v1"
    PBKDF2_ITERATIONS = 100000
    NONCE_BYTES = 16  # 128-bit nonces
    SALT_BYTES = 16  # 128-bit salts
    CHALLENGE_TTL_SECONDS = 60  # Ephemeral challenges expire in 60 seconds

    # Session Management Policies
    SESSION_IDLE_TIMEOUT_SECONDS = int(os.getenv("SESSION_IDLE_TIMEOUT_MINUTES", "15")) * 60
    SESSION_ABSOLUTE_TIMEOUT_SECONDS = int(os.getenv("SESSION_ABSOLUTE_TIMEOUT_HOURS", "8")) * 3600
    SESSION_COOKIE_NAME = "secure_auth_session"
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SECURE = True  # Enforce over HTTPS
    SESSION_COOKIE_SAMESITE = "Lax"

    # Brute-Force & Lockout Policies
    MAX_FAILED_ATTEMPTS = 5
    LOCKOUT_DURATION_SECONDS = 300  # 5-minute temporary lockout after 5 consecutive failures

    # TLS / HTTPS Paths
    SSL_CERT_PATH = str(BASE_DIR / "certs" / "localhost.crt")
    SSL_KEY_PATH = str(BASE_DIR / "certs" / "localhost.key")

    @classmethod
    def validate_secrets(cls, env_override: str = None) -> None:
        """
        Validate cryptographic secrets based on deployment environment.
        In production, fails closed if secrets are missing, too short, or using default dev fallbacks.
        """
        target_env = (env_override or cls.FLASK_ENV or "").lower().strip()
        is_production = target_env in ("production", "prod")

        secret_key = os.getenv("SECRET_KEY", "")
        server_pepper = os.getenv("SERVER_PEPPER", "")
        server_proof_secret = os.getenv("SERVER_PROOF_SECRET", "")

        if is_production:
            if not secret_key or secret_key == DEV_FALLBACK_SECRET_KEY or "replace-with" in secret_key or len(secret_key) < 32:
                raise RuntimeError(
                    "Production configuration error: SECRET_KEY must be set in environment variables "
                    "with at least 32 characters and cannot use development fallbacks or placeholders."
                )
            if not server_pepper or server_pepper == DEV_FALLBACK_SERVER_PEPPER or "replace-with" in server_pepper or len(server_pepper) < 32:
                raise RuntimeError(
                    "Production configuration error: SERVER_PEPPER must be set in environment variables "
                    "with at least 32 characters and cannot use development fallbacks or placeholders."
                )
            if not server_proof_secret or server_proof_secret == DEV_FALLBACK_SERVER_PROOF_SECRET or "replace-with" in server_proof_secret or len(server_proof_secret) < 32:
                raise RuntimeError(
                    "Production configuration error: SERVER_PROOF_SECRET must be set in environment variables "
                    "with at least 32 characters and cannot use development fallbacks or placeholders."
                )
