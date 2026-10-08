"""Cryptographic protocol implementation: SCRAM-style mathematical models, key derivation, and canonical messages."""

import hashlib
import hmac
import secrets
from typing import Dict, Tuple
from config import Config


def derive_master_key(password: str, salt_bytes: bytes, iterations: int = Config.PBKDF2_ITERATIONS) -> bytes:
    """
    Derive 256-bit Master Key from password and salt using PBKDF2-HMAC-SHA256.
    Identical to the browser's WebCrypto crypto.subtle.deriveBits calculation.
    """
    return hashlib.pbkdf2_hmac(
        hash_name="sha256",
        password=password.encode("utf-8"),
        salt=salt_bytes,
        iterations=iterations,
        dklen=32,
    )


def derive_client_key(master_key: bytes) -> bytes:
    """Derive ClientKey using domain separation string 'client-key-v1'."""
    return hmac.new(master_key, b"client-key-v1", hashlib.sha256).digest()


def derive_server_key(master_key: bytes) -> bytes:
    """Derive ServerKey using domain separation string 'server-key-v1'."""
    return hmac.new(master_key, b"server-key-v1", hashlib.sha256).digest()


def derive_stored_key(client_key: bytes) -> bytes:
    """
    Compute StoredKey = SHA256(ClientKey).
    This value is stored by the server. Even if stolen, ClientKey cannot be recovered
    without inverting SHA-256.
    """
    return hashlib.sha256(client_key).digest()


def compute_verifiers_from_password(
    password: str, salt_hex: str, iterations: int = Config.PBKDF2_ITERATIONS
) -> Dict[str, str]:
    """
    Simulate full client-side derivation of stored_key and server_key.
    Returns hex-encoded strings for salt, stored_key, and server_key.
    """
    salt_bytes = bytes.fromhex(salt_hex)
    master_key = derive_master_key(password, salt_bytes, iterations)
    client_key = derive_client_key(master_key)
    server_key = derive_server_key(master_key)
    stored_key = derive_stored_key(client_key)

    return {
        "salt": salt_hex,
        "iterations": str(iterations),
        "client_key": client_key.hex(),  # Stays on client
        "stored_key": stored_key.hex(),  # Stored on server
        "server_key": server_key.hex(),  # Stored on server
    }


def build_auth_message(
    protocol_version: str,
    context: str,
    username: str,
    client_nonce: str,
    server_nonce: str,
) -> str:
    """
    Construct canonical authentication transcript message.
    Strictly separated by '|' delimiter to prevent transcript collision attacks.
    """
    return f"{protocol_version}|{context}|{username}|{client_nonce}|{server_nonce}"


def compute_client_proof(client_key: bytes, stored_key: bytes, auth_message: str) -> str:
    """
    Compute ClientProof = ClientKey XOR HMAC(StoredKey, AuthMessage).
    Executed on client (or test client) during challenge-response authentication.
    """
    msg_bytes = auth_message.encode("utf-8")
    client_signature = hmac.new(stored_key, msg_bytes, hashlib.sha256).digest()
    proof_bytes = bytes(a ^ b for a, b in zip(client_key, client_signature))
    return proof_bytes.hex()


def verify_client_proof(
    proof_hex: str, stored_key_bytes: bytes, auth_message: str
) -> Tuple[bool, bytes]:
    """
    Server-side verification of client authentication proof:
    1. Recomputes client_signature = HMAC(StoredKey, AuthMessage)
    2. Recovers candidate_client_key = proof XOR client_signature
    3. Checks if SHA256(candidate_client_key) == StoredKey using constant-time comparison.
    """
    try:
        proof_bytes = bytes.fromhex(proof_hex)
        if len(proof_bytes) != 32:
            return False, b""
    except ValueError:
        return False, b""

    msg_bytes = auth_message.encode("utf-8")
    client_signature = hmac.new(stored_key_bytes, msg_bytes, hashlib.sha256).digest()
    recovered_client_key = bytes(a ^ b for a, b in zip(proof_bytes, client_signature))
    candidate_stored_key = hashlib.sha256(recovered_client_key).digest()

    is_valid = hmac.compare_digest(candidate_stored_key, stored_key_bytes)
    return is_valid, recovered_client_key


def compute_server_signature(server_secret: bytes, auth_message: str) -> str:
    """
    Compute ServerSignature = HMAC-SHA256(server_secret, AuthMessage).
    Used to generate ServerProof, confirming server authenticity to the client.
    Using an application-level secret (SERVER_PROOF_SECRET) ensures that even if
    the user database is compromised, the server authentication secret is not leaked.
    """
    msg_bytes = auth_message.encode("utf-8")
    server_sig = hmac.new(server_secret, msg_bytes, hashlib.sha256).digest()
    return server_sig.hex()


def verify_server_signature(server_proof_hex: str, server_secret: bytes, auth_message: str) -> bool:
    """
    Verification of server proof:
    Recomputes expected ServerSignature using server_secret and compares in constant time.
    """
    try:
        proof_bytes = bytes.fromhex(server_proof_hex.strip())
        if len(proof_bytes) != 32:
            return False
    except ValueError:
        return False
    msg_bytes = auth_message.encode("utf-8")
    expected_sig = hmac.new(server_secret, msg_bytes, hashlib.sha256).digest()
    return hmac.compare_digest(proof_bytes, expected_sig)


def generate_synthetic_salt(username: str, pepper: bytes = Config.SERVER_PEPPER) -> str:
    """
    Generate deterministic synthetic salt for non-existent users.
    Ensures that challenge requests for unknown users return normal-looking,
    consistent salts without leaking whether the account exists in the database.
    """
    synthetic_hash = hmac.new(pepper, username.lower().strip().encode("utf-8"), hashlib.sha256).hexdigest()
    return synthetic_hash[:32]  # 16 bytes = 32 hex chars

