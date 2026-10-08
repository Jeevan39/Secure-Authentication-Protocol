"""Secure verifier storage, Argon2id sealing, constant-time verification, and cryptographic trade-off analysis."""

import time
import hmac
import hashlib
from typing import Dict, Tuple, Any
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from config import Config

# Initialize Argon2id PasswordHasher with RFC 9106 recommended parameters
# memory_cost=65536 KiB (64 MB), time_cost=3 iterations, parallelism=4 threads
argon2id_hasher = PasswordHasher(
    time_cost=3,
    memory_cost=65536,
    parallelism=4,
    hash_len=32,
    salt_len=16,
)


def constant_time_compare(val_a: bytes, val_b: bytes) -> bool:
    """
    Perform constant-time byte comparison using hmac.compare_digest.
    Guarantees timing-invariant comparison, preventing side-channel timing attacks.
    """
    return hmac.compare_digest(val_a, val_b)


def seal_verifier_with_argon2id(stored_key_hex: str, pepper: bytes = Config.SERVER_PEPPER) -> str:
    """
    Apply Argon2id memory-hard sealing to stored verifiers at rest.
    Combines stored_key with server_pepper before hashing, ensuring that even if an attacker
    steals the database file, they face a memory-hard envelope bound to the server secret.
    """
    combined = hmac.new(pepper, stored_key_hex.encode("utf-8"), hashlib.sha256).hexdigest()
    return argon2id_hasher.hash(combined)


def verify_sealed_verifier(stored_key_hex: str, seal: str, pepper: bytes = Config.SERVER_PEPPER) -> bool:
    """
    Verify the integrity of a stored verifier against its Argon2id seal.
    """
    combined = hmac.new(pepper, stored_key_hex.encode("utf-8"), hashlib.sha256).hexdigest()
    try:
        return argon2id_hasher.verify(seal, combined)
    except (VerifyMismatchError, Exception):
        return False


def explain_cryptographic_conflict() -> Dict[str, Any]:
    """
    Demonstrate the mathematical reason why traditional Argon2id password hashing
    cannot be used directly as the HMAC key for challenge-response authentication.
    """
    password = "DemonstrationPassword123!"  # nosec B105
    
    # 1. Standard Argon2id produces a formatted string containing salt and parameters
    argon_hash = argon2id_hasher.hash(password)
    
    # 2. Challenge-response requires HMAC: HMAC(Key, Challenge)
    # If the server stores argon_hash and uses it as Key:
    # Any attacker who dumps the database obtains argon_hash, which IS Key!
    # The attacker can immediately compute HMAC(argon_hash, Challenge) without knowing password!
    # This is the classic "Pass-the-Hash / Pass-the-Verifier" vulnerability.
    
    # 3. Why the SCRAM model is safer:
    # Client computes: ClientKey = HMAC(PBKDF2(Password), "client-key")
    # Client computes: StoredKey = SHA256(ClientKey)
    # Server stores ONLY StoredKey.
    # To answer a challenge, the client MUST supply ClientKey (masked by HMAC).
    # Since the database only has StoredKey, an attacker with the database CANNOT
    # answer challenges because inverting SHA-256 to recover ClientKey is computationally infeasible.
    
    return {
        "vulnerability_name": "Pass-the-Hash / Pass-the-Verifier",
        "argon2id_role": "Memory-hard one-way function designed for verify(pw, hash), not symmetric HMAC keying",
        "scram_solution": "Dual-key derivation with one-way SHA-256 separation between ClientKey and StoredKey",
        "argon_sample_format": argon_hash[:30] + "...",
    }


def benchmark_kdf_costs(iterations_pbkdf2: int = Config.PBKDF2_ITERATIONS) -> Dict[str, float]:
    """
    Benchmark the execution latency of PBKDF2 (100k iterations), Argon2id (64MB), and HMAC verification.
    Demonstrates why applying Argon2id on per-challenge requests causes Denial-of-Service risks.
    """
    sample_password = "BenchmarkPassword123!"  # nosec B105
    sample_salt = b"0123456789abcdef"

    # 1. Measure PBKDF2-HMAC-SHA256 (Client-side key derivation)
    start = time.perf_counter()
    _ = hashlib.pbkdf2_hmac("sha256", sample_password.encode("utf-8"), sample_salt, iterations_pbkdf2, 32)
    pbkdf2_duration_ms = (time.perf_counter() - start) * 1000

    # 2. Measure Argon2id (Server-side password hashing / sealing)
    start = time.perf_counter()
    _ = argon2id_hasher.hash(sample_password)
    argon2id_duration_ms = (time.perf_counter() - start) * 1000

    # 3. Measure HMAC-SHA256 Challenge Verification (Critical path during login)
    stored_key = hashlib.sha256(b"sample-client-key").digest()
    auth_msg = b"SAP-v1.0|context|user|client_nonce|server_nonce"
    start = time.perf_counter()
    for _ in range(100):
        _ = hmac.new(stored_key, auth_msg, hashlib.sha256).digest()
    hmac_duration_ms = ((time.perf_counter() - start) / 100) * 1000

    return {
        "pbkdf2_100k_ms": round(pbkdf2_duration_ms, 2),
        "argon2id_64mb_ms": round(argon2id_duration_ms, 2),
        "hmac_sha256_single_ms": round(hmac_duration_ms, 4),
    }

