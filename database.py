"""Database layer for the Secure Authentication Protocol using SQLite."""

import sqlite3
import time
from typing import Optional, Dict, Any, List
from pathlib import Path
from config import Config


def get_db_connection(db_path: Optional[str] = None) -> sqlite3.Connection:
    """Create and configure a SQLite connection with foreign keys and Row factory."""
    target_path = db_path or Config.DATABASE_PATH
    Path(target_path).parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(target_path)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON;")
    return conn


def init_db(db_path: Optional[str] = None) -> None:
    """Initialize database tables, constraints, and indexes."""
    conn = get_db_connection(db_path)
    with conn:
        # 1. Users Table
        # Note on schema design: The server stores 'stored_key'.
        # ServerProof is generated using an application-level secret (SERVER_PROOF_SECRET).
        # server_key is retained as nullable for backwards compatibility with legacy development databases.
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                salt TEXT NOT NULL,
                iterations INTEGER NOT NULL,
                stored_key TEXT NOT NULL,
                server_key TEXT DEFAULT NULL,
                failed_attempts INTEGER NOT NULL DEFAULT 0,
                locked_until INTEGER DEFAULT NULL,
                created_at INTEGER NOT NULL,
                role TEXT NOT NULL DEFAULT 'user' CHECK(role IN ('user', 'admin')),
                is_admin INTEGER DEFAULT 0,
                verifier_seal TEXT DEFAULT NULL
            );
            """
        )

        # Migration: Add is_admin column if it does not already exist
        try:
            conn.execute("ALTER TABLE users ADD COLUMN is_admin INTEGER DEFAULT 0;")
        except sqlite3.OperationalError:
            pass

        # Migration: Add role column if it does not already exist
        try:
            conn.execute("ALTER TABLE users ADD COLUMN role TEXT DEFAULT 'user';")
        except sqlite3.OperationalError:
            pass

        # Migration: Add verifier_seal column if it does not already exist
        try:
            conn.execute("ALTER TABLE users ADD COLUMN verifier_seal TEXT DEFAULT NULL;")
        except sqlite3.OperationalError:
            pass

        # Synchronize role and is_admin for consistency
        conn.execute("UPDATE users SET role = 'admin' WHERE is_admin = 1 AND (role IS NULL OR role = 'user');")
        conn.execute("UPDATE users SET is_admin = 1 WHERE role = 'admin';")

        # 2. Sessions Table
        # session_id_hash stores SHA-256 of the random session token.
        # Raw session cookies are never stored in the database.
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS sessions (
                session_id_hash TEXT PRIMARY KEY,
                user_id INTEGER NOT NULL,
                created_at INTEGER NOT NULL,
                last_seen INTEGER NOT NULL,
                expires_at INTEGER NOT NULL,
                revoked INTEGER NOT NULL DEFAULT 0,
                FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
            );
            """
        )

        # 3. Challenges Table
        # Single-use challenge records bound to nonces, context, and expiration.
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS challenges (
                id TEXT PRIMARY KEY,
                username TEXT NOT NULL,
                client_nonce TEXT NOT NULL,
                server_nonce TEXT NOT NULL,
                context TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                expires_at INTEGER NOT NULL,
                used INTEGER NOT NULL DEFAULT 0
            );
            """
        )

        # 4. Authentication Logs Table
        # Sensitive security audit trail. Passwords and proofs are strictly excluded.
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS auth_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                username_attempted TEXT NOT NULL,
                event TEXT NOT NULL,
                success INTEGER NOT NULL,
                ip_address TEXT NOT NULL,
                timestamp INTEGER NOT NULL,
                FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE SET NULL
            );
            """
        )

        # Indexes for query performance and rapid security lookups
        conn.execute("CREATE INDEX IF NOT EXISTS idx_users_username ON users (username);")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON sessions (user_id);")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_sessions_expires_at ON sessions (expires_at);")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_challenges_lookup ON challenges (id, used, expires_at);")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_challenges_username ON challenges (username);")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_auth_logs_timestamp ON auth_logs (timestamp);")

    conn.close()


# ==============================================================================
# USER DATA ACCESS METHODS
# ==============================================================================

def get_user_by_username(username: str, db_path: Optional[str] = None) -> Optional[sqlite3.Row]:
    """Retrieve a user record by username."""
    conn = get_db_connection(db_path)
    try:
        cursor = conn.execute("SELECT * FROM users WHERE username = ?;", (username,))
        return cursor.fetchone()
    finally:
        conn.close()


def get_user_by_id(user_id: int, db_path: Optional[str] = None) -> Optional[sqlite3.Row]:
    """Retrieve a user record by primary key id."""
    conn = get_db_connection(db_path)
    try:
        cursor = conn.execute("SELECT * FROM users WHERE id = ?;", (user_id,))
        return cursor.fetchone()
    finally:
        conn.close()


def create_user(
    username: str,
    salt: str,
    iterations: int,
    stored_key: str,
    server_key: Optional[str] = None,
    role: str = "user",
    is_admin: int = 0,
    verifier_seal: Optional[str] = None,
    db_path: Optional[str] = None,
) -> int:
    """Create a new user with verifier material, role, and optional Argon2id seal."""
    if role not in ("user", "admin"):
        raise ValueError("Invalid role specified.")
    admin_flag = 1 if role == "admin" or is_admin else 0
    conn = get_db_connection(db_path)
    try:
        with conn:
            cursor = conn.execute(
                """
                INSERT INTO users (username, salt, iterations, stored_key, server_key, created_at, role, is_admin, verifier_seal)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?);
                """,
                (username, salt, iterations, stored_key, server_key, int(time.time()), role, admin_flag, verifier_seal),
            )
            return cursor.lastrowid
    finally:
        conn.close()


def get_user_role(user_id: int, db_path: Optional[str] = None) -> Optional[str]:
    """Retrieve the authoritative server-side role for a user."""
    conn = get_db_connection(db_path)
    try:
        cursor = conn.execute("SELECT role FROM users WHERE id = ?;", (user_id,))
        row = cursor.fetchone()
        return row["role"] if row else None
    finally:
        conn.close()


def set_user_role(user_id: int, role: str, db_path: Optional[str] = None) -> bool:
    """Set user role with strict domain validation ('user' or 'admin')."""
    if role not in ("user", "admin"):
        raise ValueError("Invalid role specified.")
    is_admin = 1 if role == "admin" else 0
    conn = get_db_connection(db_path)
    try:
        with conn:
            cursor = conn.execute(
                "UPDATE users SET role = ?, is_admin = ? WHERE id = ?;",
                (role, is_admin, user_id),
            )
            return cursor.rowcount > 0
    finally:
        conn.close()


def record_failed_login(user_id: int, db_path: Optional[str] = None) -> int:
    """Increment failed login attempts and apply temporary lockout if threshold reached."""
    conn = get_db_connection(db_path)
    now = int(time.time())
    try:
        with conn:
            user = conn.execute("SELECT failed_attempts FROM users WHERE id = ?;", (user_id,)).fetchone()
            if not user:
                return 0
            new_attempts = user["failed_attempts"] + 1
            locked_until = None
            if new_attempts >= Config.MAX_FAILED_ATTEMPTS:
                locked_until = now + Config.LOCKOUT_DURATION_SECONDS
            conn.execute(
                "UPDATE users SET failed_attempts = ?, locked_until = ? WHERE id = ?;",
                (new_attempts, locked_until, user_id),
            )
            return new_attempts
    finally:
        conn.close()


def reset_failed_login(user_id: int, db_path: Optional[str] = None) -> None:
    """Reset failed attempts and clear lockout on successful authentication."""
    conn = get_db_connection(db_path)
    try:
        with conn:
            conn.execute(
                "UPDATE users SET failed_attempts = 0, locked_until = NULL WHERE id = ?;",
                (user_id,),
            )
    finally:
        conn.close()


# ==============================================================================
# CHALLENGE DATA ACCESS METHODS
# ==============================================================================

def create_challenge(
    challenge_id: str,
    username: str,
    client_nonce: str,
    server_nonce: str,
    context: str,
    ttl_seconds: int = Config.CHALLENGE_TTL_SECONDS,
    db_path: Optional[str] = None,
) -> None:
    """Store an ephemeral challenge record."""
    now = int(time.time())
    expires_at = now + ttl_seconds
    conn = get_db_connection(db_path)
    try:
        with conn:
            conn.execute(
                """
                INSERT INTO challenges (id, username, client_nonce, server_nonce, context, created_at, expires_at, used)
                VALUES (?, ?, ?, ?, ?, ?, ?, 0);
                """,
                (challenge_id, username, client_nonce, server_nonce, context, now, expires_at),
            )
    finally:
        conn.close()


def get_challenge(challenge_id: str, db_path: Optional[str] = None) -> Optional[sqlite3.Row]:
    """Retrieve a challenge by identifier."""
    conn = get_db_connection(db_path)
    try:
        cursor = conn.execute("SELECT * FROM challenges WHERE id = ?;", (challenge_id,))
        return cursor.fetchone()
    finally:
        conn.close()


def consume_challenge_atomically(challenge_id: str, db_path: Optional[str] = None) -> bool:
    """
    Atomically mark a challenge as used.
    Returns True if the challenge was previously unused and marked used in this operation.
    Returns False if already used, preventing race-condition and replay attacks.
    """
    conn = get_db_connection(db_path)
    try:
        with conn:
            cursor = conn.execute(
                "UPDATE challenges SET used = 1 WHERE id = ? AND used = 0;",
                (challenge_id,),
            )
            return cursor.rowcount == 1
    finally:
        conn.close()


# ==============================================================================
# SESSION DATA ACCESS METHODS
# ==============================================================================

def create_session(
    session_id_hash: str,
    user_id: int,
    absolute_ttl: int = Config.SESSION_ABSOLUTE_TIMEOUT_SECONDS,
    db_path: Optional[str] = None,
) -> None:
    """Store a new hashed session record."""
    now = int(time.time())
    expires_at = now + absolute_ttl
    conn = get_db_connection(db_path)
    try:
        with conn:
            conn.execute(
                """
                INSERT INTO sessions (session_id_hash, user_id, created_at, last_seen, expires_at, revoked)
                VALUES (?, ?, ?, ?, ?, 0);
                """,
                (session_id_hash, user_id, now, now, expires_at),
            )
    finally:
        conn.close()


def get_session(session_id_hash: str, db_path: Optional[str] = None) -> Optional[sqlite3.Row]:
    """Retrieve an active session by token hash."""
    conn = get_db_connection(db_path)
    try:
        cursor = conn.execute("SELECT * FROM sessions WHERE session_id_hash = ?;", (session_id_hash,))
        return cursor.fetchone()
    finally:
        conn.close()


def update_session_activity(session_id_hash: str, db_path: Optional[str] = None) -> None:
    """Update last_seen timestamp to refresh idle timeout."""
    now = int(time.time())
    conn = get_db_connection(db_path)
    try:
        with conn:
            conn.execute(
                "UPDATE sessions SET last_seen = ? WHERE session_id_hash = ?;",
                (now, session_id_hash),
            )
    finally:
        conn.close()


def revoke_session(session_id_hash: str, db_path: Optional[str] = None) -> None:
    """Revoke an active session upon logout."""
    conn = get_db_connection(db_path)
    try:
        with conn:
            conn.execute(
                "UPDATE sessions SET revoked = 1 WHERE session_id_hash = ?;",
                (session_id_hash,),
            )
    finally:
        conn.close()


# ==============================================================================
# AUDIT LOGGING DATA ACCESS METHODS
# ==============================================================================

def log_auth_event(
    username: str,
    event: str,
    success: bool,
    ip_address: str,
    user_id: Optional[int] = None,
    db_path: Optional[str] = None,
) -> None:
    """Record an authentication event in the audit trail. Passwords and proofs are never logged."""
    conn = get_db_connection(db_path)
    try:
        with conn:
            conn.execute(
                """
                INSERT INTO auth_logs (user_id, username_attempted, event, success, ip_address, timestamp)
                VALUES (?, ?, ?, ?, ?, ?);
                """,
                (user_id, username, event, 1 if success else 0, ip_address, int(time.time())),
            )
    finally:
        conn.close()


def get_recent_auth_logs(limit: int = 50, db_path: Optional[str] = None) -> List[sqlite3.Row]:
    """Retrieve recent authentication logs for the security history dashboard."""
    conn = get_db_connection(db_path)
    try:
        cursor = conn.execute(
            "SELECT * FROM auth_logs ORDER BY timestamp DESC LIMIT ?;",
            (limit,),
        )
        return cursor.fetchall()
    finally:
        conn.close()


# ==============================================================================
# SERVER & ADMIN CONSOLE DATA ACCESS METHODS
# ==============================================================================

def get_all_users(db_path: Optional[str] = None) -> List[sqlite3.Row]:
    """Retrieve all enrolled users for the administrative console."""
    conn = get_db_connection(db_path)
    try:
        cursor = conn.execute(
            """
            SELECT id, username, salt, iterations, stored_key, failed_attempts, locked_until, created_at, is_admin
            FROM users
            ORDER BY id ASC;
            """
        )
        return cursor.fetchall()
    finally:
        conn.close()


def unlock_user_account(user_id: int, db_path: Optional[str] = None) -> bool:
    """Administratively clear failed attempts and unlock a locked account."""
    conn = get_db_connection(db_path)
    try:
        with conn:
            cursor = conn.execute(
                "UPDATE users SET failed_attempts = 0, locked_until = NULL WHERE id = ?;",
                (user_id,),
            )
            return cursor.rowcount == 1
    finally:
        conn.close()


def get_recent_challenges(limit: int = 25, db_path: Optional[str] = None) -> List[sqlite3.Row]:
    """Retrieve recent challenges for live ephemeral nonce inspection."""
    conn = get_db_connection(db_path)
    try:
        cursor = conn.execute(
            "SELECT * FROM challenges ORDER BY created_at DESC LIMIT ?;",
            (limit,),
        )
        return cursor.fetchall()
    finally:
        conn.close()


def get_system_stats(db_path: Optional[str] = None) -> Dict[str, Any]:
    """Retrieve aggregated server security telemetry."""
    now = int(time.time())
    conn = get_db_connection(db_path)
    try:
        user_count = conn.execute("SELECT COUNT(*) AS total FROM users;").fetchone()["total"]
        active_sessions = conn.execute(
            "SELECT COUNT(*) AS total FROM sessions WHERE revoked = 0 AND expires_at > ?;",
            (now,),
        ).fetchone()["total"]
        total_challenges = conn.execute("SELECT COUNT(*) AS total FROM challenges;").fetchone()["total"]
        consumed_challenges = conn.execute("SELECT COUNT(*) AS total FROM challenges WHERE used = 1;").fetchone()["total"]
        locked_accounts = conn.execute(
            "SELECT COUNT(*) AS total FROM users WHERE locked_until IS NOT NULL AND locked_until > ?;",
            (now,),
        ).fetchone()["total"]
        recent_failed_logins = conn.execute(
            "SELECT COUNT(*) AS total FROM auth_logs WHERE success = 0 AND timestamp > ?;",
            (now - 3600,),
        ).fetchone()["total"]

        return {
            "user_count": user_count,
            "active_sessions": active_sessions,
            "total_challenges": total_challenges,
            "consumed_challenges": consumed_challenges,
            "locked_accounts": locked_accounts,
            "recent_failed_logins": recent_failed_logins,
        }
    finally:
        conn.close()

