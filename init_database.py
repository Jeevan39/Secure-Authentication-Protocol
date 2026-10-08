"""Initialize the application SQLite database and verify tables and schema."""

from pathlib import Path
from config import Config
from database import init_db, get_db_connection


def main() -> None:
    print(f"[*] Initializing database at: {Config.DATABASE_PATH}")
    init_db()

    # Verify tables and schema
    conn = get_db_connection()
    cursor = conn.execute("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name;")
    tables = [row["name"] for row in cursor.fetchall() if not row["name"].startswith("sqlite_")]
    print(f"[+] Initialized tables ({len(tables)}): {', '.join(tables)}")

    cursor = conn.execute("SELECT name FROM sqlite_master WHERE type='index' ORDER BY name;")
    indexes = [row["name"] for row in cursor.fetchall() if not row["name"].startswith("sqlite_")]
    print(f"[+] Initialized indexes ({len(indexes)}): {', '.join(indexes)}")
    conn.close()

    print("\n[SUCCESS] Database schema initialized and ready for authentication protocol operations.")


if __name__ == "__main__":
    main()

