import sqlite3
from datetime import datetime
from pathlib import Path
from typing import Optional

DB_PATH = Path.home() / ".securevault" / "vault.db"


def get_connection() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def initialize_database() -> None:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)

    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS vault_config (
            id          INTEGER PRIMARY KEY,
            salt        BLOB    NOT NULL,
            pw_hash     TEXT    NOT NULL,
            created_at  TEXT    NOT NULL
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS credentials (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            service     TEXT    NOT NULL,
            login       TEXT    NOT NULL,
            password    TEXT    NOT NULL,
            notes       TEXT,
            created_at  TEXT    NOT NULL
        )
    """)

    conn.commit()
    conn.close()


def is_initialized() -> bool:
    if not DB_PATH.exists():
        return False

    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) FROM vault_config")
    count = cursor.fetchone()[0]
    conn.close()

    return count > 0


def save_vault_config(salt: bytes, pw_hash: str) -> None:
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO vault_config (salt, pw_hash, created_at) VALUES (?, ?, ?)",
        (salt, pw_hash, datetime.now().isoformat())
    )
    conn.commit()
    conn.close()


def get_vault_config() -> Optional[sqlite3.Row]:
    if not DB_PATH.exists():
        return None

    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM vault_config LIMIT 1")
    config = cursor.fetchone()
    conn.close()

    return config


def add_credential(
    service: str,
    login: str,
    encrypted_password: str,
    notes: Optional[str] = None
) -> int:
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute(
        """
        INSERT INTO credentials (service, login, password, notes, created_at)
        VALUES (?, ?, ?, ?, ?)
        """,
        (service, login, encrypted_password, notes, datetime.now().isoformat())
    )
    new_id = cursor.lastrowid
    conn.commit()
    conn.close()

    return new_id


def get_all_credentials() -> list:
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT id, service, login, created_at FROM credentials ORDER BY service")
    rows = cursor.fetchall()
    conn.close()

    return rows


def get_credential_by_service(service: str) -> Optional[sqlite3.Row]:
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute(
        "SELECT * FROM credentials WHERE LOWER(service) = LOWER(?)",
        (service,)
    )
    row = cursor.fetchone()
    conn.close()

    return row


def delete_credential(credential_id: int) -> bool:
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM credentials WHERE id = ?", (credential_id,))
    deleted = cursor.rowcount > 0
    conn.commit()
    conn.close()

    return deleted