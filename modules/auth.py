import sqlite3
import hashlib
import os

DB_PATH = "data/auth.db"


# ---------------- DB INIT ----------------

def get_connection():
    os.makedirs("data", exist_ok=True)
    return sqlite3.connect(DB_PATH, check_same_thread=False)


def init_auth_db():
    conn = get_connection()
    conn.execute("""
        CREATE TABLE IF NOT EXISTS users (
            username TEXT PRIMARY KEY,
            password_hash TEXT NOT NULL
        )
    """)
    conn.commit()
    conn.close()


# ---------------- PASSWORD UTILS ----------------

def hash_password(password: str) -> str:
    return hashlib.sha256(password.encode()).hexdigest()


# ---------------- AUTH LOGIC ----------------

def register_user(username: str, password: str) -> bool:
    username = username.strip().lower()
    init_auth_db()

    conn = get_connection()
    cur = conn.cursor()

    cur.execute("SELECT username FROM users WHERE username=?", (username,))
    if cur.fetchone():
        conn.close()
        return False

    cur.execute(
        "INSERT INTO users (username, password_hash) VALUES (?, ?)",
        (username, hash_password(password))
    )
    conn.commit()
    conn.close()
    return True


def authenticate_user(username: str, password: str) -> bool:
    username = username.strip().lower()
    init_auth_db()

    conn = get_connection()
    cur = conn.cursor()

    cur.execute(
        "SELECT password_hash FROM users WHERE username=?",
        (username,)
    )
    row = cur.fetchone()
    conn.close()

    if not row:
        return False

    return row[0] == hash_password(password)
