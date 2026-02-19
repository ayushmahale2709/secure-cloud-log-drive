import hashlib
import csv
import os

USER_DB_FILE = "data/users.csv"


# ---------------- PASSWORD UTILS ----------------

def hash_password(password: str) -> str:
    return hashlib.sha256(password.encode()).hexdigest()


def verify_password(password: str, hashed: str) -> bool:
    return hash_password(password) == hashed


# ---------------- FILE SAFETY ----------------

def ensure_user_file():
    os.makedirs("data", exist_ok=True)

    if not os.path.exists(USER_DB_FILE):
        with open(USER_DB_FILE, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(["username", "password_hash"])


# ---------------- USER STORAGE ----------------

def load_users() -> dict:
    ensure_user_file()
    users = {}

    with open(USER_DB_FILE, "r", newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)

        if not reader.fieldnames:
            return users

        for row in reader:
            username = row.get("username", "").strip().lower()
            password_hash = row.get("password_hash", "").strip()

            if username and password_hash:
                users[username] = password_hash

    return users


def register_user(username: str, password: str) -> bool:
    ensure_user_file()
    username = username.strip().lower()

    users = load_users()
    if username in users:
        return False

    # Write & flush immediately (important for Streamlit Cloud)
    with open(USER_DB_FILE, "a", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow([username, hash_password(password)])
        f.flush()
        os.fsync(f.fileno())

    return True


def authenticate_user(username: str, password: str) -> bool:
    username = username.strip().lower()
    users = load_users()

    if username not in users:
        return False

    return verify_password(password, users[username])
