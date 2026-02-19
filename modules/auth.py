import hashlib
import csv
import os

# Path to user database
USER_DB_FILE = "data/users.csv"


# ---------------- PASSWORD UTILS ----------------

def hash_password(password: str) -> str:
    """Hash password using SHA-256"""
    return hashlib.sha256(password.encode()).hexdigest()


def verify_password(password: str, hashed: str) -> bool:
    """Verify password against stored hash"""
    return hash_password(password) == hashed


# ---------------- USER STORAGE ----------------

def load_users() -> dict:
    """
    Load users from CSV file.
    Returns: {username: password_hash}
    """
    users = {}

    # Create file if not exists
    if not os.path.exists(USER_DB_FILE):
        os.makedirs(os.path.dirname(USER_DB_FILE), exist_ok=True)
        with open(USER_DB_FILE, "w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(["username", "password_hash"])
        return users

    with open(USER_DB_FILE, "r", newline="") as f:
        reader = csv.DictReader(f)
        for row in reader:
            users[row["username"]] = row["password_hash"]

    return users


def register_user(username: str, password: str) -> bool:
    """
    Register a new user.
    Returns True if success, False if user exists.
    """
    users = load_users()

    if username in users:
        return False

    with open(USER_DB_FILE, "a", newline="") as f:
        writer = csv.writer(f)
        writer.writerow([username, hash_password(password)])

    return True


def authenticate_user(username: str, password: str) -> bool:
    """
    Authenticate existing user.
    """
    users = load_users()

    if username not in users:
        return False

    return verify_password(password, users[username])
