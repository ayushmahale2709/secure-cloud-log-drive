import hashlib
import csv
import os

USER_DB_FILE = "data/users.csv"


# ---------------- PASSWORD UTILS ----------------

def hash_password(password: str) -> str:
    return hashlib.sha256(password.encode()).hexdigest()


def verify_password(password: str, hashed: str) -> bool:
    return hash_password(password) == hashed


# ---------------- USER STORAGE ----------------

def ensure_user_file():
    """
    Ensure users.csv exists with correct headers.
    """
    os.makedirs(os.path.dirname(USER_DB_FILE), exist_ok=True)

    if not os.path.exists(USER_DB_FILE):
        with open(USER_DB_FILE, "w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(["username", "password_hash"])


def load_users() -> dict:
    """
    Safely load users from CSV.
    Returns: {username: password_hash}
    """
    ensure_user_file()
    users = {}

    with open(USER_DB_FILE, "r", newline="") as f:
        reader = csv.DictReader(f)

        # Validate headers
        if not reader.fieldnames or \
           "username" not in reader.fieldnames or \
           "password_hash" not in reader.fieldnames:
            return users  # corrupted file → treat as empty

        for row in reader:
            username = row.get("username")
            password_hash = row.get("password_hash")

            if username and password_hash:
                users[username] = password_hash

    return users


def register_user(username: str, password: str) -> bool:
    """
    Register a new user.
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
