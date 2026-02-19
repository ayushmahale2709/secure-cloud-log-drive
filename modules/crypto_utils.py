import os
from cryptography.fernet import Fernet

# Path to encryption key
KEY_FILE = "data/secret.key"


# ---------------- KEY MANAGEMENT ----------------

def load_key() -> bytes:
    os.makedirs("data", exist_ok=True)

    if not os.path.exists(KEY_FILE):
        key = Fernet.generate_key()
        with open(KEY_FILE, "wb") as f:
            f.write(key)
    else:
        with open(KEY_FILE, "rb") as f:
            key = f.read()

    return key



def get_cipher() -> Fernet:
    """
    Return Fernet cipher object.
    """
    key = load_key()
    return Fernet(key)


# ---------------- ENCRYPT / DECRYPT ----------------

def encrypt_data(plain_text: str) -> str:
    """
    Encrypt plain text data.
    Returns encrypted string.
    """
    cipher = get_cipher()
    encrypted = cipher.encrypt(plain_text.encode())
    return encrypted.decode()


def decrypt_data(encrypted_text: str) -> str:
    """
    Decrypt encrypted data.
    Returns plain text.
    """
    cipher = get_cipher()
    decrypted = cipher.decrypt(encrypted_text.encode())
    return decrypted.decode()
