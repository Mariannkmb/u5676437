from pathlib import Path
import os
import base64
import json
import hashlib
import hmac
from typing import Optional, Dict, Any

from crypto_utils import (
    generate_aes_key,
    encrypt_data,
    decrypt_data,
    encrypt_key_with_rsa,
    decrypt_key_with_rsa
)

BASE_DIR = Path(__file__).resolve().parent

USERS_FILE = BASE_DIR / "data" / "auth" / "users.bin"
USERS_KEY_FILE = BASE_DIR / "data" / "auth" / "users_key.json"

ADMIN_PUBLIC_KEY = str(BASE_DIR / "keys" / "admin1_public.pem")
ADMIN_PRIVATE_KEY = str(BASE_DIR / "keys" / "admin1_private.pem")
#PBKDF2 is configured with 100,000 iterations to increase resistance against brute-force attacks.
PBKDF2_ITERATIONS = 100000

# Load and decrypt the encrypted user registry.
# Passwords are stored as salted PBKDF2 hashes, not plaintext.
def load_users() -> list[dict]:
    if not USERS_FILE.exists() or not USERS_KEY_FILE.exists():
        return []

    try:
        with open(USERS_FILE, "rb") as file:
            encrypted_data = file.read()

        nonce = encrypted_data[:12]
        ciphertext = encrypted_data[12:]

        with open(USERS_KEY_FILE, "r", encoding="utf-8") as key_file:
            key_data = json.load(key_file)

        encrypted_aes_key = base64.b64decode(key_data["encrypted_key"])
        aes_key = decrypt_key_with_rsa(encrypted_aes_key, ADMIN_PRIVATE_KEY)

        plaintext = decrypt_data(nonce, ciphertext, aes_key)
        users = json.loads(plaintext)

        return users if isinstance(users, list) else []

    except Exception:
        print("Failed to load user registry securely.")
        return []

# Encrypt and save the user registry.
# The registry is encrypted with AES-GCM and the AES key is protected with RSA-OAEP.
def save_users(users: list[dict]) -> None:
    try:
        USERS_FILE.parent.mkdir(parents=True, exist_ok=True)

        plaintext = json.dumps(users, indent=2)

        if USERS_KEY_FILE.exists():
            with open(USERS_KEY_FILE, "r", encoding="utf-8") as key_file:
                key_data = json.load(key_file)

            encrypted_aes_key = base64.b64decode(key_data["encrypted_key"])
            aes_key = decrypt_key_with_rsa(encrypted_aes_key, ADMIN_PRIVATE_KEY)

        else:
            aes_key = generate_aes_key()
            encrypted_aes_key = encrypt_key_with_rsa(aes_key, ADMIN_PUBLIC_KEY)

            with open(USERS_KEY_FILE, "w", encoding="utf-8") as key_file:
                json.dump(
                    {"encrypted_key": base64.b64encode(encrypted_aes_key).decode("utf-8")},
                    key_file,
                    indent=2
                )

        nonce, ciphertext = encrypt_data(plaintext, aes_key)

        with open(USERS_FILE, "wb") as file:
            file.write(nonce + ciphertext)

    except Exception as error:
        print(f"An error occurred while saving users securely: {error}")

# Generate a random salt for password hashing.
def generate_salt() -> str:
    salt = os.urandom(16)
    return base64.b64encode(salt).decode("utf-8")

# Derive a password hash using PBKDF2-HMAC-SHA256.
def hash_password(password: str, salt_b64: str) -> str:
    salt = base64.b64decode(salt_b64)

    password_hash = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        PBKDF2_ITERATIONS
    )

    return base64.b64encode(password_hash).decode("utf-8")

# Create a user with a salted password hash and role.
def create_user(username: str, password: str, role: str) -> bool:
    users = load_users()

    for user in users:
        if user["username"] == username:
            print("User already exists.")
            return False

    salt = generate_salt()
    password_hash = hash_password(password, salt)

    user_entry = {
        "username": username,
        "password_hash": password_hash,
        "salt": salt,
        "role": role
    }

    users.append(user_entry)
    save_users(users)

    print(f"User '{username}' created successfully.")
    print("User registry encrypted successfully.")
    return True

# Authenticate a user by recomputing the password hash and comparing it safely.
def authenticate(username: str, password: str) -> Optional[Dict[str, Any]]:
    users = load_users()

    for user in users:
        if user["username"] == username:
            salt = user["salt"]
            expected_hash = user["password_hash"]
            provided_hash = hash_password(password, salt)

            if hmac.compare_digest(provided_hash, expected_hash):
                return user

    return None