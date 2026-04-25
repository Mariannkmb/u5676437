from datetime import datetime
from pathlib import Path
import json
import base64

from crypto_utils import (
    generate_aes_key,
    encrypt_data,
    decrypt_data,
    encrypt_key_with_rsa,
    decrypt_key_with_rsa
)

BASE_DIR = Path(__file__).resolve().parent
LOG_FILE = BASE_DIR / "data" / "logs" / "logs.bin"
LOG_KEY_FILE = BASE_DIR / "data" / "logs" / "log_key.json"

ADMIN_PUBLIC_KEY = str(BASE_DIR / "keys" / "admin1_public.pem")
ADMIN_PRIVATE_KEY = str(BASE_DIR / "keys" / "admin1_private.pem")


# Load decrypted logs from encrypted storage
def load_logs() -> list[dict]:
    if not LOG_FILE.exists() or not LOG_KEY_FILE.exists():
        return []

    try:
        # Read encrypted log file
        with open(LOG_FILE, "rb") as file:
            encrypted_data = file.read()

        nonce = encrypted_data[:12]
        ciphertext = encrypted_data[12:]

        # Read encrypted AES key
        with open(LOG_KEY_FILE, "r", encoding="utf-8") as key_file:
            key_data = json.load(key_file)

        encrypted_aes_key = base64.b64decode(key_data["encrypted_key"])

        # Decrypt AES key using admin private key
        aes_key = decrypt_key_with_rsa(encrypted_aes_key, ADMIN_PRIVATE_KEY)

        # Decrypt logs content
        plaintext = decrypt_data(nonce, ciphertext, aes_key)

        return json.loads(plaintext)

    except Exception as error:
        print(f"An error occurred while loading logs: {error}")
        return []


# Save logs in encrypted form
def save_logs(logs: list[dict]) -> None:
    try:
        # Convert logs list to JSON string
        plaintext = json.dumps(logs, indent=2)

        # Check if encrypted AES key already exists
        if LOG_KEY_FILE.exists():
            with open(LOG_KEY_FILE, "r", encoding="utf-8") as key_file:
                key_data = json.load(key_file)

            encrypted_aes_key = base64.b64decode(key_data["encrypted_key"])
            aes_key = decrypt_key_with_rsa(encrypted_aes_key, ADMIN_PRIVATE_KEY)

        else:
            # Generate new AES key for logs
            aes_key = generate_aes_key()

            # Protect AES key using admin public key
            encrypted_aes_key = encrypt_key_with_rsa(aes_key, ADMIN_PUBLIC_KEY)

            with open(LOG_KEY_FILE, "w", encoding="utf-8") as key_file:
                json.dump(
                    {"encrypted_key": base64.b64encode(encrypted_aes_key).decode("utf-8")},
                    key_file,
                    indent=2
                )

        # Encrypt logs content
        nonce, ciphertext = encrypt_data(plaintext, aes_key)

        with open(LOG_FILE, "wb") as file:
            file.write(nonce + ciphertext)

    except Exception as error:
        print(f"An error occurred while saving logs: {error}")


# Add a new log entry
def log_action(username: str, role: str, action: str, status: str, details: str = "") -> None:
    logs = load_logs()

    entry = {
        "timestamp": datetime.now().isoformat(timespec="seconds"),
        "username": username,
        "role": role,
        "action": action,
        "status": status,
        "details": details
    }

    logs.append(entry)
    save_logs(logs)


# Return logs for auditor/admin view
def get_logs() -> list[dict]:
    return load_logs()

def print_logs(logs: list[dict]) -> None:
    if not logs:
        print("No logs available.")
        return

    WIDTH = 120  # fixed width for log display

    def truncate(text: str, max_len: int) -> str:
        return text[:max_len - 3] + "..." if len(text) > max_len else text

    print("\n" + "=" * WIDTH)
    print(" AUDIT LOGS ".center(WIDTH))
    print("=" * WIDTH)

    header = f"{'Timestamp':19} | {'User':10} | {'Role':10} | {'Action':18} | {'Status':8} | {'Details':40}"
    print(header)
    print("-" * WIDTH)

    for entry in logs:
        timestamp = truncate(entry.get("timestamp", "N/A"), 19)
        username = truncate(entry.get("username", "N/A"), 10)
        role = truncate(entry.get("role", "N/A"), 10)
        action = truncate(entry.get("action", "N/A"), 18)
        status = truncate(entry.get("status", "N/A"), 8)
        details = truncate(entry.get("details", ""), 40)

        line = f"{timestamp:19} | {username:10} | {role:10} | {action:18} | {status:8} | {details:40}"
        print(line)

    print("=" * WIDTH)