from pathlib import Path
import json
import hashlib
import base64

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.exceptions import InvalidSignature


BASE_DIR = Path(__file__).resolve().parent

USERS_FILE = BASE_DIR / "data" / "auth" / "users.bin"
USERS_KEY_FILE = BASE_DIR / "data" / "auth" / "users_key.json"
INTEGRITY_FILE = BASE_DIR / "data" / "auth" / "users_integrity.json"

ADMIN_PRIVATE_KEY = BASE_DIR / "keys" / "admin1_private.pem"
ADMIN_PUBLIC_KEY = BASE_DIR / "keys" / "admin1_public.pem"


# Calculate a SHA-256 hash of a file so later changes can be detected.
def sha256_file(file_path: Path) -> str:
    data = file_path.read_bytes()
    return hashlib.sha256(data).hexdigest()


# Build the exact payload that will be signed and later verified.
# Both the encrypted user registry and its protected AES key are included.
def build_payload_dict() -> dict:
    return {
        "users.bin": sha256_file(USERS_FILE),
        "users_key.json": sha256_file(USERS_KEY_FILE),
    }


# Sign the current user registry state using the admin private key.
# This is called after users were created.
def sign_user_registry_integrity() -> None:
    if not USERS_FILE.exists():
        raise FileNotFoundError("users.bin is missing.")
    if not USERS_KEY_FILE.exists():
        raise FileNotFoundError("users_key.json is missing.")
    if not ADMIN_PRIVATE_KEY.exists():
        raise FileNotFoundError("admin1_private.pem is missing.")

    payload_dict = build_payload_dict()
    payload_bytes = json.dumps(payload_dict, sort_keys=True).encode("utf-8")

    with open(ADMIN_PRIVATE_KEY, "rb") as f:
        private_key = serialization.load_pem_private_key(f.read(), password=None)

    signature = private_key.sign(
        payload_bytes,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH,
        ),
        hashes.SHA256(),
    )

    integrity_record = {
        "files": payload_dict,
        "signature": base64.b64encode(signature).decode("utf-8"),
    }

    with open(INTEGRITY_FILE, "w", encoding="utf-8") as f:
        json.dump(integrity_record, f, indent=2)


# Verify the user registry before login is allowed.
# If the registry, protected key, or signature changes, access is blocked.
def verify_user_registry_integrity() -> tuple[bool, str]:
    if not USERS_FILE.exists():
        return False, "users.bin is missing."
    if not USERS_KEY_FILE.exists():
        return False, "users_key.json is missing."
    if not INTEGRITY_FILE.exists():
        return False, "users_integrity.json is missing."
    if not ADMIN_PUBLIC_KEY.exists():
        return False, "admin1_public.pem is missing."

    with open(INTEGRITY_FILE, "r", encoding="utf-8") as f:
        integrity_record = json.load(f)

    stored_files = integrity_record.get("files")
    signature_b64 = integrity_record.get("signature")

    if not isinstance(stored_files, dict) or not signature_b64:
        return False, "Integrity record is incomplete."

    current_files = build_payload_dict()

    if current_files != stored_files:
        return False, "User registry integrity check failed: files were modified."

    payload_bytes = json.dumps(stored_files, sort_keys=True).encode("utf-8")

    try:
        signature = base64.b64decode(signature_b64)
    except Exception:
        return False, "Integrity signature is not valid Base64."

    with open(ADMIN_PUBLIC_KEY, "rb") as f:
        public_key = serialization.load_pem_public_key(f.read())

    try:
        public_key.verify(
            signature,
            payload_bytes,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH,
            ),
            hashes.SHA256(),
        )
        return True, "Integrity check passed."
    except InvalidSignature:
        return False, "Integrity signature is invalid."