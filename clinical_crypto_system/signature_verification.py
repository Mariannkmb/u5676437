from pathlib import Path
import base64
import json
import os

from argon2.low_level import hash_secret_raw, Type
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidSignature


BASE_DIR = Path(__file__).resolve().parent
KEYS_DIR = BASE_DIR / "keys"

ARGON2_TIME_COST = 2
ARGON2_MEMORY_COST = 65536
ARGON2_PARALLELISM = 2
ARGON2_HASH_LEN = 32


def ensure_keys_directory() -> None:
    KEYS_DIR.mkdir(parents=True, exist_ok=True)


def get_user_key_paths(username: str) -> tuple[Path, Path, Path]:
    private_key_path = KEYS_DIR / f"{username}_private.pem"
    encrypted_private_key_path = KEYS_DIR / f"{username}_private.pem.enc"
    public_key_path = KEYS_DIR / f"{username}_public.pem"
    return private_key_path, encrypted_private_key_path, public_key_path


def derive_key_from_passphrase(passphrase: str, salt: bytes) -> bytes:
    return hash_secret_raw(
        secret=passphrase.encode("utf-8"),
        salt=salt,
        time_cost=ARGON2_TIME_COST,
        memory_cost=ARGON2_MEMORY_COST,
        parallelism=ARGON2_PARALLELISM,
        hash_len=ARGON2_HASH_LEN,
        type=Type.ID,
    )


def encrypt_private_key_pem(private_key_pem: bytes, passphrase: str) -> dict:
    salt = os.urandom(16)
    nonce = os.urandom(12)
    aes_key = derive_key_from_passphrase(passphrase, salt)

    aesgcm = AESGCM(aes_key)
    ciphertext = aesgcm.encrypt(nonce, private_key_pem, None)

    return {
        "kdf": "Argon2id",
        "encryption": "AES-256-GCM",
        "salt": base64.b64encode(salt).decode("utf-8"),
        "nonce": base64.b64encode(nonce).decode("utf-8"),
        "ciphertext": base64.b64encode(ciphertext).decode("utf-8"),
    }


def decrypt_private_key_pem(encrypted_record: dict, passphrase: str) -> bytes:
    salt = base64.b64decode(encrypted_record["salt"])
    nonce = base64.b64decode(encrypted_record["nonce"])
    ciphertext = base64.b64decode(encrypted_record["ciphertext"])

    aes_key = derive_key_from_passphrase(passphrase, salt)
    aesgcm = AESGCM(aes_key)

    return aesgcm.decrypt(nonce, ciphertext, None)


def generate_rsa_keypair(username: str, passphrase: str | None = None) -> None:
    ensure_keys_directory()
    private_key_path, encrypted_private_key_path, public_key_path = get_user_key_paths(username)

    if public_key_path.exists() and (private_key_path.exists() or encrypted_private_key_path.exists()):
        return

    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )

    public_key = private_key.public_key()

    private_key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    if passphrase:
        encrypted_record = encrypt_private_key_pem(private_key_pem, passphrase)

        with open(encrypted_private_key_path, "w", encoding="utf-8") as private_file:
            json.dump(encrypted_record, private_file, indent=2)
    else:
        with open(private_key_path, "wb") as private_file:
            private_file.write(private_key_pem)

    with open(public_key_path, "wb") as public_file:
        public_file.write(
            public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
        )


def load_private_key(username: str, passphrase: str | None = None):
    private_key_path, encrypted_private_key_path, _ = get_user_key_paths(username)

    if encrypted_private_key_path.exists():
        if not passphrase:
            raise ValueError("Private key passphrase is required.")

        with open(encrypted_private_key_path, "r", encoding="utf-8") as private_file:
            encrypted_record = json.load(private_file)

        private_key_pem = decrypt_private_key_pem(encrypted_record, passphrase)

        return serialization.load_pem_private_key(
            private_key_pem,
            password=None
        )

    with open(private_key_path, "rb") as private_file:
        return serialization.load_pem_private_key(
            private_file.read(),
            password=None
        )


def load_public_key(username: str):
    _, _, public_key_path = get_user_key_paths(username)

    with open(public_key_path, "rb") as public_file:
        return serialization.load_pem_public_key(public_file.read())


def sign_text(username: str, text: str, passphrase: str | None = None) -> str:
    private_key = load_private_key(username, passphrase)

    signature = private_key.sign(
        text.encode("utf-8"),
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

    return base64.b64encode(signature).decode("utf-8")


def verify_text_signature(username: str, text: str, signature_b64: str) -> bool:
    try:
        public_key = load_public_key(username)
        signature = base64.b64decode(signature_b64)

        public_key.verify(
            signature,
            text.encode("utf-8"),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )

        return True

    except (InvalidSignature, ValueError, TypeError, FileNotFoundError, KeyError):
        return False