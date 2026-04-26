import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
# imports para RSA-OAEP
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding


## Generate a 256-bit AES key.
# A new AES key is used to encrypt each sensitive file.
def generate_aes_key() -> bytes:
    return AESGCM.generate_key(bit_length=256)

# Encrypt plaintext using AES-256-GCM.
# GCM provides confidentiality and detects tampering through authenticated encryption.
def encrypt_data(plaintext: str, key: bytes) -> tuple[bytes, bytes]: 
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    ciphertext = aesgcm.encrypt(nonce, plaintext.encode("utf-8"), None)
    return nonce, ciphertext

# Decrypt AES-GCM ciphertext.
# If the ciphertext or nonce has been modified, decryption fails.
def decrypt_data(nonce: bytes, ciphertext: bytes, key: bytes) -> str:
    aesgcm = AESGCM(key)
    plaintext = aesgcm.decrypt(nonce, ciphertext, None)
    return plaintext.decode("utf-8")


# Load an RSA public key from a PEM file.
# Public keys are used to protect AES keys.
def load_public_key_from_file(public_key_path: str):
    with open(public_key_path, "rb") as key_file:
        return serialization.load_pem_public_key(key_file.read())


# Load an RSA private key from a PEM file.
# Private keys are used only when recovering protected AES keys.
# DEMO NOTE:
# In this academic/demo version, the admin private key is loaded without a passphrase
# to keep the command-line workflow simple.
# In production, this key should be protected using a passphrase, KMS, Vault, or HSM.
def load_private_key_from_file(private_key_path: str):
    with open(private_key_path, "rb") as key_file:
        return serialization.load_pem_private_key(
            key_file.read(),
            password=None
        )

# Protect an AES key using RSA-OAEP.
# The system uses hybrid encryption: AES protects data, RSA protects AES keys.
def encrypt_key_with_rsa(aes_key: bytes, public_key_path: str) -> bytes:
    public_key = load_public_key_from_file(public_key_path)

    encrypted_key = public_key.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return encrypted_key


# Recover an AES key protected with RSA-OAEP.
# If the protected key has been altered, decryption fails.
def decrypt_key_with_rsa(encrypted_key: bytes, private_key_path: str) -> bytes:
    private_key = load_private_key_from_file(private_key_path)

    decrypted_key = private_key.decrypt(
        encrypted_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    return decrypted_key