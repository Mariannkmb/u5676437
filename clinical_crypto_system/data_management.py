from pathlib import Path
from datetime import datetime
import base64
import json

from crypto_utils import (
    generate_aes_key,
    encrypt_data,
    decrypt_data,
    encrypt_key_with_rsa,
    decrypt_key_with_rsa
)

# Project base directory.
BASE_DIR = Path(__file__).resolve().parent
# Storage structure for datasets and their metadata and keys.
DATASETS_DIR = BASE_DIR / "data" / "datasets" / "files"
DATASET_KEYS_DIR = BASE_DIR / "data" / "datasets" / "keys"
DATASETS_METADATA_DIR = BASE_DIR / "data" / "datasets" / "metadata"

WIDTH = 100

# Admin RSA keys are used to protect and recover AES keys.
ADMIN_PUBLIC_KEY = str(BASE_DIR / "keys" / "admin1_public.pem")
ADMIN_PRIVATE_KEY = str(BASE_DIR / "keys" / "admin1_private.pem")

# Returns the path to the metadata file of a dataset given its code.
def get_dataset_meta_file_path(dataset_code: str) -> Path:
    return DATASETS_METADATA_DIR / f"{dataset_code}_meta.json"

# Returns the path to the encrypted AES key file of a dataset given its code.
def get_dataset_key_file_path(dataset_code: str) -> Path:
    return DATASET_KEYS_DIR / f"{dataset_code}_key.json"

# Loads all dataset metadata files from disk
# Each dataset has its own metadata file (no single point of failure)
# Corrupted files are skipped to avoid breaking the system
def load_dataset_metadata() -> list[dict]:
    DATASETS_METADATA_DIR.mkdir(parents=True, exist_ok=True)
    metadata = []
    for meta_file in sorted(DATASETS_METADATA_DIR.glob("DS-*_meta.json")):
        try:
            with open(meta_file, "r", encoding="utf-8") as file:
                metadata.append(json.load(file))
        except Exception:
            continue
    return metadata

# Saves metadata for a single dataset
# Metadata is stored separately from encrypted content for security and to allow listing datasets without decryption
def save_single_dataset_metadata(dataset: dict) -> None:
    DATASETS_METADATA_DIR.mkdir(parents=True, exist_ok=True)
    meta_file = get_dataset_meta_file_path(dataset["dataset_code"])
    with open(meta_file, "w", encoding="utf-8") as file:
        json.dump(dataset, file, indent=2)


# Generate dataset codes
# It scans existing metadata to avoid collisions and allows for non-sequential codes if some datasets are deleted.
def generate_dataset_code(metadata: list[dict]) -> str:
    numbers = []

    for dataset in metadata:
        code = dataset.get("dataset_code", "")
        if code.startswith("DS-"):
            try:
                numbers.append(int(code.split("-")[1]))
            except (IndexError, ValueError):
                continue

    return f"DS-{max(numbers, default=0) + 1:03d}"



# Prevents invalid characters that could break file paths or cause security issues.
def is_valid_patient_id(patient_id: str) -> bool:
    invalid_chars = ['/', '\\', ':', '*', '?', '"', '<', '>', '|']
    return not any(char in patient_id for char in invalid_chars)


# Creates a new dataset:
# 1. Collects user input
# 2. Encrypts content using AES-256-GCM
# 3. Protects the AES key using RSA-OAEP
# 4. Stores encrypted content, key, and metadata separately
def upload_dataset(user: dict) -> str | None:
    metadata = load_dataset_metadata()

    patient_id = input("Enter patient ID (e.g. P001): ").strip().upper()
    if not patient_id:
        print("Patient ID cannot be empty.")
        return None

    if not is_valid_patient_id(patient_id):
        print("Patient ID contains invalid characters.")
        return None
    
    DATASETS_DIR.mkdir(parents=True, exist_ok=True)
    DATASET_KEYS_DIR.mkdir(parents=True, exist_ok=True)
    DATASETS_METADATA_DIR.mkdir(parents=True, exist_ok=True)


    diagnosis = input("Enter diagnosis: ").strip()
    procedure = input("Enter procedure: ").strip()
    admission_type = input("Enter admission type: ").strip()
    length_of_stay = input("Enter length of stay: ").strip()

    if not diagnosis or not procedure or not admission_type or not length_of_stay:
        print("All dataset fields must be completed.")
        return None

    dataset_code = generate_dataset_code(metadata)
    file_name = f"{dataset_code}.bin"
    file_path = DATASETS_DIR / file_name

    # This is the sensitive clinical data that will be encrypted
    dataset_content = {
        "patient_id": patient_id,
        "diagnosis": diagnosis,
        "procedure": procedure,
        "admission_type": admission_type,
        "length_of_stay": length_of_stay
    }

    # Convert structured data to JSON string before encryption
    try:
        plaintext = json.dumps(dataset_content, indent=2)

        # Encrypt the dataset with a fresh AES key.
        aes_key = generate_aes_key()
        nonce, ciphertext = encrypt_data(plaintext, aes_key)

        with open(file_path, "wb") as file:
            file.write(nonce + ciphertext)

        # Protect the AES key with the admin public key.
        encrypted_aes_key = encrypt_key_with_rsa(aes_key, ADMIN_PUBLIC_KEY)

        # Store minimal metadata outside the encrypted dataset.
        dataset_entry = {
            "dataset_code": dataset_code,
            "file_name": file_name,
            "created_by": user["username"],
            "created_at": datetime.now().isoformat(timespec="seconds"),
            "encryption": "AES-256-GCM",
            "key_protection": "RSA-OAEP"
        }

        save_single_dataset_metadata(dataset_entry)

        key_file = get_dataset_key_file_path(dataset_code)

        # Encrypt the AES key using the admin public key (key encapsulation)
        with open(key_file, "w", encoding="utf-8") as file:
            json.dump(
                {"encrypted_key": base64.b64encode(encrypted_aes_key).decode("utf-8")},
                file,
                indent=2
            )

        print("-" * WIDTH)
        print(f"Dataset '{dataset_code}' uploaded and encrypted successfully.")
        print("AES-256-GCM protects the dataset content. The AES key is stored separately and protected with RSA-OAEP.")
        print("-" * WIDTH)

        return dataset_code

    except Exception as error:
        print(f"An error occurred while uploading the dataset: {error}")
        return None


# Lists datasets that still have a valid encrypted file
# Avoids showing orphan metadata entries
def list_datasets(title: str = "DATASETS") -> list[dict]:
    metadata = load_dataset_metadata()

    if not metadata:
        print("No datasets available.")
        return []

    available_metadata = []

    for dataset in metadata:
        file_name = dataset.get("file_name")
        if not file_name:
            continue

        file_path = DATASETS_DIR / file_name
        if file_path.exists():
            available_metadata.append(dataset)

    if not available_metadata:
        print("No datasets available.")
        return []

    print("\n" + "=" * WIDTH)
    print(f" {title} ".center(WIDTH))
    print("=" * WIDTH)
    print("Note: only datasets with valid encrypted files are listed.\n")

    print(f"{'No.':4} {'Code':8} {'Created by':12} {'Created at':20}")
    print("-" * WIDTH)

    for index, dataset in enumerate(available_metadata, start=1):
        print(
            f"{index:<4} "
            f"{dataset.get('dataset_code', 'DS-XXX'):8} "
            f"{dataset.get('created_by', 'Unknown'):12} "
            f"{dataset.get('created_at', 'Unknown'):20}"
        )

    print("=" * WIDTH)
    return available_metadata


# Allows the user to select a dataset from the list
# Used for both viewing and deletion operations
def select_dataset(title: str = "DATASETS", action: str = "view") -> dict | None:
    metadata = list_datasets(title)

    if not metadata:
        return None

    choice = input(f"\nSelect dataset number to {action} (or press Enter to go back): ").strip()

    if not choice:
        return None

    if not choice.isdigit():
        print("Invalid input. Please enter a number.")
        return None

    choice_index = int(choice) - 1

    if choice_index < 0 or choice_index >= len(metadata):
        print("Invalid dataset selection.")
        return None

    return metadata[choice_index]


# Retrieves and decrypts dataset content:
# 1. Loads encrypted file
# 2. Recovers AES key using RSA private key
# 3. Decrypts content using AES-GCM
def get_dataset_content_by_code(dataset_code: str) -> dict | None:
    metadata = load_dataset_metadata()

    selected_dataset = next(
        (dataset for dataset in metadata if dataset.get("dataset_code") == dataset_code),
        None
    )

    if not selected_dataset:
        return None

    file_path = DATASETS_DIR / selected_dataset["file_name"]

    if not file_path.exists():
        return None

    try:
        with open(file_path, "rb") as file:
            encrypted_data = file.read()

        nonce = encrypted_data[:12]
        ciphertext = encrypted_data[12:]

        key_file = get_dataset_key_file_path(selected_dataset["dataset_code"])

        if not key_file.exists():
            return None

        with open(key_file, "r", encoding="utf-8") as file:
            key_data = json.load(file)

        # Decode the protected AES key from Base64 before RSA decryption.
        encrypted_aes_key = base64.b64decode(key_data["encrypted_key"])

        # Recover AES key from protected key file
        aes_key = decrypt_key_with_rsa(encrypted_aes_key, ADMIN_PRIVATE_KEY)

        # Decrypt and return structured data
        plaintext = decrypt_data(nonce, ciphertext, aes_key)
        return json.loads(plaintext)

    except Exception:
        return None


# Displays full dataset content (only for authorised roles)
# If decryption fails, integrity or key issues are assumed
def view_datasets() -> bool:
    selected_dataset = select_dataset("DATASETS", "view")

    if not selected_dataset:
        return False

    content = get_dataset_content_by_code(selected_dataset["dataset_code"])

    if not content:
        print("Failed to view the dataset securely.")
        print("The encrypted dataset may have been altered, corrupted, or accessed with the wrong key.")
        return False

    print("\n" + "=" * WIDTH)
    print(" DATASET DETAILS ".center(WIDTH))
    print("=" * WIDTH)

    print(f"{'Dataset code:':20}{selected_dataset.get('dataset_code')}")
    print(f"{'Patient ID:':20}{content.get('patient_id')}")
    print(f"{'Diagnosis:':20}{content.get('diagnosis')}")
    print(f"{'Procedure:':20}{content.get('procedure')}")
    print(f"{'Admission type:':20}{content.get('admission_type')}")
    print(f"{'Length of stay:':20}{content.get('length_of_stay')}")

    print("-" * WIDTH)

    print(f"{'Created at:':20}{selected_dataset.get('created_at')}")
    print(f"{'Encryption:':20}{selected_dataset.get('encryption', 'Unknown')}")
    print(f"{'Key protection:':20}{selected_dataset.get('key_protection', 'Unknown')}")

    print("-" * WIDTH)
    print("Security:")
    print("AES-256-GCM protects the dataset content and detects tampering.")
    print("RSA-OAEP protects the AES key, while RBAC controls which roles can view decrypted dataset content.")
    print("=" * WIDTH)

    return True


# Auditor view: shows only technical metadata
# No access to sensitive clinical data
def view_dataset_metadata() -> bool:
    selected_dataset = select_dataset("DATASETS", "view")

    if not selected_dataset:
        return False

    print("\n" + "=" * WIDTH)
    print(" DATASET METADATA ".center(WIDTH))
    print("=" * WIDTH)

    print(f"{'Dataset code:':20}{selected_dataset.get('dataset_code')}")
    print(f"{'Created at:':20}{selected_dataset.get('created_at')}")
    print(f"{'Encryption:':20}{selected_dataset.get('encryption', 'Unknown')}")
    print(f"{'Key protection:':20}{selected_dataset.get('key_protection', 'Unknown')}")

    print("=" * WIDTH)

    return True


# Deletes a dataset completely: encrypted content (.bin), metadata file, protected AES key
# Only the creator is allowed to delete it
def delete_dataset(user: dict) -> str | None:
    metadata = load_dataset_metadata()

    if not metadata:
        print("No datasets available.")
        return None

    # Only datasets created by the user can be deleted (basic ownership control)
    own_metadata = [
        dataset for dataset in metadata
        if dataset.get("created_by") == user["username"]
    ]

    if not own_metadata:
        print("No deletable datasets available for your user.")
        print("Only datasets created by you can be deleted.")
        return None

    print("\n" + "=" * WIDTH)
    print(" DELETABLE DATASETS ".center(WIDTH))
    print("=" * WIDTH)
    print(f"{'No.':4} {'Code':8} {'Created by':12} {'Created at':20}")
    print("-" * WIDTH)

    for index, dataset in enumerate(own_metadata, start=1):
        print(
            f"{index:<4} "
            f"{dataset.get('dataset_code', 'DS-XXX'):8} "
            f"{dataset.get('created_by', 'Unknown'):12} "
            f"{dataset.get('created_at', 'Unknown'):20}"
        )

    print("=" * WIDTH)

    choice = input("\nSelect dataset number to delete (or press Enter to go back): ").strip()

    if not choice:
        return None

    if not choice.isdigit():
        print("Invalid input. Please enter a number.")
        return None

    choice_index = int(choice) - 1

    if choice_index < 0 or choice_index >= len(own_metadata):
        print("Invalid dataset selection.")
        return None

    selected_dataset = own_metadata[choice_index]

    dataset_code = selected_dataset.get("dataset_code")
    file_name = selected_dataset.get("file_name")

    if not dataset_code or not file_name:
        print("Dataset information is incomplete.")
        return None

    confirm = input(f"Are you sure you want to delete {dataset_code}? (y/n): ").strip().lower()
    if confirm != "y":
        print("Dataset deletion cancelled.")
        return None

    try:
        # Remove encrypted file, metadata, and key
        # If any component is missing, the operation still continues safely
        file_path = DATASETS_DIR / file_name
        if file_path.exists():
            file_path.unlink()

        # Remove the dataset metadata file.
        meta_file = get_dataset_meta_file_path(dataset_code)

        if meta_file.exists():
            meta_file.unlink()

        key_file = get_dataset_key_file_path(dataset_code)

        if key_file.exists():
            key_file.unlink()

        print(f"Dataset {dataset_code} deleted successfully.")
        return dataset_code

    except Exception as error:
        print(f"An error occurred while deleting the dataset: {error}")
        return None