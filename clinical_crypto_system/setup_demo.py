import shutil
import json
import base64
import random

from datetime import datetime
from pathlib import Path

from crypto_utils import generate_aes_key, encrypt_data, encrypt_key_with_rsa
from data_management import (
    DATASETS_DIR,
    DATASET_KEYS_DIR,
    ADMIN_PUBLIC_KEY,
    DATASETS_METADATA_DIR,
    load_dataset_metadata,
    generate_dataset_code,
    get_dataset_key_file_path,
    save_single_dataset_metadata,
)
from findings_management import (
    FINDINGS_FILES_DIR,
    FINDINGS_KEYS_DIR,
    FINDINGS_METADATA_DIR,
    load_findings,
    save_single_finding,
    build_signing_payload,
    generate_finding_code,
)
from audit_logging import log_action
from integrity_check import sign_user_registry_integrity
from signature_verification import generate_rsa_keypair, sign_text
from auth import create_user

BASE_DIR = Path(__file__).resolve().parent

CLINICIANS = ["clinician1", "clinician2", "clinician3"]
RESEARCHERS = ["researcher1", "researcher2", "researcher3"]
AUDITORS = ["auditor1", "auditor2", "auditor3"]
ADMINS = ["admin1"]

SIGNING_USERS = RESEARCHERS
KEY_PROTECTION_USERS = ADMINS

SIGNING_PASSPHRASES = {
    "researcher1": "secret",
    "researcher2": "secret",
    "researcher3": "secret",
}

FILES_TO_DELETE = [
    BASE_DIR / "data" / "auth" / "users.bin",
    BASE_DIR / "data" / "auth" / "users_key.json",
    BASE_DIR / "data" / "auth" / "users_integrity.json",
    BASE_DIR / "data" / "logs" / "logs.bin",
    BASE_DIR / "data" / "logs" / "log_key.json",
]

DIRECTORIES_TO_CLEAN = [
    DATASETS_DIR,
    DATASET_KEYS_DIR,
    DATASETS_METADATA_DIR,
    FINDINGS_FILES_DIR,
    FINDINGS_KEYS_DIR,
    FINDINGS_METADATA_DIR,
]


def delete_path(path: Path) -> None:
    if path.exists():
        if path.is_dir():
            shutil.rmtree(path)
        else:
            path.unlink()


def reset_system() -> None:
    print("\n=== Resetting system ===")

    keys_dir = BASE_DIR / "keys"
    if keys_dir.exists():
        for key_file in keys_dir.glob("*.pem"):
            delete_path(key_file)
        for encrypted_key_file in keys_dir.glob("*.pem.enc"):
            delete_path(encrypted_key_file)

    for file_path in FILES_TO_DELETE:
        delete_path(file_path)

    for directory in DIRECTORIES_TO_CLEAN:
        directory.mkdir(parents=True, exist_ok=True)
        for item in directory.glob("*"):
            delete_path(item)

    print("✔ System reset complete")


def setup_keys() -> None:
    print("\n=== Generating RSA keys ===")

    # Researchers need signing keys. Their private keys are protected with a signing passphrase.
    for username in SIGNING_USERS:
        generate_rsa_keypair(username, SIGNING_PASSPHRASES[username])

    # Admin key is used as the key-protection authority for AES keys.
    for username in KEY_PROTECTION_USERS:
        generate_rsa_keypair(username)

    print("✔ Keys generated")


def setup_users() -> None:
    print("\n=== Creating users ===")

    for username in CLINICIANS:
        create_user(username, "clin123", "clinical")

    for username in RESEARCHERS:
        create_user(username, "research123", "researcher")

    for username in AUDITORS:
        create_user(username, "audit123", "auditor")

    create_user("admin1", "admin123", "admin")

    # Sign the encrypted user registry after all users have been created.
    sign_user_registry_integrity()

    print("✔ Users created")
    print("✔ User registry integrity signed")


DATASETS_TO_CREATE = [
    {"patient_id": "P001", "diagnosis": "Hypertension",
     "procedure": "Blood pressure monitoring", "admission_type": "Outpatient", "length_of_stay": "1 day"},
    {"patient_id": "P002", "diagnosis": "Type 2 Diabetes",
     "procedure": "Glucose monitoring", "admission_type": "Scheduled", "length_of_stay": "2 days"},
    {"patient_id": "P003", "diagnosis": "Coronary artery disease",
     "procedure": "ECG and blood tests", "admission_type": "Emergency", "length_of_stay": "4 days"},
    {"patient_id": "P004", "diagnosis": "Asthma",
     "procedure": "Respiratory function review", "admission_type": "Outpatient", "length_of_stay": "1 day"},
    {"patient_id": "P005", "diagnosis": "Chronic kidney disease",
     "procedure": "Renal function monitoring", "admission_type": "Scheduled", "length_of_stay": "3 days"},
    {"patient_id": "P006", "diagnosis": "Post-operative infection risk",
     "procedure": "Blood culture and observation", "admission_type": "Emergency", "length_of_stay": "5 days"},
]

FINDING_SUMMARIES = [
    "Initial hypertension risk assessment completed.",
    "Glucose control pattern reviewed.",
    "Cardiovascular observation summary prepared.",
    "Respiratory stability indicators reviewed.",
    "Renal function trend analysis completed.",
    "Post-operative infection risk summary prepared.",
    "Cross-dataset clinical observation completed.",
    "Follow-up monitoring recommendation prepared.",
]


def clear_logs() -> None:
    delete_path(BASE_DIR / "data" / "logs" / "logs.bin")
    delete_path(BASE_DIR / "data" / "logs" / "log_key.json")


def clear_demo_data() -> None:
    for directory in DIRECTORIES_TO_CLEAN:
        directory.mkdir(parents=True, exist_ok=True)
        for item in directory.glob("*"):
            delete_path(item)


def seed_datasets() -> list[str]:
    print("\n--- Creating datasets ---")

    metadata = load_dataset_metadata()
    created_codes = []

    # Demo datasets follow the same encryption and key-protection flow as the live upload feature.
    for data in DATASETS_TO_CREATE:
        clinician = random.choice(CLINICIANS)

        code = generate_dataset_code(metadata)
        path = DATASETS_DIR / f"{code}.bin"

        aes_key = generate_aes_key()
        nonce, ciphertext = encrypt_data(json.dumps(data), aes_key)

        with open(path, "wb") as file:
            file.write(nonce + ciphertext)

        encrypted_key = encrypt_key_with_rsa(aes_key, ADMIN_PUBLIC_KEY)

        dataset_entry = {
            "dataset_code": code,
            "file_name": f"{code}.bin",
            "created_by": clinician,
            "created_at": datetime.now().isoformat(timespec="seconds"),
            "encryption": "AES-256-GCM",
            "key_protection": "RSA-OAEP"
        }

        metadata.append(dataset_entry)
        save_single_dataset_metadata(dataset_entry)

        key_file = get_dataset_key_file_path(code)
        with open(key_file, "w", encoding="utf-8") as file:
            json.dump(
                {"encrypted_key": base64.b64encode(encrypted_key).decode()},
                file,
                indent=2
            )

        created_codes.append(code)

        log_action(
            clinician,
            "clinical",
            "upload_dataset",
            "success",
            f"Dataset {code} uploaded by {clinician}"
        )

        print(f"✔ Dataset {code} created by {clinician}")

    return created_codes


def seed_findings(dataset_codes: list[str]) -> None:
    print("\n--- Creating findings ---")

    next_id = max((finding.get("id", 0) for finding in load_findings()), default=0) + 1

    # Create a mix of signed and unsigned findings for researcher and auditor testing.
    for index in range(8):
        current_findings = load_findings()

        dataset_code = random.choice(dataset_codes)
        creator = random.choice(RESEARCHERS)

        finding = {
            "id": next_id,
            "finding_code": generate_finding_code(current_findings),
            "dataset_code": dataset_code,
            "study_summary": FINDING_SUMMARIES[index % len(FINDING_SUMMARIES)],
            "created_by": creator,
            "created_at": datetime.now().isoformat(timespec="seconds"),
            "signed": False,
            "signed_by": None,
            "signed_at": None,
            "signature": None
        }

        should_sign = index in [0, 1, 3, 5]

        if should_sign:
            # Keep the signer as the creator to preserve ownership and non-repudiation.
            payload = build_signing_payload(finding)
            signature = sign_text(creator, payload, SIGNING_PASSPHRASES[creator])

            finding["signed"] = True
            finding["signed_by"] = creator
            finding["signed_at"] = datetime.now().isoformat(timespec="seconds")
            finding["signature"] = signature

            log_action(
                creator,
                "researcher",
                "sign_finding",
                "success",
                f"{finding['finding_code']} signed by {creator}"
            )

        save_single_finding(finding)

        log_action(
            creator,
            "researcher",
            "create_finding",
            "success",
            f"{finding['finding_code']} created for {dataset_code}"
        )

        status = "signed" if finding["signed"] else "unsigned"
        print(f"✔ Finding {finding['finding_code']} created by {creator} ({status})")

        next_id += 1


def prepare_demo() -> None:
    print("\n=== Preparing demo data ===")

    for directory in DIRECTORIES_TO_CLEAN:
        directory.mkdir(parents=True, exist_ok=True)

    clear_logs()
    clear_demo_data()

    dataset_codes = seed_datasets()
    seed_findings(dataset_codes)

    log_action("system", "internal", "prepare_demo", "success", "Clean demo data ready")

    print("✔ Demo ready")


def run_all() -> None:
    print("\nFULL DEMO SETUP\n")

    random.seed(24)

    reset_system()
    setup_keys()
    setup_users()
    prepare_demo()

    print("\nREADY to run: python main.py")
    print("\nDemo passwords:")
    print("clinician1/2/3  -> clin123")
    print("researcher1/2/3 -> research123")
    print("auditor1/2/3    -> audit123")
    print("Signing phrase  -> secret")


if __name__ == "__main__":
    run_all()