from datetime import datetime
from pathlib import Path
import json
import base64
import pwinput

from utils.input_utils import ask_yes_no, ask_non_empty, ask_choice_number
from crypto_utils import (
    generate_aes_key,
    encrypt_data,
    decrypt_data,
    encrypt_key_with_rsa,
    decrypt_key_with_rsa
)
from signature_verification import sign_text, verify_text_signature
from data_management import get_dataset_content_by_code

BASE_DIR = Path(__file__).resolve().parent
# Findings are stored in three separated areas: files (encrypted finding content), keys (AES keys protected with RSA-OAEP), and metadata (signature and non-sensitive audit information).
FINDINGS_FILES_DIR = BASE_DIR / "data" / "findings" / "files"
FINDINGS_KEYS_DIR = BASE_DIR / "data" / "findings" / "keys"
FINDINGS_METADATA_DIR = BASE_DIR / "data" / "findings" / "metadata"

# Admin RSA keys protect the AES keys used for encrypted findings.
# The findings themselves are encrypted with AES-GCM.
ADMIN_PUBLIC_KEY = str(BASE_DIR / "keys" / "admin1_public.pem")
ADMIN_PRIVATE_KEY = str(BASE_DIR / "keys" / "admin1_private.pem")

WIDTH = 100


# Path to the encrypted finding content.
def get_finding_file_path(finding_code: str) -> Path:
    return FINDINGS_FILES_DIR / f"{finding_code}.bin"


# Path to the protected AES key for a finding.
def get_finding_key_file_path(finding_code: str) -> Path:
    return FINDINGS_KEYS_DIR / f"{finding_code}_key.json"

# Path to the finding metadata and signature.
def get_finding_meta_file_path(finding_code: str) -> Path:
    return FINDINGS_METADATA_DIR / f"{finding_code}_meta.json"

# Load the finding metadata without accessing the protected content.
def load_finding_metadata(finding_code: str) -> dict | None:
    meta_file = get_finding_meta_file_path(finding_code)

    if not meta_file.exists():
        return None

    try:
        with open(meta_file, "r", encoding="utf-8") as file:
            return json.load(file)
    except Exception:
        return None

# Load and decrypt one finding from disk.
def load_single_finding(finding_code: str) -> dict | None:
    finding_file = get_finding_file_path(finding_code)
    key_file = get_finding_key_file_path(finding_code)

    if not finding_file.exists() or not key_file.exists():
        return None

    try:
        with open(finding_file, "rb") as file:
            encrypted_data = file.read()

        nonce = encrypted_data[:12]
        ciphertext = encrypted_data[12:]

        with open(key_file, "r", encoding="utf-8") as file:
            key_data = json.load(file)

        encrypted_aes_key = base64.b64decode(key_data["encrypted_key"])
        aes_key = decrypt_key_with_rsa(encrypted_aes_key, ADMIN_PRIVATE_KEY)

        plaintext = decrypt_data(nonce, ciphertext, aes_key)
        finding = json.loads(plaintext)

        metadata = load_finding_metadata(finding_code)
        if metadata:
            finding["signed"] = metadata.get("signed", False)
            finding["signed_by"] = metadata.get("signed_by")
            finding["signed_at"] = metadata.get("signed_at")
            finding["signature"] = metadata.get("signature")
        else:
            finding["signed"] = False
            finding["signed_by"] = None
            finding["signed_at"] = None
            finding["signature"] = None

        return finding

    except Exception:
        return None

# Get all finding codes from storage, even if files are corrupted.
def get_all_finding_codes_from_storage() -> list[str]:
    FINDINGS_FILES_DIR.mkdir(parents=True, exist_ok=True)
    FINDINGS_KEYS_DIR.mkdir(parents=True, exist_ok=True)
    FINDINGS_METADATA_DIR.mkdir(parents=True, exist_ok=True)

    codes = set()

    for path in FINDINGS_FILES_DIR.glob("F-*.bin"):
        codes.add(path.stem)

    for path in FINDINGS_KEYS_DIR.glob("F-*_key.json"):
        codes.add(path.name.replace("_key.json", ""))

    for path in FINDINGS_METADATA_DIR.glob("F-*_meta.json"):
        codes.add(path.name.replace("_meta.json", ""))

    return sorted(codes)


# Encrypt and save one finding to disk.
def save_single_finding(finding: dict) -> None:
    finding_code = finding["finding_code"]
    finding_file = get_finding_file_path(finding_code)
    key_file = get_finding_key_file_path(finding_code)
    meta_file = get_finding_meta_file_path(finding_code)

    FINDINGS_FILES_DIR.mkdir(parents=True, exist_ok=True)
    FINDINGS_KEYS_DIR.mkdir(parents=True, exist_ok=True)
    FINDINGS_METADATA_DIR.mkdir(parents=True, exist_ok=True)

    try:
        # The digital signature is stored in metadata.
        finding_content = finding.copy()
        finding_content.pop("signed", None)
        finding_content.pop("signed_by", None)
        finding_content.pop("signed_at", None)
        finding_content.pop("signature", None)

        plaintext = json.dumps(finding_content, indent=2)

        # Reuse the existing AES key when updating the same finding.
        if key_file.exists():
            with open(key_file, "r", encoding="utf-8") as file:
                key_data = json.load(file)

            encrypted_aes_key = base64.b64decode(key_data["encrypted_key"])
            aes_key = decrypt_key_with_rsa(encrypted_aes_key, ADMIN_PRIVATE_KEY)

        else:
            # Create a new AES key for a new finding and protect it with RSA-OAEP.
            aes_key = generate_aes_key()
            encrypted_aes_key = encrypt_key_with_rsa(aes_key, ADMIN_PUBLIC_KEY)

            with open(key_file, "w", encoding="utf-8") as file:
                json.dump(
                    {"encrypted_key": base64.b64encode(encrypted_aes_key).decode("utf-8")},
                    file,
                    indent=2
                )

        nonce, ciphertext = encrypt_data(plaintext, aes_key)

        with open(finding_file, "wb") as file:
            file.write(nonce + ciphertext)

        # Store signature information separately so auditors can inspect verification status without exposing the encrypted finding content.
        metadata = {
            "finding_code": finding_code,
            "created_by": finding.get("created_by"),
            "created_at": finding.get("created_at"),
            "signed": finding.get("signed", False),
            "signed_by": finding.get("signed_by"),
            "signed_at": finding.get("signed_at"),
            "signature_algorithm": "RSA-PSS" if finding.get("signed") else None,
            "signature": finding.get("signature")
        }

        with open(meta_file, "w", encoding="utf-8") as file:
            json.dump(metadata, file, indent=2)
            

    except Exception as error:
        print(f"An error occurred while saving finding {finding_code}: {error}")


# Load all findings stored as separate encrypted files.
def load_findings() -> list[dict]:
    FINDINGS_FILES_DIR.mkdir(parents=True, exist_ok=True)

    findings = []

    finding_files = sorted(
        path for path in FINDINGS_FILES_DIR.glob("F-*.bin")
        if path.is_file()
    )

    for path in finding_files:
        finding = load_single_finding(path.stem)
        if finding:
            findings.append(finding)

    # Keep the display order stable by sorting on the stored ID.
    findings.sort(key=lambda item: item.get("id", 0))
    return findings


# Generate the next finding code based on the existing ones.
def generate_finding_code(findings: list[dict]) -> str:
    if not findings:
        return "F-001"

    numbers = []

    for finding in findings:
        code = finding.get("finding_code", "")
        if code.startswith("F-"):
            try:
                numbers.append(int(code.split("-")[1]))
            except (IndexError, ValueError):
                continue

    return f"F-{max(numbers, default=0) + 1:03d}"


# Builds a payload for RSA-PSS signing. The same fields must be used during verification.
def build_signing_payload(finding: dict) -> str:
    return (
        f"finding_code:{finding['finding_code']}\n"
        f"dataset_code:{finding['dataset_code']}\n"
        f"study_summary:{finding['study_summary']}\n"
        f"created_by:{finding['created_by']}\n"
        f"created_at:{finding['created_at']}"
    )


# Show one finding in a structured format.
def show_finding_details(finding: dict, viewer_role: str) -> None:
    dataset = get_dataset_content_by_code(finding.get("dataset_code", ""))

    print("\n" + "=" * WIDTH)
    print(" FINDING DETAILS ".center(WIDTH))
    print("=" * WIDTH)

    print(f"{'Finding code:':25}{finding.get('finding_code')}")
    print(f"{'Linked dataset:':25}{finding.get('dataset_code')}")
    print(f"{'Study summary:':25}{finding.get('study_summary')}")

    # Creator information is shown to researchers for operational context.
    if viewer_role == "researcher":
        print(f"{'Created by:':25}{finding.get('created_by')}")

    print(f"{'Created at:':25}{finding.get('created_at')}")

    print("-" * WIDTH)

    # Findings only expose the minimum dataset fields needed for analysis.
    if dataset:
        print(f"{'Diagnosis:':25}{dataset.get('diagnosis')}")
        print(f"{'Procedure:':25}{dataset.get('procedure')}")
    else:
        print(f"{'Dataset details:':25}Not available")

    print("-" * WIDTH)

    signed = finding.get("signed", False)
    print(f"{'Signed:':25}{'Yes' if signed else 'No'}")

    if signed:
        print(f"{'Signed by:':25}{finding.get('signed_by')}")
        print(f"{'Signed at:':25}{finding.get('signed_at')}")
    else:
        print(f"{'Signature status:':25}No signature stored")

    print("=" * WIDTH)
    print(f"{'Security:':25}Encrypted with AES-256-GCM.")
    print(f"{'':25}Key protected with RSA-OAEP.")
    if signed:
        print(f"{'':25}Digitally signed with RSA-PSS.")
    else:
        print(f"{'':25}No digital signature present.")
    print("=" * WIDTH)


# Show the list of findings and optionally let the user open one.
def list_findings(viewer_role: str, show_signature_status: bool = True) -> list[dict]:
    findings = load_findings()

    if not findings:
        print("No findings available.")
        return []

    print("\n" + "=" * WIDTH)
    print(" FINDINGS ".center(WIDTH))
    print("=" * WIDTH)
    print(f"{'No.':4} {'Code':8} {'Owner':12} {'Signed':8} {'Summary':55}")
    print("-" * WIDTH)

    for index, finding in enumerate(findings, start=1):
        summary = finding.get("study_summary", "No summary")
        if len(summary) > 70:
            summary = summary[:67] + "..."

        signed_status = "Yes" if finding.get("signed") else "No"

        if show_signature_status:
            print(
                f"{index:4} "
                f"{finding['finding_code']:8} "
                f"{finding.get('created_by', 'N/A'):12} "
                f"{signed_status:8} "
                f"{summary:55}"
            )
        else:
            print(f"{index:4} {finding['finding_code']:8} {'':8} {summary:70}")

    print("=" * WIDTH)

    selected_index = ask_choice_number("\nSelect finding number to view details", len(findings))

    if selected_index is None:
        return findings

    finding = findings[selected_index - 1]
    show_finding_details(finding, viewer_role)

    return findings


# Create a new finding and optionally sign it immediately.
def create_finding(user: dict) -> str | None:
    findings = load_findings()

    dataset_code = ask_non_empty("Enter related dataset code (e.g. DS-001)")

    
    if dataset_code is None:
        print("Finding creation cancelled.")
        return None
    dataset_code = dataset_code.upper()

    study_summary = ask_non_empty("Enter analysis/study")
    if study_summary is None:
        print("Finding creation cancelled.")
        return None

    if not get_dataset_content_by_code(dataset_code):
        print("Linked dataset code not found.")
        return None

    finding_code = generate_finding_code(findings)
    next_id = max((finding.get("id", 0) for finding in findings), default=0) + 1

    print(f"Generated finding with code: {finding_code}")

    sign_now = ask_yes_no("Do you want to sign this finding now?")

    entry = {
        "id": next_id,
        "finding_code": finding_code,
        "dataset_code": dataset_code,
        "study_summary": study_summary,
        "created_by": user["username"],
        "created_at": datetime.now().isoformat(timespec="seconds"),
        "signed": False,
        "signed_by": None,
        "signed_at": None,
        "signature": None
    }

    if sign_now:
        payload = build_signing_payload(entry)
        signing_passphrase = pwinput.pwinput(prompt="Enter signing passphrase: ").strip()

        if not signing_passphrase:
            print("Signing cancelled.")
            return None

        try:
            signature = sign_text(user["username"], payload, signing_passphrase)
        except Exception:
            print("Signing failed. Incorrect signing passphrase or protected key error.")
            return None

        entry["signed"] = True
        entry["signed_by"] = user["username"]
        entry["signed_at"] = datetime.now().isoformat(timespec="seconds")
        entry["signature"] = signature
        print("Finding signed successfully.")

    save_single_finding(entry)


    return finding_code


# Sign one unsigned finding.
def sign_finding(user: dict) -> str | None:
    findings = load_findings()

    # Only unsigned findings created by the current researcher can be signed.
    unsigned_findings = [
        finding for finding in findings
        if not finding.get("signed") and finding.get("created_by") == user["username"]
    ]

    if not unsigned_findings:
        print("No findings available for signing for your user.")
        print("Only unsigned findings created by you can be signed.")
        return None

    print("\n" + "=" * WIDTH)
    print(" SIGNABLE FINDINGS ".center(WIDTH))
    print("=" * WIDTH)
    print(f"{'No.':4} {'Code':8} {'Dataset':10} {'Summary':65}")
    print("-" * WIDTH)

    for index, finding in enumerate(unsigned_findings, start=1):
        summary = finding.get("study_summary", "No summary")
        if len(summary) > 65:
            summary = summary[:62] + "..."

        print(
            f"{index:4} "
            f"{finding['finding_code']:8} "
            f"{finding.get('dataset_code', 'N/A'):10} "
            f"{summary:65}"
        )

    print("=" * WIDTH)

    selected_index = ask_choice_number("Select finding number to sign", len(unsigned_findings))

    if selected_index is None:
        return None

    finding = unsigned_findings[selected_index - 1]

    # Build protected payload
    payload = build_signing_payload(finding)
    signing_passphrase = pwinput.pwinput(prompt="Enter signing passphrase: ").strip()

    if not signing_passphrase:
        print("Signing cancelled.")
        return None

    try:
        signature = sign_text(user["username"], payload, signing_passphrase)
    except Exception:
        print("Signing failed. Incorrect signing passphrase or protected key error.")
        return None

    # Update finding
    finding["signed"] = True
    finding["signed_by"] = user["username"]
    finding["signed_at"] = datetime.now().isoformat(timespec="seconds")
    finding["signature"] = signature

    save_single_finding(finding)

    print("Finding signed successfully.")

    return finding["finding_code"]


# Performs the auditor security check: verifies the encrypted file can be decrypted, checks AES-GCM integrity andverifies the RSA-PSS signature if present
def inspect_finding_security(finding_code: str) -> dict:
    checked_at = datetime.now().isoformat(timespec="seconds")

    result = {
        "code": finding_code,
        "checked_at": checked_at,
        "finding": None,
        "storage_check": "FAILED",
        "storage_method": "AES-256-GCM",
        "key_protection": "RSA-OAEP",
        "signature_check": "NOT VERIFIED",
        "signature_method": "RSA-PSS",
        "content_access": "BLOCKED",
        "reason": "The finding file or its protected key may have been changed or corrupted."
    }

    finding_file = get_finding_file_path(finding_code)
    key_file = get_finding_key_file_path(finding_code)

    if not finding_file.exists():
        result["reason"] = "The encrypted finding file is missing or was deleted."
        return result

    if not key_file.exists():
        result["reason"] = "The protected encryption key is missing or was deleted."
        return result

    try:
        with open(finding_file, "rb") as file:
            encrypted_data = file.read()

        nonce = encrypted_data[:12]
        ciphertext = encrypted_data[12:]

        with open(key_file, "r", encoding="utf-8") as file:
            key_data = json.load(file)

        encrypted_aes_key = base64.b64decode(key_data["encrypted_key"])
        aes_key = decrypt_key_with_rsa(encrypted_aes_key, ADMIN_PRIVATE_KEY)

    except Exception:
        result["reason"] = "The protected encryption key could not be recovered."
        return result

    try:
        plaintext = decrypt_data(nonce, ciphertext, aes_key)
        finding = json.loads(plaintext)

        result["finding"] = finding
        result["storage_check"] = "PASSED"
        result["content_access"] = "ALLOWED"
        result["reason"] = ""

    except Exception:
        result["reason"] = "The encrypted finding file failed integrity verification."
        return result
        
    metadata = load_finding_metadata(finding_code)
    if metadata:
        finding["signed"] = metadata.get("signed", False)
        finding["signed_by"] = metadata.get("signed_by")
        finding["signed_at"] = metadata.get("signed_at")
        finding["signature"] = metadata.get("signature")

    if not finding.get("signed") or not finding.get("signature"):
        result["signature_check"] = "NOT SIGNED"
        result["reason"] = "Finding is intact but has no digital signature."
        return result

    payload = build_signing_payload(finding)
    signed_by = finding.get("signed_by")
    signature = finding.get("signature")

    if verify_text_signature(signed_by, payload, signature):
        result["signature_check"] = "VALID"
        result["reason"] = "The finding is readable and the digital signature is valid."
    else:
        result["signature_check"] = "INVALID"
        result["reason"] = "The finding content or signature was altered."

    return result


# Verify the digital signature of one finding.
def verify_finding() -> dict | None:
    finding_codes = get_all_finding_codes_from_storage()

    if not finding_codes:
        print("No findings available.")
        print("Only findings with available storage files can be verified.")
        return None

    rows = []

    for code in finding_codes:
        result = inspect_finding_security(code)

        rows.append({
            "code": code,
            "storage": result["storage_check"],
            "signature": result["signature_check"],
            "result": result
        })

    print("\n" + "=" * WIDTH)
    print(" FINDING SECURITY CHECK ".center(WIDTH))
    print("=" * WIDTH)
    print(f"{'No.':4} {'Code':8} {'File status':18} {'Signature':15}")
    print("-" * WIDTH)

    for index, row in enumerate(rows, start=1):
        file_status = "Readable" if row["storage"] == "PASSED" else "Cannot read"
        signature_status = row["signature"].title()

        print(
            f"{index:4} "
            f"{row['code']:8} "
            f"{file_status:18} "
            f"{signature_status:15}"
        )

    print("=" * WIDTH)

    selected_index = ask_choice_number(
        "Select finding number to run security check",
        len(rows)
    )

    if selected_index is None:
        return None

    result = rows[selected_index - 1]["result"]
    finding = result["finding"]
    metadata = load_finding_metadata(result["code"])

    print("\n" + "=" * WIDTH)
    print(" FINDING SECURITY CHECK RESULT ".center(WIDTH))
    print("=" * WIDTH)
    print(f"{'Finding code:':25}{result['code']}")
    if finding:
        print(f"{'Created by:':25}{finding.get('created_by')}")
        print(f"{'Created at:':25}{finding.get('created_at')}")
    elif metadata:
        print(f"{'Created by:':25}{metadata.get('created_by')}")
        print(f"{'Created at:':25}{metadata.get('created_at')}")
    else:
        print(f"{'Checked at:':25}{result['checked_at']}")

    file_status = "Readable" if result["storage_check"] == "PASSED" else "Not accessible"
    signature_status = result["signature_check"].title()
    content_access = result["content_access"].title()

    print(f"{'File status:':25}{file_status}")
    print(f"{'Signature:':25}{signature_status}")

    if finding and finding.get("signed"):
        print(f"{'Signed by:':25}{finding.get('signed_by')}")
        print(f"{'Signed at:':25}{finding.get('signed_at')}")

    print(f"{'Content access:':25}{content_access}")

    print("\nProtection used:")
    print(f"{'- Data encryption:':25}{result['storage_method']}")
    print(f"{'- Key protection:':25}{result['key_protection']}")
    if result["signature_check"] in ["VALID", "INVALID"]:
        signature_method = result["signature_method"]
    elif result["signature_check"] == "NOT SIGNED":
        signature_method = "Not applied"
    else:
        signature_method = "Not verified"
        
    print(f"{'- Digital signature:':25}{signature_method}")

    if result["reason"]:
        print(f"{'Reason:':25}{result['reason']}")

    print("=" * WIDTH)

    return result

# Edit one unsigned finding, only the owner can edit.
def edit_finding(user: dict) -> str | None:
    findings = load_findings()
    unsigned_findings = [
    finding for finding in findings
    if not finding.get("signed") and finding.get("created_by") == user["username"]
]

    if not unsigned_findings:
        print("No editable findings available for your user.")
        print("Only unsigned findings created by you can be edited.")
        return None

    print("\n" + "=" * WIDTH)
    print(" EDITABLE FINDINGS ".center(WIDTH))
    print("=" * WIDTH)
    print(f"{'No.':4} {'Code':8} {'Dataset':10} {'Created by':12} {'Summary':50}")
    print("-" * WIDTH)

    for index, finding in enumerate(unsigned_findings, start=1):
        summary = finding.get("study_summary", "No summary")
        if len(summary) > 65:
            summary = summary[:62] + "..."
        print(
            f"{index:4} "
            f"{finding['finding_code']:8} "
            f"{finding.get('dataset_code', 'N/A'):10} "
            f"{finding.get('created_by', 'N/A'):12} "
            f"{summary:50}"
        )

    print("=" * WIDTH)

    selected_index = ask_choice_number("Select finding number to edit", len(unsigned_findings))
    if selected_index is None:
        return None

    finding = unsigned_findings[selected_index - 1]

    print(f"Current summary: {finding.get('study_summary')}")

    new_summary = ask_non_empty("Enter new analysis/study")

    if new_summary is None:
        print("Finding update cancelled.")
        return None

    finding["study_summary"] = new_summary
    save_single_finding(finding)

    print("Finding updated successfully.")
    return finding["finding_code"]


# Delete one unsigned finding.
def delete_finding(user: dict) -> str | None:
    findings = load_findings()
    
    unsigned_findings = [
    finding for finding in findings
    if not finding.get("signed") and finding.get("created_by") == user["username"]
    ]

    if not unsigned_findings:
        print("No deletable findings available for your user.")
        print("Only unsigned findings created by you can be deleted.")
        return None

    print("\n" + "=" * WIDTH)
    print(" DELETABLE FINDINGS ".center(WIDTH))
    print("=" * WIDTH)
    print(f"{'No.':4} {'Code':8} {'Dataset':10} {'Created by':12} {'Summary':50}")
    print("-" * WIDTH)

    for index, finding in enumerate(unsigned_findings, start=1):
        summary = finding.get("study_summary", "No summary")
        if len(summary) > 65:
            summary = summary[:62] + "..."
        print(
            f"{index:4} "
            f"{finding['finding_code']:8} "
            f"{finding.get('dataset_code', 'N/A'):10} "
            f"{finding.get('created_by', 'N/A'):12} "
            f"{summary:50}"
        )

    print("=" * WIDTH)

    selected_index = ask_choice_number("Select finding number to delete", len(unsigned_findings))
    if selected_index is None:
        return None

    finding = unsigned_findings[selected_index - 1]
    finding_code = finding["finding_code"]

    if not ask_yes_no(f"Are you sure you want to delete {finding_code}?"):
        print("Finding deletion cancelled.")
        return None

    try:
        finding_file = get_finding_file_path(finding_code)
        key_file = get_finding_key_file_path(finding_code)
        meta_file = get_finding_meta_file_path(finding_code)

        if finding_file.exists():
            finding_file.unlink()

        if key_file.exists():
            key_file.unlink()

        if meta_file.exists():
            meta_file.unlink()

        print(f"Finding {finding_code} deleted successfully.")
        return finding_code

    except Exception as error:
        print(f"An error occurred while deleting the finding: {error}")
        return None