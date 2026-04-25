from auth import authenticate
from storage import ensure_directories
from audit_logging import log_action, get_logs, print_logs
from data_management import upload_dataset, view_datasets, view_dataset_metadata, delete_dataset
from findings_management import create_finding, sign_finding, verify_finding, list_findings, edit_finding, delete_finding
from integrity_check import verify_user_registry_integrity
import pwinput


def show_welcome_screen() -> None:
    print("\n" + "=" * 100)
    print(" Secure Clinical Research Collaboration Platform ")
    print("=" * 100)
    print("1. Login")
    print("2. Exit")


def show_clinical_menu() -> None:
    print("\n--- Clinical Menu ---")
    print("1. Upload dataset")
    print("2. View datasets")
    print("3. Delete dataset")
    print("4. Logout")


def show_researcher_menu() -> None:
    print("\n--- Researcher Menu ---")
    print("1. View datasets")
    print("2. Create findings")
    print("3. View findings")
    print("4. Edit finding")
    print("5. Delete finding")
    print("6. Sign findings")
    print("7. Logout")


def show_auditor_menu() -> None:
    print("\n--- Auditor Menu ---")
    print("1. View datasets")
    print("2. View findings")
    print("3. Finding Security Check")
    print("4. View audit logs")
    print("5. Logout")


def clinical_session(user: dict) -> None:
    while True:
        show_clinical_menu()
        choice = input("Choose an option: ").strip()

        if choice == "1":
            uploaded_dataset_code = upload_dataset(user)

            if uploaded_dataset_code:
                log_action(
                    user["username"],
                    user["role"],
                    "upload_dataset",
                    "success",
                    f"Dataset {uploaded_dataset_code} uploaded successfully"
                )
            else:
                log_action(
                    user["username"],
                    user["role"],
                    "upload_dataset",
                    "failed",
                    "Dataset upload failed"
                )

        elif choice == "2":
            success = view_datasets()
            if success:
                log_action(
                    user["username"],
                    user["role"],
                    "view_datasets",
                    "success",
                    "Dataset viewed successfully"
                )
            else:
                log_action(
                    user["username"],
                    user["role"],
                    "view_datasets",
                    "failed",
                    "Dataset view cancelled or failed"
                )

        elif choice == "3":
            deleted_dataset_code = delete_dataset(user)
            if deleted_dataset_code:
                log_action(
                    user["username"],
                    user["role"],
                    "delete_dataset",
                    "success",
                    f"Dataset {deleted_dataset_code} deleted successfully"
                )
            else:
                log_action(
                    user["username"],
                    user["role"],
                    "delete_dataset",
                    "failed",
                    "Dataset deletion failed or was cancelled"
                )

        elif choice == "4":
            log_action(
                user["username"],
                user["role"],
                "user_logout",
                "success",
                "User logged out"
            )
            print("Logged out.")
            break

        else:
            print("Invalid option.")
            log_action(
                user["username"],
                user["role"],
                "invalid_menu_choice",
                "failed",
                "Invalid option selected in clinical menu"
            )


def researcher_session(user: dict) -> None:
    while True:
        show_researcher_menu()
        choice = input("Choose an option: ").strip()

        if choice == "1":
            success = view_datasets()
            if success:
                log_action(
                    user["username"],
                    user["role"],
                    "view_datasets",
                    "success",
                    "Dataset viewed successfully"
                )
            else:
                log_action(
                    user["username"],
                    user["role"],
                    "view_datasets",
                    "failed",
                    "Dataset view cancelled or failed"
                )

        elif choice == "2":
            created_finding_code = create_finding(user)
            if created_finding_code:
                log_action(
                    user["username"],
                    user["role"],
                    "create_finding",
                    "success",
                    f"Finding {created_finding_code} created successfully"
                )
            else:
                log_action(
                    user["username"],
                    user["role"],
                    "create_finding",
                    "failed",
                    "Finding creation failed"
                )

        elif choice == "3":
            findings = list_findings(user["role"])
            if findings:
                log_action(
                    user["username"],
                    user["role"],
                    "view_findings",
                    "success",
                    "Findings viewed successfully"
                )
            else:
                log_action(
                    user["username"],
                    user["role"],
                    "view_findings",
                    "failed",
                    "No findings available"
                )

        elif choice == "4":
            edited_finding_code = edit_finding(user)
            if edited_finding_code:
                log_action(
                    user["username"],
                    user["role"],
                    "edit_finding",
                    "success",
                    f"Finding {edited_finding_code} edited successfully"
                )
            else:
                log_action(
                    user["username"],
                    user["role"],
                    "edit_finding",
                    "failed",
                    "Finding edit failed or was cancelled"
                )

        elif choice == "5":
            deleted_finding_code = delete_finding(user)
            if deleted_finding_code:
                log_action(
                    user["username"],
                    user["role"],
                    "delete_finding",
                    "success",
                    f"Finding {deleted_finding_code} deleted successfully"
                )
            else:
                log_action(
                    user["username"],
                    user["role"],
                    "delete_finding",
                    "failed",
                    "Finding deletion failed or was cancelled"
                )

        elif choice == "6":
            signed_finding_code = sign_finding(user)
            if signed_finding_code:
                log_action(
                    user["username"],
                    user["role"],
                    "sign_finding",
                    "success",
                    f"Finding {signed_finding_code} signed successfully"
                )
            else:
                log_action(
                    user["username"],
                    user["role"],
                    "sign_finding",
                    "failed",
                    "Finding signing failed"
                )

        elif choice == "7":
            log_action(
                user["username"],
                user["role"],
                "user_logout",
                "success",
                "User logged out"
            )
            print("Logged out.")
            break

        else:
            print("Invalid option.")
            log_action(
                user["username"],
                user["role"],
                "invalid_menu_choice",
                "failed",
                "Invalid option selected in researcher menu"
            )


def auditor_session(user: dict) -> None:
    while True:
        show_auditor_menu()
        choice = input("Choose an option: ").strip()

        if choice == "1":
            success = view_dataset_metadata()

            if success:
                log_action(
                    user["username"],
                    user["role"],
                    "view_dataset_metadata",
                    "success",
                    "Auditor viewed dataset metadata"
                )
            else:
                log_action(
                    user["username"],
                    user["role"],
                    "view_dataset_metadata",
                    "failed",
                    "Dataset metadata view cancelled or failed"
                )

        elif choice == "2":
            findings = list_findings(user["role"])
            if findings:
                log_action(
                    user["username"],
                    user["role"],
                    "view_findings",
                    "success",
                    "Auditor viewed findings successfully"
                )
            else:
                log_action(
                    user["username"],
                    user["role"],
                    "view_findings",
                    "failed",
                    "No findings available"
                )

        elif choice == "3":
            check_result = verify_finding()

            if check_result:
                if check_result["storage_check"] == "FAILED":
                    log_action(
                        user["username"],
                        user["role"],
                        "finding_security_check",
                        "failed",
                        f"Finding {check_result['code']} cannot be read safely"
                    )
                elif check_result["signature_check"] == "VALID":
                    log_action(
                        user["username"],
                        user["role"],
                        "finding_security_check",
                        "success",
                        f"Finding {check_result['code']} passed security check"
                    )
                else:
                    log_action(
                        user["username"],
                        user["role"],
                        "finding_security_check",
                        "failed",
                        f"Finding {check_result['code']} signature status: {check_result['signature_check']}"
                    )
            else:
                log_action(
                    user["username"],
                    user["role"],
                    "finding_security_check",
                    "failed",
                    "Finding security check cancelled or no findings available"
                )

        elif choice == "4":
            log_action(
                user["username"],
                user["role"],
                "view_logs",
                "success",
                "Audit logs accessed"
            )
            logs = get_logs()
            print_logs(logs)

        elif choice == "5":
            log_action(
                user["username"],
                user["role"],
                "user_logout",
                "success",
                "User logged out"
            )
            print("Logged out.")
            break

        else:
            print("Invalid option.")
            log_action(
                user["username"],
                user["role"],
                "invalid_menu_choice",
                "failed",
                "Invalid option selected in auditor menu"
            )


def login_flow() -> None:
    username = input("Username: ").strip()
    password = pwinput.pwinput(prompt="Password: ", mask="*").strip()

    user = authenticate(username, password)

    if user and user["role"] == "admin":
        log_action(
            username,
            "admin",
            "interactive_login_attempt",
            "blocked",
            "Interactive login blocked for internal key-management account"
        )
        print("\nInvalid username or password.")
        return

    if user:
        log_action(
            user["username"],
            user["role"],
            "user_login",
            "success",
            "User authenticated successfully"
        )
        print(f"\nLogin successful. Welcome, {user['username']} ({user['role']}).")

        if user["role"] == "clinical":
            clinical_session(user)
        elif user["role"] == "researcher":
            researcher_session(user)
        elif user["role"] == "auditor":
            auditor_session(user)
        else:
            print("Unknown role. Access denied.")
            log_action(
                user["username"],
                user["role"],
                "role_validation",
                "failed",
                "Unknown role detected during session assignment"
            )
    else:
        log_action(
            username,
            "unknown",
            "user_login",
            "failed",
            "Invalid credentials"
        )
        print("\nInvalid username or password.")


def main() -> None:
    ensure_directories()

    ok, message = verify_user_registry_integrity()
    if not ok:
        print(f"\n[SECURITY ERROR] {message}")
        print("The system cannot continue because the user registry is missing or has been modified.")
        raise SystemExit(1)

    print("[OK] User registry integrity verified.\n")

    while True:
        show_welcome_screen()
        choice = input("Choose an option: ").strip()

        if choice == "1":
            login_flow()
        elif choice == "2":
            print("Exiting system...")
            break
        else:
            print("Invalid option. Please try again.")


if __name__ == "__main__":
    main()