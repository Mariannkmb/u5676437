# Utility functions for safe and consistent user input handling.

def ask_yes_no(prompt: str) -> bool:
    while True:
        answer = input(f"{prompt} (y/n): ").strip().lower()

        if answer == "y":
            return True
        if answer == "n":
            return False

        print("Please enter 'y' or 'n'.")


def ask_non_empty(prompt: str, max_attempts: int = 3) -> str | None:
    attempts = 0

    while attempts < max_attempts:
        value = input(f"{prompt}: ").strip()

        if value:
            return value

        attempts += 1
        remaining = max_attempts - attempts

        if remaining > 0:
            print(f"This field cannot be empty. Attempts remaining: {remaining}")
        else:
            print("Too many invalid attempts. Returning to previous menu.")
            return None


def ask_choice_number(prompt: str, max_option: int, max_attempts: int = 3) -> int | None:
    attempts = 0

    while attempts < max_attempts:
        value = input(f"{prompt} (or press Enter to go back): ").strip()

        if value == "":
            return None

        if value.isdigit():
            number = int(value)
            if 1 <= number <= max_option:
                return number

        attempts += 1
        remaining = max_attempts - attempts

        if remaining > 0:
            print(f"Invalid option. Attempts remaining: {remaining}")
        else:
            print("Too many invalid attempts. Returning to previous menu.")
            return None