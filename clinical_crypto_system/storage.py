from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data"

# Create the storage structure used by encrypted data, protected keys, metadata, logs, and RSA keys.
def ensure_directories() -> None:
    directories = [
        # Auth
        DATA_DIR / "auth",

        # Logs
        DATA_DIR / "logs",

        # Datasets structure
        DATA_DIR / "datasets" / "files",
        DATA_DIR / "datasets" / "keys",
        DATA_DIR / "datasets" / "metadata",

        # Findings structure
        DATA_DIR / "findings" / "files",
        DATA_DIR / "findings" / "keys",
        DATA_DIR / "findings" / "metadata",

        # Keys
        BASE_DIR / "keys",
    ]
    for directory in directories:
        directory.mkdir(parents=True, exist_ok=True) 