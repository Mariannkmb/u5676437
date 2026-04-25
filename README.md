# Demo Guide

## Run in GitHub Codespaces (Recommended)

1. Open this repository in GitHub https://github.com/Mariannkmb/u5676437
2. Click Code → Codespaces → Create codespace
3. Wait a few seconds while dependencies install automatically
4. Open the terminal and run:

cd clinical_crypto_system

python main.py

## Dependences
Dependencies are installed automatically in Codespaces.
If running locally:

pip install -r requirements.txt

## Test Accounts

| Username     | Role        | Password     | Digital Firm |
|--------------|-------------|--------------|--------------|
| clinician1   | clinical    | clin123      |			         |
| clinician2   | clinical    | clin123      |			         |
| clinician3   | clinical    | clin123      |			         |
| researcher1  | researcher  | research123  | secret       |
| researcher2  | researcher  | research123  | secret       |
| researcher3  | researcher  | research123  | secret       |
| auditor1     | auditor     | audit123     |		      	   |
| auditor2     | auditor     | audit123     |	      		   |
| auditor3     | auditor     | audit123     |		      	   |


## Notes for Testing

-   admin1 acts as the trusted authority for AES key protection
    (RSA-OAEP).
-   Researchers can create and digitally sign findings (RSA-PSS).
-   Only dataset owners can delete datasets.
-   Only finding owners can edit/delete unsigned findings.
-   Signed findings cannot be modified.
-   Auditors can verify encryption integrity, signatures, and audit
    logs.

## Reset the System including demo values
Use this command to restore the system to its initial demo state. This is useful after testing operations, modifying data, or when you need to start from a clean and consistent environment.

python setup_demo.py

