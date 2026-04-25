# Demo Guide

## Test Accounts

| Username     | Role        | Password     | Digital Firm |
|--------------|-------------|--------------|--------------|
| clinician1   | clinical    | clin123      |			   |
| researcher1  | researcher  | research123  | secret       |
| auditor1     | auditor     | audit123     |			   |
| admin1       | admin       | admin123     |			   |

## Notes for Testing
- `admin1` is used to decrypt centrally protected AES keys in this prototype.
- `researcher1` is used to sign findings.
- The other roles are used to test access control, visibility, and workflow separation.

## Dataset Examples

DS-001
	•	Patient ID: P001
	•	Age: 45
	•	Diagnosis: Acute appendicitis
	•	Procedure: Laparoscopic appendectomy
	•	Admission type: Emergency
	•	Length of stay: 3 days

DS-002
	•	Patient ID: P002
	•	Age: 60
	•	Diagnosis: Type 2 diabetes mellitus
	•	Procedure: Insulin therapy initiation
	•	Admission type: Outpatient
	•	Length of stay: 1 day

DS-003
	•	Patient ID: P003
	•	Age: 30
	•	Diagnosis: Femoral fracture
	•	Procedure: Open reduction and internal fixation
	•	Admission type: Emergency
	•	Length of stay: 5 days

(Note: actual datasets are encrypted in the system)

## Findings Examples

F-001
	•	Dataset code: DS-001
	•	Patient name: John Carter
	•	Analysis/study: Post-operative review after laparoscopic appendectomy

F-002
	•	Dataset code: DS-002
	•	Patient name: Maria Lopez
	•	Analysis/study: Monitoring after insulin therapy initiation

F-003
	•	Dataset code: DS-003
	•	Patient name: David Kim
	•	Analysis/study: Recovery assessment after fracture fixation

(Note: findings are encrypted and digitally signed in the system)

## Reset the System including demo values
python setup_demo.py
