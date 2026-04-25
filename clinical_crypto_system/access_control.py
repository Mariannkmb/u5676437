PERMISSIONS = {
    "clinical": ["upload_dataset", "view_datasets", "delete_dataset"],
    "researcher": ["view_datasets", "create_finding", "view_findings", "edit_finding", "delete_finding", "sign_finding"],
    "auditor": ["view_dataset_metadata", "view_findings", "verify_signature", "view_logs"],
    "admin": []
}



def has_permission(role: str, action: str) -> bool: # This function checks if a given role has permission to perform a specific action by looking up the action in the PERMISSIONS dictionary for that role. If the role is not found in the dictionary, it defaults to an empty list, meaning no permissions.
    return action in PERMISSIONS.get(role, [])