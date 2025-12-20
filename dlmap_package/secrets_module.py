import re
import os
from typing import List, Dict, Any

# -------------------------------------------------------------------------
# Secrets Search Patterns
# -------------------------------------------------------------------------

SECRET_PATTERNS = {
    "High_Conf_API_Key": r'(sk-live-[a-zA-Z0-9]{24,60})',
    "AWS_Secret_Key": r'([A-Za-z0-9+/]{40})',
    "Basic_Auth_Creds": r'https?:\/\/\w+:\w+@'
}

# -------------------------------------------------------------------------
# Secret Scanning Function
# -------------------------------------------------------------------------

def run_secrets_scan(target_file_path: str) -> List[Dict[str, Any]]:
    """Scans the file for any hardcoded secrets using the defined patterns."""

    secrets_found = []

    if not os.path.exists(target_file_path):
        return secrets_found

    try:
        # CRITICAL: Reading file content explicitly to ensure it works
        with open(target_file_path, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()

            # Iterate through all defined search rules
            for rule_name, pattern in SECRET_PATTERNS.items():

                # Use re.findall to find all matching expressions
                matches = re.findall(pattern, content)

                for match in matches:
                    # Masking the secret for display 
                    if len(match) > 10:
                        masked_secret = f"{match[:7]}*****************"
                    else:
                        masked_secret = match
                        
                    secrets_found.append({
                        "Rule": rule_name,
                        "Secret": masked_secret,
                        "File": target_file_path
                    })

    except Exception as e:
        # Handle any reading errors
        print(f"[ERROR]: Secrets Module Failed to read file content: {e}")

    return secrets_found

# -------------------------------------------------------------------------
# Report Printing Function
# -------------------------------------------------------------------------

def print_secrets_report(secrets: List[Dict[str, Any]]):
    """Prints the results in DLMap report format."""
    print("|_  secrets-search (VULNERABILITY):")

    if not secrets:
        print("|     No high-confidence secrets found.")
        return

    for secret_data in secrets:
        print(f"|     [{secret_data['Rule']}]: Secret Found: \"{secret_data['Secret']}\"")

    print("|")

