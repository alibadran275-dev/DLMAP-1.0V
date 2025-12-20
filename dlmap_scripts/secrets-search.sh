#!/bin/bash
# File: secrets-search.sh (Generalized Scan)

echo "|_  secrets-search (VULNERABILITY):"
FILE_PATH="$1"
STRINGS_OUTPUT=$(strings "$FILE_PATH")

# Define High-Confidence Secret Patterns (General/Cloud)
# 1. AWS Access Key ID (AKIA...)
AWS_ACCESS_KEY_REGEX='AKIA[0-9A-Z]{16}'
# 2. AWS Secret Access Key (Base64 format)
AWS_SECRET_KEY_REGEX='[0-9a-zA-Z/+]{40}'
# 3. Private RSA Key Headers
RSA_KEY_REGEX='(BEGIN|END) (RSA|DSA|EC|OPENSSH) PRIVATE KEY'
# 4. Generic API Key patterns (e.g., used in various web services)
GENERIC_API_KEY_REGEX='(API_KEY|api_key|SECRET|secret|TOKEN|token|password|passwd|pwd)'

FOUND_SECRETS=0

# Check 1: AWS Keys
if echo "$STRINGS_OUTPUT" | grep -E "$AWS_ACCESS_KEY_REGEX|$AWS_SECRET_KEY_REGEX"; then
    echo "|     [CRITICAL]: Found pattern matching AWS Access Keys (AKIA... or base64)."
    echo "|        - Risk: Potential direct access to AWS resources."
    FOUND_SECRETS=1
fi

# Check 2: Private Keys
if echo "$STRINGS_OUTPUT" | grep -E "$RSA_KEY_REGEX"; then
    echo "|     [CRITICAL]: Found Private Key header (e.g., BEGIN RSA PRIVATE KEY)."
    echo "|        - Risk: Compromise of encryption, signing, or SSH access."
    FOUND_SECRETS=1
fi

# Check 3: Generic Credentials/Tokens
if echo "$STRINGS_OUTPUT" | grep -E -i "$GENERIC_API_KEY_REGEX" | grep -v 'firebase'; then
    echo "|     [HIGH]: Found generic credential keywords (API_KEY, secret, token, password)."
    echo "|        - Risk: Requires manual validation, but high potential for secrets."
    FOUND_SECRETS=1
fi

if [ "$FOUND_SECRETS" -eq 0 ]; then
    echo "|     No high-confidence secrets or private keys found in the file strings."
fi

