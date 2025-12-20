#!/bin/bash
# File: firebase-check.sh (Generalized Scan)

echo "|_  firebase-check (CONFIGURATION):"
FILE_PATH="$1"
STRINGS_OUTPUT=$(strings "$FILE_PATH")

# Check 1: Find Firebase Database URLs (still valid for general files)
FIREBASE_DB_REGEX='https?://[^.]+\.firebaseio\.com'
DB_URLS=$(echo "$STRINGS_OUTPUT" | grep -E -i "$FIREBASE_DB_REGEX")

if [ -n "$DB_URLS" ]; then
    echo "|     [MEDIUM]: Found Firebase Realtime Database URL(s) hardcoded."
    echo "|        - Risk: Check if Firebase Rules are misconfigured (allowing public read/write)."
    echo "$DB_URLS" | sed 's/^/|          -> /' | sort -u | head -n 3
else
    echo "|     Firebase Database URL: No clear Firebase database endpoints found."
fi

# Check 2: Find Google/Firebase API Key patterns (general search)
GOOGLE_KEY_REGEX='AIza[0-9A-Za-z_-]{35}'
if echo "$STRINGS_OUTPUT" | grep -E "$GOOGLE_KEY_REGEX"; then
    echo "|     [HIGH]: Found Google/Firebase API Key pattern (AIza...) hardcoded."
    echo "|        - Risk: Key may be restricted, but exposure is a security risk."
fi

