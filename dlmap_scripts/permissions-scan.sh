#!/bin/bash
# File: permissions-scan.sh (Generalized Scan)

echo "|_  permissions-scan (ACCESS CONTROL):"
FILE_PATH="$1"

# We search the strings for common permission texts or access control terms.
# This works on any file type (binary, config, etc.)
if strings "$FILE_PATH" | grep -E -i 'read|write|execute|admin|root|system|permission|auth'; then
    echo "|     [MEDIUM]: Found access-related keywords (read/write/admin/root/auth) in file strings."
    echo "|        - Use: Indicates potential access control requirements or commands."
else
    echo "|     Access Keyword Check: No common access/permission keywords found."
fi

