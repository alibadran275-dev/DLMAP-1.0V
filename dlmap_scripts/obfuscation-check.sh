#!/bin/bash
# File: obfuscation-check.sh (Generalized Scan)

echo "|_  obfuscation-check (REVERSE ENGINEERING):"
FILE_PATH="$1"

# Check for ProGuard/R8 indicators which are often just text strings or file references
if strings "$FILE_PATH" | grep -q 'proguard\|R8\|Lcom/google/gson/annotations'; then
    echo "|     [INFO]: Found obfuscation/code hardening indicators."
    echo "|        - Result: Code analysis difficulty may be HIGH."
else
    echo "|     [WARNING]: No clear code obfuscation found."
    echo "|        - Risk: File contents may be easily reversible (DECOMPILED)."
fi

