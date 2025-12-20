#!/bin/bash
# File: uri-scheme-check.sh
# Finds deep links and custom URI schemes used as entry points.

echo "|_  uri-scheme-check (ENTRY POINTS):"
APK_PATH="$1"

# Search for custom URI schemes (e.g., myscheme://host)
URI_SCHEMES=$(strings "$APK_PATH" | grep -E -i 'android.intent.category.BROWSABLE' -A 5 | grep -E -i 'android.intent.action.VIEW' -B 5 | grep -E -i 'android.intent.scheme')

if [ -n "$URI_SCHEMES" ]; then
    echo "|     [MEDIUM]: Found custom deep link schemes (potential entry points):"
    # Filter unique schemes and display
    echo "$URI_SCHEMES" | grep -E -i 'android.intent.scheme' | sort -u | sed 's/^/|          -> /' | head -n 5
else
    echo "|     URI Schemes: No custom or browsable URI schemes detected."
fi

