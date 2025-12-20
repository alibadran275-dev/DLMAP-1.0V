#!/bin/bash
# File: component-scan.sh
# Scans for exported Activities and Receivers (primary attack vectors).

echo "|_  component-scan (ATTACK SURFACE):"
APK_PATH="$1"

# NOTE: Since pure bash cannot parse complex XML manifest easily,
# we flag the required deep analysis here.

if strings "$APK_PATH" | grep -i 'android:exported="true"'; then
    echo "|     [WARNING]: Indicator of EXPORTED components found (exported=\"true\")."
    echo "|        - Risk: Activities/Receivers may be exposed for external hijacking."
    echo "|        - ACTION: Needs dedicated Python XML parser (v2.0) for precise listing."
else
    echo "|     Component Export Check: No clear indicator of 'exported=true' found (Good)."
fi

