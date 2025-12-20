#!/bin/bash
# File: integrity-check.sh
# Checks Min/Target SDK compliance and core security flags.

echo "|_  integrity-check (COMPLIANCE):"
APK_PATH="$1"
AAPT_DUMP=$(aapt dump badging "$APK_PATH")

# Extract and sanitize SDK values, setting default to 0 if not found
MIN_SDK=$(echo "$AAPT_DUMP" | grep 'minSdkVersion:' | awk -F"'" '{print $2}' | tr -d '\r\n')
if [ -z "$MIN_SDK" ]; then MIN_SDK=0; fi

TARGET_SDK=$(echo "$AAPT_DUMP" | grep 'targetSdkVersion:' | awk -F"'" '{print $2}' | tr -d '\r\n')
if [ -z "$TARGET_SDK" ]; then TARGET_SDK=0; fi

# Check 1: Min SDK (Security baseline)
if [ "$MIN_SDK" -lt 23 ]; then
    echo "|     [HIGH]: minSdkVersion ($MIN_SDK) is below recommended 23 (Android 6)."
    echo "|        - Risk: App may lack modern security features (Runtime Permissions)."
fi

# Check 2: Target SDK (Feature and behavior compliance)
if [ "$TARGET_SDK" -lt 31 ]; then
    echo "|     [MEDIUM]: targetSdkVersion ($TARGET_SDK) is below recommended 31+."
    echo "|        - Risk: Misses behavioral changes for modern privacy/security."
fi

# Check 3: Debuggable Flag (CRITICAL VULNERABILITY)
if echo "$AAPT_DUMP" | grep 'application-debuggable'; then
    echo "|     [CRITICAL]: Application is marked 'android:debuggable=true'."
    echo "|        - Risk: Allows full inspection and debugging on production builds."
fi

