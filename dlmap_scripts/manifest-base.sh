#!/bin/bash
# File: manifest-base.sh (Base info extraction)

APK_PATH="$1"
# Use aapt to dump basic information
AAPT_DUMP=$(aapt dump badging "$APK_PATH")

PACKAGE_NAME=$(echo "$AAPT_DUMP" | grep 'package: name=' | awk -F"'" '{print $2}')
VERSION_NAME=$(echo "$AAPT_DUMP" | grep 'versionName=' | awk -F"'" '{print $4}')
TARGET_SDK=$(echo "$AAPT_DUMP" | grep 'targetSdkVersion:' | awk -F"'" '{print $2}')

echo ""
echo "PACKAGE: $PACKAGE_NAME"
echo "VERSION: $VERSION_NAME (Target SDK: $TARGET_SDK)"

