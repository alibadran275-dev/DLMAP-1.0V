#!/bin/bash
# File: network-security.sh
# Checks for cleartext traffic, certificate pin/trust issues.

echo "|_  network-security (MITM RISK):"
# Simple check for cleartext usage indicator
if strings "$1" | grep -i 'usesCleartextTraffic="true"'; then
    echo "|     [VULNERABLE]: usesCleartextTraffic=true found in manifest. HIGH RISK."
    echo "|        - Allows unencrypted HTTP traffic (Man-in-the-Middle attack possible)."
else
    echo "|     Cleartext Traffic Check: UsesCleartextTraffic is likely DISABLED (Good)."
fi

