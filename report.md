# DLMap Pro - Static Application Security Testing (SAST) Report
**Target:** `./dlmap_unpack_test_app_temp`  
**Date:** 2026-05-25 12:56:39  
**Duration:** 0.005 seconds  

## 1. Executive Summary
This report outlines the vulnerabilities found during the static code analysis. Each vulnerability is mapped to **OWASP MASVS** (Mobile Application Security Verification Standard) and **CWE** (Common Weakness Enumeration) standards to ensure compliance with enterprise guidelines.

| Severity | Count |
| :--- | :--- |
| **CRITICAL** | 0 |
| **HIGH** | 4 |
| **MEDIUM** | 2 |
| **LOW** | 0 |
| **INFO** | 0 |


## 2. Detailed File Analysis
### File: `AndroidManifest.xml`
* **Service Type:** AndroidManifest
* **Entropy:** 5.00/8.00


#### Dangerous Permissions Requested
| Permission | Risk Description |
| :--- | :--- |
| `android.permission.READ_SMS` | Allows the app to read SMS messages, which could expose 2FA login codes. |
| `android.permission.SYSTEM_ALERT_WINDOW` | Allows drawing overlays over other apps, commonly hijacked by malware for overlay/phishing attacks. |


#### Code & Configuration Findings
##### [HIGH] Application is Debuggable
* **Location:** Line 4
* **Standards:** MASVS-PLATFORM-1 | CWE-489
* **Evidence:** `android:debuggable="true"`
* **Description:** The debuggable flag is enabled in the manifest. This allows attackers to attach a debugger, run arbitrary code under the app's context, and extract sensitive data.
* **Remediation:** Set android:debuggable="false" in your AndroidManifest.xml before building the production release.


##### [MEDIUM] Application Backup Enabled
* **Location:** Line 4
* **Standards:** MASVS-STORAGE-1 | CWE-921
* **Evidence:** `android:allowBackup="true"`
* **Description:** Application data backup is enabled. Anyone with ADB access to the device can backup and extract private application data, even on non-rooted devices.
* **Remediation:** Set android:allowBackup="false" in your AndroidManifest.xml, or configure a secure BackupAgent.


##### [HIGH] Cleartext Network Traffic Allowed
* **Location:** Line 4
* **Standards:** MASVS-NETWORK-1 | CWE-319
* **Evidence:** `android:usesCleartextTraffic="true"`
* **Description:** The application explicitly allows unencrypted HTTP traffic. This exposes user credentials and data to Man-In-The-Middle (MITM) sniffing and tampering.
* **Remediation:** Remove android:usesCleartextTraffic or set it to "false". Enforce HTTPS globally.


---

### File: `AppCode.java`
* **Service Type:** Source Code
* **Entropy:** 4.99/8.00


#### Code & Configuration Findings
##### [MEDIUM] Weak Cryptographic Hash (MD5)
* **Location:** Line 12
* **Standards:** MASVS-CRYPTO-1 | CWE-327
* **Evidence:** `MessageDigest.getInstance("MD5"`
* **Description:** MD5 is a cryptographically broken hash function vulnerable to collision attacks. It should not be used for integrity checks or sensitive data hashing.
* **Remediation:** Upgrade to secure hashing algorithms such as SHA-256, SHA-512, or Argon2.


---
