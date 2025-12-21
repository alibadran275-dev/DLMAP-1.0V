# DLMap - Nmap-style Static Analysis Tool for Mobile Applications

DLMap (Deep Logic Map) is a static analysis security tool designed to scan mobile application archives (like APKs) or source code directories and report potential security vulnerabilities and misconfigurations using an output format inspired by the popular network scanner, Nmap.

## ✨ Features

* **Nmap Aesthetic:** Outputs results in a clean, familiar format (File, Status, Service, Scripting Engine output).
* **Aggressive Scan Mode (`-A`):** Performs deep logic checks across 9 integrated security modules (Scripts).
* **Comprehensive Coverage:** Integrates checks for manifest settings, hardcoded secrets, weak cryptography, network security, and more.
* **Portable:** Written in Python, making it easy to run across different platforms.

## 🛠️ Integrated DLMap-NSE Scripts (9 Modules)

| Script Name | Focus Area | Description |
| :--- | :--- | :--- |
| `entropy-check` | Analysis | Measures file entropy (data randomness/compression). |
| `integrity-check` | Compliance | Checks SDK versions and code/binary integrity. |
| `secrets-search` | Vulnerability | Detects hardcoded API keys, tokens, and credentials. |
| `crypto-checker` | Security | Identifies weak hash functions (MD5) or hardcoded encryption keys. |
| `network-analyzer`| Communication | Flags cleartext traffic, weak SSL trust, and insecure URLs. |
| `manifest-settings`| Exploitable | Checks for dangerous manifest flags (e.g., debuggable, allowBackup). |
| `permissions-scan`| Access Control | Analyzes use of dangerous permissions within the code. |
| `component-analyzer`| Access Control | Identifies exposed app components (Activities, Receivers, etc.). |
| `deeplink-analyzer`| Exposed Functionality| Checks for vulnerable deep-linking schemes and intents. |

## 🚀 Usage

### Requirements

DLMap is written in Python 3.

### Running the Scan

The primary usage mode is the Aggressive Scan (`-A`), similar to Nmap's `-A`.

```bash
# 1. Ensure the main script is executable
chmod +x dlmap

# 2. Run the scan against a directory (e.g., unpacked APK contents)
# The tool will automatically look for relevant files (Java, XML, Manifest, etc.)
./dlmap -A ./target_directory_or_apk

Example Output (Nmap Style)
~/DLMap $ ./dlmap -A ./dlmap_unpack_test_app_temp
Starting DLMap 1.0 ([https://dlmap.io](https://dlmap.io)) at 2025-12-21 20:07:13
DLMap scan report for ./dlmap_unpack_test_app_temp
Host is up (N/A latency).
Not shown: Directory/Package contents not listed.

FILE                 SCAN-STATUS     SERVICE
AndroidManifest.xml  open            AndroidManifest
|_  entropy-check:
|   Entropy: 5.00 (Max 8.00)
|_  integrity-check:
|   [HIGH] minSdkVersion (18)
|     - Risk: App uses a low minimum SDK version, lacking modern security features (Runtime Permissions).
... (other results)

Service detection performed. Please report any incorrect results at [https://dlmap.io/submit/](https://dlmap.io/submit/) .
DLMap done: 2 file(s) scanned in 0.02 seconds.

📜 Contributing and License
​This project is open-source. Contributions are welcome! Please see the LICENSE file for details (Copyright 2025 by lega).
