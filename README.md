# DLMAP - Deep Learning Mobile Application Processor

[![GitHub license](https://img.shields.io/github/license/Alibadran275-dev/DLMAP.svg)](https://github.com/Alibadran275-dev/DLMAP/blob/main/LICENSE)
[![GitHub stars](https://img.shields.io/github/stars/Alibadran275-dev/DLMAP.svg?style=social)](https://github.com/Alibadran275-dev/DLMAP)
[![GitHub forks](https://img.shields.io/github/forks/Alibadran275-dev/DLMAP.svg?style=social)](https://github.com/Alibadran275-dev/DLMAP)
[![Version](https://img.shields.io/badge/Version-V1.0.1-blue)](https://github.com/Alibadran275-dev/DLMAP/releases/tag/v1.0.1)

---

## 🚀 Stable Release V1.0.1: Project Rebuild and Advanced Secrets Analysis

DLMAP (Deep Learning Mobile Application Processor) is a mobile application analysis tool designed specifically for **Termux environments**. It provides a comprehensive static analysis of application files (like APKs) to discover vulnerabilities, information disclosure points, and sensitive data using a rapid scanning approach.

This release marks a complete transition to a clean, efficient Python project structure, integrating a powerful module for secrets scanning.

# DLMap 1.0 (Python Core - Ultimate Edition)

DLMap is a comprehensive Static Analysis Security Testing (SAST) tool designed to scan Python code (and simulated application files like APKs/Manifests) for common security vulnerabilities, insecure configurations, and dangerous information disclosure risks.

It uses 9 dedicated security modules to provide a detailed, actionable security report.

## 🚀 Key Features

* **9 Integrated Security Modules:** Covers Secrets, Cryptography, Network, Component, Storage, Deeplink, Integrity, Manifest, and Permissions analysis.
* **High Fidelity Patterns:** Uses specific regex and logic to detect high-risk patterns (e.g., hardcoded API keys, MD5 usage, cleartext traffic).
* **Unified Reporting:** Generates a structured, easy-to-read report similar to common professional security scanners (Nmap/Nuclei style).

## 🛠️ Requirements

DLMap is built entirely on Python 3 and requires no external dependencies beyond the standard library.

* Python 3.x

## ⚙️ Installation and Setup

1.  **Clone the Repository (Using the New Location):**
    ```bash
    git clone [https://github.com/alibadran275-dev/DLMAP-1.0V.git](https://github.com/alibadran275-dev/DLMAP-1.0V.git)
    cd DLMAP-1.0V
    ```

2.  **Ensure Execution Permissions:**
    ```bash
    chmod +x dlmap
    ```

3.  **Run the Test File (Optional but Recommended):**
    To ensure all 9 modules are running correctly, run the comprehensive test file:
    ```bash
    ./dlmap -A ./comprehensive_test.py
    ```

## 💡 Usage

DLMap currently focuses on analyzing single files containing code snippets, variables, and simulated configurations (like a Python file containing Android Manifest variables).

**Command Syntax:**
```bash
./dlmap -A <target_file_path>

Example:./dlmap -A ./my_app_code.py

📝 Analysis Modules (The 9 Core Scanners)

Module Description Risks Detected
secrets-search Finds hardcoded credentials, API keys, tokens, and sensitive data. High-Conf API Keys, AWS Access Keys, Passwords/Secrets.
crypto-checker Identifies weak or outdated cryptographic implementations. MD5 usage, Hardcoded Encryption Keys/IVs.
network-analyzer Flags insecure communication protocols and hardcoded network data. Cleartext HTTP URLs, Hardcoded Server IPs, Cleartext Traffic Flag.
storage-checker Checks for insecure data storage practices on the device. Insecure Shared Preferences (Auth Tokens), World-Readable/Writable files.
deeplink-analyzer Examines deep link schemes for exploitable, unauthenticated entry points. Sensitive deep links (e.g., password reset), Custom Insecure Schemes.
integrity-check Assesses application compliance based on target SDK versions. Low minSdkVersion (lacks Runtime Permissions), Old targetSdkVersion.
manifest-settings Detects critical, exploitable settings defined in the manifest. android:debuggable="true" in production code.
permissions-scan Flags requests for dangerous, high-risk system permissions. READ_SMS, SYSTEM_ALERT_WINDOW, ACCESS_FINE_LOCATION.
static-analysis Measures file entropy to detect packed, compressed, or encrypted content. High Entropy (indicates obfuscation or native code).

🤝 Contribution
​Contributions are welcome! Feel free to fork the repository, enhance the analysis patterns, or propose new features.
​Developed by Ali Badran.
