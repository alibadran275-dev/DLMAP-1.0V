# DLMAP - Deep Learning Mobile Application Processor

[![GitHub license](https://img.shields.io/github/license/Alibadran275-dev/DLMAP.svg)](https://github.com/Alibadran275-dev/DLMAP/blob/main/LICENSE)
[![GitHub stars](https://img.shields.io/github/stars/Alibadran275-dev/DLMAP.svg?style=social)](https://github.com/Alibadran275-dev/DLMAP)
[![GitHub forks](https://img.shields.io/github/forks/Alibadran275-dev/DLMAP.svg?style=social)](https://github.com/Alibadran275-dev/DLMAP)
[![Version](https://img.shields.io/badge/Version-V1.0.1-blue)](https://github.com/Alibadran275-dev/DLMAP/releases/tag/v1.0.1)

---

## 🚀 Stable Release V1.0.1: Project Rebuild and Advanced Secrets Analysis

DLMAP (Deep Learning Mobile Application Processor) is a mobile application analysis tool designed specifically for **Termux environments**. It provides a comprehensive static analysis of application files (like APKs) to discover vulnerabilities, information disclosure points, and sensitive data using a rapid scanning approach.

This release marks a complete transition to a clean, efficient Python project structure, integrating a powerful module for secrets scanning.

### 🌟 New and Current Features (V1.0.1)

* **High-Confidence Secrets Scan (`secrets-search`):** A new built-in module to detect hardcoded keys, tokens, and encrypted/embedded credentials directly within the code, focusing on high-confidence secrets (e.g., live API keys).
* **Clean Project Structure:** Transitioned to a Python Package model with separate modules (e.g., `dlmap_package/secrets_module.py`) for easier development and maintenance.
* **Execution Path Fix:** Resolved the execution issue in Termux, allowing the tool to be run directly via the `$PATH` variable (`dlmap`) without the need for `./`.
* **Comprehensive Metadata Analysis:** Extracts SDK versions, file size, and data type information.
* **Encryption and Obfuscation Check (Entropy):** Analyzes the file's entropy level to detect signs of encryption or code obfuscation.
* **Security Compliance Check:** Analyzes `minSdkVersion` and `targetSdkVersion` for outdated or weak security practices.

### ⚙️ Installation and Usage (Termux)

#### Prerequisites

* **Termux** (with `python` installed).

#### Installation Steps

```bash
# 1. Install Git and Python (if not already installed)
pkg install git python -y

# 2. Clone the repository
git clone [https://github.com/Alibadran275-dev/DLMAP.git](https://github.com/Alibadran275-dev/DLMAP.git)

# 3. Navigate to the project directory
cd DLMAP

# 4. Grant execution permissions to the main file
chmod +x dlmap

# 5. [Optional/Recommended] To run the tool globally (without ./):
# (Ensure the bin folder exists)
mkdir -p $HOME/bin
mv dlmap $HOME/bin/
export PATH=$PATH:$HOME/bin
Usage Examples
Command Description
dlmap <target_file> Shows the help options.
dlmap -sS /sdcard/app.apk Runs Secrets Scan only.
dlmap -A /sdcard/app.apk Runs the Comprehensive (Ultimate) Analysis.
dlmap -A ./test_file.txt Runs the analysis on a local test file.
🛑 Important Note
This tool is designed for security analysis and educational purposes. It must be used in compliance with all local laws and ethics, and only on applications for which you have explicit authorization to analyze.