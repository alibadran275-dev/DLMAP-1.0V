# DLMap v1.0: Ultimate Static Analysis Tool 🛡️

DLMap is a high-performance Python-based tool designed for comprehensive static security analysis of files and Android APKs. It provides deep insights into secrets, network traces, permissions, and code integrity without execution.

## 🚀 Final Release Features (v1.0)

| Flag | Scan Name | Description |
| :--- | :--- | :--- |
| `-A` / `--all` | Ultimate Scan | Runs ALL default deep scans below. (Recommended) |
| `-sS` / `--secrets`| Secret Search | Scans for hardcoded tokens (JWT, AWS, API keys). |
| `-sN` / `--network`| Network Traces | Looks for cleartext HTTP endpoints and hardcoded IPs. |
| `-sP` / `--permissions`| Privileges Check | Detects high-privilege keywords (`root`, `sudo`, `system`). |
| **`-sA` / `--static`** | **Deep Static Analysis** | **[NEW]** Runs Entropy calculation (for obfuscation/encryption detection) and native code function checks. |
| **`-sI` / `--integrity`**| **APK Integrity** | **[NEW]** Checks Min/Target SDK compliance and exploitable Android Manifest settings (`allowBackup`, `debuggable`). |

## ⚙️ Usage Example

```bash
# Running the comprehensive ultimate scan on an APK:
dlmap -A /sdcard/Download/app.apk

