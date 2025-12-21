# dlmap_package/dlmap_core.py
# Contains the core logic for the 9 static analysis "scripts"

import os
import re

# --- Constants for analysis ---
# Regex patterns for demonstration
SECRETS_PATTERNS = {
    "High_Conf_API_Key": r'pk_live_[A-Za-z0-9]+',
    "Medium_Conf_Credential": r'KEY = "[A-Za-z0-9_]{5,}"',
}
CRYPTO_PATTERNS = {
    "Weak_Hash_MD5": r'hashlib\.md5',
    "Hardcoded_Key": r'key\s*=\s*"[A-Za-z0-9]{8,}"'
}
MANIFEST_PATTERNS = {
    "Debuggable_Flag": r'android:debuggable\s*=\s*"true"',
    "Allow Backup Flag": r'android:allowBackup\s*=\s*"true"',
    "minSdkVersion": r'minSdkVersion\s*=\s*"(\d+)"',
    "targetSdkVersion": r'targetSdkVersion\s*=\s*"(\d+)"',
    "Cleartext_Traffic_Flag": r'android:usesCleartextTraffic\s*=\s*"true"'
}

# --- Core Scanner Logic ---

def analyze_manifest(content):
    """Checks AndroidManifest.xml for security misconfigurations and returns structured results."""
    results = []
    
    # 1. SDK Version Checks (Mapped to integrity-check)
    min_sdk_match = re.search(MANIFEST_PATTERNS["minSdkVersion"], content)
    if min_sdk_match and int(min_sdk_match.group(1)) < 23:
        results.append({
            "risk": "HIGH", 
            "type": f"minSdkVersion ({min_sdk_match.group(1)})",
            "details": "App uses a low minimum SDK version, lacking modern security features (Runtime Permissions)."
        })
        
    target_sdk_match = re.search(MANIFEST_PATTERNS["targetSdkVersion"], content)
    if target_sdk_match and int(target_sdk_match.group(1)) < 29:
        results.append({
            "risk": "MEDIUM", 
            "type": f"targetSdkVersion ({target_sdk_match.group(1)})",
            "details": "App targets an old SDK version, missing behavioral changes for modern privacy/security."
        })
        
    # 2. Manifest Settings Checks (Mapped to manifest-settings)
    if re.search(MANIFEST_PATTERNS["Debuggable_Flag"], content):
        results.append({
            "risk": "HIGH", 
            "type": "Debuggable_Flag",
            "details": "The debuggable flag is set to true, allowing arbitrary code execution and data extraction via ADB in production."
        })
        
    if re.search(MANIFEST_PATTERNS["Allow Backup Flag"], content):
        results.append({
            "risk": "MEDIUM", 
            "type": "Allow Backup Flag",
            "details": "android:allowBackup is true, allowing data extraction on rooted devices."
        })
        
    # 3. Network Checks (Mapped to network-analyzer)
    if re.search(r'http:\/\/[^\s]+', content):
        results.append({
            "risk": "HIGH", 
            "type": "Cleartext_HTTP_URL (http://schemas.android.com/apk/res/android)",
            "details": "Detected a hardcoded HTTP URL, suggesting cleartext traffic and vulnerability to MITM attacks."
        })
        
    if re.search(MANIFEST_PATTERNS["Cleartext_Traffic_Flag"], content):
        results.append({
            "risk": "HIGH", 
            "type": "Cleartext_Traffic_Flag",
            "details": "Detected a flag that explicitly allows cleartext (unencrypted HTTP) traffic, bypassing system security standards."
        })
        
    return results

def analyze_code_for_secrets(content):
    """Searches code content for hardcoded secrets."""
    results = []
    for pattern_name, pattern in SECRETS_PATTERNS.items():
        for match in re.finditer(pattern, content):
            # Mask the actual key for simulated output
            value = match.group(0)
            masked_value = value[:8] + '**********' + value[-4:]
            
            risk = "HIGH" if "High_Conf" in pattern_name else "MEDIUM"
            details = "High confidence API key or token found. Must be removed from source code."
            
            results.append({
                "risk": risk, 
                "type": pattern_name, 
                "value": masked_value,
                "details": details
            })
    return results

def analyze_code_for_crypto(content):
    """Checks code for weak cryptographic implementations."""
    results = []
    for pattern_name, pattern in CRYPTO_PATTERNS.items():
        if pattern_name == "Weak_Hash_MD5" and re.search(pattern, content, re.IGNORECASE):
            results.append({
                "risk": "HIGH", 
                "type": "Weak_Hash_MD5",
                "details": "Detected use of MD5, which is highly discouraged and vulnerable to collision attacks."
            })
        elif pattern_name == "Hardcoded_Key" and re.search(pattern, content, re.IGNORECASE):
            results.append({
                "risk": "MEDIUM", 
                "type": "Hardcoded_Key",
                "details": "Encryption key or IV is hardcoded and visible in the binary, risking exposure."
            })
    return results

def analyze_passive_checks(filepath, content):
    """Placeholder for the other code analysis tools."""
    results = []
    
    # 1. storage-checker (Example: check for SharedPreferences usage)
    if "SharedPreferences" in content or ".plist" in filepath:
        results.append({
            "risk": "INFO",
            "type": "Potential Insecure Storage",
            "details": "Storage component (like SharedPreferences) detected. Data integrity review required."
        })

    # 2. permissions-scan (Simulated High Risk for older code)
    if "ACCESS_FINE_LOCATION" in content and "AppCode.java" in filepath:
        results.append({
            "risk": "HIGH",
            "type": "Dangerous Permission Use",
            "details": "High risk permission used directly in code (ACCESS_FINE_LOCATION). Check for runtime safeguards."
        })

    return results


def scan_file(filepath):
    """
    The main DLMap function to scan a file and return results
    structured for Nmap aesthetic output.
    """
    
    if not os.path.exists(filepath):
        return {"error": f"File not found: {filepath}"}
    
    try:
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
    except Exception as e:
        return {"error": f"Could not read file: {e}"}

    all_results = {
        "integrity-check": [],        # SDK versions
        "secrets-search": [],         # Code checks
        "crypto-checker": [],         # Code checks
        "network-analyzer": [],       # Cleartext flags/URLs
        
        "component-analyzer": [],     # (Simulated via Mocks in main dlmap)
        "storage-checker": [],
        "deeplink-analyzer": [],      # (Simulated via Mocks in main dlmap)
        "manifest-settings": [],      # Debuggable/Backup
        "permissions-scan": [],       # Runtime permission use
    }
    
    if os.path.basename(filepath) == 'AndroidManifest.xml':
        manifest_results = analyze_manifest(content)
        
        # Separate results into their corresponding sections based on type/risk
        for item in manifest_results:
            if "minSdkVersion" in item['type'] or "targetSdkVersion" in item['type']:
                all_results["integrity-check"].append(item)
            elif "Cleartext" in item['type']:
                all_results["network-analyzer"].append(item)
            elif "Debuggable" in item['type'] or "Backup" in item['type']:
                all_results["manifest-settings"].append(item)

    elif filepath.lower().endswith(('.java', '.kt', '.swift', '.js')):
        all_results["secrets-search"] = analyze_code_for_secrets(content)
        all_results["crypto-checker"] = analyze_code_for_crypto(content)
        
        # Run passive checks on code
        passive_results = analyze_passive_checks(filepath, content)
        for item in passive_results:
             if "Storage" in item['type']:
                 all_results["storage-checker"].append(item)
             elif "Permission" in item['type']:
                 all_results["permissions-scan"].append(item)


    # Clean up empty lists 
    final_results = {}
    for script, results in all_results.items():
        if results:
            final_results[script] = results
            
    return final_results

