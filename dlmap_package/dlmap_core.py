# dlmap_package/dlmap_core.py

import re
import math

# ===============================================
# 1. SECRETS SEARCH CONFIGURATION
# ===============================================

SECRETS_PATTERNS = {
    "High_Conf_API_Key": {
        "regex": r'(pk_live_[\w]{20,})',
        "details": "High confidence API key or token found. Must be removed from source code."
    },
    "High_Conf_AWS_Key": {
        "regex": r'(AKIA[0-9A-Z]{16})',
        "details": "AWS Access Key ID found. Poses an immediate threat to cloud infrastructure."
    },
    "Medium_Conf_Credential": {
        "regex": r'((passwo?r?d|secret|key)\s*=\s*["\'][\w@#$%^&*()]{8,})',
        "details": "Possible hardcoded credential (password/key) found, risking unauthorized access."
    }
}

# ===============================================
# 2. COMPONENT ANALYZER CONFIGURATION
# ===============================================

COMPONENT_PATTERNS = {
    "Explicitly_Exported": r'class\s+\w+\(Activity\):\s*(?:.|\n)*?is_exported\s*=\s*True',
    "Dangerous_Permission": r'class\s+\w+\(BroadcastReceiver\):\s*(?:.|\n)*?permission\s*=\s*["\'](android\.permission\.INTERACT_ACROSS_USERS)[\"\']'
}

# ===============================================
# 3. CRYPTO CHECKER CONFIGURATION
# ===============================================

CRYPTO_PATTERNS = {
    "Weak_Hash_MD5": {
        "regex": r'hashlib\.md5\s*\(|\.md5\s*\(',
        "risk": "HIGH",
        "description": "Detected use of MD5, which is highly discouraged and vulnerable to collision attacks."
    },
    "Hardcoded_Key": {
        "regex": r'(KEY|SECRET|IV)\s*=\s*["\']([a-zA-Z0-9_]{16,})["\']',
        "risk": "MEDIUM",
        "description": "Encryption key or IV is hardcoded and visible in the binary, risking exposure."
    },
}

# ===============================================
# 4. NETWORK ANALYZER CONFIGURATION
# ===============================================

NETWORK_PATTERNS = {
    "Cleartext_HTTP_URL": {
        "regex": r'["\'](http://[^"\']+)["\']',
        "risk": "HIGH",
        "description": "Detected a hardcoded HTTP URL, suggesting cleartext traffic and vulnerability to MITM attacks."
    },
    "Hardcoded_IP": {
        "regex": r'["\'](\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})["\']',
        "risk": "MEDIUM",
        "description": "Hardcoded IP addresses found, which is a weak practice for production servers and affects maintenance."
    },
    "Cleartext_Traffic_Flag": {
        "regex": r'android:usesCleartextTraffic\s*=\s*["\']true["\']',
        "risk": "HIGH",
        "description": "Detected a flag that explicitly allows cleartext (unencrypted HTTP) traffic, bypassing system security standards."
    }
}

# ===============================================
# 5. STORAGE CHECKER CONFIGURATION
# ===============================================

STORAGE_PATTERNS = {
    "Insecure_SharedPrefs_Token": {
        "regex": r'\.putString\s*\(["\'](auth_token|password|secret_key)["\']',
        "risk": "HIGH",
        "description": "Sensitive data (e.g., Auth Tokens) is being saved in SharedPreferences without encryption."
    },
    "World_Readable_Writeable": {
        "regex": r'(MODE_WORLD_READABLE|MODE_WORLD_WRITEABLE)',
        "risk": "MEDIUM",
        "description": "Found file permissions set to World-Readable or World-Writable, exposing data to other apps."
    }
}

# ===============================================
# 6. DEEPLINK ANALYZER CONFIGURATION
# ===============================================

DEEPLINK_REGEX = r'INTENT_FILTER\s*=\s*\{\s*["\']scheme["\']:\s*["\']([^"\']+)["\']\s*,\s*["\']host["\']:\s*["\']([^"\']+)["\']'
SENSITIVE_KEYWORDS = ['reset', 'password', 'login', 'admin', 'execute', 'token']

def assess_deeplink_risk(scheme, host):
    """Determines the risk level based on the scheme and host keywords."""
    
    for keyword in SENSITIVE_KEYWORDS:
        if keyword in host.lower():
            return "HIGH", "Deep Link handles sensitive function (e.g., Password Reset) without explicit authentication checks."
            
    if scheme not in ['http', 'https']:
        return "MEDIUM", "Uses a custom scheme (not http/https) which can be susceptible to hijacking if unverified."
        
    if scheme in ['https']:
        return "INFO", "Standard App Link using HTTPS; generally safe but requires host verification."
    
    return "INFO", "Low-risk deep link definition found."

# ===============================================
# 7. INTEGRITY CHECK CONFIGURATION
# ===============================================

INTEGRITY_PATTERNS = {
    "minSdkVersion": {
        "regex": r'MIN_SDK_VERSION\s*=\s*(\d+)',
        "threshold": 23, # For Runtime Permissions
        "risk_level": "HIGH",
        "description": "App uses a low minimum SDK version, lacking modern security features (Runtime Permissions)."
    },
    "targetSdkVersion": {
        "regex": r'TARGET_SDK_VERSION\s*=\s*(\d+)',
        "threshold": 31, # Current target recommendation
        "risk_level": "MEDIUM",
        "description": "App targets an old SDK version, missing behavioral changes for modern privacy/security."
    }
}

# ===============================================
# 8. MANIFEST SETTINGS CONFIGURATION
# ===============================================

MANIFEST_PATTERNS = {
    "Debuggable_Flag": {
        "regex": r'android:debuggable\s*=\s*["\']true["\']',
        "risk": "HIGH",
        "description": "The debuggable flag is set to true, allowing arbitrary code execution and data extraction via ADB in production."
    }
}

# ===============================================
# 9. PERMISSIONS SCAN CONFIGURATION (NEW)
# ===============================================

DANGEROUS_PERMISSIONS_MAP = {
    "READ_SMS": {
        "risk": "HIGH",
        "description": "Permission to read SMS/MMS, allowing attacker access to private messages/MFA codes."
    },
    "ACCESS_FINE_LOCATION": {
        "risk": "MEDIUM",
        "description": "Permission for precise location data, risking user tracking if not handled carefully."
    },
    "SYSTEM_ALERT_WINDOW": {
        "risk": "HIGH",
        "description": "Permission to draw over other apps, commonly used for overlay attacks (tapjacking) and phishing."
    }
}

# ===============================================
# CORE SCANNER FUNCTION (Unified Run Function)
# ===============================================

def scan_file(target_file):
    """Unified function to run all 9 analysis modules on the target file."""
    try:
        with open(target_file, 'r', encoding='utf-8') as f:
            content = f.read()
    except Exception as e:
        return {"error": f"Failed to read file: {e}"}

    results = {}
    
    # 1. SECRETS SEARCH
    secrets_results = []
    for type, details in SECRETS_PATTERNS.items(): 
        for match in re.finditer(details["regex"], content, re.IGNORECASE | re.DOTALL): 
            if match.groups():
                 value = match.group(1) 
                 masked = value[:8] + ("*" * 10) + value[-4:]
                 secrets_results.append({
                     "type": type,
                     "value": masked,
                     "details": details["details"]
                 })
    results['secrets-search'] = secrets_results

    # 2. COMPONENT ANALYZER
    component_results = []
    # Explicitly Exported
    if re.search(COMPONENT_PATTERNS["Explicitly_Exported"], content, re.IGNORECASE | re.DOTALL):
         component_results.append({
            "type": "Component - SensitiveComponent",
            "risk": "HIGH",
            "details": "Found a component class explicitly marked as exported (is_exported=True) which may expose sensitive functions."
        })
    # Dangerous Permission
    if re.search(COMPONENT_PATTERNS["Dangerous_Permission"], content, re.IGNORECASE | re.DOTALL):
         component_results.append({
            "type": "Component - SensitiveComponent",
            "risk": "MEDIUM",
            "details": "Found a Receiver component requesting a dangerous permission (INTERACT_ACROSS_USERS) in its definition."
        })
    results['component-analyzer'] = component_results

    # 3. CRYPTO CHECKER
    crypto_results = []
    for pattern_name, details in CRYPTO_PATTERNS.items():
        matches = re.finditer(details["regex"], content, re.IGNORECASE | re.DOTALL)
        for match in matches:
            item = {"type": pattern_name, "risk": details["risk"], "details": details["description"]}
            if pattern_name == "Hardcoded_Key":
                var_name = match.group(1)
                key_value = match.group(2)
                item["type"] = f"{pattern_name} ({var_name})"
                item["value"] = key_value[:8] + ("*" * 10) + key_value[-4:]
            crypto_results.append(item)
    results['crypto-checker'] = crypto_results

    # 4. NETWORK ANALYZER
    network_results = []
    for pattern_name, details in NETWORK_PATTERNS.items():
        matches = re.finditer(details["regex"], content, re.IGNORECASE | re.DOTALL)
        for match in matches:
            output_type = pattern_name
            if match.groups():
                value = match.group(1).strip()
                output_type = f"{pattern_name} ({value})"
            
            network_results.append({
                "type": output_type,
                "risk": details["risk"],
                "details": details["description"]
            })
    results['network-analyzer'] = network_results

    # 5. STORAGE CHECKER
    storage_results = []
    for pattern_name, details in STORAGE_PATTERNS.items():
        matches = re.finditer(details["regex"], content, re.IGNORECASE | re.DOTALL)
        for match in matches:
            if pattern_name == "Insecure_SharedPrefs_Token":
                key_name = match.group(1).strip()
                output_type = f"Insecure SharedPrefs (Key: {key_name})"
            else:
                mode_used = match.group(1).strip()
                output_type = f"Insecure File Permission ({mode_used})"
                
            storage_results.append({
                "type": output_type,
                "risk": details["risk"],
                "details": details["description"]
            })
    results['storage-checker'] = storage_results

    # 6. DEEPLINK ANALYZER
    deeplink_results = []
    matches = re.finditer(DEEPLINK_REGEX, content, re.IGNORECASE | re.DOTALL)
    for match in matches:
        scheme = match.group(1).strip()
        host = match.group(2).strip()
        risk, description = assess_deeplink_risk(scheme, host)
        
        deeplink_results.append({
            "type": "Deep Link Definition",
            "scheme": f"{scheme}://{host}",
            "risk": risk,
            "details": description
        })
    results['deeplink-analyzer'] = deeplink_results
    
    # 7. INTEGRITY CHECK
    integrity_results = []
    for type, details in INTEGRITY_PATTERNS.items():
        match = re.search(details["regex"], content, re.IGNORECASE)
        if match:
            current_version = int(match.group(1))
            if current_version < details["threshold"]:
                integrity_results.append({
                    "type": f"{type} ({current_version})",
                    "risk": details["risk_level"],
                    "details": details["description"]
                })
    results['integrity-check'] = integrity_results
    
    # 8. MANIFEST SETTINGS
    manifest_results = []
    for pattern_name, details in MANIFEST_PATTERNS.items():
        if re.search(details["regex"], content, re.IGNORECASE | re.DOTALL):
            manifest_results.append({
                "type": pattern_name,
                "risk": details["risk"],
                "details": details["description"]
            })
    results['manifest-settings'] = manifest_results
    
    # 9. PERMISSIONS SCAN (NEW LOGIC)
    permissions_results = []
    
    # Iterate through all dangerous permissions defined
    for perm_name, perm_details in DANGEROUS_PERMISSIONS_MAP.items():
        # Build the regex to search for the permission string
        perm_regex = r'["\'](android\.permission\.' + perm_name + r')["\']'
        
        if re.search(perm_regex, content, re.IGNORECASE):
            permissions_results.append({
                "type": f"Dangerous Permission ({perm_name})",
                "risk": perm_details["risk"],
                "details": perm_details["description"]
            })

    results['permissions-scan'] = permissions_results


    return results

