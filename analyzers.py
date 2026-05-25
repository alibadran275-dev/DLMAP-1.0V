# analyzers.py - Advanced Static Analysis Engines for Android Manifests and Source Code
import os
import re
import math
from rules import RULES, DANGEROUS_PERMISSIONS

def calculate_shannon_entropy(filepath):
    """Calculates true Shannon Entropy of a file to check for obfuscation/encryption."""
    if not os.path.exists(filepath) or os.path.isdir(filepath):
        return 0.0
    try:
        with open(filepath, 'rb') as f:
            data = f.read()
    except Exception:
        return 0.0
    if not data:
        return 0.0
    
    byte_counts = {}
    for byte in data:
        byte_counts[byte] = byte_counts.get(byte, 0) + 1
    
    file_size = len(data)
    entropy = 0.0
    for count in byte_counts.values():
        prob = count / file_size
        entropy -= prob * math.log2(prob)
    return entropy

def analyze_manifest_xml(content):
    """
    Scans an AndroidManifest.xml string for rules and extracts dangerous permissions 
    and exposed components.
    """
    findings = []
    
    # 1. Standard rules from rules.py
    for rule in RULES["manifest"]:
        # Compile pattern and search
        matches = re.finditer(rule["pattern"], content)
        for match in matches:
            findings.append({
                "rule_id": rule["id"],
                "risk": rule["risk"],
                "title": rule["title"],
                "desc": rule["desc"],
                "masvs": rule["masvs"],
                "cwe": rule["cwe"],
                "remediation": rule["remediation"],
                "line": content[:match.start()].count('\n') + 1,
                "evidence": match.group(0)
            })
            
    # 2. Extract and analyze permissions
    permission_pattern = r'<uses-permission\s+[^>]*android:name\s*=\s*"([^"]+)"[^>]*>'
    matches = re.finditer(permission_pattern, content)
    permissions_found = []
    for match in matches:
        perm_name = match.group(1)
        if perm_name in DANGEROUS_PERMISSIONS:
            permissions_found.append({
                "name": perm_name,
                "desc": DANGEROUS_PERMISSIONS[perm_name]
            })
            
    # 3. Component analysis (Check for unauthenticated exported activities/receivers/services)
    # Finding exported components and checking if they have intent-filters but don't require permissions
    component_block_pattern = r'<(activity|service|receiver|provider)\b([^>]*)>(.*?)</\1>'
    component_matches = re.finditer(component_block_pattern, content, re.DOTALL)
    exported_components = []
    
    for comp in component_matches:
        comp_type = comp.group(1)
        comp_attrs = comp.group(2)
        comp_body = comp.group(3)
        
        # Check if exported
        is_exported = False
        if 'android:exported="true"' in comp_attrs:
            is_exported = True
        elif 'android:exported="false"' in comp_attrs:
            is_exported = False
        elif '<intent-filter' in comp_body:
            # Android default for components with intent filters is exported=true prior to API 31
            is_exported = True
            
        if is_exported:
            # Check if protected by permission
            has_permission = "android:permission=" in comp_attrs or "android:permission=" in comp_body
            # Extract component name
            name_match = re.search(r'android:name="([^"]+)"', comp_attrs)
            comp_name = name_match.group(1) if name_match else "Unknown"
            
            if not has_permission:
                exported_components.append({
                    "type": comp_type,
                    "name": comp_name,
                    "risk": "HIGH" if comp_type in ["activity", "provider"] else "MEDIUM"
                })
                
    return {
        "findings": findings,
        "permissions": permissions_found,
        "exported_components": exported_components
    }

def analyze_source_code(content, file_extension):
    """
    Scans source code contents against rules database for secrets, crypto, 
    and storage bugs.
    """
    findings = []
    
    for rule in RULES["code"]:
        matches = re.finditer(rule["pattern"], content)
        for match in matches:
            # Highlight and mask secrets to avoid printing plaintext secrets in console
            matched_text = match.group(0)
            if len(matched_text) > 12 and any(kw in rule["id"] for kw in ["SECRET", "KEY", "TOKEN", "GOOGLE"]):
                masked = matched_text[:6] + "..." + matched_text[-6:]
            else:
                masked = matched_text
                
            findings.append({
                "rule_id": rule["id"],
                "risk": rule["risk"],
                "title": rule["title"],
                "desc": rule["desc"],
                "masvs": rule["masvs"],
                "cwe": rule["cwe"],
                "remediation": rule["remediation"],
                "line": content[:match.start()].count('\n') + 1,
                "evidence": masked
            })
            
    return findings
