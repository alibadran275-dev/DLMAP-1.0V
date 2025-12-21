# dlmap_package/secrets_module.py

import re

SECRET_PATTERNS = { 
    "API_Key": r'pk_(live|test)_[0-9a-zA-Z]{24,60}',
    "AWS_Key": r'AKIA[0-9A-Z]{16,20}',
    "Password": r'(password|passwd|pwd|pass|secret)([^=]*=[\s\'"]*)([a-zA-Z0-9_]{6,})',
    "Database_User": r'(db_user|user|username)\s*=\s*[\'"]?admin[\'"]?',
}

def run_secrets_scan(target_file):
    results = []
    
    try:
        with open(target_file, 'r', encoding='utf-8') as f:
            content = f.read()
    except Exception as e:
        print(f"[Error] Could not read target file for secrets scan: {e}")
        return results

    for pattern_name, regex in SECRET_PATTERNS.items():
        
        matches = re.finditer(regex, content, re.IGNORECASE)
        
        for match in matches:
            if pattern_name == "Password":
                sensitive_value = match.group(3) if match.groups() and len(match.groups()) >= 3 else match.group(0)
            else:
                sensitive_value = match.group(0)
                
            masked_value = sensitive_value[:6] + ("*" * 10) + sensitive_value[-4:]
            
            results.append({
                "type": pattern_name,
                "value": masked_value,
                "risk": "High_Conf_API_Key" if pattern_name in ["API_Key", "AWS_Key"] else "Medium_Conf_Credential",
                "line": "N/A"
            })
            
    return results

def print_secrets_report(secrets_results):
    print("|_  secrets-search (VULNERABILITY):")
    
    if not secrets_results:
        print("|     [INFO]: No hardcoded secrets or API keys found.")
        return

    for secret in secrets_results:
        tag = f"[{secret['risk']}]"
        
        print(f"|     {tag}: Secret Found ({secret['type']}): \"{secret['value']}\"")
    print("|")

