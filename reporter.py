# reporter.py - Professional Nmap-Style CLI Formatter and Security Report Generator
import json
import time

def generate_nmap_cli(scan_results, target_path, duration):
    """
    Formates findings into a stunning, authentic Nmap-style CLI output
    but with extremely rich, professional security details.
    """
    lines = []
    lines.append(f"Starting DLMap Pro 2.0 (https://dlmap.io) at {time.strftime('%Y-%m-%d %H:%M:%S')}")
    lines.append(f"DLMap Pro scan report for {target_path}")
    lines.append("Host is up (0.001s latency).")
    lines.append(f"Scanned directory contents: {len(scan_results)} relevant files analyzed.\n")
    
    # Header
    lines.append(f"{'FILE':<28} {'SCAN-STATUS':<15} {'SERVICE'}")
    lines.append(f"{'-'*28} {'-'*15} {'-'*15}")
    
    total_issues = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    
    for file_path, data in scan_results.items():
        rel_path = file_path
        service_type = data["service"]
        lines.append(f"{rel_path:<28} {'open':<15} {service_type}")
        
        # Entropy
        lines.append(f"|_  entropy-check:")
        lines.append(f"|   Entropy: {data['entropy']:.2f} (Max 8.00) - {'[OBFUSCATED/COMPRESSED]' if data['entropy'] > 7.2 else '[NORMAL]'}")
        
        # Permissions (if Manifest)
        if "permissions" in data and data["permissions"]:
            lines.append("|_  permissions-scan:")
            for perm in data["permissions"]:
                lines.append(f"|   [HIGH] Dangerous Permission: {perm['name']}")
                lines.append(f"|     - Risk: {perm['desc']}")
                total_issues["HIGH"] += 1
                
        # Exported Components (if Manifest)
        if "exported_components" in data and data["exported_components"]:
            lines.append("|_  component-analyzer:")
            for comp in data["exported_components"]:
                risk = comp["risk"]
                lines.append(f"|   [{risk}] Exported {comp['type'].capitalize()}: {comp['name']}")
                lines.append(f"|     - Risk: Component is public and lacks 'android:permission' enforcement. Hijackable by local apps.")
                total_issues[risk] += 1
                
        # Findings
        if data["findings"]:
            # Group findings by OWASP Category
            grouped = {}
            for f in data["findings"]:
                cat = f["masvs"].split('-')[1] if '-' in f["masvs"] else "GENERAL"
                grouped.setdefault(cat, []).append(f)
                
            for cat, findings in grouped.items():
                section_name = f"{cat.lower()}-analyzer"
                lines.append(f"|_  {section_name}:")
                for f in findings:
                    risk = f["risk"]
                    total_issues[risk] += 1
                    lines.append(f"|   [{risk}] Line {f['line']}: {f['title']} ({f['masvs']} | {f['cwe']})")
                    lines.append(f"|     - Evidence: {f['evidence']}")
                    lines.append(f"|     - Impact: {f['desc']}")
                    lines.append(f"|     - Remediation: {f['remediation']}")
        lines.append("") # Spacer
        
    lines.append("Service detection performed. Please submit any bugs to https://dlmap.io/submit/ .")
    
    # Summary of Issues
    lines.append("\n" + "="*50)
    lines.append("DLMap Scan Executive Summary:")
    lines.append("="*50)
    for risk_level, count in total_issues.items():
        lines.append(f" - {risk_level:<10}: {count} vulnerability(ies) found.")
    lines.append(f"DLMap Pro done: {len(scan_results)} file(s) scanned in {duration:.3f} seconds.")
    
    return "\n".join(lines), total_issues

def generate_markdown_report(scan_results, target_path, duration, total_issues):
    """
    Generates a world-class, corporate penetration testing markdown report.
    This can be shared directly with clients.
    """
    md = []
    md.append(f"# DLMap Pro - Static Application Security Testing (SAST) Report")
    md.append(f"**Target:** `{target_path}`  ")
    md.append(f"**Date:** {time.strftime('%Y-%m-%d %H:%M:%S')}  ")
    md.append(f"**Duration:** {duration:.3f} seconds  \n")
    
    md.append("## 1. Executive Summary")
    md.append("This report outlines the vulnerabilities found during the static code analysis. Each vulnerability is mapped to **OWASP MASVS** (Mobile Application Security Verification Standard) and **CWE** (Common Weakness Enumeration) standards to ensure compliance with enterprise guidelines.\n")
    
    md.append("| Severity | Count |")
    md.append("| :--- | :--- |")
    for r, c in total_issues.items():
        md.append(f"| **{r}** | {c} |")
    md.append("\n")
    
    md.append("## 2. Detailed File Analysis")
    for file_path, data in scan_results.items():
        md.append(f"### File: `{file_path}`")
        md.append(f"* **Service Type:** {data['service']}")
        md.append(f"* **Entropy:** {data['entropy']:.2f}/8.00")
        md.append("\n")
        
        if "permissions" in data and data["permissions"]:
            md.append("#### Dangerous Permissions Requested")
            md.append("| Permission | Risk Description |")
            md.append("| :--- | :--- |")
            for perm in data["permissions"]:
                md.append(f"| `{perm['name']}` | {perm['desc']} |")
            md.append("\n")
            
        if "exported_components" in data and data["exported_components"]:
            md.append("#### Exposed Attack Surface (Exported Components)")
            md.append("| Component Name | Type | Risk |")
            md.append("| :--- | :--- | :--- |")
            for comp in data["exported_components"]:
                md.append(f"| `{comp['name']}` | {comp['type']} | **{comp['risk']}** |")
            md.append("\n")
            
        if data["findings"]:
            md.append("#### Code & Configuration Findings")
            for f in data["findings"]:
                md.append(f"##### [{f['risk']}] {f['title']}")
                md.append(f"* **Location:** Line {f['line']}")
                md.append(f"* **Standards:** {f['masvs']} | {f['cwe']}")
                md.append(f"* **Evidence:** `{f['evidence']}`")
                md.append(f"* **Description:** {f['desc']}")
                md.append(f"* **Remediation:** {f['remediation']}")
                md.append("\n")
        md.append("---\n")
        
    return "\n".join(md)
