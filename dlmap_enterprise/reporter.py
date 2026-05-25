# dlmap_enterprise/reporter.py
"""
Compliance Reports & Professional Document Generators.
Generates CLI outputs, Markdown, and machine-readable JSON structure.
"""

import os
import json
import time

def build_cli_nmap_output(scan_results, target_path, duration):
    """Generates iconic Nmap console layout."""
    output = []
    output.append(f"Starting DLMap Enterprise 3.1 (https://dlmap.io) at {time.strftime('%Y-%m-%d %H:%M:%S')}")
    output.append(f"Enterprise scan report for {target_path}")
    output.append(f"Host is up (0.0001s latency).")
    output.append(f"Scanned {len(scan_results)} asset targets in multi-threaded pipeline.\n")
    
    output.append(f"{'FILEPATH':<35} {'STATE':<10} {'SERVICE'}")
    output.append(f"{'='*35} {'='*10} {'='*15}")
    
    metrics = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    
    for path, data in scan_results.items():
        if "error" in data:
            continue
            
        service_type = "AndroidManifest" if "AndroidManifest" in path else "Source Code"
        output.append(f"{path:<35} {'scanned':<10} {service_type}")
        output.append(f"|_  entropy-check:")
        output.append(f"|   Shannon Randomness Entropy: {data['entropy']:.2f}/8.00")
        
        if data["findings"]:
            output.append(f"|_  vulnerability-dissector:")
            for f in data["findings"]:
                risk = f["risk"]
                metrics[risk] += 1
                output.append(f"|   [{risk}] Line {f['line']}: {f['title']} ({f['masvs']} | {f['cwe']})")
                output.append(f"|     - Code Proof: {f['evidence']}")
                output.append(f"|     - Impact: {f['desc']}")
        output.append("")
        
    output.append("\n" + "="*50)
    output.append("DLMAP SECURITY COMPLIANCE EXECUTIVE MATRIX")
    output.append("="*50)
    for risk_lvl, count in metrics.items():
        output.append(f" - {risk_lvl:<12}: {count} vulnerability(ies) flagged.")
        
    output.append(f"\nDLMap Enterprise complete: Scan session duration was {duration:.4f} seconds.")
    return "\n".join(output), metrics

def build_html_report(scan_results, target_path, duration, metrics):
    """Generates an executive, client-ready HTML dashboard with inline CSS."""
    html = []
    html.append("""<!DOCTYPE html>
<html>
<head>
    <title>DLMap Enterprise Compliance Report</title>
    <style>
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background-color: #f4f6f9; color: #333; margin: 40px; }
        .container { max-width: 1200px; background: white; padding: 30px; border-radius: 8px; box-shadow: 0 4px 15px rgba(0,0,0,0.05); }
        h1, h2, h3 { color: #1e293b; border-bottom: 2px solid #e2e8f0; padding-bottom: 10px; }
        .summary-box { display: flex; gap: 20px; margin-bottom: 30px; }
        .card { flex: 1; padding: 20px; border-radius: 6px; text-align: center; color: white; font-weight: bold; }
        .critical { background-color: #ef4444; }
        .high { background-color: #f97316; }
        .medium { background-color: #eab308; }
        .low { background-color: #3b82f6; }
        .info { background-color: #64748b; }
        .file-section { margin-bottom: 30px; padding: 20px; border: 1px solid #e2e8f0; border-radius: 6px; }
        .evidence { background-color: #0f172a; color: #38bdf8; padding: 10px; border-radius: 4px; font-family: monospace; }
        .tag { display: inline-block; padding: 3px 8px; border-radius: 4px; font-size: 0.85em; font-weight: bold; margin-right: 10px; }
    </style>
</head>
<body>
<div class="container">
    <h1>DLMap Enterprise SAST Compliance Audit</h1>
    <p><strong>Target File / Folder Path:</strong> <code>""" + target_path + """</code></p>
    <p><strong>Scan Timestamp:</strong> """ + time.strftime('%Y-%m-%d %H:%M:%S') + """</p>
    <p><strong>Total Duration:</strong> """ + f"{duration:.4f}" + """ seconds</p>
    
    <h2>Vulnerabilities Matrix Summary</h2>
    <div class="summary-box">""")
    
    for lvl in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
        count = metrics.get(lvl, 0)
        html.append(f'        <div class="card {lvl.lower()}">{lvl}: {count}</div>')
        
    html.append("""    </div>
    
    <h2>Asset Analysis Records</h2>""")
    
    for path, data in scan_results.items():
        if "error" in data:
            continue
        html.append(f'    <div class="file-section">')
        html.append(f'        <h3>File Path: <code>{path}</code></h3>')
        html.append(f'        <p><strong>Shannon Entropy:</strong> {data["entropy"]:.2f}/8.00</p>')
        
        if data["findings"]:
            html.append('        <h4>Discovered Security Issues:</h4>')
            for f in data["findings"]:
                risk_cls = f["risk"].lower()
                html.append(f'        <div style="border-left: 4px solid #ef4444; padding-left: 15px; margin-bottom: 20px;">')
                html.append(f'            <p><span class="tag {risk_cls}">{f["risk"]}</span> <strong>Line {f["line"]}: {f["title"]}</strong></p>')
                html.append(f'            <p><strong>Impact:</strong> {f["desc"]}</p>')
                html.append(f'            <p><strong>Compliance Standards:</strong> {f["masvs"]} | {f["cwe"]}</p>')
                html.append(f'            <div class="evidence">{f["evidence"]}</div>')
                html.append(f'        </div>')
        else:
            html.append('        <p style="color: #10b981;"><strong>Compliance Status:</strong> Passed (No issues flagged)</p>')
            
        html.append('    </div>')
        
    html.append("""</div>
</body>
</html>""")
    return "\n".join(html)
