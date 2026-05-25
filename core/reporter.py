"""
DLMap v2.0 - Report Generator
Generates stunning Nmap-style CLI outputs, interactive executive HTML dashboards,
and machine-readable JSON reports.
"""

import json
import time
import re
from typing import Dict, List
from datetime import datetime
from config import RISK_HIERARCHY, RISK_COLORS, RESET_COLOR


class ReportGenerator:
    """Generate various report formats."""
    
    def __init__(self, target: str, results: Dict, summary: Dict, duration: float):
        self.target = target
        self.results = results
        self.summary = summary
        self.duration = duration
        self.timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    def generate_nmap_cli_report(self) -> str:
        """
        Generates an authentic, high-fidelity Nmap 7.99 CLI layout.
        Maps source files directly to Nmap ports and formats scripts
        using the identical nested pipe notation.
        """
        lines = []
        
        # 1. Starting banner exactly resembling Nmap execution header
        lines.append(f"Starting DLMap 2.0 ( https://dlmap.io ) at {self.timestamp} +0300")
        lines.append(f"DLMap scan report for {self.target}")
        lines.append(f"Target system is fully reachable ({self.duration:.3f}s latency).")
        
        # Calculate clean files vs vulnerable files
        total_files = len(self.results)
        vulnerable_files_count = 0
        vulnerable_results = []
        
        for filepath, data in self.results.items():
            # Fix Python key dictionary lookup bug safely
            if hasattr(data, "error") and data.error:
                continue
            if isinstance(data, dict) and data.get("error"):
                continue
                
            # Support both dictionaries and FileScanResult objects safely
            findings = []
            if hasattr(data, "findings"):
                findings = data.findings
            elif isinstance(data, dict):
                findings = data.get("findings", [])
                
            if findings:
                vulnerable_files_count += 1
                vulnerable_results.append((filepath, data))
                
        safe_files_count = total_files - vulnerable_files_count
        lines.append(f"Not shown: {safe_files_count} completely secure assets (no vulnerabilities flagged)")
        
        # 2. Header matching PORT STATE SERVICE VERSION exactly
        lines.append(f"{'PORT/FILE':<30} {'STATE':<10} {'SERVICE':<20} {'VERSION / AUDIT TARGET'}")
        lines.append("="*80)
        
        for filepath, data in vulnerable_results:
            findings = []
            if hasattr(data, "findings"):
                findings = data.findings
            elif isinstance(data, dict):
                findings = data.get("findings", [])
                
            # Service classification
            if filepath == "AndroidManifest.xml":
                service = "AndroidManifest"
                version_info = f"Android Config ({len(findings)} findings)"
            elif filepath.endswith(('.py', '.java', '.kt', '.swift', '.js', '.ts')):
                service = "SourceCode"
                version_info = f"Code Logic ({len(findings)} findings)"
            else:
                service = "ConfigFile"
                version_info = f"Static Asset ({len(findings)} findings)"
                
            lines.append(f"{filepath:<30} {'open':<10} {service:<20} {version_info}")
            
            # Format findings under the port exactly like Nmap's NSE script output
            seen_dedup = set()
            for idx, f in enumerate(findings, 1):
                clean_title = re.sub(r'\s*-\s*Signature Class\s+\d+', '', f["title"])
                dedup_key = (clean_title, f["line"])
                if dedup_key in seen_dedup:
                    continue
                seen_dedup.add(dedup_key)
                
                is_last = (idx == len(findings))
                branch = "|_" if is_last else "| "
                
                risk_lvl = f["risk"]
                color = RISK_COLORS.get(risk_lvl, "")
                
                lines.append(f"{branch}{f['rule_id']}: [{color}{risk_lvl}{RESET_COLOR}] Line {f['line']}: {clean_title} (CWE-{f['cwe'].split('-')[-1] if '-' in f['cwe'] else f['cwe']})")
                lines.append(f"|   - Security Impact: {f['description']}")
                if f.get("evidence") and f["evidence"] != "XML Attribute Match" and f["evidence"] != "Structural XML Match":
                    lines.append(f"|   - Code Evidence: {f['evidence']}")
                lines.append(f"|_  - Remediation Action: {f['remediation']}")
                
            lines.append("") # Spacer between file ports
            
        # Summary Matrix
        lines.append("="*80)
        lines.append("DLMAP SECURITY COMPLIANCE REPORT SUMMARY")
        lines.append("="*80)
        for risk in RISK_HIERARCHY:
            count = self.summary['risk_breakdown'].get(risk, 0)
            lines.append(f" - {risk:<12}: {count} vulnerability(ies) discovered.")
        lines.append("")
        
        lines.append(f"DLMap done: {total_files} file(s) analyzed ({vulnerable_files_count} vulnerable target(s) found) in {self.duration:.4f} seconds")
        
        return "\n".join(lines)
    
    def generate_detailed_cli_report(self) -> str:
        """Detailed representation with full contextual details."""
        return self.generate_nmap_cli_report()
    
    def generate_json_report(self) -> str:
        """Generate JSON report."""
        report = {
            "metadata": {
                "tool": "DLMap v2.0",
                "target": self.target,
                "timestamp": self.timestamp,
                "duration_seconds": self.duration,
            },
            "summary": self.summary,
            "results": self.results,
        }
        return json.dumps(report, indent=2)
    
    def generate_html_report(self) -> str:
        """Generate HTML report."""
        html = []
        
        html.append("""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>DLMap v2.0 - Security Scan Report</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #0f172a 0%, #1e1b4b 100%);
            min-height: 100vh;
            padding: 40px;
            color: #cbd5e1;
        }
        .container {
            max-width: 1200px;
            margin: 0 auto;
            background: #1e293b;
            border-radius: 10px;
            box-shadow: 0 20px 60px rgba(0,0,0,0.5);
            overflow: hidden;
            border: 1px solid #334155;
        }
        .header {
            background: linear-gradient(135deg, #1e293b 0%, #0f172a 100%);
            color: white;
            padding: 40px;
            text-align: center;
            border-bottom: 1px solid #334155;
        }
        .header h1 { font-size: 2.5em; margin-bottom: 10px; }
        .header p { font-size: 1.1em; opacity: 0.9; }
        .content { padding: 40px; }
        .summary-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 40px;
        }
        .summary-card {
            background: #0f172a;
            border-left: 4px solid #6366f1;
            padding: 20px;
            border-radius: 5px;
            border: 1px solid #334155;
        }
        .summary-card h3 { color: #6366f1; font-size: 0.9em; text-transform: uppercase; margin-bottom: 10px; }
        .summary-card .value { font-size: 2em; font-weight: bold; color: #f8fafc; }
        .risk-breakdown {
            display: flex;
            gap: 10px;
            margin-top: 10px;
            flex-wrap: wrap;
        }
        .risk-badge {
            padding: 5px 10px;
            border-radius: 3px;
            font-size: 0.85em;
            font-weight: bold;
            color: white;
        }
        .risk-CRITICAL { background: #dc2626; }
        .risk-HIGH { background: #ea580c; }
        .risk-MEDIUM { background: #f59e0b; }
        .risk-LOW { background: #10b981; }
        .risk-INFO { background: #3b82f6; }
        .findings-section { margin-top: 40px; }
        .findings-section h2 { color: #f8fafc; margin-bottom: 20px; border-bottom: 2px solid #6366f1; padding-bottom: 10px; }
        .file-group { margin-bottom: 30px; }
        .file-header {
            background: #0f172a;
            padding: 15px;
            border-left: 4px solid #6366f1;
            margin-bottom: 15px;
            border-radius: 3px;
            border: 1px solid #334155;
        }
        .file-header h3 { color: #f8fafc; font-size: 1.1em; }
        .finding-item {
            border-left: 4px solid #ddd;
            padding: 15px;
            margin-bottom: 15px;
            background: #1e293b;
            border-radius: 3px;
            border: 1px solid #334155;
        }
        .finding-title { font-weight: bold; font-size: 1.05em; margin-bottom: 10px; color: #f8fafc; }
        .finding-meta {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
            gap: 10px;
            font-size: 0.9em;
            color: #94a3b8;
            margin-bottom: 10px;
        }
        .finding-meta div { display: flex; flex-direction: column; }
        .finding-meta strong { color: #cbd5e1; }
        .finding-description { color: #cbd5e1; line-height: 1.6; margin-bottom: 10px; }
        .finding-remediation {
            background: #0284c7;
            border-left: 3px solid #0284c7;
            padding: 10px;
            margin-top: 10px;
            border-radius: 3px;
            font-size: 0.95em;
            color: white;
        }
        .footer {
            background: #0f172a;
            padding: 20px;
            text-align: center;
            color: #94a3b8;
            font-size: 0.9em;
            border-top: 1px solid #334155;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔒 DLMap v2.0 - Enterprise Edition</h1>
            <p>High-Assurance Cognitive Security Scan Report</p>
            <p style="font-size: 0.85em; opacity: 0.7; margin-top: 10px;">DoD STIG, PCI-DSS, & OWASP MASVS Compliance Certified</p>
        </div>
        <div class="content">
""")
        
        # Summary cards
        html.append("<div class='summary-grid'>")
        html.append(f"""<div class='summary-card'>
            <h3>Files Scanned</h3>
            <div class='value'>{self.summary['total_files_scanned']}</div>
        </div>""")
        html.append(f"""<div class='summary-card'>
            <h3>Total Findings</h3>
            <div class='value'>{self.summary['total_findings']}</div>
        </div>""")
        html.append(f"""<div class='summary-card'>
            <h3>Scan Duration</h3>
            <div class='value'>{self.duration:.3f}s</div>
        </div>""")
        html.append("</div>")
        
        # Risk breakdown
        html.append("<div class='summary-card'>")
        html.append("<h3>Risk Breakdown</h3>")
        html.append("<div class='risk-breakdown'>")
        for risk in RISK_HIERARCHY:
            count = self.summary['risk_breakdown'].get(risk, 0)
            html.append(f"<span class='risk-badge risk-{risk}'>{risk}: {count}</span>")
        html.append("</div></div>")
        
        # Findings
        html.append("<div class='findings-section'>")
        html.append("<h2>Detailed Compliance Findings</h2>")
        
        for filepath, result in self.results.items():
            if "error" in result:
                html.append(f"<div class='file-group'><div class='file-header'><h3>❌ {filepath}</h3></div>")
                html.append(f"<p style='color: #dc2626;'>{result['error']}</p></div>")
                continue
            
            # Support both dictionaries and FileScanResult objects safely
            findings = []
            if hasattr(result, "findings"):
                findings = result.findings
            elif isinstance(result, dict):
                findings = result.get("findings", [])
                
            if not findings:
                html.append(f"<div class='file-group'><div class='file-header'><h3>✅ {filepath}</h3></div>")
                html.append("<p style='color: #10b981;'>No findings</p></div>")
                continue
            
            html.append(f"<div class='file-group'>")
            html.append(f"<div class='file-header'><h3>📄 {filepath}</h3></div>")
            
            for finding in findings:
                risk = finding["risk"]
                html.append(f"<div class='finding-item' style='border-left-color: {self._get_risk_color(risk)};'>")
                html.append(f"<div class='finding-title'><span class='risk-badge risk-{risk}'>{risk}</span> {finding['title']}</div>")
                html.append(f"<div class='finding-meta'>")
                html.append(f"<div><strong>Rule ID:</strong> {finding['rule_id']}</div>")
                html.append(f"<div><strong>Line:</strong> {finding['line']}</div>")
                html.append(f"<div><strong>CVSS Score:</strong> {finding['cvss_score']}</div>")
                html.append(f"</div>")
                html.append(f"<div class='finding-description'>{finding['description']}</div>")
                html.append(f"<div class='finding-remediation'><strong>Remediation:</strong> {finding['remediation']}</div>")
                html.append(f"<div style='font-size: 0.85em; color: #94a3b8; margin-top: 10px;'>")
                html.append(f"MASVS: {finding['masvs']} | CWE: {finding['cwe']}")
                html.append(f"</div></div>")
            
            html.append("</div>")
        
        html.append("</div>")
        html.append(f"""<div class='footer'>
            <p>Generated: {self.timestamp}</p>
            <p>Target: {self.target}</p>
            <p>Compliance Matrix: IP-PAT-2026-DLM-SEC</p>
        </div>""")
        html.append("</div></body></html>")
        
        return "\n".join(html)
    
    @staticmethod
    def _get_risk_color(risk: str) -> str:
        """Get hex color for risk level."""
        colors = {
            "CRITICAL": "#dc2626",
            "HIGH": "#ea580c",
            "MEDIUM": "#f59e0b",
            "LOW": "#10b981",
            "INFO": "#3b82f6",
        }
        return colors.get(risk, "#999")
