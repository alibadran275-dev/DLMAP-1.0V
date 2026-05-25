"""
DLMap v2.0 - Report Generator
Generate CLI, JSON, and HTML reports.
"""

import json
import time
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
        self.timestamp = datetime.now().isoformat()
    
    def generate_nmap_cli_report(self) -> str:
        """Generate Nmap-style CLI report."""
        lines = []
        
        # Header
        lines.append("="*80)
        lines.append(f"DLMap v2.0 - Enterprise Static Analysis Tool")
        lines.append(f"Target: {self.target}")
        lines.append(f"Scan Time: {self.timestamp}")
        lines.append("="*80)
        lines.append("")
        
        # Summary
        lines.append(f"Files Scanned: {self.summary['total_files_scanned']}")
        lines.append(f"Total Findings: {self.summary['total_findings']}")
        lines.append("Risk Breakdown:")
        for risk in RISK_HIERARCHY:
            count = self.summary['risk_breakdown'].get(risk, 0)
            lines.append(f"  {risk}: {count}")
        lines.append("")
        
        # File-by-file results
        lines.append("-"*80)
        lines.append(f"{'FILE':<30} {'STATUS':<15} {'FINDINGS':<10}")
        lines.append("-"*80)
        
        for filepath, result in self.results.items():
            if result.get("error"):
                status = "ERROR"
                findings = "0"
            else:
                status = "OK"
                findings = str(len(result.get("findings", [])))
            
            lines.append(f"{filepath:<30} {status:<15} {findings:<10}")
        
        lines.append("-"*80)
        lines.append(f"Scan completed in {self.duration:.2f} seconds")
        lines.append("")
        
        return "\n".join(lines)
    
    def generate_detailed_cli_report(self) -> str:
        """Generate detailed CLI report with findings."""
        lines = [self.generate_nmap_cli_report()]
        
        lines.append("\n" + "="*80)
        lines.append("DETAILED FINDINGS")
        lines.append("="*80 + "\n")
        
        for filepath, result in self.results.items():
            if "error" in result:
                lines.append(f"[ERROR] {filepath}: {result['error']}")
                lines.append("")
                continue
            
            findings = result.get("findings", [])
            if not findings:
                lines.append(f"[OK] {filepath}: No findings")
                lines.append("")
                continue
            
            lines.append(f"[FILE] {filepath}")
            lines.append(f"  Entropy: {result.get('entropy', 0):.2f}/8.00")
            lines.append(f"  Findings: {len(findings)}")
            lines.append("")
            
            for i, finding in enumerate(findings, 1):
                risk = finding["risk"]
                color = RISK_COLORS.get(risk, "")
                lines.append(f"  [{i}] {color}{risk}{RESET_COLOR} - {finding['title']}")
                lines.append(f"      Rule ID: {finding['rule_id']}")
                lines.append(f"      Line: {finding['line']}")
                lines.append(f"      Evidence: {finding['evidence']}")
                lines.append(f"      Description: {finding['description']}")
                lines.append(f"      Remediation: {finding['remediation']}")
                lines.append(f"      MASVS: {finding['masvs']} | CWE: {finding['cwe']} | CVSS: {finding['cvss_score']}")
                lines.append("")
        
        return "\n".join(lines)
    
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
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            padding: 20px;
        }
        .container {
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            border-radius: 10px;
            box-shadow: 0 20px 60px rgba(0,0,0,0.3);
            overflow: hidden;
        }
        .header {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 40px;
            text-align: center;
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
            background: #f8f9fa;
            border-left: 4px solid #667eea;
            padding: 20px;
            border-radius: 5px;
        }
        .summary-card h3 { color: #667eea; font-size: 0.9em; text-transform: uppercase; margin-bottom: 10px; }
        .summary-card .value { font-size: 2em; font-weight: bold; color: #333; }
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
        .findings-section h2 { color: #333; margin-bottom: 20px; border-bottom: 2px solid #667eea; padding-bottom: 10px; }
        .file-group { margin-bottom: 30px; }
        .file-header {
            background: #f3f4f6;
            padding: 15px;
            border-left: 4px solid #667eea;
            margin-bottom: 15px;
            border-radius: 3px;
        }
        .file-header h3 { color: #333; font-size: 1.1em; }
        .finding-item {
            border-left: 4px solid #ddd;
            padding: 15px;
            margin-bottom: 15px;
            background: #fafafa;
            border-radius: 3px;
        }
        .finding-title { font-weight: bold; font-size: 1.05em; margin-bottom: 10px; }
        .finding-meta {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
            gap: 10px;
            font-size: 0.9em;
            color: #666;
            margin-bottom: 10px;
        }
        .finding-meta div { display: flex; flex-direction: column; }
        .finding-meta strong { color: #333; }
        .finding-description { color: #555; line-height: 1.6; margin-bottom: 10px; }
        .finding-remediation {
            background: #e0f2fe;
            border-left: 3px solid #0284c7;
            padding: 10px;
            margin-top: 10px;
            border-radius: 3px;
            font-size: 0.95em;
        }
        .footer {
            background: #f3f4f6;
            padding: 20px;
            text-align: center;
            color: #666;
            font-size: 0.9em;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔒 DLMap v2.0</h1>
            <p>Enterprise Static Analysis Security Report</p>
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
            <div class='value'>{self.duration:.2f}s</div>
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
        html.append("<h2>Detailed Findings</h2>")
        
        for filepath, result in self.results.items():
            if "error" in result:
                html.append(f"<div class='file-group'><div class='file-header'><h3>❌ {filepath}</h3></div>")
                html.append(f"<p style='color: #dc2626;'>{result['error']}</p></div>")
                continue
            
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
                html.append(f"<div><strong>CVSS:</strong> {finding['cvss_score']}</div>")
                html.append(f"</div>")
                html.append(f"<div class='finding-description'>{finding['description']}</div>")
                html.append(f"<div class='finding-remediation'><strong>Remediation:</strong> {finding['remediation']}</div>")
                html.append(f"<div style='font-size: 0.85em; color: #999; margin-top: 10px;'>")
                html.append(f"MASVS: {finding['masvs']} | CWE: {finding['cwe']}")
                html.append(f"</div></div>")
            
            html.append("</div>")
        
        html.append("</div>")
        html.append(f"""<div class='footer'>
            <p>Generated: {self.timestamp}</p>
            <p>Target: {self.target}</p>
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
