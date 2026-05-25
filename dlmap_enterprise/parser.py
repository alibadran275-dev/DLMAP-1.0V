# dlmap_enterprise/parser.py
"""
Semantic Static Analysis Parsers, Entropy Computations, and Cognitive Heuristics.
"""

import os
import re
import math
from dlmap_enterprise.config import SCAN_SETTINGS
from dlmap_enterprise.rules import VULNERABILITY_DB

def calculate_shannon_entropy(data_bytes):
    """Calculates pure Shannon Entropy of binary byte chunks."""
    if not data_bytes:
        return 0.0
    entropy = 0.0
    byte_counts = {}
    for byte in data_bytes:
        byte_counts[byte] = byte_counts.get(byte, 0) + 1
    total_len = len(data_bytes)
    for count in byte_counts.values():
        p = count / total_len
        entropy -= p * math.log2(p)
    return entropy

def evaluate_cognitive_context(lines, match_line, default_risk):
    """
    Cognitive Context Analyzer. Looks around lines to classify if risk
    should be escalated or downgraded. Reduces False Positives.
    """
    start = max(0, match_line - 5)
    end = min(len(lines), match_line + 5)
    context_text = "\n".join(lines[start:end]).lower()
    
    escalators = ["prod", "production", "live", "db_url", "main_server", "master", "admin"]
    de_escalators = ["test", "mock", "dummy", "example", "fake", "sandbox", "localhost", "127.0.0.1"]
    
    esc_score = sum(1 for word in escalators if word in context_text)
    de_esc_score = sum(1 for word in de_escalators if word in context_text)
    
    hierarchy = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
    idx = hierarchy.index(default_risk)
    
    if esc_score > 0 and de_esc_score == 0:
        idx = min(len(hierarchy) - 1, idx + 1)
    elif de_esc_score > 1:
        idx = max(0, idx - 1)
        
    return hierarchy[idx], esc_score, de_esc_score

class FileSecurityDissector:
    """Core analysis logic for single files."""
    def __init__(self, filepath):
        self.filepath = filepath
        self.filename = os.path.basename(filepath)
        
    def scan(self):
        findings = []
        
        # Check size limit
        try:
            sz = os.path.getsize(self.filepath)
            if sz > SCAN_SETTINGS["max_file_size_bytes"]:
                return {"error": f"File size exceeds max config limit ({sz} bytes)"}
        except OSError:
            return {"error": "Unable to read file metadata"}
            
        # Read content
        try:
            with open(self.filepath, 'rb') as f:
                raw_bytes = f.read()
        except IOError as e:
            return {"error": f"Failed reading file: {e}"}
            
        file_entropy = calculate_shannon_entropy(raw_bytes)
        
        # Binary strings extraction for compiled/compressed files
        is_binary = any(self.filename.endswith(ext) for ext in ['.dex', '.class', '.so', '.dll', '.exe', '.jar'])
        
        if is_binary:
            # Extract printable ASCII
            strings = re.findall(rb'[ -~]{4,}', raw_bytes)
            content = "\n".join(s.decode('ascii', errors='ignore') for s in strings)
        else:
            content = raw_bytes.decode('utf-8', errors='ignore')
            
        lines = content.splitlines()
        
        # Dispatch scanner based on filename
        if self.filename == 'AndroidManifest.xml':
            self.analyze_manifest(content, lines, findings)
        else:
            self.analyze_source_code(content, lines, findings)
            
        return {
            "entropy": file_entropy,
            "findings": findings,
            "is_binary": is_binary
        }
        
    def analyze_manifest(self, content, lines, findings):
        for rule in VULNERABILITY_DB["manifest"]:
            for match in re.finditer(rule["pattern"], content):
                line_no = content[:match.start()].count('\n') + 1
                risk, esc, de_esc = evaluate_cognitive_context(lines, line_no, rule["risk"])
                findings.append({
                    "rule_id": rule["id"],
                    "risk": risk,
                    "title": rule["title"],
                    "line": line_no,
                    "evidence": match.group(0),
                    "masvs": rule["masvs"],
                    "cwe": rule["cwe"],
                    "desc": rule["desc"]
                })
                
    def analyze_source_code(self, content, lines, findings):
        for rule in VULNERABILITY_DB["code"]:
            for match in re.finditer(rule["pattern"], content):
                line_no = content[:match.start()].count('\n') + 1
                risk, esc, de_esc = evaluate_cognitive_context(lines, line_no, rule["risk"])
                
                matched_text = match.group(0)
                # Mask critical keys
                if len(matched_text) > 12 and any(kw in rule["id"] for kw in ["KEY", "TOKEN", "SECRET"]):
                    masked_evidence = matched_text[:6] + "..." + matched_text[-6:]
                else:
                    masked_evidence = matched_text
                    
                findings.append({
                    "rule_id": rule["id"],
                    "risk": risk,
                    "title": rule["title"],
                    "line": line_no,
                    "evidence": masked_evidence,
                    "masvs": rule["masvs"],
                    "cwe": rule["cwe"],
                    "desc": rule["desc"]
                })
