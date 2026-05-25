"""
DLMap v2.0 - Core Scanner Engine
Main scanning logic with multi-threading support and cognitive context analysis.
"""

import os
import re
import sys
import time
from typing import Dict, List, Optional, Tuple
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

# Ensure the root path is in sys.path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from config import SCAN_CONFIG, RISK_HIERARCHY
from utils.helpers import (
    EntropyCalculator, DataMasker, ContextAnalyzer, FileAnalyzer, LineMapper
)
from rules.vulnerability_rules import get_rules_by_category, get_all_rules


class FileScanResult:
    """Data structure for file scan results."""
    
    def __init__(self, filepath: str):
        self.filepath = filepath
        self.filename = os.path.basename(filepath)
        self.file_size = FileAnalyzer.get_file_size(filepath)
        self.is_binary = FileAnalyzer.is_binary_file(filepath)
        self.entropy = 0.0
        self.findings = []
        self.error = None
        self.scan_duration = 0.0
    
    def to_dict(self) -> Dict:
        """Convert result to dictionary."""
        return {
            "filepath": self.filepath,
            "filename": self.filename,
            "file_size": self.file_size,
            "is_binary": self.is_binary,
            "entropy": self.entropy,
            "findings": self.findings,
            "error": self.error,
            "scan_duration": self.scan_duration,
        }


class FileScanner:
    """Scan individual files for vulnerabilities."""
    
    def __init__(self, filepath: str):
        self.filepath = filepath
        self.filename = os.path.basename(filepath)
        self.result = FileScanResult(filepath)
    
    def scan(self) -> FileScanResult:
        """Execute scan on file."""
        start_time = time.time()
        
        try:
            # Check file size
            if self.result.file_size > SCAN_CONFIG["max_file_size_bytes"]:
                self.result.error = f"File exceeds max size ({self.result.file_size} bytes)"
                return self.result
            
            # Read file content
            content = FileAnalyzer.read_file_content(self.filepath, self.result.is_binary)
            if content is None:
                self.result.error = "Could not read file"
                return self.result
            
            # Calculate entropy
            try:
                with open(self.filepath, 'rb') as f:
                    raw_bytes = f.read()
                self.result.entropy = EntropyCalculator.calculate_shannon_entropy(raw_bytes)
            except Exception:
                self.result.entropy = 0.0
            
            # Dispatch to appropriate analyzer
            if self.filename == "AndroidManifest.xml":
                self._scan_manifest(content)
            else:
                self._scan_source_code(content)
            
            self.result.scan_duration = time.time() - start_time
            
        except Exception as e:
            self.result.error = str(e)
        
        return self.result
    
    def _scan_manifest(self, content: str):
        """Scan AndroidManifest.xml file."""
        rules = get_rules_by_category("manifest")
        lines = content.splitlines()
        
        for rule in rules:
            try:
                for match in re.finditer(rule["pattern"], content, re.IGNORECASE):
                    line_no = LineMapper.get_line_number(content, match.start())
                    
                    # Adjust risk based on context
                    adjusted_risk, esc_score, de_esc_score = ContextAnalyzer.evaluate_context(
                        lines, line_no, rule["risk"]
                    )
                    
                    finding = {
                        "rule_id": rule["id"],
                        "risk": adjusted_risk,
                        "title": rule["title"],
                        "line": line_no,
                        "evidence": DataMasker.mask_evidence(match.group(0)),
                        "description": rule["description"],
                        "impact": rule["impact"],
                        "remediation": rule["remediation"],
                        "masvs": rule["masvs"],
                        "cwe": rule["cwe"],
                        "cvss_score": rule["cvss_score"],
                    }
                    self.result.findings.append(finding)
            except Exception:
                continue
    
    def _scan_source_code(self, content: str):
        """Scan source code files."""
        rules = get_rules_by_category("code")
        lines = content.splitlines()
        
        for rule in rules:
            try:
                for match in re.finditer(rule["pattern"], content, re.IGNORECASE):
                    line_no = LineMapper.get_line_number(content, match.start())
                    
                    # Adjust risk based on context
                    adjusted_risk, esc_score, de_esc_score = ContextAnalyzer.evaluate_context(
                        lines, line_no, rule["risk"]
                    )
                    
                    # Mask sensitive evidence
                    evidence = match.group(0)
                    if any(kw in rule["id"] for kw in ["KEY", "TOKEN", "SECRET", "AWS", "GCP", "STRIPE", "GITHUB", "SLACK"]):
                        evidence = DataMasker.mask_secret(evidence)
                    
                    finding = {
                        "rule_id": rule["id"],
                        "risk": adjusted_risk,
                        "title": rule["title"],
                        "line": line_no,
                        "evidence": DataMasker.mask_evidence(evidence),
                        "description": rule["description"],
                        "impact": rule["impact"],
                        "remediation": rule["remediation"],
                        "masvs": rule["masvs"],
                        "cwe": rule["cwe"],
                        "cvss_score": rule["cvss_score"],
                    }
                    self.result.findings.append(finding)
            except Exception:
                continue


class ProjectScanner:
    """Scan entire project/directory with multi-threading."""
    
    def __init__(self, target_path: str, threads: int = None):
        self.target_path = target_path
        self.threads = threads or SCAN_CONFIG["default_threads"]
        self.results = {}
        self.total_files_scanned = 0
        self.total_findings = 0
    
    def find_target_files(self) -> List[str]:
        """Find all files to scan in target path."""
        targets = []
        
        if os.path.isfile(self.target_path):
            targets.append(self.target_path)
            return targets
        
        if not os.path.isdir(self.target_path):
            return targets
        
        for root, dirs, files in os.walk(self.target_path):
            # Prune ignored directories
            dirs[:] = [d for d in dirs if not any(
                ignored in d for ignored in SCAN_CONFIG["ignored_directories"]
            )]
            
            for file in files:
                filepath = os.path.join(root, file)
                
                # Check if file should be scanned
                if self._should_scan_file(file):
                    targets.append(filepath)
        
        return targets
    
    def _should_scan_file(self, filename: str) -> bool:
        """Check if file should be scanned."""
        if filename == "AndroidManifest.xml":
            return True
        
        _, ext = os.path.splitext(filename)
        return ext.lower() in SCAN_CONFIG["supported_extensions"]
    
    def scan(self) -> Tuple[Dict, float]:
        """Execute scan with multi-threading."""
        start_time = time.time()
        
        targets = self.find_target_files()
        
        if not targets:
            return {}, 0.0
        
        # Multi-threaded scanning
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {}
            
            for filepath in targets:
                scanner = FileScanner(filepath)
                future = executor.submit(scanner.scan)
                futures[future] = filepath
            
            for future in as_completed(futures):
                filepath = futures[future]
                try:
                    result = future.result()
                    rel_path = os.path.relpath(filepath, self.target_path) if os.path.isdir(self.target_path) else os.path.basename(filepath)
                    
                    self.results[rel_path] = result.to_dict()
                    self.total_files_scanned += 1
                    self.total_findings += len(result.findings)
                    
                except Exception as e:
                    rel_path = os.path.relpath(filepath, self.target_path) if os.path.isdir(self.target_path) else os.path.basename(filepath)
                    self.results[rel_path] = {
                        "error": f"Scan failed: {str(e)}"
                    }
        
        duration = time.time() - start_time
        return self.results, duration
    
    def get_summary(self) -> Dict:
        """Get scan summary statistics."""
        risk_counts = {risk: 0 for risk in RISK_HIERARCHY}
        
        for result in self.results.values():
            if "findings" in result:
                for finding in result["findings"]:
                    risk_counts[finding["risk"]] += 1
        
        return {
            "total_files_scanned": self.total_files_scanned,
            "total_findings": self.total_findings,
            "risk_breakdown": risk_counts,
        }
