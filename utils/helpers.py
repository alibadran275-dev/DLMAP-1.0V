"""
DLMap v2.0 - Utility Functions
Helper functions for entropy calculation, masking, and data processing.
"""

import os
import re
import math
from typing import Dict, List, Tuple, Optional
from config import ENTROPY_CONFIG, OUTPUT_CONFIG, RISK_HIERARCHY, CONTEXT_CONFIG


class EntropyCalculator:
    """Calculate Shannon entropy for data analysis."""
    
    @staticmethod
    def calculate_shannon_entropy(data: bytes) -> float:
        """
        Calculate Shannon entropy of binary data.
        Entropy range: 0 (uniform) to 8 (maximum randomness for 8-bit data).
        """
        if not data:
            return 0.0
        
        byte_counts = {}
        for byte in data:
            byte_counts[byte] = byte_counts.get(byte, 0) + 1
        
        total_len = len(data)
        entropy = 0.0
        
        for count in byte_counts.values():
            probability = count / total_len
            entropy -= probability * math.log2(probability)
        
        return entropy
    
    @staticmethod
    def analyze_token_entropy(token: str) -> float:
        """Analyze entropy of a text token (potential secret/key)."""
        if len(token) < ENTROPY_CONFIG["min_token_length"]:
            return 0.0
        
        token_bytes = token.encode('utf-8')
        return EntropyCalculator.calculate_shannon_entropy(token_bytes)
    
    @staticmethod
    def is_high_entropy_token(token: str) -> bool:
        """Check if token has suspiciously high entropy (potential secret)."""
        entropy = EntropyCalculator.analyze_token_entropy(token)
        return entropy >= ENTROPY_CONFIG["high_entropy_threshold"]


class DataMasker:
    """Mask sensitive information in output."""
    
    @staticmethod
    def mask_secret(secret: str, visible_chars: int = 6) -> str:
        """
        Mask a secret/key, showing only first and last N characters.
        Example: "sk_live_abc123def456" -> "sk_live_...def456"
        """
        if not OUTPUT_CONFIG["mask_sensitive_data"] or len(secret) <= visible_chars * 2:
            return secret
        
        start = secret[:visible_chars]
        end = secret[-visible_chars:]
        return f"{start}...{end}"
    
    @staticmethod
    def mask_evidence(evidence: str, max_length: int = None) -> str:
        """Truncate and mask evidence for display."""
        max_len = max_length or OUTPUT_CONFIG["max_evidence_length"]
        
        if len(evidence) <= max_len:
            return evidence
        
        return evidence[:max_len - 3] + "..."


class ContextAnalyzer:
    """Analyze surrounding context to adjust risk levels."""
    
    @staticmethod
    def evaluate_context(lines: List[str], match_line: int, default_risk: str) -> Tuple[str, int, int]:
        """
        Analyze context around matched line to adjust risk level.
        Returns: (adjusted_risk, escalator_score, de_escalator_score)
        """
        context_start = max(0, match_line - CONTEXT_CONFIG["context_lines_before"])
        context_end = min(len(lines), match_line + CONTEXT_CONFIG["context_lines_after"])
        
        context_text = "\n".join(lines[context_start:context_end]).lower()
        
        # Count escalators and de-escalators
        escalator_score = sum(
            1 for word in CONTEXT_CONFIG["escalators"]
            if word in context_text
        )
        de_escalator_score = sum(
            1 for word in CONTEXT_CONFIG["de_escalators"]
            if word in context_text
        )
        
        # Adjust risk level
        risk_idx = RISK_HIERARCHY.index(default_risk)
        
        if escalator_score > 0 and de_escalator_score == 0:
            # Escalate risk if production indicators found
            risk_idx = min(len(RISK_HIERARCHY) - 1, risk_idx + 1)
        elif de_escalator_score > 1:
            # De-escalate risk if test/mock indicators found
            risk_idx = max(0, risk_idx - 1)
        
        adjusted_risk = RISK_HIERARCHY[risk_idx]
        return adjusted_risk, escalator_score, de_escalator_score


class StringExtractor:
    """Extract meaningful strings from binary files."""
    
    @staticmethod
    def extract_strings(data: bytes, min_length: int = 4) -> List[str]:
        """Extract printable ASCII strings from binary data."""
        pattern = rb'[ -~]{' + str(min_length).encode() + b',}'
        strings = re.findall(pattern, data)
        return [s.decode('ascii', errors='ignore') for s in strings]
    
    @staticmethod
    def extract_urls(text: str) -> List[str]:
        """Extract URLs from text."""
        url_pattern = r'https?://[^\s\'"<>]+'
        return re.findall(url_pattern, text, re.IGNORECASE)
    
    @staticmethod
    def extract_emails(text: str) -> List[str]:
        """Extract email addresses from text."""
        email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
        return re.findall(email_pattern, text)


class FileAnalyzer:
    """Analyze file properties and metadata."""
    
    @staticmethod
    def is_binary_file(filepath: str) -> bool:
        """Determine if file is binary based on extension."""
        binary_extensions = {'.dex', '.class', '.so', '.dll', '.exe', '.jar', '.apk', '.aar'}
        _, ext = os.path.splitext(filepath)
        return ext.lower() in binary_extensions
    
    @staticmethod
    def get_file_size(filepath: str) -> int:
        """Get file size in bytes."""
        try:
            return os.path.getsize(filepath)
        except OSError:
            return 0
    
    @staticmethod
    def read_file_content(filepath: str, is_binary: bool = False) -> Optional[str]:
        """Read file content safely."""
        try:
            if is_binary:
                with open(filepath, 'rb') as f:
                    raw_bytes = f.read()
                # Extract strings from binary
                strings = StringExtractor.extract_strings(raw_bytes)
                return "\n".join(strings)
            else:
                with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                    return f.read()
        except Exception as e:
            return None


class LineMapper:
    """Map byte positions to line numbers."""
    
    @staticmethod
    def get_line_number(text: str, byte_position: int) -> int:
        """Get line number from byte position in text."""
        return text[:byte_position].count('\n') + 1
    
    @staticmethod
    def get_line_content(text: str, line_number: int) -> str:
        """Get content of specific line."""
        lines = text.splitlines()
        if 0 <= line_number - 1 < len(lines):
            return lines[line_number - 1]
        return ""
