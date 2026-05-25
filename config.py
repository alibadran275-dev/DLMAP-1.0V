"""
DLMap v2.0 - Global Configuration Module
Centralized settings for the entire scanning engine.
"""

import os
from typing import Dict, List, Set

# ============================================================================
# PROJECT METADATA
# ============================================================================
PROJECT_NAME = "DLMap"
VERSION = "2.0"
AUTHOR = "Security Team"
WEBSITE = "https://dlmap.io"
DESCRIPTION = "Enterprise-Grade Static Analysis Tool for Mobile Applications"

# ============================================================================
# SCANNING CONFIGURATION
# ============================================================================
SCAN_CONFIG = {
    "default_threads": 8,
    "max_file_size_bytes": 50 * 1024 * 1024,  # 50 MB
    "timeout_per_file": 30,  # seconds
    "supported_extensions": {
        ".java", ".kt", ".swift", ".js", ".ts", ".jsx", ".tsx",
        ".py", ".go", ".rs", ".cpp", ".c", ".h", ".xml", ".json",
        ".config", ".properties", ".gradle", ".plist", ".yml", ".yaml"
    },
    "ignored_directories": {
        "__pycache__", ".git", ".gradle", "build", "dist", "node_modules",
        ".idea", ".vscode", "venv", "env", ".env"
    },
    "archive_extensions": {".zip", ".apk", ".aar", ".jar", ".tar", ".gz"},
}

# ============================================================================
# RISK LEVELS AND SEVERITY HIERARCHY
# ============================================================================
RISK_HIERARCHY = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
RISK_COLORS = {
    "INFO": "\033[94m",      # Blue
    "LOW": "\033[92m",       # Green
    "MEDIUM": "\033[93m",    # Yellow
    "HIGH": "\033[91m",      # Red
    "CRITICAL": "\033[95m",  # Magenta
}
RESET_COLOR = "\033[0m"

# ============================================================================
# COGNITIVE CONTEXT ANALYZER SETTINGS
# ============================================================================
CONTEXT_CONFIG = {
    "context_lines_before": 5,
    "context_lines_after": 5,
    "escalators": [
        "prod", "production", "live", "db_url", "main_server", "master",
        "admin", "root", "password", "secret", "api_key", "token"
    ],
    "de_escalators": [
        "test", "mock", "dummy", "example", "fake", "sandbox", "localhost",
        "127.0.0.1", "0.0.0.0", "demo", "staging", "dev", "development"
    ],
}

# ============================================================================
# ENTROPY ANALYSIS SETTINGS
# ============================================================================
ENTROPY_CONFIG = {
    "max_entropy": 8.0,
    "high_entropy_threshold": 6.5,  # Potential encrypted/encoded data
    "min_token_length": 4,
}

# ============================================================================
# OUTPUT CONFIGURATION
# ============================================================================
OUTPUT_CONFIG = {
    "nmap_style_output": True,
    "include_evidence": True,
    "mask_sensitive_data": True,
    "max_evidence_length": 100,
}

# ============================================================================
# COMPLIANCE STANDARDS MAPPING
# ============================================================================
COMPLIANCE_STANDARDS = {
    "OWASP_MASVS": "Mobile Application Security Verification Standard",
    "CWE": "Common Weakness Enumeration",
    "CVSS": "Common Vulnerability Scoring System",
}

# ============================================================================
# HELPER FUNCTIONS
# ============================================================================
def get_config_value(section: str, key: str, default=None):
    """Retrieve configuration value safely."""
    config_map = {
        "scan": SCAN_CONFIG,
        "risk": {"hierarchy": RISK_HIERARCHY, "colors": RISK_COLORS},
        "context": CONTEXT_CONFIG,
        "entropy": ENTROPY_CONFIG,
        "output": OUTPUT_CONFIG,
    }
    return config_map.get(section, {}).get(key, default)

def is_supported_file(filename: str) -> bool:
    """Check if file extension is supported for scanning."""
    _, ext = os.path.splitext(filename)
    return ext.lower() in SCAN_CONFIG["supported_extensions"] or filename == "AndroidManifest.xml"

def is_ignored_directory(dirname: str) -> bool:
    """Check if directory should be ignored during scanning."""
    return dirname in SCAN_CONFIG["ignored_directories"]
