# dlmap_enterprise/config.py
"""
High-Assurance Security Scanner Configuration Engine
Enterprise Rules, Risk Severity Tuning, and Scan Parameters.
"""

SCAN_SETTINGS = {
    "default_threads": 8,
    "entropy_threshold": 4.5,
    "min_token_length": 15,
    "max_file_size_bytes": 10 * 1024 * 1024, # 10MB limit per file
    "ignored_directories": [
        ".git", ".idea", "node_modules", "venv", "__pycache__", ".gradle", "build"
    ],
    "supported_extensions": [
        ".java", ".kt", ".py", ".swift", ".js", ".ts", ".c", ".cpp", ".h", 
        ".cs", ".go", ".rb", ".xml", ".json", ".yaml", ".yml", ".properties"
    ]
}

RISK_LEVELS = {
    "CRITICAL": 5,
    "HIGH": 4,
    "MEDIUM": 3,
    "LOW": 2,
    "INFO": 1
}
