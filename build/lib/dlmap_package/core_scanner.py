# File: dlmap_package/core_scanner.py
import subprocess
import re
import os
import sys
from time import time

# --- Configuration ---
# Define common secret patterns for generic files
SECRET_PATTERNS = {
    'AWS_KEY': r'AKIA[0-9A-Z]{16}',
    'RSA_PRIVATE': r'(BEGIN|END) (RSA|DSA|EC|OPENSSH) PRIVATE KEY',
    'GENERIC_TOKEN': r'(API_KEY|api_key|SECRET|secret|TOKEN|token|password|passwd|pwd)',
}

def get_file_strings(file_path):
    """Executes the 'strings' command on the file and returns the output."""
    try:
        # Use subprocess to call the external 'strings' utility (General for all files)
        result = subprocess.run(['strings', file_path], capture_output=True, text=True, check=True)
        return result.stdout
    except subprocess.CalledProcessError as e:
        return f"Error running strings: {e.stderr}"
    except FileNotFoundError:
        return "Error: 'strings' utility not found. Please install it (e.g., pkg install binutils)."


def scan_secrets(strings):
    """Scans file strings for hardcoded secrets (-sS)."""
    output = "|_  secrets-search (VULNERABILITY):\n"
    found = False
    
    for name, pattern in SECRET_PATTERMs.items():
        if re.search(pattern, strings):
            output += f"|     [CRITICAL]: Found pattern matching {name}.\n"
            output += "|        - Risk: Hardcoded credential exposure.\n"
            found = True
            
    if not found:
        output += "|     No high-confidence secrets found.\n"
        
    return output


def scan_network(strings):
    """Scans for hardcoded network traces like IPs and URLs (-sN)."""
    output = "|_  network-security (NETWORK TRACES):\n"
    
    ip_regex = r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'
    ips = set(re.findall(ip_regex, strings))
    ips.discard('0.0.0.0')
    
    if ips:
        output += f"|     [INFO]: Found potential hardcoded IP addresses ({len(ips)} unique).\n"
        output += "|        - Use: Indicates direct connection endpoints.\n"
    else:
        output += "|     Network Traces: No obvious IP addresses found.\n"
        
    return output


def scan_permissions(strings):
    """Scans for access and permission-related keywords (-sP)."""
    output = "|_  permissions-scan (ACCESS CONTROL):\n"
    
    keywords = r'(read|write|execute|admin|root|system|permission|auth|access)'
    if re.search(keywords, strings, re.IGNORECASE):
        output += "|     [MEDIUM]: Found access-related keywords in file strings.\n"
        output += "|        - Use: Indicates potential access control requirements.\n"
    else:
        output += "|     Access Keyword Check: No common access/permission keywords found.\n"
        
    return output


def run_scan(target_file, flags):
    """The main logic that executes all security checks."""
    
    start_time = time()
    
    # 1. Base Information
    try:
        # Using the external 'file' command, which should be available via 'pkg install file'
        file_type = subprocess.run(['file', '-b', '--mime-type', target_file], capture_output=True, text=True, check=True).stdout.strip()
    except:
        file_type = "Unknown (Command 'file' not found)"

    file_size = os.path.getsize(target_file)
    
    # Get all strings once (Crucial for performance improvement)
    file_strings = get_file_strings(target_file)
    
    # --- Start Report Output ---
    
    output = f"\nStarting DLMap 1.0 (Python Core) at {time()}\n" # VERSION 1.0 HERE
    output += f"DLMap scan report for {target_file}\n"
    output += f"Host is up (0.00s latency).\n"
    output += f"File Type: {file_type}\n"
    output += f"File Size: {file_size / (1024*1024):.2f} MB\n"
    output += "\n| DLMap-NSE Scripts (General Scan Mode):\n"

    # --- 2. Security Check Scripts ---
    
    # Check 2.1: Secrets Search (-sS)
    if '-sS' in flags or '-A' in flags:
        output += scan_secrets(file_strings)

    # Check 2.2: Network Security Check (-sN)
    if '-sN' in flags or '-A' in flags:
        output += scan_network(file_strings)

    # Check 2.3: Permissions/Access Check (-sP)
    if '-sP' in flags or '-A' in flags:
        output += scan_permissions(file_strings)
    
    # --- Final Summary ---
    end_time = time()
    duration = end_time - start_time
    
    output += f"\nDLMap done: 1 IP address (1 host up) scanned in {duration:.2f} seconds\n"
    
    return output


