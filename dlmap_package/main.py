# File: dlmap_package/main.py
import sys
import os
import shutil
from .core_scanner import run_scan

def check_os_dependencies():
    """Checks for essential operating system tools (file, strings)."""
    
    # 1. Check for 'file' command (Required for File Type)
    if shutil.which('file') is None:
        print("\n[CRITICAL ERROR] Dependency Missing:")
        print("  Command 'file' not found. This is required for File Type detection.")
        print("  RECOMMENDATION (Termux): pkg install file")
        print("  RECOMMENDATION (Linux): sudo apt install file (or equivalent)")
        return False
        
    # 2. Check for 'strings' command (Required for all scans)
    if shutil.which('strings') is None:
        print("\n[CRITICAL ERROR] Dependency Missing:")
        print("  Command 'strings' not found. This is required for all security analysis.")
        print("  RECOMMENDATION (Termux): pkg install binutils")
        print("  RECOMMENDATION (Linux): sudo apt install binutils (or equivalent)")
        return False
        
    return True

def main():
    """Parses command line arguments and runs the scanner."""
    
    # --- STEP 1: Check Dependencies ---
    if not check_os_dependencies():
        sys.exit(1)
        
    # --- STEP 2: Argument Parsing ---
    if len(sys.argv) < 2:
        print("DLMap 1.0: Must specify target. Use -h for help.")
        print("Usage: dlmap [OPTIONS] <TARGET_FILE>")
        sys.exit(1)

    target_file = None
    flags = []

    for arg in sys.argv[1:]:
        if arg.startswith('-'):
            flags.append(arg)
        else:
            target_file = arg
            
    if not target_file:
        print("DLMap 1.0: Error: Target file not specified.")
        sys.exit(1)

    # Simple help handler
    if '-h' in flags or '--help' in flags:
        print("DLMap 1.0 Usage:")
        print("  dlmap [OPTIONS] <TARGET_FILE>")
        print("  -A: Aggressive scan (includes -sS, -sN, -sP, etc.)")
        print("  -sS: Secrets scan")
        print("  -sN: Network traces scan")
        print("  -sP: Permissions/Access scan")
        sys.exit(0)
        
    
    # Final check for file existence
    if not os.path.exists(target_file):
        print(f"DLMap 1.0: Target file '{target_file}' not found.")
        sys.exit(1)
        
    print(run_scan(target_file, flags))

if __name__ == '__main__':
    main()

