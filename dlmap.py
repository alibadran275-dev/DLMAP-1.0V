#!/usr/bin/env python3
"""
DLMap v2.0 - Enterprise Static Analysis Tool
Main CLI entry point for scanning mobile applications and source code.
"""

import sys
import os
import argparse
import time
from pathlib import Path

# Add project root to path
project_root = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, project_root)

try:
    from config import PROJECT_NAME, VERSION, WEBSITE, DESCRIPTION
    from core.scanner import ProjectScanner
    from core.archive_handler import ArchiveHandler
    from core.reporter import ReportGenerator
except ImportError as e:
    print(f"[!] Critical Error: Failed to import core modules: {e}")
    sys.exit(1)


def print_banner():
    """Print DLMap banner."""
    banner = f"""
╔════════════════════════════════════════════════════════════════════════════╗
║                                                                            ║
║                    🔒 {PROJECT_NAME} v{VERSION} - Enterprise SAST                  ║
║                                                                            ║
║                    {DESCRIPTION}                 ║
║                                                                            ║
║                          {WEBSITE}                            ║
║                                                                            ║
╚════════════════════════════════════════════════════════════════════════════╝
    """
    print(banner)


def main():
    # Redirect execution to the ultimate pro version which is the new v1 beta
    current_dir = os.path.dirname(os.path.abspath(__file__))
    ultimate_script = os.path.join(current_dir, "dlmap_ultimate_pro.py")
    
    if os.path.exists(ultimate_script):
        # Pass all arguments to the ultimate script
        args = sys.argv[1:]
        # Use subprocess to run the other script and keep the environment
        import subprocess
        cmd = [sys.executable, ultimate_script] + args
        subprocess.run(cmd)
        sys.exit(0)
    
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description=f"{PROJECT_NAME} v{VERSION} - {DESCRIPTION}",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Scan a directory
  python dlmap.py -A ./target_directory
  
  # Scan an APK file
  python dlmap.py -A ./app.apk
  
  # Generate HTML report
  python dlmap.py -A ./target_directory --html report.html
  
  # Generate JSON report
  python dlmap.py -A ./target_directory --json report.json
  
  # Use custom thread count
  python dlmap.py -A ./target_directory -t 16
        """
    )
    
    parser.add_argument(
        "-A", "--aggressive",
        action="store_true",
        help="Enable aggressive scanning mode (required)"
    )
    parser.add_argument(
        "target",
        nargs="?",
        help="Target file, directory, or archive to scan"
    )
    parser.add_argument(
        "-t", "--threads",
        type=int,
        default=8,
        help="Number of parallel scanning threads (default: 8)"
    )
    parser.add_argument(
        "--html",
        help="Path to save HTML report"
    )
    parser.add_argument(
        "--json",
        help="Path to save JSON report"
    )
    parser.add_argument(
        "--detailed",
        action="store_true",
        help="Show detailed findings in CLI output"
    )
    
    args = parser.parse_args()
    
    # Validate arguments
    if not args.aggressive:
        print_banner()
        print("[!] Error: Aggressive flag (-A) is required to start scanning.")
        print(f"\nUsage: python dlmap.py -A <target>")
        sys.exit(1)
    
    if not args.target:
        print_banner()
        print("[!] Error: Target path is required.")
        print(f"\nUsage: python dlmap.py -A <target>")
        sys.exit(1)
    
    # Print banner
    print_banner()
    
    # Check if target exists
    if not os.path.exists(args.target):
        print(f"[ERROR] Target not found: {args.target}")
        sys.exit(1)
    
    # Handle archives
    target_path = args.target
    cleanup_needed = False
    
    if ArchiveHandler.is_archive(args.target):
        print(f"[*] Detected archive file: {args.target}")
        print(f"[*] Extracting archive...")
        target_path, cleanup_needed = ArchiveHandler.extract(args.target)
        print(f"[+] Extracted to: {target_path}")
        print()
    
    # Execute scan
    print(f"[*] Starting scan...")
    print(f"[*] Target: {target_path}")
    print(f"[*] Threads: {args.threads}")
    print()
    
    start_time = time.time()
    
    try:
        scanner = ProjectScanner(target_path, threads=args.threads)
        results, duration = scanner.scan()
        summary = scanner.get_summary()
        
        # Generate reports
        reporter = ReportGenerator(args.target, results, summary, duration)
        
        # CLI output
        if args.detailed:
            cli_report = reporter.generate_detailed_cli_report()
        else:
            cli_report = reporter.generate_nmap_cli_report()
        
        print(cli_report)
        
        # Save HTML report
        if args.html:
            html_report = reporter.generate_html_report()
            with open(args.html, 'w', encoding='utf-8') as f:
                f.write(html_report)
            print(f"[+] HTML report saved: {args.html}")
        
        # Save JSON report
        if args.json:
            json_report = reporter.generate_json_report()
            with open(args.json, 'w', encoding='utf-8') as f:
                f.write(json_report)
            print(f"[+] JSON report saved: {args.json}")
        
        # Cleanup
        if cleanup_needed:
            print(f"\n[*] Cleaning up temporary files...")
            if ArchiveHandler.cleanup(target_path):
                print(f"[+] Cleanup successful")
            else:
                print(f"[!] Manual cleanup required: {target_path}")
        
        print(f"\n[+] Scan completed successfully!")
        sys.exit(0)
    except Exception as e:
        print(f"[ERROR] Unexpected error during scan: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[!] Scan interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"[ERROR] Unexpected error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
