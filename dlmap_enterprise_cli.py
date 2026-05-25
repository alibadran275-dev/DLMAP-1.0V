#!/usr/bin/env python3
"""
DLMap Enterprise 3.1 CLI Runner
Optimized for corporate pipelines and deep static application scanning.
"""

import sys
import os
import argparse
import json

from dlmap_enterprise import EnterpriseScanCoordinator, build_cli_nmap_output, build_html_report

def main():
    parser = argparse.ArgumentParser(description="DLMap Enterprise Security Scanner Suite v3.1")
    parser.add_argument("-A", "--aggressive", action="store_true", help="Run multi-threaded vulnerability detection scan")
    parser.add_argument("target", help="File path or folder structure to scan")
    parser.add_argument("-t", "--threads", type=int, help="Number of worker threads (default: 8)")
    parser.add_argument("--html", help="Path to write client-ready HTML dashboard report")
    parser.add_argument("--json", help="Path to write machine-readable JSON output")
    
    args = parser.parse_args()
    
    if not args.aggressive:
        print("="*80)
        print("          DLMAP ENTERPRISE 3.1 - HIGH ASSURANCE CODE AUDITING")
        print("="*80)
        print("[!] For automated security scanning, please invoke with the Aggressive flag (-A).")
        print("Usage: python dlmap_enterprise_cli.py -A <target_path>")
        sys.exit(1)
        
    if not os.path.exists(args.target):
        print(f"[!] Error: Target path '{args.target}' does not exist.")
        sys.exit(1)
        
    print("[*] Dispatching DLMap Enterprise Multi-threaded Analyzer...")
    coordinator = EnterpriseScanCoordinator(args.target, threads=args.threads)
    scan_results, duration = coordinator.run()
    
    cli_output, metrics = build_cli_nmap_output(scan_results, args.target, duration)
    print("\n" + cli_output + "\n")
    
    # Exporters
    if args.html:
        html_content = build_html_report(scan_results, args.target, duration, metrics)
        with open(args.html, "w", encoding="utf-8") as f:
            f.write(html_content)
        print(f"[+] Compliance HTML dashboard exported to: {args.html}")
        
    if args.json:
        payload = {
            "scanner": "DLMap Enterprise v3.1",
            "target": args.target,
            "metrics": {
                "scan_duration_seconds": duration,
                "findings_summary": metrics
            },
            "assets": scan_results
        }
        with open(args.json, "w", encoding="utf-8") as f:
            json.dump(payload, f, indent=4)
        print(f"[+] JSON report data exported to: {args.json}")

if __name__ == "__main__":
    main()
