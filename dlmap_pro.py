#!/usr/bin/env python3
# dlmap_pro.py - Elite-grade Static Analysis Tool for Android and Mobile Applications
import sys
import os
import time
import zipfile
import shutil
import argparse
import json

from rules import RULES
from analyzers import calculate_shannon_entropy, analyze_manifest_xml, analyze_source_code
from reporter import generate_nmap_cli, generate_markdown_report

def handle_target_archive(target_path):
    """If target is an APK or ZIP archive, extracts it to a temp folder."""
    if os.path.isdir(target_path):
        return target_path, False
        
    if not target_path.lower().endswith(('.zip', '.apk')):
        return target_path, False
        
    base_name = os.path.splitext(os.path.basename(target_path))[0]
    unpack_dir = f"dlmap_unpacked_{base_name}_{int(time.time())}"
    
    print(f"[*] Extracting archive {target_path} into {unpack_dir}...")
    try:
        with zipfile.ZipFile(target_path, 'r') as zip_ref:
            zip_ref.extractall(unpack_dir)
        return unpack_dir, True
    except Exception as e:
        print(f"[!] Extraction failed: {e}. Scanning as plain file.")
        return target_path, False

def run_scan(target_dir):
    """Traverses files, executes analyzers, and returns aggregated structured results."""
    scan_results = {}
    
    target_files = []
    if os.path.isdir(target_dir):
        for root, _, files in os.walk(target_dir):
            for file in files:
                filepath = os.path.join(root, file)
                # Filter useful files
                if file == "AndroidManifest.xml" or file.endswith(('.java', '.kt', '.py', '.swift', '.js', '.xml', '.json', '.config')):
                    target_files.append((filepath, file))
    else:
        target_files.append((target_dir, os.path.basename(target_dir)))
        
    for filepath, filename in target_files:
        # Determine service classification
        if filename == 'AndroidManifest.xml':
            service = 'AndroidManifest'
        elif filename.endswith(('.java', '.kt', '.swift', '.js', '.py')):
            service = 'Source Code'
        elif filename.endswith(('.xml', '.json', '.config')):
            service = 'Config/Resource'
        else:
            service = 'File'
            
        entropy = calculate_shannon_entropy(filepath)
        
        # Read contents
        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
        except Exception as e:
            print(f"[!] Warning: Could not read {filepath}: {e}")
            continue
            
        file_data = {
            "service": service,
            "entropy": entropy,
            "findings": [],
            "permissions": [],
            "exported_components": []
        }
        
        # Dispatch to appropriate analyzer
        if filename == 'AndroidManifest.xml':
            manifest_info = analyze_manifest_xml(content)
            file_data["findings"] = manifest_info["findings"]
            file_data["permissions"] = manifest_info["permissions"]
            file_data["exported_components"] = manifest_info["exported_components"]
        else:
            # Source Code and general files
            ext = os.path.splitext(filename)[1]
            file_data["findings"] = analyze_source_code(content, ext)
            
        # Store relative path for clean reporting
        rel_path = os.path.relpath(filepath, target_dir) if os.path.isdir(target_dir) else filename
        scan_results[rel_path] = file_data
        
    return scan_results

def main():
    parser = argparse.ArgumentParser(description="DLMap Pro 2.0 - Professional-Grade Static Application Security Testing Tool")
    parser.add_argument("-A", "--aggressive", action="store_true", help="Perform deep aggressive static logic and secrets analysis")
    parser.add_argument("target", help="Path to decompiled APK directory, ZIP archive, or raw file")
    parser.add_argument("--out-markdown", help="Export a professional Markdown report for clients")
    parser.add_argument("--out-json", help="Export structured JSON scan results")
    
    args = parser.parse_args()
    
    if not args.aggressive:
        print("DLMap Pro 2.0 (https://dlmap.io)")
        print("[!] For full, professional security logic audits, please run with the Aggressive flag (-A).")
        print("Example: python dlmap_pro.py -A <target>")
        sys.exit(1)
        
    start_time = time.time()
    
    # Handle archives
    scan_path, cleanup_needed = handle_target_archive(args.target)
    
    # Run core engines
    scan_results = run_scan(scan_path)
    
    duration = time.time() - start_time
    
    # Format CLI Nmap style output
    cli_report, total_issues = generate_nmap_cli(scan_results, args.target, duration)
    print(cli_report)
    
    # Save reports if requested
    if args.out_markdown:
        md_report = generate_markdown_report(scan_results, args.target, duration, total_issues)
        with open(args.out_markdown, 'w', encoding='utf-8') as f:
            f.write(md_report)
        print(f"[+] Professional Markdown report exported to: {args.out_markdown}")
        
    if args.out_json:
        # Custom JSON serializer
        with open(args.out_json, 'w', encoding='utf-8') as f:
            json.dump({
                "target": args.target,
                "scan_time": duration,
                "vulnerabilities_summary": total_issues,
                "results": scan_results
            }, f, indent=4)
        print(f"[+] Structured JSON data exported to: {args.out_json}")
        
    # Cleanup temp extraction folder
    if cleanup_needed and os.path.isdir(scan_path):
        try:
            shutil.rmtree(scan_path)
        except Exception as e:
            print(f"[!] Cleanup failed for temporary directory {scan_path}: {e}")

if __name__ == "__main__":
    main()
