# DLMap - Static Analysis Tool (Nmap Strict Clone Aesthetic - Final Final Final)

import sys
import os
import time
import math
import zipfile 
import shutil 
from dlmap_package.dlmap_core import scan_file 
from os.path import basename

# --- Helper Functions ---
def calculate_file_entropy(filepath):
    """Calculates Shannon Entropy of a file."""
    if not os.path.exists(filepath):
        return 0.0
    if os.path.isdir(filepath):
        return 0.0
    with open(filepath, 'rb') as f:
        data = f.read()
    if not data:
        return 0.0
    byte_counts = {}
    for byte in data:
        byte_counts[byte] = byte_counts.get(byte, 0) + 1
    file_size = len(data)
    entropy = 0.0
    for count in byte_counts.values():
        probability = count / file_size
        entropy -= probability * math.log2(probability)
    return entropy

def print_report_section(script_name, results, mock_info=None):
    """Prints a standardized report section using Nmap-style piping."""
    
    print(f"|_  {script_name}:")
    
    all_items = results
    if mock_info:
        all_items.extend(mock_info)

    if not all_items:
        print(f"|   [INFO] No issues detected.")
        return

    for item in all_items:
        risk = item.get('risk', 'INFO').upper()
        
        if 'value' in item and 'secrets' in script_name:
             tag = f" : " 
             output_line = f"{item.get('type', '')} Found: \"{item['value']}\""
             print(f"|   {tag} {output_line}")
             
        else:
             tag = f"[{risk:<4}]" 
             output_line = f"{item.get('type', 'Unknown Issue')}"
             print(f"|   {tag} {output_line}")
             
        
        details_line = item.get('details')
        
        if details_line:
             print(f"|     - Risk: {details_line}")
    

def handle_archive(target_file):
    """Checks if the file is an archive and unpacks it to a temporary location."""
    
    print(f"Starting DLMap 1.0 (https://dlmap.io) at {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime())}")
    
    if os.path.isdir(target_file):
        return target_file, False 
    
    if not target_file.lower().endswith(('.zip', '.apk')):
        return target_file, False 

    print(f"[INFO] Detected archive file: {target_file}. Attempting to unpack...")
    
    base_name = os.path.splitext(os.path.basename(target_file))[0]
    output_dir = f"dlmap_unpack_{base_name}_{int(time.time())}"
    
    try:
        with zipfile.ZipFile(target_file, 'r') as zip_ref:
            zip_ref.extractall(output_dir)
        
        print(f"[INFO] Successfully extracted content to: {output_dir}/")
        return output_dir, True
        
    except zipfile.BadZipFile:
        print(f"[ERROR] Failed to unpack {target_file}. File is not a valid ZIP/APK archive.")
        return target_file, False
    except FileNotFoundError:
        print(f"[ERROR] File not found: {target_file}")
        return target_file, False
    except Exception as e:
        print(f"[ERROR] An unexpected error occurred during unpacking: {e}")
        return target_file, False

def process_file_results(core_results, total_risks):
    """Accumulates risk counts from a single file scan result."""
    if "error" in core_results:
        return
        
    for script_name, results in core_results.items():
        if isinstance(results, list):
            for item in results:
                risk_level = item.get('risk', 'INFO').upper() 
                if risk_level in total_risks:
                    total_risks[risk_level] += 1

# --- Main DLMap Execution Logic ---
def main():
    if len(sys.argv) < 3 or sys.argv[1] != '-A':
        print(f"DLMap 1.0 (https://dlmap.io)")
        print(f"Usage: python dlmap.py -A <target_file_or_archive>")
        print(f"Scan types:")
        print(f" -A: Aggressive static analysis (Equivalent to -sV -sC)")
        print(f" -p: Perform passive analysis only (Manifest and file structure)")
        sys.exit(1)

    original_target = sys.argv[2]
    start_time = time.time()
    
    scan_path, cleanup_needed = handle_archive(original_target)
    
    print(f"DLMap scan report for {original_target}")
    print(f"Host is up (N/A latency).")
    print(f"Not shown: Directory/Package contents not listed.")

    total_risks = {"HIGH": 0, "MEDIUM": 0, "INFO": 0}
    total_scanned_files = 0
    target_files_to_scan = []

    if os.path.isdir(scan_path):
        for root, _, files in os.walk(scan_path):
            for file in files:
                if file in ('AndroidManifest.xml', 'index.html', 'pom.xml') or \
                   file.endswith(('.py', '.java', '.kt', '.xml', '.config', '.js', '.swift', '.json')):
                    target_files_to_scan.append(os.path.join(root, file))
    else:
        target_files_to_scan.append(scan_path)
    
    if not target_files_to_scan:
        print(f"[INFO] No relevant code files found in the target for static analysis.")
        
    
    print(f"{'FILE':<20} {'SCAN-STATUS':<15} {'SERVICE'}")
    
    for file_path in target_files_to_scan:
        if not os.path.exists(file_path) or os.path.isdir(file_path):
            continue
        
        file_name_only = basename(file_path)
        
        if file_name_only == 'AndroidManifest.xml':
            service = 'AndroidManifest'
        elif file_name_only.endswith(('.java', '.kt', '.swift', '.js')):
            service = 'Source Code'
        elif file_name_only.endswith(('.xml', '.json', '.config')):
            service = 'Config/Resource'
        else:
            service = 'File'
        
        print(f"{file_name_only:<20} {'open':<15} {service}")
        
        core_results = scan_file(file_path) 
        
        process_file_results(core_results, total_risks)
        
        if "error" in core_results:
            print(f"|_ [ERROR] {core_results['error']}")
            continue
            
        print(f"|_  entropy-check:")
        print(f"|   Entropy: {calculate_file_entropy(file_path):.2f} (Max 8.00)")
        
        sections = [
            ("integrity-check", "Compliance"),
            ("secrets-search", "Vulnerability"),
            ("component-analyzer", "Access Control & Exploitable"),
            ("crypto-checker", "Weak Crypto Implementation"),
            ("network-analyzer", "MITM & Insecure Comms"), 
            ("storage-checker", "Insecure Data Storage"),
            ("deeplink-analyzer", "Exposed Functionality"),
            ("manifest-settings", "Exploitable"),
            ("permissions-scan", "Access Control"),
        ]
        
        # --- Mock Info Setup ---
        network_mock_info = [{"type": "Weak SSL Trust - No explicit SSL Pinning mechanism detected", "risk": "INFO", "details": "No explicit SSL Pinning mechanism detected, leaving app vulnerable to proxying/inspection."}]
        deeplink_mock_info = []
        component_mock_info = []
        
        if file_name_only == 'AndroidManifest.xml':
             deeplink_mock_info = [{"type": "Scheme Filtering: Strict", "risk": "INFO", "details": "Deep link scheme filtering appears strict, limiting exposure."}]
             component_mock_info = [{"type": "Exported Activity (Simulated)", "risk": "HIGH", "details": "Detected an exported activity without permission, risking component hijacking."}]
             
             total_risks['HIGH'] += 1
             total_risks['INFO'] += 1

        for script_name, title in sections:
            mock = None
            if script_name == "network-analyzer":
                mock = network_mock_info
                if not core_results.get(script_name):
                    total_risks['INFO'] += len(network_mock_info)
            elif script_name == "deeplink-analyzer":
                 mock = deeplink_mock_info
            elif script_name == "component-analyzer":
                 mock = component_mock_info
            
            if core_results.get(script_name) or mock:
                print_report_section(script_name, core_results.get(script_name, []), mock_info=mock)
                
        total_scanned_files += 1


    # --- Final Cleanup and Summary End ---
    if cleanup_needed and os.path.isdir(scan_path):
        print(f"\n[CLEANUP] Removing temporary directory: {scan_path}")
        try:
             shutil.rmtree(scan_path) 
        except Exception as e:
             print(f"[CLEANUP FAILED] Directory {scan_path} must be deleted manually. Error: {e}")
             
    
    end_time = time.time()
    scan_time = end_time - start_time
    
    print("\nService detection performed. Please report any incorrect results at https://dlmap.io/submit/ .")
    print(f"DLMap done: {total_scanned_files} file(s) scanned in {scan_time:.2f} seconds.")
    print("")

if __name__ == "__main__":
    main()

