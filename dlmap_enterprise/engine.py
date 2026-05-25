# dlmap_enterprise/engine.py
"""
Multi-threaded Scan Coordinator and Task Dispatcher.
Optimized for scale and enterprise workloads.
"""

import os
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dlmap_enterprise.config import SCAN_SETTINGS
from dlmap_enterprise.parser import FileSecurityDissector

class EnterpriseScanCoordinator:
    """Manages system target traversing, worker thread pooling and consolidation."""
    def __init__(self, target_path, threads=None):
        self.target_path = target_path
        self.threads = threads or SCAN_SETTINGS["default_threads"]
        self.scan_results = {}
        self.total_scanned_files = 0
        
    def find_target_files(self):
        targets = []
        if os.path.isfile(self.target_path):
            targets.append(self.target_path)
            return targets
            
        for root, dirs, files in os.walk(self.target_path):
            # Prune ignored directory structures
            dirs[:] = [d for d in dirs if d not in SCAN_SETTINGS["ignored_directories"]]
            for file in files:
                ext = os.path.splitext(file)[1].lower()
                if ext in SCAN_SETTINGS["supported_extensions"] or file == "AndroidManifest.xml":
                    targets.append(os.path.join(root, file))
        return targets

    def run(self):
        start_time = time.time()
        targets = self.find_target_files()
        
        if not targets:
            return {}, 0.0
            
        # Parallel Execution Block
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {}
            for filepath in targets:
                dissector = FileSecurityDissector(filepath)
                future = executor.submit(dissector.scan)
                futures[future] = filepath
                
            for future in as_completed(futures):
                filepath = futures[future]
                rel_path = os.path.relpath(filepath, self.target_path) if os.path.isdir(self.target_path) else os.path.basename(filepath)
                try:
                    result = future.result()
                    if "error" not in result:
                        self.scan_results[rel_path] = result
                        self.total_scanned_files += 1
                except Exception as e:
                    # Thread execution safety trap
                    self.scan_results[rel_path] = {"error": f"Thread exception: {e}"}
                    
        duration = time.time() - start_time
        return self.scan_results, duration
