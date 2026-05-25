"""
DLMap v2.0 - Archive Handler
Handle extraction and processing of APK, ZIP, and other archive formats.
"""

import os
import zipfile
import tarfile
import shutil
import time
from typing import Tuple, Optional
from pathlib import Path


class ArchiveHandler:
    """Handle archive extraction and cleanup."""
    
    SUPPORTED_FORMATS = {'.zip', '.apk', '.aar', '.jar', '.tar', '.tar.gz', '.tgz'}
    
    @staticmethod
    def is_archive(filepath: str) -> bool:
        """Check if file is a supported archive format."""
        _, ext = os.path.splitext(filepath)
        return ext.lower() in ArchiveHandler.SUPPORTED_FORMATS or filepath.endswith('.tar.gz')
    
    @staticmethod
    def extract(archive_path: str, output_dir: Optional[str] = None) -> Tuple[str, bool]:
        """
        Extract archive to temporary directory.
        Returns: (extraction_path, cleanup_needed)
        """
        if not os.path.exists(archive_path):
            return archive_path, False
        
        if not ArchiveHandler.is_archive(archive_path):
            return archive_path, False
        
        # Create output directory
        if output_dir is None:
            base_name = os.path.splitext(os.path.basename(archive_path))[0]
            output_dir = f"dlmap_extract_{base_name}_{int(time.time())}"
        
        os.makedirs(output_dir, exist_ok=True)
        
        try:
            archive_path_lower = archive_path.lower()
            
            if archive_path_lower.endswith(('.zip', '.apk', '.aar', '.jar')):
                ArchiveHandler._extract_zip(archive_path, output_dir)
            elif archive_path_lower.endswith(('.tar.gz', '.tgz')):
                ArchiveHandler._extract_tar_gz(archive_path, output_dir)
            elif archive_path_lower.endswith('.tar'):
                ArchiveHandler._extract_tar(archive_path, output_dir)
            else:
                return archive_path, False
            
            return output_dir, True
            
        except Exception as e:
            print(f"[ERROR] Failed to extract archive: {e}")
            # Cleanup on failure
            if os.path.exists(output_dir):
                shutil.rmtree(output_dir, ignore_errors=True)
            return archive_path, False
    
    @staticmethod
    def _extract_zip(zip_path: str, output_dir: str):
        """Extract ZIP/APK/AAR/JAR archive."""
        try:
            with zipfile.ZipFile(zip_path, 'r') as zip_ref:
                zip_ref.extractall(output_dir)
        except zipfile.BadZipFile:
            raise ValueError(f"Invalid ZIP file: {zip_path}")
    
    @staticmethod
    def _extract_tar_gz(tar_path: str, output_dir: str):
        """Extract TAR.GZ archive."""
        try:
            with tarfile.open(tar_path, 'r:gz') as tar_ref:
                tar_ref.extractall(output_dir)
        except tarfile.ReadError:
            raise ValueError(f"Invalid TAR.GZ file: {tar_path}")
    
    @staticmethod
    def _extract_tar(tar_path: str, output_dir: str):
        """Extract TAR archive."""
        try:
            with tarfile.open(tar_path, 'r') as tar_ref:
                tar_ref.extractall(output_dir)
        except tarfile.ReadError:
            raise ValueError(f"Invalid TAR file: {tar_path}")
    
    @staticmethod
    def cleanup(directory: str):
        """Remove extracted directory."""
        if os.path.exists(directory) and os.path.isdir(directory):
            try:
                shutil.rmtree(directory)
                return True
            except Exception as e:
                print(f"[WARNING] Could not cleanup {directory}: {e}")
                return False
        return False
