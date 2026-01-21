# core/scanner.py - COMPLETE MALWARE SCANNER WITH DETECTION METHODS
import os
import sys
import hashlib
import re
import yara
from pathlib import Path

class MalwareScanner:
    """Complete Malware Scanner with Directory Scanning"""
    
    def __init__(self):
        """Initialize scanner with signatures"""
        # Malware signatures (hashes)
        self.malware_hashes = {
            '6f8db29ba9b83f1b9f09e7e5e5e1f8c2': 'EICAR Test File',
            'd131dd02c5e6eec4693d23c8e8482e15': 'Test Malware',
        }
        
        # Suspicious file extensions
        self.suspicious_extensions = {
            '.exe': 'Executable',
            '.dll': 'Dynamic Library',
            '.com': 'Command File',
            '.bat': 'Batch Script',
            '.cmd': 'Command Script',
            '.ps1': 'PowerShell Script',
            '.vbs': 'VBScript',
            '.js': 'JavaScript',
            '.jar': 'Java Archive',
        }
        
        # Malware patterns (regex)
        self.malware_patterns = [
            r'X5O!P%@AP\[4',  # EICAR pattern
            r'INFECTED',       # Generic infected marker
            r'MALWARE',        # Malware marker
            r'MZ.*INFECTED',   # PE header with infected
        ]
    
    def scan_directory(self, folder_path):
        """Scan entire directory recursively"""
        results = {
            'files_scanned': 0,
            'malware_found': 0,
            'detections': [],
            'scan_time': 0,
            'speed': 0
        }
        
        import time
        start_time = time.time()
        
        try:
            # Walk through directory
            for root, dirs, files in os.walk(folder_path):
                for file in files:
                    file_path = os.path.join(root, file)
                    
                    # Skip system files and large files
                    try:
                        file_size = os.path.getsize(file_path)
                        if file_size > 100 * 1024 * 1024:  # Skip > 100MB
                            continue
                    except:
                        continue
                    
                    results['files_scanned'] += 1
                    
                    # Scan individual file
                    threat = self.scan_file(file_path)
                    if threat['is_malware']:
                        results['malware_found'] += 1
                        results['detections'].append({
                            'filename': file_path,
                            'threat_type': threat['threat_name'],
                            'risk_score': threat['risk_score'],
                            'detection_method': threat['detection_method']
                        })
            
            # Calculate stats
            elapsed = time.time() - start_time
            results['scan_time'] = elapsed
            if elapsed > 0:
                results['speed'] = results['files_scanned'] / elapsed
            
        except Exception as e:
            results['error'] = str(e)
        
        return results
    
    def scan_file(self, file_path):
        """Scan individual file"""
        threat = {
            'is_malware': False,
            'threat_name': 'Clean',
            'risk_score': 0,
            'detection_method': 'None'
        }
        
        try:
            # Check file extension
            ext = Path(file_path).suffix.lower()
            if ext in self.suspicious_extensions:
                # Read file content
                try:
                    with open(file_path, 'rb') as f:
                        content = f.read(10000)  # Read first 10KB
                    
                    # Check EICAR pattern
                    if b'X5O!P%@AP[4' in content:
                        threat['is_malware'] = True
                        threat['threat_name'] = 'EICAR-Test-File'
                        threat['risk_score'] = 100
                        threat['detection_method'] = 'Signature'
                        return threat
                    
                    # Check for INFECTED marker
                    if b'INFECTED' in content or 'INFECTED' in str(content):
                        threat['is_malware'] = True
                        threat['threat_name'] = 'Generic.Malware'
                        threat['risk_score'] = 85
                        threat['detection_method'] = 'Heuristic'
                        return threat
                    
                    # Check file hash
                    file_hash = hashlib.md5(content).hexdigest()
                    if file_hash in self.malware_hashes:
                        threat['is_malware'] = True
                        threat['threat_name'] = self.malware_hashes[file_hash]
                        threat['risk_score'] = 95
                        threat['detection_method'] = 'Hash'
                        return threat
                    
                    # Regex pattern matching
                    content_str = content.decode('utf-8', errors='ignore')
                    for pattern in self.malware_patterns:
                        if re.search(pattern, content_str, re.IGNORECASE):
                            threat['is_malware'] = True
                            threat['threat_name'] = 'Suspicious.Pattern'
                            threat['risk_score'] = 70
                            threat['detection_method'] = 'Pattern'
                            return threat
                
                except Exception as e:
                    pass
            
        except Exception as e:
            pass
        
        return threat
    
    def quick_scan(self):
        """Quick scan common folders"""
        high_risk_folders = [
            os.path.expandvars(r'C:\Users\%USERNAME%\Downloads'),
            os.path.expandvars(r'C:\Users\%USERNAME%\Desktop'),
            r'C:\Temp',
            r'C:\Windows\Temp'
        ]
        
        total_results = {
            'files_scanned': 0,
            'malware_found': 0,
            'detections': [],
            'scan_time': 0,
            'speed': 0
        }
        
        import time
        start_time = time.time()
        
        for folder in high_risk_folders:
            if os.path.exists(folder):
                results = self.scan_directory(folder)
                total_results['files_scanned'] += results.get('files_scanned', 0)
                total_results['malware_found'] += results.get('malware_found', 0)
                total_results['detections'].extend(results.get('detections', []))
        
        elapsed = time.time() - start_time
        total_results['scan_time'] = elapsed
        if elapsed > 0:
            total_results['speed'] = total_results['files_scanned'] / elapsed
        
        return total_results
    
    def full_scan(self, path=None):
        """Full drive scan"""
        if path is None:
            path = 'C:\\'
        
        return self.scan_directory(path)
    
    def custom_scan(self, path):
        """Custom folder scan"""
        return self.scan_directory(path)
    
    def quarantine_file(self, file_path):
        """Quarantine (move) a file"""
        try:
            quarantine_dir = Path('quarantine')
            quarantine_dir.mkdir(exist_ok=True)
            
            # Move file to quarantine
            import shutil
            filename = Path(file_path).name
            dest = quarantine_dir / filename
            shutil.move(file_path, str(dest))
            return True
        except:
            return False
