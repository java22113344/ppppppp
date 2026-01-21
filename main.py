# main.py - FIXED VERSION (Works with fixed scanner.py)
import sys
import os
import shutil
import string
import time
import math
from pathlib import Path
from datetime import timedelta

sys.path.insert(0, '.')
from core.scanner import MalwareScanner

class DriveScanner:
    def __init__(self):
        self.scanner = MalwareScanner()
        self.start_time = None

def print_progress(current, total, start_time):
    """Progress bar with ETA"""
    if total == 0:
        return
    percent = (current / total) * 100
    elapsed = time.time() - start_time
    rate = current / elapsed if elapsed > 0 else 0
    eta = (total - current) / rate if rate > 0 else 0
    bar = "█" * int(percent // 2) + "░" * (50 - int(percent // 2))
    eta_str = str(timedelta(seconds=int(eta)))
    print(f"\r[{bar}] {percent:5.1f}% | ETA: {eta_str}", end="", flush=True)

def get_drives():
    """List all drives"""
    drives = []
    for letter in string.ascii_uppercase:
        drive = f"{letter}:\\"
        if os.path.exists(drive):
            try:
                total = shutil.disk_usage(drive).total / (1024**3)
                free = shutil.disk_usage(drive).free / (1024**3)
                drives.append({
                    'letter': letter,
                    'path': drive,
                    'total_gb': f"{total:.1f}",
                    'free_gb': f"{free:.1f}"
                })
            except:
                pass
    return drives

def quick_scan(scanner):
    """Quick scan high-risk folders"""
    print("\n⚡ QUICK SCAN (Downloads/Desktop/Temp)")
    
    folders = [
        os.path.expandvars(r"C:\Users\%USERNAME%\Downloads"),
        os.path.expandvars(r"C:\Users\%USERNAME%\Desktop"),
        r"C:\Temp", 
        r"C:\Windows\Temp"
    ]
    
    total_files = 0
    total_threats = []
    start_time = time.time()
    
    for folder in folders:
        if os.path.exists(folder):
            print(f"\n🔍 {folder}")
            results = scanner.scan_directory(folder)
            total_files += results['files_scanned']
            total_threats.extend(results['detections'])
    
    duration = time.time() - start_time
    
    print(f"\n{'='*70}")
    print(f"📊 QUICK SCAN RESULTS")
    print(f"{'='*70}")
    print(f"📄 Files: {total_files:,}")
    print(f"🚨 Threats: {len(total_threats):,}")
    print(f"⏱️  Time: {duration:.1f}s")
    print(f"{'='*70}")
    
    return total_threats

def full_drive_scan(scanner):
    """Full drive scan"""
    drives = get_drives()
    
    if not drives:
        print("❌ No drives found")
        return []
    
    print("\n💾 DRIVES:")
    for i, d in enumerate(drives, 1):
        print(f"{i}. {d['path']} ({d['total_gb']}GB, {d['free_gb']}GB free)")
    
    try:
        choice = int(input(f"\n📁 Select drive (1-{len(drives)}): "))
        drive = drives[choice-1]['path']
    except:
        print("❌ Invalid")
        return []
    
    print(f"\n💾 FULL DRIVE SCAN: {drive}")
    start_time = time.time()
    results = scanner.scan_directory(drive)
    duration = time.time() - start_time
    
    print(f"\n{'='*70}")
    print(f"📊 FULL DRIVE RESULTS")
    print(f"{'='*70}")
    print(f"📁 Drive: {drive}")
    print(f"📄 Files: {results['files_scanned']:,}")
    print(f"🚨 Threats: {results['malware_found']:,}")
    print(f"⏱️  Time: {duration:.1f}s")
    print(f"⚡ Speed: {results['speed']:.0f} files/sec")
    print(f"{'='*70}")
    
    return results['detections']

def custom_scan(scanner, folder):
    """Custom folder scan"""
    if not os.path.exists(folder):
        print(f"❌ Folder not found: {folder}")
        return []
    
    print(f"\n📁 CUSTOM SCAN: {folder}")
    start_time = time.time()
    results = scanner.scan_directory(folder)
    duration = time.time() - start_time
    
    print(f"\n{'='*70}")
    print(f"📊 CUSTOM SCAN RESULTS")
    print(f"{'='*70}")
    print(f"📁 Folder: {folder}")
    print(f"📄 Files: {results['files_scanned']:,}")
    print(f"🚨 Threats: {results['malware_found']:,}")
    print(f"⏱️  Time: {duration:.1f}s")
    print(f"{'='*70}")
    
    return results['detections']

def extract_threat_files(threats):
    """Extract threat file paths"""
    threat_files = []
    for threat in threats:
        if isinstance(threat, dict) and 'filename' in threat:
            threat_files.append(threat['filename'])
        elif isinstance(threat, str):
            threat_files.append(threat)
    return threat_files

def eicar_test(scanner):
    """EICAR test"""
    Path("test_samples").mkdir(exist_ok=True)
    test_file = "test_samples/eicar_test.com"
    
    eicar_content = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
    with open(test_file, "w") as f:
        f.write(eicar_content)
    
    print(f"\n🧪 EICAR test: {test_file}")
    result = scanner.scan_file(test_file)
    
    print(f"\n{'='*70}")
    if result['is_malware']:
        print(f"🚨 DETECTED: {result['threat_name']}")
        print(f"Score: {result['risk_score']} | Method: {result['detection_method']}")
    else:
        print(f"✅ Clean (Test file)")
    print(f"{'='*70}")
    
    return [test_file] if result['is_malware'] else []

def quarantine_menu(scanner, threats):
    """Quarantine/Delete/Keep threats"""
    if not threats:
        print("\n✅ No threats found!")
        return
    
    # ALWAYS SHOW THREATS
    print("\n" + "="*70)
    print("🚨 DETECTED THREATS:")
    print("="*70)
    for i, threat in enumerate(threats, 1):
        if isinstance(threat, dict):
            print(f"{i:2d}. {threat.get('filename', threat)}")
        else:
            print(f"{i:2d}. {threat}")
    print("="*70)
    
    # Action menu
    print("\n🗑️  ACTIONS:")
    print("1. ✅ QUARANTINE ALL")
    print("2. 🗑️  DELETE ALL")
    print("3. 📋 KEEP (logged)")
    
    choice = input("\n👉 Choose (1-3): ").strip()
    
    # Extract file paths
    threat_files = extract_threat_files(threats)
    
    if choice == '1':
        count = 0
        for threat_file in threat_files:
            if scanner.quarantine_file(threat_file):
                count += 1
        print(f"\n✅ {count}/{len(threat_files)} QUARANTINED!")
    elif choice == '2':
        count = 0
        for threat_file in threat_files:
            try:
                os.remove(threat_file)
                count += 1
            except:
                pass
        print(f"\n🗑️  {count}/{len(threat_files)} DELETED!")
    else:
        print("\n📋 Threats LOGGED!")

def main():
    print("🛡️  MALWARE DEFENDER PRO v5.0")
    print("="*70)
    scanner = MalwareScanner()
    
    while True:
        print("\n🎯 SCAN TYPE:")
        print("1. ⚡ QUICK SCAN (5 min)")
        print("2. 💾 FULL DRIVE (30-60 min)")
        print("3. 📁 CUSTOM FOLDER")
        print("4. 🧪 EICAR TEST")
        print("0. ❌ EXIT")
        
        choice = input("\n👉 Choose (0-4): ").strip()
        threats = []
        
        if choice == '1':
            threats = quick_scan(scanner)
        elif choice == '2':
            threats = full_drive_scan(scanner)
        elif choice == '3':
            folder = input("📁 Path: ").strip()
            if folder:
                threats = custom_scan(scanner, folder)
        elif choice == '4':
            threats = eicar_test(scanner)
        elif choice == '0':
            print("\n👋 Goodbye!")
            break
        else:
            print("❌ Invalid option")
            continue
        
        if threats:
            quarantine_menu(scanner, threats)
        
        again = input("\n🔄 Another scan? (y/N): ").lower()
        if not again.startswith('y'):
            break
    
    print("\n🎉 Thanks for using Malware Defender!")

if __name__ == "__main__":
    main()
