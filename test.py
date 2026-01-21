#!/usr/bin/env python3
print("🛡️ Testing Malware Defender Dependencies...")

# Core GUI
try:
    from PyQt6.QtWidgets import QApplication
    print("✅ PyQt6 GUI: OK")
except: print("❌ PyQt6 GUI: FAILED")

# Charts
try:
    from PyQt6.QtCharts import QChart
    print("✅ PyQt6 Charts: OK")
except: print("❌ PyQt6 Charts: FAILED")

# Malware Detection
try:
    import yara
    print("✅ YARA Signatures: OK")
except: print("❌ YARA: FAILED")

try:
    import pefile
    print("✅ PE File Analysis: OK")
except: print("❌ PEFile: FAILED")

# Security
try:
    from cryptography.fernet import Fernet
    print("✅ Encryption: OK")
except: print("❌ Cryptography: FAILED")

try:
    from argon2 import PasswordHasher
    print("✅ Password Hashing: OK")
except: print("❌ Argon2: FAILED")

# System Monitoring
try:
    import psutil
    print("✅ System Monitoring: OK")
except: print("❌ psutil: FAILED")

try:
    from watchdog.observers import Observer
    print("✅ File Monitoring: OK")
except: print("❌ Watchdog: FAILED")

# Network
try:
    import scapy
    print("✅ Network Analysis: OK")
except: print("❌ Scapy: FAILED")

print("\n🎉 INSTALL COMPLETE!")
