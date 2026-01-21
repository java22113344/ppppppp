"""
YARA Integration Tests
Run: python -m pytest tests/test_yara.py
"""

import pytest
from core.scanner import YaraScanner

def test_yara_compilation():
    """Test YARA rules compile without errors"""
    scanner = YaraScanner()
    assert scanner.rules is not None
    print("✅ YARA compilation successful")

def test_eicar_detection():
    """Test EICAR test file detection"""
    scanner = YaraScanner()
    # EICAR test string
    eicar = b"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
    
    matches = scanner._scan_yara(eicar)
    assert len(matches) > 0
    print("✅ EICAR detection working")

if __name__ == "__main__":
    test_yara_compilation()
    test_eicar_detection()
