# database/db_manager.py
"""
Local SQLite Database for Malware Signatures
"""

import sqlite3
import json
from pathlib import Path
from datetime import datetime
from typing import List, Dict

class DatabaseManager:
    """Manage local malware signature database"""
    
    def __init__(self, db_path: str = "database/malware_defender.db"):
        self.db_path = db_path
        self.conn = None
        self.setup_database()
    
    def connect(self):
        """Connect to SQLite database"""
        self.conn = sqlite3.connect(self.db_path)
        self.conn.row_factory = sqlite3.Row
        return self.conn
    
    def setup_database(self):
        """Create tables if not exist"""
        conn = self.connect()
        cursor = conn.cursor()
        
        # Table 1: Malware Hashes
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS malware_hashes (
                id INTEGER PRIMARY KEY,
                hash_sha256 TEXT UNIQUE NOT NULL,
                hash_md5 TEXT,
                threat_name TEXT NOT NULL,
                threat_type TEXT,
                severity INTEGER,
                first_seen TEXT,
                last_updated TEXT
            )
        ''')
        
        # Table 2: Scan History
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS scan_history (
                id INTEGER PRIMARY KEY,
                file_path TEXT NOT NULL,
                scan_date TEXT NOT NULL,
                file_hash TEXT,
                is_malware BOOLEAN,
                threat_name TEXT,
                risk_score INTEGER,
                detection_method TEXT
            )
        ''')
        
        # Table 3: Threats
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS threats (
                id INTEGER PRIMARY KEY,
                threat_name TEXT UNIQUE,
                threat_type TEXT,
                description TEXT,
                mitigation TEXT,
                severity_level INTEGER
            )
        ''')
        
        # Table 4: Quarantine
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS quarantine (
                id INTEGER PRIMARY KEY,
                original_path TEXT,
                quarantine_path TEXT,
                file_hash TEXT,
                quarantine_date TEXT,
                threat_name TEXT
            )
        ''')
        
        conn.commit()
        conn.close()
        print("✅ Database initialized")
    
    def add_malware_hash(self, hash_sha256: str, threat_name: str, 
                        threat_type: str = "Unknown", severity: int = 5):
        """Add known malware hash"""
        conn = self.connect()
        cursor = conn.cursor()
        
        try:
            cursor.execute('''
                INSERT OR REPLACE INTO malware_hashes 
                (hash_sha256, threat_name, threat_type, severity, first_seen, last_updated)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (hash_sha256, threat_name, threat_type, severity, 
                  datetime.now().isoformat(), datetime.now().isoformat()))
            
            conn.commit()
            return True
        except Exception as e:
            print(f"❌ Error adding hash: {e}")
            return False
        finally:
            conn.close()
    
    def check_hash(self, hash_sha256: str) -> Dict:
        """Check if hash is known malware"""
        conn = self.connect()
        cursor = conn.cursor()
        
        try:
            cursor.execute('SELECT * FROM malware_hashes WHERE hash_sha256 = ?', 
                          (hash_sha256,))
            result = cursor.fetchone()
            
            if result:
                return dict(result)
            return None
        finally:
            conn.close()
    
    def add_scan_record(self, file_path: str, file_hash: str, is_malware: bool, 
                       threat_name: str = None, risk_score: int = 0):
        """Record scan result"""
        conn = self.connect()
        cursor = conn.cursor()
        
        try:
            cursor.execute('''
                INSERT INTO scan_history
                (file_path, scan_date, file_hash, is_malware, threat_name, risk_score)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (file_path, datetime.now().isoformat(), file_hash, is_malware, 
                  threat_name, risk_score))
            
            conn.commit()
        finally:
            conn.close()
    
    def load_offline_signatures(self, json_file: str):
        """Load signatures from JSON file"""
        try:
            with open(json_file, 'r') as f:
                data = json.load(f)
            
            conn = self.connect()
            cursor = conn.cursor()
            
            for hash_val, threat_info in data.items():
                cursor.execute('''
                    INSERT OR REPLACE INTO malware_hashes
                    (hash_sha256, threat_name, threat_type, severity)
                    VALUES (?, ?, ?, ?)
                ''', (hash_val, threat_info.get('name'), 
                      threat_info.get('type', 'Unknown'),
                      threat_info.get('severity', 5)))
            
            conn.commit()
            conn.close()
            print(f"✅ Loaded {len(data)} signatures")
        except Exception as e:
            print(f"❌ Error loading signatures: {e}")
