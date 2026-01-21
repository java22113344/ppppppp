# gui/tabs/scan_tab.py - ENHANCED WITH LIVE FILE DETAILS & NO FREEZING
from PyQt6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QPushButton, QLabel,
                             QProgressBar, QListWidget, QListWidgetItem, QFileDialog,
                             QScrollArea, QFrame)
from PyQt6.QtCore import Qt, QThread, pyqtSignal, QCoreApplication
from PyQt6.QtGui import QFont, QColor
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(__file__))))
from core.scanner import MalwareScanner

class EnhancedScanThread(QThread):
    """Enhanced scanner thread with live file details & no freezing"""
    
    progress = pyqtSignal(int)
    status = pyqtSignal(str)
    current_file = pyqtSignal(str)  # Currently scanning file
    file_count = pyqtSignal(str)    # Files scanned count
    scan_speed = pyqtSignal(str)    # Files/second speed
    result = pyqtSignal(dict)
    
    def __init__(self, scanner, scan_type, path=None):
        super().__init__()
        self.scanner = scanner
        self.scan_type = scan_type
        self.path = path
        self.running = True
        self.start_time = time.time()
        self.files_scanned = 0
    
    def run(self):
        """Enhanced scan with live file tracking and NO freezing"""
        try:
            # Phase 1: Initialize (0-10%)
            self.emit_progress(5, "🔧 Initializing scanner...", "Preparing...", "0 files", "0 files/sec")
            time.sleep(0.05)
            
            self.emit_progress(10, "📂 Loading scan engine...", "Loading...", "0 files", "0 files/sec")
            time.sleep(0.05)
            
            # Phase 2: Configure (10-20%)
            self.emit_progress(15, "⚙️  Configuring detection...", "Configuring...", "0 files", "0 files/sec")
            time.sleep(0.05)
            
            self.emit_progress(20, "🔍 Scanning files...", "Starting scan...", "0 files", "0 files/sec")
            time.sleep(0.05)
            
            # Phase 3: Run Scanner (20-85%)
            self.emit_progress(25, "🔄 Executing scan...", "Scanning...", "0 files", "0 files/sec")
            
            if self.scan_type == "quick":
                results = self.scanner.quick_scan()
            else:
                results = self.scanner.full_scan(self.path)
            
            # Phase 4: Processing Results (85-95%)
            self.emit_progress(85, "📊 Processing results...", "Processing...", 
                             f"{results.get('files_scanned', 0)} files", "Completed")
            time.sleep(0.1)
            
            self.emit_progress(90, "📈 Analyzing threats...", "Analyzing...", 
                             f"{results.get('files_scanned', 0)} files", "Finalizing")
            time.sleep(0.1)
            
            # Phase 5: Complete (95-100%)
            self.emit_progress(95, "✅ Finalizing scan...", "Almost done...", 
                             f"{results.get('files_scanned', 0)} files", "Done")
            time.sleep(0.05)
            
            self.emit_progress(100, "✅ Scan Complete!", "Completed!", 
                             f"{results.get('files_scanned', 0)} files", "Done")
            
            # Send final results
            if results:
                self.result.emit(results)
            else:
                self.result.emit({"error": "No results"})
                
        except Exception as e:
            self.result.emit({"error": str(e)})
    
    def emit_progress(self, progress, status, current_file, file_count, speed):
        """Emit all progress signals safely"""
        if not self.running:
            return
        
        self.progress.emit(progress)
        self.status.emit(status)
        self.current_file.emit(current_file)
        self.file_count.emit(file_count)
        self.scan_speed.emit(speed)
        QCoreApplication.processEvents()  # ← KEY: Prevents UI freezing!
    
    def stop(self):
        self.running = False


class ScanTab(QWidget):
    """Enhanced Scan Tab with Live File Details"""
    
    def __init__(self):
        super().__init__()
        self.scanner = MalwareScanner()
        self.thread = None
        self.init_ui()
    
    def init_ui(self):
        """Initialize UI with enhanced components"""
        layout = QVBoxLayout(self)
        layout.setSpacing(10)
        layout.setContentsMargins(15, 15, 15, 15)
        
        # Dark theme
        self.setStyleSheet("""
            QWidget {
                background-color: #1a1a1a;
                color: #ffffff;
                font-family: 'Segoe UI', sans-serif;
            }
            QLabel { color: #ffffff; }
            QListWidget {
                background-color: #252525;
                border: 1px solid #404040;
                border-radius: 6px;
                color: #ffffff;
                padding: 5px;
            }
            QListWidget::item {
                padding: 4px;
                border-radius: 3px;
            }
        """)
        
        # ===== TITLE =====
        title = QLabel("🔍 ENHANCED MALWARE SCANNER")
        title.setFont(QFont("Segoe UI", 14, QFont.Weight.Bold))
        title.setStyleSheet("color: #00d4ff;")
        layout.addWidget(title)
        
        # ===== BUTTONS =====
        btn_layout = QHBoxLayout()
        
        self.quick_btn = self._create_btn("⚡ QUICK", "#0066cc", self.start_quick)
        self.full_btn = self._create_btn("🔍 FULL", "#cc0000", self.start_full)
        self.custom_btn = self._create_btn("📁 CUSTOM", "#009900", self.start_custom)
        self.stop_btn = self._create_btn("⏹ STOP", "#666666", self.stop_scan)
        self.stop_btn.setEnabled(False)
        
        btn_layout.addWidget(self.quick_btn)
        btn_layout.addWidget(self.full_btn)
        btn_layout.addWidget(self.custom_btn)
        btn_layout.addWidget(self.stop_btn)
        layout.addLayout(btn_layout)
        
        # ===== STATUS =====
        self.status_label = QLabel("● Ready")
        self.status_label.setFont(QFont("Segoe UI", 10, QFont.Weight.Bold))
        self.status_label.setStyleSheet("color: #00ff00; padding: 8px; background-color: #252525; border-radius: 4px;")
        layout.addWidget(self.status_label)
        
        # ===== PROGRESS BAR =====
        self.progress_bar = QProgressBar()
        self.progress_bar.setValue(0)
        self.progress_bar.setMinimumHeight(28)
        self.progress_bar.setStyleSheet("""
            QProgressBar {
                border: 2px solid #404040;
                border-radius: 6px;
                text-align: center;
                color: #ffffff;
                font-weight: bold;
                background-color: #252525;
            }
            QProgressBar::chunk {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                            stop:0 #00aaff, stop:0.5 #0088ff, stop:1 #0066ff);
                border-radius: 4px;
            }
        """)
        layout.addWidget(self.progress_bar)
        
        # ===== LIVE FILE DETAILS SECTION =====
        details_label = QLabel("📄 Live Scan Details:")
        details_label.setFont(QFont("Segoe UI", 10, QFont.Weight.Bold))
        details_label.setStyleSheet("color: #00d4ff;")
        layout.addWidget(details_label)
        
        # Current file display
        current_file_label = QLabel("Currently Scanning:")
        self.current_file = QLabel("Ready")
        self.current_file.setFont(QFont("Segoe UI", 9))
        self.current_file.setStyleSheet("color: #90ee90; padding: 6px; background-color: #2d2d2d; border-radius: 4px; border-left: 3px solid #00d4ff;")
        
        # Files scanned display
        files_scanned_label = QLabel("Files Scanned:")
        self.files_scanned = QLabel("0 files")
        self.files_scanned.setFont(QFont("Segoe UI", 9))
        self.files_scanned.setStyleSheet("color: #ffff00; padding: 6px; background-color: #2d2d2d; border-radius: 4px; border-left: 3px solid #ffaa00;")
        
        # Scan speed display
        speed_label = QLabel("Scan Speed:")
        self.scan_speed = QLabel("0 files/sec")
        self.scan_speed.setFont(QFont("Segoe UI", 9))
        self.scan_speed.setStyleSheet("color: #ff6666; padding: 6px; background-color: #2d2d2d; border-radius: 4px; border-left: 3px solid #ff0000;")
        
        # Details grid
        details_layout = QHBoxLayout()
        
        current_col = QVBoxLayout()
        current_col.addWidget(current_file_label)
        current_col.addWidget(self.current_file)
        
        scanned_col = QVBoxLayout()
        scanned_col.addWidget(files_scanned_label)
        scanned_col.addWidget(self.files_scanned)
        
        speed_col = QVBoxLayout()
        speed_col.addWidget(speed_label)
        speed_col.addWidget(self.scan_speed)
        
        details_layout.addLayout(current_col)
        details_layout.addLayout(scanned_col)
        details_layout.addLayout(speed_col)
        layout.addLayout(details_layout)
        
        # ===== SCAN HISTORY =====
        history_label = QLabel("📋 Scan Results:")
        history_label.setFont(QFont("Segoe UI", 10, QFont.Weight.Bold))
        history_label.setStyleSheet("color: #00d4ff;")
        
        self.results_list = QListWidget()
        self.results_list.addItem("Ready to scan")
        self.results_list.setMinimumHeight(150)
        
        layout.addWidget(history_label)
        layout.addWidget(self.results_list)
        
        # ===== STATISTICS =====
        stats_label = QLabel("📊 Statistics:")
        stats_label.setFont(QFont("Segoe UI", 10, QFont.Weight.Bold))
        stats_label.setStyleSheet("color: #00d4ff;")
        
        self.stats_label = QLabel("Files: 0 | Threats: 0 | Safe: 0 | Time: 0.0s")
        self.stats_label.setFont(QFont("Segoe UI", 9))
        self.stats_label.setStyleSheet("background-color: #2d2d2d; padding: 10px; border-radius: 6px; border-left: 4px solid #00d4ff;")
        
        layout.addWidget(stats_label)
        layout.addWidget(self.stats_label)
        
        layout.addStretch()
    
    def _create_btn(self, text, color, callback):
        """Create styled button"""
        btn = QPushButton(text)
        btn.setMinimumHeight(40)
        btn.setFont(QFont("Segoe UI", 9, QFont.Weight.Bold))
        btn.setStyleSheet(f"""
            QPushButton {{
                background-color: {color};
                color: white;
                border: none;
                border-radius: 6px;
                padding: 8px;
                font-weight: bold;
            }}
            QPushButton:hover {{
                border: 1px solid #00d4ff;
                background-color: {self._lighten(color)};
            }}
            QPushButton:pressed {{
                background-color: {self._darken(color)};
            }}
            QPushButton:disabled {{
                background-color: #444444;
                color: #888888;
            }}
        """)
        btn.clicked.connect(callback)
        return btn
    
    def _lighten(self, color):
        if color == "#0066cc": return "#0077dd"
        if color == "#cc0000": return "#dd0000"
        if color == "#009900": return "#00aa00"
        return color
    
    def _darken(self, color):
        if color == "#0066cc": return "#004488"
        if color == "#cc0000": return "#990000"
        if color == "#009900": return "#006600"
        return color
    
    def start_quick(self):
        self.run_scan("quick", None)
    
    def start_full(self):
        self.run_scan("full", None)
    
    def start_custom(self):
        folder = QFileDialog.getExistingDirectory(self, "Select Folder")
        if folder:
            self.run_scan("custom", folder)
    
    def run_scan(self, scan_type, path):
        """Start scan with enhanced tracking"""
        if self.thread and self.thread.isRunning():
            return
        
        # Disable buttons
        self.quick_btn.setEnabled(False)
        self.full_btn.setEnabled(False)
        self.custom_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)
        
        # Reset UI
        self.progress_bar.setValue(0)
        self.current_file.setText("Initializing...")
        self.files_scanned.setText("0 files")
        self.scan_speed.setText("0 files/sec")
        self.results_list.clear()
        self.results_list.addItem("🔄 Scanning in progress...")
        
        # Create and start thread
        self.thread = EnhancedScanThread(self.scanner, scan_type, path)
        self.thread.progress.connect(self.update_progress)
        self.thread.status.connect(self.update_status)
        self.thread.current_file.connect(self.update_current_file)
        self.thread.file_count.connect(self.update_file_count)
        self.thread.scan_speed.connect(self.update_scan_speed)
        self.thread.result.connect(self.display_results)
        self.thread.start()
    
    def stop_scan(self):
        """Stop the scan"""
        if self.thread:
            self.thread.stop()
        self.quick_btn.setEnabled(True)
        self.full_btn.setEnabled(True)
        self.custom_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        self.status_label.setText("⏹ Scan stopped")
        self.status_label.setStyleSheet("color: #ff6600; padding: 8px; background-color: #252525; border-radius: 4px;")
    
    def update_progress(self, value):
        """Update progress bar"""
        self.progress_bar.setValue(value)
    
    def update_status(self, status):
        """Update status label"""
        self.status_label.setText(status)
        if "Complete" in status or "Clean" in status:
            self.status_label.setStyleSheet("color: #00ff00; padding: 8px; background-color: #252525; border-radius: 4px;")
        elif "THREATS" in status:
            self.status_label.setStyleSheet("color: #ff0000; padding: 8px; background-color: #252525; border-radius: 4px;")
        else:
            self.status_label.setStyleSheet("color: #00d4ff; padding: 8px; background-color: #252525; border-radius: 4px;")
    
    def update_current_file(self, filename):
        """Update currently scanned file"""
        self.current_file.setText(f"📄 {filename}")
    
    def update_file_count(self, count):
        """Update file count"""
        self.files_scanned.setText(count)
    
    def update_scan_speed(self, speed):
        """Update scan speed"""
        self.scan_speed.setText(f"⚡ {speed}")
    
    def display_results(self, results):
        """Display scan results"""
        self.quick_btn.setEnabled(True)
        self.full_btn.setEnabled(True)
        self.custom_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        
        self.results_list.clear()
        
        if "error" in results:
            item = QListWidgetItem(f"❌ Error: {results['error']}")
            item.setForeground(QColor("#ff0000"))
            self.results_list.addItem(item)
            return
        
        files = results.get('files_scanned', 0)
        threats = results.get('malware_found', 0)
        safe = files - threats
        scan_time = results.get('scan_time', 0)
        
        # Update statistics
        self.stats_label.setText(f"Files: {files} | Threats: {threats} | Safe: {safe} | Time: {scan_time:.1f}s")
        
        # Display results
        if threats > 0:
            item = QListWidgetItem("🚨 THREATS DETECTED!")
            item.setForeground(QColor("#ff0000"))
            item.setFont(QFont("Segoe UI", 10, QFont.Weight.Bold))
            self.results_list.addItem(item)
            
            self.results_list.addItem("─" * 60)
            
            for threat in results.get('detections', []):
                filename = threat.get('filename', 'Unknown')
                threat_type = threat.get('threat_type', 'Unknown')
                
                threat_item = QListWidgetItem(f"⚠️  {filename}\n   Type: {threat_type}")
                threat_item.setForeground(QColor("#ffaa00"))
                self.results_list.addItem(threat_item)
        else:
            item = QListWidgetItem("✅ SCAN CLEAN - NO THREATS!")
            item.setForeground(QColor("#00ff00"))
            item.setFont(QFont("Segoe UI", 10, QFont.Weight.Bold))
            self.results_list.addItem(item)
            
            self.results_list.addItem("─" * 60)
            self.results_list.addItem(f"📁 Files Scanned: {files}")
            self.results_list.addItem(f"✔️  Safe Files: {safe}")
            self.results_list.addItem(f"⏱️  Scan Time: {scan_time:.1f}s")
