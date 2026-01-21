# gui/tabs/scan_tab.py - Full Scan & Quick Scan Tab
from PyQt6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QPushButton, 
                             QLabel, QProgressBar, QListWidget, QListWidgetItem)
from PyQt6.QtCore import Qt, QTimer
from PyQt6.QtGui import QFont

class ScanTab(QWidget):
    """Full Scan & Quick Scan Interface"""
    
    def __init__(self):
        super().__init__()
        self.init_ui()
    
    def init_ui(self):
        layout = QVBoxLayout(self)
        layout.setSpacing(15)
        layout.setContentsMargins(20, 20, 20, 20)
        
        # Title
        title = QLabel("🔍 Malware Scan Center")
        title.setFont(QFont("Segoe UI", 16, QFont.Weight.Bold))
        layout.addWidget(title)
        
        # Scan Options
        options_layout = QHBoxLayout()
        
        quick_btn = QPushButton("⚡ Quick Scan (30s)")
        quick_btn.setMinimumHeight(50)
        quick_btn.setStyleSheet("font-size: 12px; font-weight: bold;")
        
        full_btn = QPushButton("🔍 Full System Scan")
        full_btn.setMinimumHeight(50)
        full_btn.setStyleSheet("font-size: 12px; font-weight: bold;")
        
        custom_btn = QPushButton("📁 Custom Scan")
        custom_btn.setMinimumHeight(50)
        custom_btn.setStyleSheet("font-size: 12px; font-weight: bold;")
        
        options_layout.addWidget(quick_btn)
        options_layout.addWidget(full_btn)
        options_layout.addWidget(custom_btn)
        
        layout.addLayout(options_layout)
        
        # Progress
        progress_label = QLabel("Status: Ready")
        self.progress_bar = QProgressBar()
        self.progress_bar.setValue(0)
        
        layout.addWidget(progress_label)
        layout.addWidget(self.progress_bar)
        
        # Results
        results_label = QLabel("📋 Scan Results:")
        results_label.setFont(QFont("Segoe UI", 12, QFont.Weight.Bold))
        
        self.results_list = QListWidget()
        self.results_list.addItem("✅ No threats detected")
        
        layout.addWidget(results_label)
        layout.addWidget(self.results_list)
        
        layout.addStretch()


# gui/tabs/sandbox_tab.py - Isolated Testing Environment
class SandboxTab(QWidget):
    """Sandbox for testing suspicious files"""
    
    def __init__(self):
        super().__init__()
        self.init_ui()
    
    def init_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 20, 20, 20)
        
        title = QLabel("🧪 Sandbox - Test Suspicious Files")
        title.setFont(QFont("Segoe UI", 16, QFont.Weight.Bold))
        layout.addWidget(title)
        
        info = QLabel("📝 Drag & drop files here to test in isolated environment\nor click below to select files")
        layout.addWidget(info)
        
        upload_btn = QPushButton("📤 Upload File")
        upload_btn.setMinimumHeight(60)
        layout.addWidget(upload_btn)
        
        layout.addStretch()


# gui/tabs/password_tab.py - Password Manager Vault
class PasswordTab(QWidget):
    """Encrypted Password Vault"""
    
    def __init__(self):
        super().__init__()
        self.init_ui()
    
    def init_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 20, 20, 20)
        
        title = QLabel("🔐 Password Manager")
        title.setFont(QFont("Segoe UI", 16, QFont.Weight.Bold))
        layout.addWidget(title)
        
        add_btn = QPushButton("➕ Add Password")
        add_btn.setMinimumHeight(45)
        layout.addWidget(add_btn)
        
        passwords_list = QListWidget()
        passwords_list.addItem("🔒 Passwords stored: 0")
        layout.addWidget(passwords_list)
        
        layout.addStretch()


# gui/tabs/vpn_tab.py - VPN Configuration
class VpnTab(QWidget):
    """VPN Connection Manager"""
    
    def __init__(self):
        super().__init__()
        self.init_ui()
    
    def init_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 20, 20, 20)
        
        title = QLabel("🌐 VPN Protection")
        title.setFont(QFont("Segoe UI", 16, QFont.Weight.Bold))
        layout.addWidget(title)
        
        status = QLabel("🔴 Disconnected")
        status.setFont(QFont("Segoe UI", 12))
        layout.addWidget(status)
        
        connect_btn = QPushButton("🚀 Connect to VPN")
        connect_btn.setMinimumHeight(50)
        layout.addWidget(connect_btn)
        
        layout.addStretch()


# gui/tabs/history_tab.py - Threat Detection History
class HistoryTab(QWidget):
    """Threat History & Quarantine"""
    
    def __init__(self):
        super().__init__()
        self.init_ui()
    
    def init_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 20, 20, 20)
        
        title = QLabel("📊 Threat History")
        title.setFont(QFont("Segoe UI", 16, QFont.Weight.Bold))
        layout.addWidget(title)
        
        history_list = QListWidget()
        history_list.addItem("📅 No threats in history")
        layout.addWidget(history_list)
        
        layout.addStretch()


# gui/tabs/analytics_tab.py - Threat Analytics Dashboard
class AnalyticsTab(QWidget):
    """Analytics & Statistics"""
    
    def __init__(self):
        super().__init__()
        self.init_ui()
    
    def init_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 20, 20, 20)
        
        title = QLabel("📈 Analytics Dashboard")
        title.setFont(QFont("Segoe UI", 16, QFont.Weight.Bold))
        layout.addWidget(title)
        
        stats_label = QLabel("📊 System Statistics:\nScans: 0\nThreats Found: 0\nLast Scan: Never")
        layout.addWidget(stats_label)
        
        layout.addStretch()


# gui/tabs/hardware_tab.py - Hardware Monitor
class HardwareTab(QWidget):
    """System Hardware Monitoring"""
    
    def __init__(self):
        super().__init__()
        self.init_ui()
    
    def init_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 20, 20, 20)
        
        title = QLabel("⚙️ Hardware Monitor")
        title.setFont(QFont("Segoe UI", 16, QFont.Weight.Bold))
        layout.addWidget(title)
        
        info = QLabel("CPU: 15%\nMemory: 45%\nDisk: 60%")
        layout.addWidget(info)
        
        layout.addStretch()


# gui/tabs/protection_tab.py - Real-time Protection Settings
class ProtectionTab(QWidget):
    """Real-time Protection Configuration"""
    
    def __init__(self):
        super().__init__()
        self.init_ui()
    
    def init_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 20, 20, 20)
        
        title = QLabel("🛡️ Real-time Protection")
        title.setFont(QFont("Segoe UI", 16, QFont.Weight.Bold))
        layout.addWidget(title)
        
        status = QLabel("✅ Real-time Protection: ACTIVE")
        status.setStyleSheet("color: green; font-weight: bold;")
        layout.addWidget(status)
        
        toggle_btn = QPushButton("⏸ Pause Protection")
        layout.addWidget(toggle_btn)
        
        layout.addStretch()


# gui/tabs/parental_tab.py - Parental Controls
class ParentalTab(QWidget):
    """Parental Control Settings"""
    
    def __init__(self):
        super().__init__()
        self.init_ui()
    
    def init_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 20, 20, 20)
        
        title = QLabel("👨‍👩‍👧 Parental Controls")
        title.setFont(QFont("Segoe UI", 16, QFont.Weight.Bold))
        layout.addWidget(title)
        
        info = QLabel("Configure parental controls for family accounts")
        layout.addWidget(info)
        
        layout.addStretch()


# gui/tabs/settings_tab.py - Application Settings
class SettingsTab(QWidget):
    """Application Settings & Preferences"""
    
    def __init__(self):
        super().__init__()
        self.init_ui()
    
    def init_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 20, 20, 20)
        
        title = QLabel("⚙️ Settings")
        title.setFont(QFont("Segoe UI", 16, QFont.Weight.Bold))
        layout.addWidget(title)
        
        options = QLabel("🔧 Auto-update: ON\n🔔 Notifications: ON\n💾 Startup: ON")
        layout.addWidget(options)
        
        layout.addStretch()


# gui/tabs/about_tab.py - About & Version Info
class AboutTab(QWidget):
    """Application Information"""
    
    def __init__(self):
        super().__init__()
        self.init_ui()
    
    def init_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 20, 20, 20)
        
        title = QLabel("ℹ️ About Malware Defender v5")
        title.setFont(QFont("Segoe UI", 16, QFont.Weight.Bold))
        layout.addWidget(title)
        
        about_text = QLabel(
            "🛡️ Malware Defender v5\n"
            "Version: 5.0.0\n\n"
            "Ultimate Protection Suite\n"
            "Advanced Malware Detection & Prevention\n\n"
            "© 2026 Security Labs\n"
            "License: MIT\n\n"
            "Built with PyQt6 & Python\n"
            "All rights reserved."
        )
        about_text.setFont(QFont("Segoe UI", 11))
        layout.addWidget(about_text)
        
        layout.addStretch()
