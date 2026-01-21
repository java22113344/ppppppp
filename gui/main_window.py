# gui/main_window.py - Complete Malware Defender v5 GUI Foundation
import sys
import json
from pathlib import Path
from PyQt6.QtWidgets import (QApplication, QMainWindow, QTabWidget, QVBoxLayout, 
                             QWidget, QHBoxLayout, QPushButton, QLabel, QComboBox,
                             QStatusBar, QDialog, QLineEdit, QTextEdit, QFileDialog)
from PyQt6.QtCore import Qt, QTimer, pyqtSignal
from PyQt6.QtGui import QIcon, QFont, QPixmap, QColor
from PyQt6.QtCore import QTimer

# Import all tabs
from tabs.scan_tab import ScanTab
from tabs.sandbox_tab import SandboxTab
from tabs.password_tab import PasswordTab
from tabs.vpn_tab import VpnTab
from tabs.hardware_tab import HardwareTab
from tabs.realtime_protection_tab import ProtectionTab
from tabs.parental_tab import ParentalTab
from tabs.settings_tab import SettingsTab
from tabs.about_tab import AboutTab
from tabs.analysis_details_tab import AnalysisDetailsTab
from tabs.threat_history_tab import ThreatHistoryTab
from styles import ThemeManager


class MalwareDefenderMain(QMainWindow):
    """Main Application Window - Malware Defender v5"""
    
    def __init__(self):
        super().__init__()
        self.setWindowTitle("🛡️  Malware Defender v5 - Ultimate Protection Suite")
        self.setGeometry(50, 50, 1600, 950)
        self.setMinimumSize(1200, 800)
        
        # Theme Manager
        self.theme_manager = ThemeManager()
        
        # Application State
        self.scan_status = "Ready"
        self.protection_status = "Active"
        self.threats_count = 0
        self.current_theme = "Dark"
        
        # Initialize UI
        self.init_ui()
        self.load_custom_themes()
        self.start_status_timer()
        
        # Apply default theme
        self.change_theme("Dark")
    
    def init_ui(self):
        """Initialize all UI components"""
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QVBoxLayout(central_widget)
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.setSpacing(0)
        
        # 1. Header Bar
        self.header_widget = self.create_header_bar()
        main_layout.addWidget(self.header_widget)
        
        # 2. Main Tab Widget
        self.tab_widget = self.create_tab_widget()
        main_layout.addWidget(self.tab_widget, 1)
        
        # 3. Status Bar
        self.create_status_bar()
    
    def create_header_bar(self):
        """Create professional header with theme switcher and quick actions"""
        header = QWidget()
        header.setMaximumHeight(80)
        header_layout = QHBoxLayout(header)
        header_layout.setContentsMargins(20, 10, 20, 10)
        header_layout.setSpacing(15)
        
        # Logo & Title Section
        logo_frame = QWidget()
        logo_layout = QHBoxLayout(logo_frame)
        logo_layout.setContentsMargins(0, 0, 0, 0)
        
        logo_label = QLabel("🛡️ ")
        logo_label.setFont(QFont("Segoe UI", 24, QFont.Weight.Bold))
        
        title_label = QLabel("Malware Defender v5")
        title_label.setFont(QFont("Segoe UI", 16, QFont.Weight.Bold))
        
        version_label = QLabel("Ultimate Protection Suite")
        version_label.setFont(QFont("Segoe UI", 10))
        version_label.setStyleSheet("color: #888888;")
        
        title_frame = QWidget()
        title_layout = QVBoxLayout(title_frame)
        title_layout.setContentsMargins(0, 0, 0, 0)
        title_layout.setSpacing(2)
        title_layout.addWidget(title_label)
        title_layout.addWidget(version_label)
        
        logo_layout.addWidget(logo_label)
        logo_layout.addWidget(title_frame)
        
        header_layout.addWidget(logo_frame)
        header_layout.addStretch()
        
        # Theme Selector
        theme_label = QLabel("🎨 Theme:")
        theme_label.setFont(QFont("Segoe UI", 10, QFont.Weight.Bold))
        
        self.theme_combo = QComboBox()
        self.theme_combo.addItems([
            "Light",
            "Dark", 
            "Win11 Dark Blue",
            "Win11 Light",
            "Cyberpunk Dark",
            "Ocean Wave",
            "Forest Green",
            "Sunset Orange"
        ])
        self.theme_combo.setMinimumWidth(180)
        self.theme_combo.currentTextChanged.connect(self.change_theme)
        
        header_layout.addWidget(theme_label)
        header_layout.addWidget(self.theme_combo)
        
        
        # Divider
        header_layout.addSpacing(20)
        
        # Status Indicators
        self.protection_status_btn = QPushButton("🛡️ Protection: ACTIVE")
        self.protection_status_btn.setMaximumWidth(200)
        self.protection_status_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self.protection_status_btn.clicked.connect(self.toggle_protection)
        
        self.quick_scan_btn = QPushButton("🔍 Quick Scan (30s)")
        self.quick_scan_btn.setMaximumWidth(180)
        self.quick_scan_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self.quick_scan_btn.clicked.connect(self.quick_scan)
        
        header_layout.addWidget(self.protection_status_btn)
        header_layout.addWidget(self.quick_scan_btn)
        
        return header
    
    def create_tab_widget(self):
        """Create tabbed interface with all 11 features"""
        tab_widget = QTabWidget()
        tab_widget.setTabPosition(QTabWidget.TabPosition.North)
        
        # Define all tabs
        self.tabs = {
            "🔍 Full Scan": ScanTab(),
            "🧪 Sandbox": SandboxTab(),
            "🔐 Password Manager": PasswordTab(),
            "🌐 VPN": VpnTab(),
            "📊 Threat History": ThreatHistoryTab(),
            "📈 Analytics": AnalysisDetailsTab(),
            "⚙️ Hardware Monitor": HardwareTab(),
            "🛡️ Real-time Protection": ProtectionTab(),
            "👨‍👩‍👧 Parental Controls": ParentalTab(),
            "⚙️ Settings": SettingsTab(),
            "ℹ️ About": AboutTab()
        }
        
        # Add tabs to widget
        for tab_name, tab_widget_obj in self.tabs.items():
            tab_widget.addTab(tab_widget_obj, tab_name)
        
        return tab_widget
    
    def create_status_bar(self):
        """Create dynamic status bar with real-time updates"""
        status_widget = QWidget()
        status_layout = QHBoxLayout(status_widget)
        status_layout.setContentsMargins(20, 5, 20, 5)
        
        # Scan Status
        self.scan_label = QLabel("🔍 Scan: Ready")
        self.scan_label.setFont(QFont("Segoe UI", 10))
        
        # Protection Status
        self.prot_label = QLabel("🛡️ Protection: Active")
        self.prot_label.setFont(QFont("Segoe UI", 10))
        
        # Threats Count
        self.threats_label = QLabel("⚠️ Threats Today: 0")
        self.threats_label.setFont(QFont("Segoe UI", 10))
        
        # Last Scan Time
        self.last_scan_label = QLabel("📅 Last Scan: Never")
        self.last_scan_label.setFont(QFont("Segoe UI", 10))
        
        status_layout.addWidget(self.scan_label)
        status_layout.addWidget(self.prot_label)
        status_layout.addStretch()
        status_layout.addWidget(self.threats_label)
        status_layout.addWidget(self.last_scan_label)
        
        self.statusBar().addWidget(status_widget, 1)
    
    def load_custom_themes(self):
        """Load custom themes from winthemes.net (simulated)"""
        self.custom_themes = {
            "Cyberpunk Dark": self.get_cyberpunk_dark_theme(),
            "Ocean Wave": self.get_ocean_wave_theme(),
            "Forest Green": self.get_forest_green_theme(),
            "Sunset Orange": self.get_sunset_orange_theme(),
        }
    
    def change_theme(self, theme_name):
        """Apply selected theme to entire application"""
        theme_css = None
        
        if theme_name == "Light":
            theme_css = self.get_light_theme()
        elif theme_name == "Dark":
            theme_css = self.get_dark_theme()
        elif theme_name == "Win11 Dark Blue":
            theme_css = self.get_win11_dark_theme()
        elif theme_name == "Win11 Light":
            theme_css = self.get_win11_light_theme()
        elif theme_name in self.custom_themes:
            theme_css = self.custom_themes[theme_name]
        
        if theme_css:
            self.setStyleSheet(theme_css)
            self.current_theme = theme_name
            print(f"✅ Theme changed to: {theme_name}")
    
    # ==================== THEME DEFINITIONS ====================
    
    def get_light_theme(self):
        """Light Theme - Professional Office Style"""
        return """
        QMainWindow {
            background: qlineargradient(x1:0, y1:0, x2:1, y2:1, 
                       stop:0 #f8f9fa, stop:1 #e9ecef);
        }
        QWidget {
            color: #212529;
            background: transparent;
        }
        QTabWidget::pane {
            border: 2px solid #dee2e6;
            background: white;
            border-radius: 8px;
            padding: 5px;
        }
        QTabBar::tab {
            background: #e9ecef;
            color: #495057;
            border: 1px solid #dee2e6;
            padding: 10px 20px;
            margin-right: 2px;
            border-radius: 6px 6px 0 0;
            font-weight: bold;
        }
        QTabBar::tab:selected {
            background: qlineargradient(x1:0, y1:0, x2:0, y2:1, 
                       stop:0 #007bff, stop:1 #0056b3);
            color: white;
            border: 1px solid #0056b3;
        }
        QTabBar::tab:hover {
            background: #dee2e6;
        }
        QPushButton {
            background: qlineargradient(x1:0, y1:0, x2:0, y2:1, 
                       stop:0 #007bff, stop:1 #0056b3);
            color: white;
            border: none;
            border-radius: 6px;
            padding: 10px 20px;
            font-weight: bold;
            font-size: 11px;
        }
        QPushButton:hover {
            background: qlineargradient(x1:0, y1:0, x2:0, y2:1, 
                       stop:0 #0056b3, stop:1 #003d82);
        }
        QPushButton:pressed {
            background: #003d82;
        }
        QLineEdit, QTextEdit {
            background: white;
            border: 1px solid #dee2e6;
            border-radius: 4px;
            padding: 8px;
            color: #212529;
        }
        QLineEdit:focus, QTextEdit:focus {
            border: 2px solid #007bff;
        }
        QComboBox {
            background: white;
            border: 1px solid #dee2e6;
            border-radius: 4px;
            padding: 8px;
            color: #212529;
        }
        QComboBox:focus {
            border: 2px solid #007bff;
        }
        QStatusBar {
            background: #f8f9fa;
            border-top: 1px solid #dee2e6;
        }
        """
    
    def get_dark_theme(self):
        """Dark Theme - Modern Night Mode"""
        return """
        QMainWindow {
            background: qlineargradient(x1:0, y1:0, x2:1, y2:1, 
                       stop:0 #1a1a1a, stop:1 #2d2d30);
        }
        QWidget {
            color: #e0e0e0;
            background: transparent;
        }
        QTabWidget::pane {
            border: 2px solid #444;
            background: #2d2d30;
            border-radius: 8px;
            padding: 5px;
        }
        QTabBar::tab {
            background: #3c3c3c;
            color: #b0b0b0;
            border: 1px solid #555;
            padding: 10px 20px;
            margin-right: 2px;
            border-radius: 6px 6px 0 0;
            font-weight: bold;
        }
        QTabBar::tab:selected {
            background: qlineargradient(x1:0, y1:0, x2:0, y2:1, 
                       stop:0 #0078d4, stop:1 #106ebe);
            color: white;
            border: 1px solid #106ebe;
        }
        QTabBar::tab:hover {
            background: #454545;
        }
        QPushButton {
            background: qlineargradient(x1:0, y1:0, x2:0, y2:1, 
                       stop:0 #28a745, stop:1 #1e7e34);
            color: white;
            border: none;
            border-radius: 6px;
            padding: 10px 20px;
            font-weight: bold;
            font-size: 11px;
        }
        QPushButton:hover {
            background: qlineargradient(x1:0, y1:0, x2:0, y2:1, 
                       stop:0 #1e7e34, stop:1 #155724);
        }
        QPushButton:pressed {
            background: #155724;
        }
        QLineEdit, QTextEdit {
            background: #3c3c3c;
            border: 1px solid #555;
            border-radius: 4px;
            padding: 8px;
            color: #e0e0e0;
        }
        QLineEdit:focus, QTextEdit:focus {
            border: 2px solid #0078d4;
        }
        QComboBox {
            background: #3c3c3c;
            border: 1px solid #555;
            border-radius: 4px;
            padding: 8px;
            color: #e0e0e0;
        }
        QComboBox:focus {
            border: 2px solid #0078d4;
        }
        QStatusBar {
            background: #252526;
            border-top: 1px solid #444;
        }
        """
    
    def get_win11_dark_theme(self):
        """Windows 11 Dark Theme - Official Microsoft Style"""
        return """
        QMainWindow {
            background: qlineargradient(x1:0, y1:0, x2:1, y2:1, 
                       stop:0 #202020, stop:1 #171717);
        }
        QWidget {
            color: #e0e0e0;
            background: transparent;
        }
        QTabWidget::pane {
            background: #252526;
            border: 1px solid #3e3e42;
            border-radius: 8px;
        }
        QTabBar::tab {
            background: #2d2d30;
            color: #d0d0d0;
            border: none;
            padding: 12px 24px;
            margin-right: 4px;
            border-radius: 8px 8px 0 0;
            font-weight: bold;
            font-size: 11px;
        }
        QTabBar::tab:selected {
            background: qlineargradient(x1:0, y1:0, x2:0, y2:1, 
                       stop:0 #0e639c, stop:1 #094d7f);
            color: white;
        }
        QTabBar::tab:hover {
            background: #3e3e42;
        }
        QPushButton {
            background: #0e639c;
            color: white;
            border: none;
            border-radius: 4px;
            padding: 10px 20px;
            font-weight: bold;
            font-size: 11px;
        }
        QPushButton:hover {
            background: #1177bb;
        }
        QPushButton:pressed {
            background: #0a4668;
        }
        QLineEdit, QTextEdit {
            background: #3c3c3c;
            border: 1px solid #555;
            border-radius: 4px;
            padding: 8px;
            color: #e0e0e0;
        }
        QLineEdit:focus, QTextEdit:focus {
            border: 2px solid #0e639c;
        }
        QComboBox {
            background: #3c3c3c;
            border: 1px solid #555;
            border-radius: 4px;
            padding: 8px;
            color: #e0e0e0;
        }
        QComboBox:focus {
            border: 2px solid #0e639c;
        }
        QStatusBar {
            background: #252526;
            border-top: 1px solid #3e3e42;
        }
        """
    
    def get_win11_light_theme(self):
        """Windows 11 Light Theme - Official Microsoft Light Style"""
        return """
        QMainWindow {
            background: qlineargradient(x1:0, y1:0, x2:1, y2:1, 
                       stop:0 #f3f3f3, stop:1 #e5e5e5);
        }
        QWidget {
            color: #201f1e;
            background: transparent;
        }
        QTabWidget::pane {
            background: white;
            border: 1px solid #edebe9;
            border-radius: 8px;
        }
        QTabBar::tab {
            background: #f3f2f1;
            color: #201f1e;
            border: none;
            padding: 12px 24px;
            margin-right: 4px;
            border-radius: 8px 8px 0 0;
            font-weight: bold;
            font-size: 11px;
        }
        QTabBar::tab:selected {
            background: qlineargradient(x1:0, y1:0, x2:0, y2:1, 
                       stop:0 #0078d4, stop:1 #106ebe);
            color: white;
        }
        QTabBar::tab:hover {
            background: #e8e7e6;
        }
        QPushButton {
            background: #0078d4;
            color: white;
            border: none;
            border-radius: 4px;
            padding: 10px 20px;
            font-weight: bold;
            font-size: 11px;
        }
        QPushButton:hover {
            background: #106ebe;
        }
        QPushButton:pressed {
            background: #005ba1;
        }
        QLineEdit, QTextEdit {
            background: white;
            border: 1px solid #e1dfdd;
            border-radius: 4px;
            padding: 8px;
            color: #201f1e;
        }
        QLineEdit:focus, QTextEdit:focus {
            border: 2px solid #0078d4;
        }
        QComboBox {
            background: white;
            border: 1px solid #e1dfdd;
            border-radius: 4px;
            padding: 8px;
            color: #201f1e;
        }
        QComboBox:focus {
            border: 2px solid #0078d4;
        }
        QStatusBar {
            background: #f3f3f3;
            border-top: 1px solid #edebe9;
        }
        """
    
    def get_cyberpunk_dark_theme(self):
        """Cyberpunk Dark Theme - Neon Colors"""
        return """
        QMainWindow {
            background: qlineargradient(x1:0, y1:0, x2:1, y2:1, 
                       stop:0 #0a0e27, stop:1 #1a0033);
        }
        QWidget {
            color: #00ff88;
            background: transparent;
        }
        QTabWidget::pane {
            background: #0f1419;
            border: 2px solid #ff006e;
            border-radius: 0px;
        }
        QTabBar::tab {
            background: #1a1f2e;
            color: #00ff88;
            border: 1px solid #ff006e;
            padding: 10px 20px;
            font-weight: bold;
        }
        QTabBar::tab:selected {
            background: qlineargradient(x1:0, y1:0, x2:0, y2:1, 
                       stop:0 #ff006e, stop:1 #8338ec);
            color: #00ff88;
        }
        QPushButton {
            background: qlineargradient(x1:0, y1:0, x2:0, y2:1, 
                       stop:0 #ff006e, stop:1 #8338ec);
            color: #00ff88;
            border: 2px solid #00ff88;
            border-radius: 0px;
            padding: 10px 20px;
            font-weight: bold;
        }
        QPushButton:hover {
            background: qlineargradient(x1:0, y1:0, x2:0, y2:1, 
                       stop:0 #8338ec, stop:1 #3a86ff);
            border: 2px solid #ffbe0b;
        }
        QLineEdit, QTextEdit {
            background: #1a1f2e;
            border: 2px solid #00ff88;
            color: #00ff88;
        }
        QComboBox {
            background: #1a1f2e;
            border: 2px solid #00ff88;
            color: #00ff88;
        }
        """
    
    def get_ocean_wave_theme(self):
        """Ocean Wave Theme - Blue & Cyan Colors"""
        return """
        QMainWindow {
            background: qlineargradient(x1:0, y1:0, x2:1, y2:1, 
                       stop:0 #0a2342, stop:1 #1a4d6d);
        }
        QWidget {
            color: #e0f7ff;
            background: transparent;
        }
        QTabWidget::pane {
            background: #0f3a54;
            border: 2px solid #00bfff;
            border-radius: 8px;
        }
        QTabBar::tab {
            background: #1a5276;
            color: #e0f7ff;
            border: 1px solid #00bfff;
            padding: 10px 20px;
            font-weight: bold;
        }
        QTabBar::tab:selected {
            background: qlineargradient(x1:0, y1:0, x2:0, y2:1, 
                       stop:0 #00bfff, stop:1 #1e90ff);
            color: #001a33;
        }
        QPushButton {
            background: qlineargradient(x1:0, y1:0, x2:0, y2:1, 
                       stop:0 #00bfff, stop:1 #1e90ff);
            color: #001a33;
            border: none;
            border-radius: 6px;
            padding: 10px 20px;
            font-weight: bold;
        }
        QPushButton:hover {
            background: qlineargradient(x1:0, y1:0, x2:0, y2:1, 
                       stop:0 #1e90ff, stop:1 #4169e1);
        }
        QLineEdit, QTextEdit {
            background: #1a5276;
            border: 2px solid #00bfff;
            color: #e0f7ff;
        }
        QComboBox {
            background: #1a5276;
            border: 2px solid #00bfff;
            color: #e0f7ff;
        }
        """
    
    def get_forest_green_theme(self):
        """Forest Green Theme - Natural Earth Tones"""
        return """
        QMainWindow {
            background: qlineargradient(x1:0, y1:0, x2:1, y2:1, 
                       stop:0 #1b3d2e, stop:1 #2d5a3d);
        }
        QWidget {
            color: #d4f1d4;
            background: transparent;
        }
        QTabWidget::pane {
            background: #2d5a3d;
            border: 2px solid #4ca75a;
            border-radius: 8px;
        }
        QTabBar::tab {
            background: #3d6b4d;
            color: #d4f1d4;
            border: 1px solid #4ca75a;
            padding: 10px 20px;
            font-weight: bold;
        }
        QTabBar::tab:selected {
            background: qlineargradient(x1:0, y1:0, x2:0, y2:1, 
                       stop:0 #4ca75a, stop:1 #5db870);
            color: #1b3d2e;
        }
        QPushButton {
            background: qlineargradient(x1:0, y1:0, x2:0, y2:1, 
                       stop:0 #4ca75a, stop:1 #5db870);
            color: #1b3d2e;
            border: none;
            border-radius: 6px;
            padding: 10px 20px;
            font-weight: bold;
        }
        QPushButton:hover {
            background: qlineargradient(x1:0, y1:0, x2:0, y2:1, 
                       stop:0 #5db870, stop:1 #6ec97d);
        }
        QLineEdit, QTextEdit {
            background: #3d6b4d;
            border: 2px solid #4ca75a;
            color: #d4f1d4;
        }
        QComboBox {
            background: #3d6b4d;
            border: 2px solid #4ca75a;
            color: #d4f1d4;
        }
        """
    
    def get_sunset_orange_theme(self):
        """Sunset Orange Theme - Warm Colors"""
        return """
        QMainWindow {
            background: qlineargradient(x1:0, y1:0, x2:1, y2:1, 
                       stop:0 #4d2214, stop:1 #6b3a1f);
        }
        QWidget {
            color: #ffe6cc;
            background: transparent;
        }
        QTabWidget::pane {
            background: #5d2e1f;
            border: 2px solid #ff8c42;
            border-radius: 8px;
        }
        QTabBar::tab {
            background: #6b3a1f;
            color: #ffe6cc;
            border: 1px solid #ff8c42;
            padding: 10px 20px;
            font-weight: bold;
        }
        QTabBar::tab:selected {
            background: qlineargradient(x1:0, y1:0, x2:0, y2:1, 
                       stop:0 #ff8c42, stop:1 #ffa500);
            color: #4d2214;
        }
        QPushButton {
            background: qlineargradient(x1:0, y1:0, x2:0, y2:1, 
                       stop:0 #ff8c42, stop:1 #ffa500);
            color: #4d2214;
            border: none;
            border-radius: 6px;
            padding: 10px 20px;
            font-weight: bold;
        }
        QPushButton:hover {
            background: qlineargradient(x1:0, y1:0, x2:0, y2:1, 
                       stop:0 #ffa500, stop:1 #ffb84d);
        }
        QLineEdit, QTextEdit {
            background: #6b3a1f;
            border: 2px solid #ff8c42;
            color: #ffe6cc;
        }
        QComboBox {
            background: #6b3a1f;
            border: 2px solid #ff8c42;
            color: #ffe6cc;
        }
        """
    
    # ==================== ACTIONS ====================
    
    def quick_scan(self):
        """Quick scan button handler"""
        self.scan_label.setText("🔍 Scan: Running...")
        self.quick_scan_btn.setEnabled(False)
        self.quick_scan_btn.setText("🔍 Scanning... (10s)")
        
        # Simulate scan
        QTimer.singleShot(3000, self.scan_complete)
    
    def scan_complete(self):
        """Scan completion handler"""
        self.scan_label.setText("🔍 Scan: Completed")
        self.quick_scan_btn.setEnabled(True)
        self.quick_scan_btn.setText("🔍 Quick Scan (30s)")
        self.threats_count += 0  # Update if threats found
    
    def toggle_protection(self):
        """Toggle real-time protection"""
        if self.protection_status == "Active":
            self.protection_status = "Inactive"
            self.protection_status_btn.setText("🔴 Protection: INACTIVE")
            self.protection_status_btn.setStyleSheet("background: #dc3545;")
        else:
            self.protection_status = "Active"
            self.protection_status_btn.setText("🛡️ Protection: ACTIVE")
            self.protection_status_btn.setStyleSheet("background: #28a745;")
    
    def start_status_timer(self):
        """Update status bar every 5 seconds"""
        self.timer = QTimer()
        self.timer.timeout.connect(self.update_status_bar)
        self.timer.start(5000)
    
    def update_status_bar(self):
        """Update status bar information"""
        self.prot_label.setText(f"🛡️ Protection: {self.protection_status}")
        self.threats_label.setText(f"⚠️ Threats Today: {self.threats_count}")

    
class ThemeManager:
    """Manages application themes"""
    pass

def closeEvent(self, event):
    try:
        self.vpn_tab.cleanup()
    except:
        pass
    event.accept()


def main():
    """Application entry point"""
    app = QApplication(sys.argv)
    app.setApplicationName("Malware Defender v5")
    app.setApplicationVersion("5.0.0")
    
    window = MalwareDefenderMain()
    window.show()
    
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
