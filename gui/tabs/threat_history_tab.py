# gui/tabs/threat_history_tab.py - ENHANCED WITH ACTIONS + CHARTS + SANDBOX/SCAN INTEGRATION

from PyQt6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QPushButton, QLabel, QTableWidget,
QTableWidgetItem, QLineEdit, QComboBox, QSpinBox, QFileDialog, QMessageBox, QDialog,
QTextEdit, QFrame, QScrollArea, QProgressBar, QTabWidget, QHeaderView)
from PyQt6.QtCore import Qt, QTimer, pyqtSignal, QDate, QDateTime
from PyQt6.QtGui import QFont, QColor, QIcon, QStandardItem, QStandardItemModel
from PyQt6.QtChart import QChart, QChartView, QBarSeries, QBarSet, QBarCategoryAxis, QValueAxis, QLineSeries, QLineChart
from PyQt6.QtCore import QPointF
import sqlite3
import csv
import os
import sys
from datetime import datetime, timedelta

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(__file__))))

# ============================================================================
# DATABASE MANAGER
# ============================================================================

class ThreatDatabaseManager:
    """Manage threat history database"""
    
    def __init__(self, db_path="threat_history.db"):
        self.db_path = db_path
        self.init_database()
    
    def init_database(self):
        """Create database and tables"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS threat_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            file_name TEXT NOT NULL,
            file_path TEXT NOT NULL,
            file_size TEXT,
            file_hash TEXT,
            risk_level TEXT,
            risk_score INTEGER,
            suspicious_patterns INTEGER,
            behavioral_flags INTEGER,
            static_indicators INTEGER,
            action TEXT,
            scan_type TEXT,
            source TEXT DEFAULT 'MANUAL',
            status TEXT DEFAULT 'DETECTED'
        )
        ''')
        
        cursor.execute('''
        CREATE INDEX IF NOT EXISTS idx_timestamp ON threat_history(timestamp DESC)
        ''')
        
        cursor.execute('''
        CREATE INDEX IF NOT EXISTS idx_risk_level ON threat_history(risk_level)
        ''')
        
        conn.commit()
        conn.close()
    
    def add_threat(self, file_name, file_path, file_size="", file_hash="", risk_level="UNKNOWN",
                   risk_score=0, suspicious=0, behavioral=0, static=0, action="DETECTED", 
                   scan_type="MANUAL", source="MANUAL"):
        """Add threat to database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        cursor.execute('''
        INSERT INTO threat_history 
        (timestamp, file_name, file_path, file_size, file_hash, risk_level, risk_score,
         suspicious_patterns, behavioral_flags, static_indicators, action, scan_type, source, status)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (timestamp, file_name, file_path, file_size, file_hash, risk_level, risk_score,
              suspicious, behavioral, static, action, scan_type, source, "DETECTED"))
        
        conn.commit()
        threat_id = cursor.lastrowid
        conn.close()
        
        return threat_id
    
    def get_all_threats(self):
        """Get all threats from database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
        SELECT id, timestamp, file_name, file_path, file_size, risk_level, risk_score,
               suspicious_patterns, behavioral_flags, static_indicators, action, scan_type, source, status
        FROM threat_history
        ORDER BY timestamp DESC
        ''')
        
        threats = cursor.fetchall()
        conn.close()
        return threats
    
    def update_threat_action(self, threat_id, action):
        """Update threat action (ALLOW, QUARANTINE, DELETE)"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
        UPDATE threat_history
        SET action = ?, status = ?
        WHERE id = ?
        ''', (action, "HANDLED", threat_id))
        
        conn.commit()
        conn.close()
    
    def delete_threat(self, threat_id):
        """Delete threat from database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('DELETE FROM threat_history WHERE id = ?', (threat_id,))
        
        conn.commit()
        conn.close()
    
    def clear_all_threats(self):
        """Delete all threats"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('DELETE FROM threat_history')
        
        conn.commit()
        conn.close()
    
    def get_threat_stats(self):
        """Get statistics about threats"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Total threats
        cursor.execute('SELECT COUNT(*) FROM threat_history')
        total = cursor.fetchone()[0]
        
        # By risk level
        cursor.execute('''
        SELECT risk_level, COUNT(*) 
        FROM threat_history 
        GROUP BY risk_level
        ''')
        risk_stats = cursor.fetchall()
        
        # By scan type
        cursor.execute('''
        SELECT scan_type, COUNT(*) 
        FROM threat_history 
        GROUP BY scan_type
        ''')
        scan_stats = cursor.fetchall()
        
        # By action
        cursor.execute('''
        SELECT action, COUNT(*) 
        FROM threat_history 
        GROUP BY action
        ''')
        action_stats = cursor.fetchall()
        
        conn.close()
        
        return {
            'total': total,
            'by_risk': risk_stats,
            'by_scan': scan_stats,
            'by_action': action_stats
        }
    
    def get_daily_stats(self, days=30):
        """Get daily threat count for last N days"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
        SELECT DATE(timestamp) as date, COUNT(*) as count
        FROM threat_history
        WHERE datetime(timestamp) >= datetime('now', '-' || ? || ' days')
        GROUP BY DATE(timestamp)
        ORDER BY date ASC
        ''', (days,))
        
        stats = cursor.fetchall()
        conn.close()
        
        return stats

# ============================================================================
# THREAT DETAIL DIALOG
# ============================================================================

class ThreatDetailDialog(QDialog):
    """Show detailed threat information"""
    
    def __init__(self, parent, threat_data):
        super().__init__(parent)
        self.threat_data = threat_data
        self.setWindowTitle("🔍 Threat Details")
        self.setGeometry(100, 100, 700, 500)
        self.setStyleSheet(self._get_dark_theme())
        self.init_ui()
    
    def init_ui(self):
        """Create UI"""
        layout = QVBoxLayout(self)
        
        title = QLabel("📋 THREAT ANALYSIS REPORT")
        title.setFont(QFont("Segoe UI", 12, QFont.Weight.Bold))
        title.setStyleSheet("color: #00d4ff;")
        layout.addWidget(title)
        
        details_text = QTextEdit()
        details_text.setReadOnly(True)
        details_text.setFont(QFont("Courier New", 9))
        
        threat_info = f"""
═══════════════════════════════════════════════════════════════
📊 THREAT INFORMATION
═══════════════════════════════════════════════════════════════

🆔 ID:              {self.threat_data[0]}
📅 Timestamp:       {self.threat_data[1]}
📄 File Name:       {self.threat_data[2]}
📍 File Path:       {self.threat_data[3]}
📦 File Size:       {self.threat_data[4]}
🎯 Risk Level:      {self.threat_data[5]}
📈 Risk Score:      {self.threat_data[6]}
⚠️  Suspicious:     {self.threat_data[7]}
🔴 Behavioral:      {self.threat_data[8]}
🟡 Static:          {self.threat_data[9]}
✅ Action:          {self.threat_data[10]}
🔍 Scan Type:       {self.threat_data[11]}
📍 Source:          {self.threat_data[12]}
🔐 Status:          {self.threat_data[13]}

═══════════════════════════════════════════════════════════════
⚠️  ANALYSIS SUMMARY
═══════════════════════════════════════════════════════════════

• Risk Level: {self._get_risk_emoji(self.threat_data[5])} {self.threat_data[5]}
• Detection Score: {self.threat_data[6]}/100
• Suspicious Patterns Found: {self.threat_data[7]}
• Behavioral Flags: {self.threat_data[8]}
• Static Indicators: {self.threat_data[9]}
• Total Detections: {self.threat_data[7] + self.threat_data[8] + self.threat_data[9]}

═══════════════════════════════════════════════════════════════
📍 ACTION TAKEN
═══════════════════════════════════════════════════════════════

Current Action: {self.threat_data[10]}
Source: {self.threat_data[12]}
Time: {self.threat_data[1]}

═══════════════════════════════════════════════════════════════
"""
        
        details_text.setText(threat_info)
        layout.addWidget(details_text)
        
        # Buttons
        btn_layout = QHBoxLayout()
        close_btn = QPushButton("✅ Close")
        close_btn.setMinimumHeight(40)
        close_btn.setFont(QFont("Segoe UI", 10, QFont.Weight.Bold))
        close_btn.setStyleSheet("""
        QPushButton {
            background-color: #0066cc;
            color: white;
            border: none;
            border-radius: 6px;
            padding: 8px;
        }
        QPushButton:hover {
            background-color: #0088ff;
        }
        """)
        close_btn.clicked.connect(self.accept)
        btn_layout.addStretch()
        btn_layout.addWidget(close_btn)
        layout.addLayout(btn_layout)
    
    def _get_risk_emoji(self, risk_level):
        """Get emoji for risk level"""
        emojis = {
            "LOW": "🟢",
            "MEDIUM": "🟡",
            "HIGH": "🟠",
            "CRITICAL": "🔴"
        }
        return emojis.get(risk_level, "⚪")
    
    def _get_dark_theme(self):
        return """
        QDialog {
            background-color: #1a1a1a;
            color: #ffffff;
        }
        QTextEdit {
            background-color: #252525;
            color: #00ff00;
            border: 1px solid #404040;
            border-radius: 6px;
            font-family: 'Courier New';
            font-size: 9px;
            padding: 10px;
        }
        QLabel {
            color: #ffffff;
        }
        """

# ============================================================================
# THREAT HISTORY TAB - MAIN
# ============================================================================

class ThreatHistoryTab(QWidget):
    """Threat History Tab with Actions + Charts + Scanner Integration"""
    
    # Signal to update threat history
    threat_detected = pyqtSignal(dict)
    
    def __init__(self):
        super().__init__()
        
        self.db_manager = ThreatDatabaseManager()
        self.selected_threat_id = None
        
        # Auto-refresh timer
        self.refresh_timer = QTimer()
        self.refresh_timer.timeout.connect(self.load_threat_history)
        self.refresh_timer.start(5000)  # Refresh every 5 seconds
        
        self.init_ui()
        self._insert_sample_data()
    
    def init_ui(self):
        """Initialize UI"""
        layout = QVBoxLayout(self)
        layout.setSpacing(10)
        layout.setContentsMargins(15, 15, 15, 15)
        
        self.setStyleSheet("""
        QWidget {
            background-color: #1a1a1a;
            color: #ffffff;
            font-family: 'Segoe UI', sans-serif;
        }
        QLabel { color: #ffffff; }
        QLineEdit, QComboBox, QSpinBox {
            background-color: #252525;
            border: 1px solid #404040;
            border-radius: 6px;
            color: #ffffff;
            padding: 5px;
        }
        QTableWidget {
            background-color: #252525;
            border: 1px solid #404040;
            border-radius: 6px;
            color: #ffffff;
        }
        QTableWidget::item {
            padding: 5px;
            border-bottom: 1px solid #404040;
        }
        QTableWidget::item:selected {
            background-color: #404040;
        }
        QHeaderView::section {
            background-color: #1e293b;
            color: #00d4ff;
            padding: 5px;
            border: 1px solid #404040;
            font-weight: bold;
        }
        QScrollBar:vertical {
            background-color: #252525;
            width: 12px;
            border-radius: 6px;
        }
        QScrollBar::handle:vertical {
            background-color: #404040;
            border-radius: 6px;
        }
        QScrollBar::handle:vertical:hover {
            background-color: #505050;
        }
        """)
        
        # ===== TITLE =====
        title = QLabel("📊 THREAT HISTORY & ANALYSIS")
        title.setFont(QFont("Segoe UI", 14, QFont.Weight.Bold))
        title.setStyleSheet("color: #00d4ff;")
        layout.addWidget(title)
        
        # ===== STATISTICS CARD =====
        stats_layout = self._create_stats_card()
        layout.addLayout(stats_layout)
        
        # ===== TABS: TABLE + CHARTS =====
        tabs = QTabWidget()
        tabs.setStyleSheet("""
        QTabWidget::pane { border: 1px solid #404040; }
        QTabBar::tab {
            background-color: #252525;
            color: #ffffff;
            padding: 8px 20px;
            border: 1px solid #404040;
            margin-right: 2px;
        }
        QTabBar::tab:selected {
            background-color: #0066cc;
            color: #ffffff;
        }
        """)
        
        # Tab 1: Threat Table
        table_widget = self._create_threat_table()
        tabs.addTab(table_widget, "📋 Threat List")
        
        # Tab 2: Charts
        charts_widget = self._create_charts()
        tabs.addTab(charts_widget, "📊 Analytics")
        
        layout.addWidget(tabs, 1)
        
        # ===== FILTERS =====
        filter_layout = self._create_filter_controls()
        layout.addLayout(filter_layout)
        
        # ===== ACTION BUTTONS =====
        action_layout = self._create_action_buttons()
        layout.addLayout(action_layout)
    
    def _create_stats_card(self):
        """Create statistics card"""
        layout = QHBoxLayout()
        
        stats = self.db_manager.get_threat_stats()
        
        # Total threats
        total_label = QLabel(f"📊 Total Threats: {stats['total']}")
        total_label.setFont(QFont("Segoe UI", 11, QFont.Weight.Bold))
        total_label.setStyleSheet("background: rgba(0, 100, 150, 100); color: #00d4ff; padding: 10px; border-radius: 6px;")
        layout.addWidget(total_label)
        
        # Critical
        critical_count = next((item[1] for item in stats['by_risk'] if item[0] == 'CRITICAL'), 0)
        critical_label = QLabel(f"🔴 Critical: {critical_count}")
        critical_label.setFont(QFont("Segoe UI", 11, QFont.Weight.Bold))
        critical_label.setStyleSheet("background: rgba(200, 0, 0, 100); color: #ff6666; padding: 10px; border-radius: 6px;")
        layout.addWidget(critical_label)
        
        # High
        high_count = next((item[1] for item in stats['by_risk'] if item[0] == 'HIGH'), 0)
        high_label = QLabel(f"🟠 High: {high_count}")
        high_label.setFont(QFont("Segoe UI", 11, QFont.Weight.Bold))
        high_label.setStyleSheet("background: rgba(200, 100, 0, 100); color: #ffaa00; padding: 10px; border-radius: 6px;")
        layout.addWidget(high_label)
        
        # Medium
        medium_count = next((item[1] for item in stats['by_risk'] if item[0] == 'MEDIUM'), 0)
        medium_label = QLabel(f"🟡 Medium: {medium_count}")
        medium_label.setFont(QFont("Segoe UI", 11, QFont.Weight.Bold))
        medium_label.setStyleSheet("background: rgba(200, 150, 0, 100); color: #ffff00; padding: 10px; border-radius: 6px;")
        layout.addWidget(medium_label)
        
        layout.addStretch()
        
        return layout
    
    def _create_threat_table(self):
        """Create threat table"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        self.threat_table = QTableWidget()
        self.threat_table.setColumnCount(11)
        self.threat_table.setHorizontalHeaderLabels([
            "ID", "Time", "File Name", "Risk Level", "Score", 
            "Patterns", "Action", "Scan Type", "Source", "Status", "Details"
        ])
        self.threat_table.setMinimumHeight(400)
        self.threat_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.ResizeToContents)
        self.threat_table.itemSelectionChanged.connect(self.on_threat_selected)
        
        layout.addWidget(self.threat_table)
        
        return widget
    
    def _create_charts(self):
        """Create analytics charts"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # Chart tabs
        chart_tabs = QTabWidget()
        
        # Chart 1: Risk Distribution (Bar Chart)
        risk_chart = self._create_risk_chart()
        chart_tabs.addTab(risk_chart, "📊 Risk Distribution")
        
        # Chart 2: Daily Threats (Line Chart)
        trend_chart = self._create_trend_chart()
        chart_tabs.addTab(trend_chart, "📈 Threat Trends")
        
        # Chart 3: Scan Type Distribution
        scan_chart = self._create_scan_chart()
        chart_tabs.addTab(scan_chart, "🔍 Scan Types")
        
        layout.addWidget(chart_tabs)
        
        return widget
    
    def _create_risk_chart(self):
        """Create risk distribution bar chart"""
        chart = QChart()
        chart.setTitle("📊 Threats by Risk Level")
        chart.setBackgroundBrush(QColor("#1a1a1a"))
        chart.setTitleBrush(QColor("#00d4ff"))
        
        stats = self.db_manager.get_threat_stats()
        
        # Create bar set
        bar_set = QBarSet("Threats")
        bar_set.setColor(QColor("#0066cc"))
        
        categories = []
        for risk_level in ["LOW", "MEDIUM", "HIGH", "CRITICAL"]:
            count = next((item[1] for item in stats['by_risk'] if item[0] == risk_level), 0)
            bar_set.append(count)
            categories.append(risk_level)
        
        series = QBarSeries()
        series.append(bar_set)
        chart.addSeries(series)
        
        # Axes
        axis_x = QBarCategoryAxis()
        axis_x.append(categories)
        axis_x.setLabelsColor(QColor("#ffffff"))
        chart.addAxis(axis_x, Qt.AlignmentFlag.AlignBottom)
        series.attachAxis(axis_x)
        
        axis_y = QValueAxis()
        axis_y.setLabelsColor(QColor("#ffffff"))
        chart.addAxis(axis_y, Qt.AlignmentFlag.AlignLeft)
        series.attachAxis(axis_y)
        
        # Create chart view
        chart_view = QChartView(chart)
        chart_view.setRenderHint(chart_view.RenderHint.Antialiasing)
        
        return chart_view
    
    def _create_trend_chart(self):
        """Create daily threat trend line chart"""
        chart = QLineChart()
        chart.setTitle("📈 Daily Threat Trends (Last 30 Days)")
        chart.setBackgroundBrush(QColor("#1a1a1a"))
        chart.setTitleBrush(QColor("#00d4ff"))
        
        stats = self.db_manager.get_daily_stats(30)
        
        # Create line series
        series = QLineSeries()
        series.setName("Threats")
        series.setColor(QColor("#00ff00"))
        
        for date, count in stats:
            series.append(QPointF(len(series), count))
        
        chart.addSeries(series)
        
        # Axes
        axis_x = QValueAxis()
        axis_x.setLabelsColor(QColor("#ffffff"))
        chart.addAxis(axis_x, Qt.AlignmentFlag.AlignBottom)
        series.attachAxis(axis_x)
        
        axis_y = QValueAxis()
        axis_y.setLabelsColor(QColor("#ffffff"))
        chart.addAxis(axis_y, Qt.AlignmentFlag.AlignLeft)
        series.attachAxis(axis_y)
        
        # Create chart view
        chart_view = QChartView(chart)
        chart_view.setRenderHint(chart_view.RenderHint.Antialiasing)
        
        return chart_view
    
    def _create_scan_chart(self):
        """Create scan type distribution"""
        chart = QChart()
        chart.setTitle("🔍 Threats by Scan Type")
        chart.setBackgroundBrush(QColor("#1a1a1a"))
        chart.setTitleBrush(QColor("#00d4ff"))
        
        stats = self.db_manager.get_threat_stats()
        
        bar_set = QBarSet("Count")
        bar_set.setColor(QColor("#00aa00"))
        
        categories = []
        for scan_type, count in stats['by_scan']:
            bar_set.append(count)
            categories.append(scan_type if scan_type else "UNKNOWN")
        
        series = QBarSeries()
        series.append(bar_set)
        chart.addSeries(series)
        
        axis_x = QBarCategoryAxis()
        axis_x.append(categories)
        axis_x.setLabelsColor(QColor("#ffffff"))
        chart.addAxis(axis_x, Qt.AlignmentFlag.AlignBottom)
        series.attachAxis(axis_x)
        
        axis_y = QValueAxis()
        axis_y.setLabelsColor(QColor("#ffffff"))
        chart.addAxis(axis_y, Qt.AlignmentFlag.AlignLeft)
        series.attachAxis(axis_y)
        
        chart_view = QChartView(chart)
        chart_view.setRenderHint(chart_view.RenderHint.Antialiasing)
        
        return chart_view
    
    def _create_filter_controls(self):
        """Create filter controls"""
        layout = QHBoxLayout()
        
        # Search
        search_label = QLabel("🔍 Search:")
        search_label.setFont(QFont("Segoe UI", 10, QFont.Weight.Bold))
        self.search_field = QLineEdit()
        self.search_field.setPlaceholderText("Search by filename...")
        self.search_field.setMaximumWidth(250)
        self.search_field.textChanged.connect(self.load_threat_history)
        
        # Risk filter
        risk_label = QLabel("⚠️ Risk Level:")
        risk_label.setFont(QFont("Segoe UI", 10, QFont.Weight.Bold))
        self.risk_filter = QComboBox()
        self.risk_filter.addItems(["All", "CRITICAL", "HIGH", "MEDIUM", "LOW"])
        self.risk_filter.currentTextChanged.connect(self.load_threat_history)
        
        # Action filter
        action_label = QLabel("✅ Action:")
        action_label.setFont(QFont("Segoe UI", 10, QFont.Weight.Bold))
        self.action_filter = QComboBox()
        self.action_filter.addItems(["All", "BLOCKED", "QUARANTINED", "ALLOWED", "DETECTED"])
        self.action_filter.currentTextChanged.connect(self.load_threat_history)
        
        # Days filter
        days_label = QLabel("📅 Last:")
        days_label.setFont(QFont("Segoe UI", 10, QFont.Weight.Bold))
        self.days_spinner = QSpinBox()
        self.days_spinner.setMinimum(1)
        self.days_spinner.setMaximum(365)
        self.days_spinner.setValue(30)
        self.days_spinner.setMaximumWidth(80)
        self.days_spinner.valueChanged.connect(self.load_threat_history)
        
        days_suffix = QLabel("days")
        days_suffix.setFont(QFont("Segoe UI", 10))
        
        layout.addWidget(search_label)
        layout.addWidget(self.search_field)
        layout.addSpacing(20)
        layout.addWidget(risk_label)
        layout.addWidget(self.risk_filter, 1)
        layout.addWidget(action_label)
        layout.addWidget(self.action_filter, 1)
        layout.addWidget(days_label)
        layout.addWidget(self.days_spinner)
        layout.addWidget(days_suffix)
        layout.addStretch()
        
        return layout
    
    def _create_action_buttons(self):
        """Create action buttons"""
        layout = QHBoxLayout()
        
        # Action buttons
        allow_btn = QPushButton("✅ ALLOW")
        allow_btn.setMinimumHeight(40)
        allow_btn.setFont(QFont("Segoe UI", 10, QFont.Weight.Bold))
        allow_btn.setStyleSheet("""
        QPushButton {
            background-color: #009900;
            color: white;
            border: none;
            border-radius: 6px;
        }
        QPushButton:hover {
            background-color: #00bb00;
        }
        """)
        allow_btn.clicked.connect(lambda: self.set_threat_action("ALLOWED"))
        
        quarantine_btn = QPushButton("🔒 QUARANTINE")
        quarantine_btn.setMinimumHeight(40)
        quarantine_btn.setFont(QFont("Segoe UI", 10, QFont.Weight.Bold))
        quarantine_btn.setStyleSheet("""
        QPushButton {
            background-color: #ffaa00;
            color: white;
            border: none;
            border-radius: 6px;
        }
        QPushButton:hover {
            background-color: #ffbb00;
        }
        """)
        quarantine_btn.clicked.connect(lambda: self.set_threat_action("QUARANTINED"))
        
        block_btn = QPushButton("❌ BLOCK")
        block_btn.setMinimumHeight(40)
        block_btn.setFont(QFont("Segoe UI", 10, QFont.Weight.Bold))
        block_btn.setStyleSheet("""
        QPushButton {
            background-color: #cc0000;
            color: white;
            border: none;
            border-radius: 6px;
        }
        QPushButton:hover {
            background-color: #dd0000;
        }
        """)
        block_btn.clicked.connect(lambda: self.set_threat_action("BLOCKED"))
        
        delete_btn = QPushButton("🗑️ DELETE")
        delete_btn.setMinimumHeight(40)
        delete_btn.setFont(QFont("Segoe UI", 10, QFont.Weight.Bold))
        delete_btn.setStyleSheet("""
        QPushButton {
            background-color: #666666;
            color: white;
            border: none;
            border-radius: 6px;
        }
        QPushButton:hover {
            background-color: #888888;
        }
        """)
        delete_btn.clicked.connect(self.delete_threat)
        
        # Export button
        export_btn = QPushButton("💾 EXPORT CSV")
        export_btn.setMinimumHeight(40)
        export_btn.setFont(QFont("Segoe UI", 10, QFont.Weight.Bold))
        export_btn.setStyleSheet("""
        QPushButton {
            background-color: #0066cc;
            color: white;
            border: none;
            border-radius: 6px;
        }
        QPushButton:hover {
            background-color: #0088ff;
        }
        """)
        export_btn.clicked.connect(self.export_csv)
        
        # Clear all button
        clear_btn = QPushButton("🗑️ CLEAR ALL")
        clear_btn.setMinimumHeight(40)
        clear_btn.setFont(QFont("Segoe UI", 10, QFont.Weight.Bold))
        clear_btn.setStyleSheet("""
        QPushButton {
            background-color: #660000;
            color: white;
            border: none;
            border-radius: 6px;
        }
        QPushButton:hover {
            background-color: #880000;
        }
        """)
        clear_btn.clicked.connect(self.clear_all_threats)
        
        layout.addWidget(allow_btn)
        layout.addWidget(quarantine_btn)
        layout.addWidget(block_btn)
        layout.addWidget(delete_btn)
        layout.addSpacing(20)
        layout.addWidget(export_btn)
        layout.addWidget(clear_btn)
        layout.addStretch()
        
        return layout
    
    def add_threat_from_scan(self, file_name, file_path, file_size="", risk_level="UNKNOWN", 
                            risk_score=0, suspicious=0, behavioral=0, static=0, 
                            action="DETECTED", scan_type="QUICK_SCAN"):
        """Add threat from scan (called by Scan Tab)"""
        threat_id = self.db_manager.add_threat(
            file_name=file_name,
            file_path=file_path,
            file_size=file_size,
            risk_level=risk_level,
            risk_score=risk_score,
            suspicious=suspicious,
            behavioral=behavioral,
            static=static,
            action=action,
            scan_type=scan_type,
            source="SCANNER"
        )
        
        self.load_threat_history()
        return threat_id
    
    def add_threat_from_sandbox(self, file_name, file_path, file_size="", risk_level="UNKNOWN",
                               risk_score=0, suspicious=0, behavioral=0, static=0,
                               action="DETECTED"):
        """Add threat from sandbox (called by Sandbox Tab)"""
        threat_id = self.db_manager.add_threat(
            file_name=file_name,
            file_path=file_path,
            file_size=file_size,
            risk_level=risk_level,
            risk_score=risk_score,
            suspicious=suspicious,
            behavioral=behavioral,
            static=static,
            action=action,
            scan_type="SANDBOX",
            source="SANDBOX"
        )
        
        self.load_threat_history()
        return threat_id
    
    def load_threat_history(self):
        """Load threat history into table"""
        self.threat_table.setRowCount(0)
        
        threats = self.db_manager.get_all_threats()
        
        # Apply filters
        search_text = self.search_field.text().lower()
        risk_filter = self.risk_filter.currentText()
        action_filter = self.action_filter.currentText()
        days_filter = self.days_spinner.value()
        
        cutoff_date = datetime.now() - timedelta(days=days_filter)
        
        row = 0
        for threat in threats:
            threat_id, timestamp, file_name, file_path, file_size, risk_level, risk_score, \
            suspicious, behavioral, static, action, scan_type, source, status = threat
            
            # Apply search filter
            if search_text and search_text not in file_name.lower():
                continue
            
            # Apply risk filter
            if risk_filter != "All" and risk_level != risk_filter:
                continue
            
            # Apply action filter
            if action_filter != "All" and action != action_filter:
                continue
            
            # Apply date filter
            try:
                threat_date = datetime.strptime(timestamp, "%Y-%m-%d %H:%M:%S")
                if threat_date < cutoff_date:
                    continue
            except:
                pass
            
            # Add row
            self.threat_table.insertRow(row)
            
            # ID
            self.threat_table.setItem(row, 0, QTableWidgetItem(str(threat_id)))
            
            # Time
            self.threat_table.setItem(row, 1, QTableWidgetItem(timestamp.split()[1]))
            
            # File Name
            name_item = QTableWidgetItem(file_name)
            self.threat_table.setItem(row, 2, name_item)
            
            # Risk Level
            risk_item = QTableWidgetItem(f"{self._get_risk_emoji(risk_level)} {risk_level}")
            self.threat_table.setItem(row, 3, risk_item)
            
            # Score
            score_item = QTableWidgetItem(f"{risk_score}%")
            self.threat_table.setItem(row, 4, score_item)
            
            # Patterns
            patterns_item = QTableWidgetItem(str(suspicious + behavioral + static))
            self.threat_table.setItem(row, 5, patterns_item)
            
            # Action
            action_item = QTableWidgetItem(action)
            if action == "BLOCKED":
                action_item.setForeground(QColor("#ff0000"))
            elif action == "QUARANTINED":
                action_item.setForeground(QColor("#ffaa00"))
            elif action == "ALLOWED":
                action_item.setForeground(QColor("#00ff00"))
            self.threat_table.setItem(row, 6, action_item)
            
            # Scan Type
            self.threat_table.setItem(row, 7, QTableWidgetItem(scan_type if scan_type else "UNKNOWN"))
            
            # Source
            source_item = QTableWidgetItem(source)
            if source == "SCANNER":
                source_item.setForeground(QColor("#00d4ff"))
            elif source == "SANDBOX":
                source_item.setForeground(QColor("#ffff00"))
            self.threat_table.setItem(row, 8, source_item)
            
            # Status
            status_item = QTableWidgetItem(status)
            if status == "HANDLED":
                status_item.setForeground(QColor("#00ff00"))
            self.threat_table.setItem(row, 9, status_item)
            
            # Details button (store threat data)
            details_btn = QPushButton("👁️ View")
            details_btn.setMaximumWidth(80)
            details_btn.setStyleSheet("""
            QPushButton {
                background-color: #0066cc;
                color: white;
                border: none;
                border-radius: 4px;
                font-size: 9px;
            }
            QPushButton:hover {
                background-color: #0088ff;
            }
            """)
            details_btn.clicked.connect(lambda checked, t=threat: self.show_threat_details(t))
            self.threat_table.setCellWidget(row, 10, details_btn)
            
            # Store threat ID in first column for reference
            id_item = self.threat_table.item(row, 0)
            id_item.setData(Qt.ItemDataRole.UserRole, threat_id)
            
            row += 1
    
    def on_threat_selected(self):
        """Handle threat selection"""
        if self.threat_table.selectedIndexes():
            row = self.threat_table.selectedIndexes()[0].row()
            threat_id = self.threat_table.item(row, 0).data(Qt.ItemDataRole.UserRole)
            self.selected_threat_id = threat_id if threat_id else int(self.threat_table.item(row, 0).text())
    
    def show_threat_details(self, threat_data):
        """Show threat detail dialog"""
        dialog = ThreatDetailDialog(self, threat_data)
        dialog.exec()
    
    def set_threat_action(self, action):
        """Set action for selected threat"""
        if not self.selected_threat_id:
            QMessageBox.warning(self, "⚠️ Select a Threat", "Please select a threat first")
            return
        
        self.db_manager.update_threat_action(self.selected_threat_id, action)
        self.load_threat_history()
        QMessageBox.information(self, "✅ Success", f"Threat {action} successfully")
    
    def delete_threat(self):
        """Delete selected threat"""
        if not self.selected_threat_id:
            QMessageBox.warning(self, "⚠️ Select a Threat", "Please select a threat first")
            return
        
        reply = QMessageBox.question(self, "🗑️ Delete Threat", "Delete this threat record?")
        if reply == QMessageBox.StandardButton.Yes:
            self.db_manager.delete_threat(self.selected_threat_id)
            self.load_threat_history()
            QMessageBox.information(self, "✅ Deleted", "Threat record deleted")
    
    def clear_all_threats(self):
        """Clear all threats"""
        reply = QMessageBox.question(self, "🗑️ Clear All Threats", 
                                     "Delete ALL threat records? This cannot be undone!")
        if reply == QMessageBox.StandardButton.Yes:
            self.db_manager.clear_all_threats()
            self.load_threat_history()
            QMessageBox.information(self, "✅ Cleared", "All threat records cleared")
    
    def export_csv(self):
        """Export threats to CSV"""
        file_path, _ = QFileDialog.getSaveFileName(self, "Export Threats", "", "CSV Files (*.csv)")
        if not file_path:
            return
        
        threats = self.db_manager.get_all_threats()
        
        try:
            with open(file_path, 'w', newline='') as csvfile:
                writer = csv.writer(csvfile)
                writer.writerow(['ID', 'Timestamp', 'File Name', 'File Path', 'File Size', 'Risk Level',
                               'Risk Score', 'Suspicious', 'Behavioral', 'Static', 'Action', 'Scan Type',
                               'Source', 'Status'])
                
                for threat in threats:
                    writer.writerow(threat)
            
            QMessageBox.information(self, "✅ Exported", f"Threats exported to {file_path}")
        except Exception as e:
            QMessageBox.critical(self, "❌ Error", f"Export failed: {str(e)}")
    
    def _get_risk_emoji(self, risk_level):
        """Get emoji for risk level"""
        emojis = {
            "LOW": "🟢",
            "MEDIUM": "🟡",
            "HIGH": "🟠",
            "CRITICAL": "🔴"
        }
        return emojis.get(risk_level, "⚪")
    
    def _insert_sample_data(self):
        """Insert sample data on first run"""
        threats = self.db_manager.get_all_threats()
        if not threats:
            sample_threats = [
                ("sample.exe", "C:\\Windows\\Temp\\sample.exe", "2.5 MB", "HIGH", 75, 3, 2, 1, "BLOCKED", "QUICK_SCAN"),
                ("installer.msi", "C:\\Users\\User\\Downloads\\installer.msi", "50 MB", "MEDIUM", 45, 2, 1, 0, "ALLOWED", "FULL_SCAN"),
                ("library.dll", "C:\\Program Files\\library.dll", "500 KB", "CRITICAL", 95, 5, 3, 2, "QUARANTINED", "FULL_SCAN"),
                ("setup.exe", "C:\\Downloads\\setup.exe", "100 MB", "LOW", 15, 1, 0, 0, "ALLOWED", "QUICK_SCAN"),
                ("update.exe", "C:\\Windows\\System32\\update.exe", "2 MB", "MEDIUM", 55, 2, 2, 1, "QUARANTINED", "REAL_TIME"),
                ("malware.exe", "C:\\Temp\\malware.exe", "1.2 MB", "CRITICAL", 98, 8, 5, 3, "BLOCKED", "QUICK_SCAN"),
                ("trojan.dll", "C:\\Windows\\trojan.dll", "300 KB", "HIGH", 80, 4, 3, 1, "QUARANTINED", "FULL_SCAN"),
            ]
            
            for threat in sample_threats:
                self.db_manager.add_threat(
                    file_name=threat[0],
                    file_path=threat[1],
                    file_size=threat[2],
                    risk_level=threat[3],
                    risk_score=threat[4],
                    suspicious=threat[5],
                    behavioral=threat[6],
                    static=threat[7],
                    action=threat[8],
                    scan_type=threat[9],
                    source="SAMPLE"
                )
            
            self.load_threat_history()
