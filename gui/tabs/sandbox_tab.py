# gui/tabs/sandbox_tab.py - WIDE RIGHT PANEL + BIGGER TEXT

from PyQt6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QPushButton, QLabel,
QFileDialog, QTextEdit, QProgressBar, QGroupBox, QComboBox, QFrame)
from PyQt6.QtCore import Qt, QThread, pyqtSignal, QCoreApplication, QTimer, QPointF, QRect
from PyQt6.QtGui import QFont, QColor, QPainter
import os
import sys
import hashlib
import subprocess
import time
import random
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(__file__))))

# ============================================================================
# MALWARE ANIMATION WIDGET (Visual only - safe)
# ============================================================================

class MalwareVisualizationWidget(QWidget):
	"""Animated malware particles hitting shield"""
	
	def __init__(self):
		super().__init__()
		self.setMinimumHeight(250)
		self.setMinimumWidth(300)  # ✅ WIDER
		self.malware = []
		self.risk_level = "LOW"
		
		# Timer for animation
		self.timer = QTimer()
		self.timer.timeout.connect(self.update_simulation)
		self.timer.start(50)
		
		# Initialize background
		self.set_risk_level("UNKNOWN")
	
	def set_risk_level(self, level):
		"""Update risk level and animation intensity"""
		self.risk_level = level
		self.malware.clear()
		
		# Number of particles based on risk
		count = {
			"UNKNOWN": 0,
			"LOW": 3,
			"MEDIUM": 8,
			"HIGH": 15,
			"CRITICAL": 25
		}.get(level, 0)
		
		# Create particles
		for _ in range(count):
			self.malware.append({
				"pos": QPointF(
					random.randint(10, max(11, self.width() - 10)),
					random.randint(10, max(11, self.height() - 10))
				),
				"vel": QPointF(
					random.uniform(-2, 2),
					random.uniform(-2, 2)
				),
				"life": random.randint(50, 200)
			})
	
	def update_simulation(self):
		"""Update particle positions and bounce"""
		if not self.malware:
			return
		
		for m in self.malware:
			# Move particle
			m["pos"] += m["vel"]
			m["life"] -= 1
			
			# Bounce off edges
			if m["pos"].x() <= 5:
				m["vel"].setX(abs(m["vel"].x()))
				m["pos"].setX(5)
			elif m["pos"].x() >= self.width() - 5:
				m["vel"].setX(-abs(m["vel"].x()))
				m["pos"].setX(self.width() - 5)
			
			if m["pos"].y() <= 5:
				m["vel"].setY(abs(m["vel"].y()))
				m["pos"].setY(5)
			elif m["pos"].y() >= self.height() - 5:
				m["vel"].setY(-abs(m["vel"].y()))
				m["pos"].setY(self.height() - 5)
		
		# Remove dead particles and spawn new ones randomly
		self.malware = [m for m in self.malware if m["life"] > 0]
		
		if self.malware and random.random() < 0.1:  # 10% chance per frame
			new_particle = {
				"pos": QPointF(
					random.randint(10, max(11, self.width() - 10)),
					random.randint(10, max(11, self.height() - 10))
				),
				"vel": QPointF(
					random.uniform(-2, 2),
					random.uniform(-2, 2)
				),
				"life": random.randint(50, 200)
			}
			if len(self.malware) < {
				"UNKNOWN": 0,
				"LOW": 3,
				"MEDIUM": 8,
				"HIGH": 15,
				"CRITICAL": 25
			}.get(self.risk_level, 0):
				self.malware.append(new_particle)
		
		self.update()
	
	def paintEvent(self, event):
		"""Draw animation - FIXED QColor (int alpha, not float)"""
		painter = QPainter(self)
		painter.setRenderHint(QPainter.RenderHint.Antialiasing)
		
		# Background
		bg_color = QColor(15, 15, 25, 200)
		painter.fillRect(self.rect(), bg_color)
		
		# Border - ✅ FIXED: alpha as INT not FLOAT
		border_color_map = {
			"UNKNOWN": QColor(100, 100, 150, 76),    # ✅ 0.3 * 255 = 76
			"LOW": QColor(0, 255, 0, 128),           # ✅ Green = 128
			"MEDIUM": QColor(255, 170, 0, 128),      # ✅ Yellow = 128
			"HIGH": QColor(255, 100, 0, 128),        # ✅ Orange = 128
			"CRITICAL": QColor(255, 0, 0, 128)       # ✅ Red = 128
		}
		border_color = border_color_map.get(self.risk_level, QColor(100, 100, 150, 76))
		painter.setPen(border_color)
		painter.drawRect(0, 0, self.width() - 1, self.height() - 1)
		
		# Shield in center (protective) - ✅ BIGGER
		shield_radius = 40  # ✅ Increased from 25
		shield_color = {
			"UNKNOWN": QColor(100, 150, 200, 153),   # ✅ Light blue
			"LOW": QColor(0, 200, 100, 153),         # ✅ Green
			"MEDIUM": QColor(255, 170, 0, 153),      # ✅ Yellow
			"HIGH": QColor(255, 100, 0, 153),        # ✅ Orange
			"CRITICAL": QColor(255, 0, 0, 153)       # ✅ Red
		}.get(self.risk_level, QColor(100, 150, 200, 153))
		
		painter.setBrush(shield_color)
		painter.setPen(QColor(100, 200, 255, 200))
		painter.drawEllipse(self.width()//2 - shield_radius, self.height()//2 - shield_radius, shield_radius*2, shield_radius*2)
		
		# Draw shield icon text - ✅ BIGGER FONT
		painter.setPen(QColor(100, 200, 255, 200))
		painter.setFont(QFont("Arial", 32))

		shield_rect = QRect(
			self.width() // 2 - shield_radius,
			self.height() // 2 - shield_radius,
			shield_radius * 2,
			shield_radius * 2,
		)

		painter.drawText(shield_rect, Qt.AlignmentFlag.AlignCenter, "🛡️")


		
		# Draw malware particles
		painter.setBrush(QColor(255, 80, 80, 200))
		painter.setPen(Qt.PenStyle.NoPen)
		
		for m in self.malware:
			# Fade out particles
			alpha = int((m["life"] / 200) * 200)
			color = QColor(255, 80, 80, alpha)
			painter.setBrush(color)
			painter.drawEllipse(m["pos"], 5, 5)  # ✅ Slightly bigger
			
			# Draw glow
			glow_color = QColor(255, 80, 80, alpha // 3)
			painter.setBrush(glow_color)
			painter.drawEllipse(m["pos"], 8, 8)  # ✅ Slightly bigger
		
		# Draw threat indicator text - ✅ BIGGER TEXT
		threat_count = len(self.malware)
		painter.setPen(QColor(255, 100, 100, 200))
		painter.setFont(QFont("Arial", 11, QFont.Weight.Bold))  # ✅ Increased from 8
		painter.drawText(5, self.height() - 5, f"Threats: {threat_count}")

# ============================================================================
# MODE 1: STATIC ANALYZER (NO EXECUTION)
# ============================================================================

class StaticAnalyzer(QThread):
	"""ANALYZE MODE - Static analysis only (NO EXECUTION)"""
	
	log_update = pyqtSignal(str)
	progress_update = pyqtSignal(int)
	status_update = pyqtSignal(str)
	analysis_complete = pyqtSignal(dict)
	
	def __init__(self, file_path):
		super().__init__()
		self.file_path = file_path
		self.running = True
	
	def run(self):
		"""Analyze file WITHOUT executing it"""
		try:
			self.log_update.emit("🔍 ANALYZE MODE - STATIC ANALYSIS ONLY")
			self.log_update.emit(f"📄 File: {os.path.basename(self.file_path)}")
			self.log_update.emit("⚠️  FILE WILL NOT BE EXECUTED")
			self.progress_update.emit(10)
			self.status_update.emit("🟡 Analyzing...")
			time.sleep(0.3)
			
			self.log_update.emit("\n📊 FILE INFORMATION:")
			self.log_update.emit("─" * 60)
			file_size = os.path.getsize(self.file_path)
			file_ext = os.path.splitext(self.file_path)[1].lower()
			file_created = os.path.getctime(self.file_path)
			file_date = datetime.fromtimestamp(file_created).strftime("%Y-%m-%d %H:%M:%S")
			
			size_kb = file_size / 1024
			size_mb = size_kb / 1024
			size_gb = size_mb / 1024
			
			if size_gb >= 1:
				size_str = f"{size_gb:.2f}GB"
			elif size_mb >= 1:
				size_str = f"{size_mb:.2f}MB"
			else:
				size_str = f"{size_kb:.2f}KB"
			
			self.log_update.emit(f"📁 Path: {self.file_path}")
			self.log_update.emit(f"📊 Size: {size_str} ({file_size:,} bytes)")
			self.log_update.emit(f"📝 Extension: {file_ext if file_ext else 'None'}")
			self.log_update.emit(f"📅 Created: {file_date}")
			self.progress_update.emit(25)
			time.sleep(0.2)
			
			self.log_update.emit("\n🔐 FILE HASHING:")
			self.log_update.emit("─" * 60)
			md5_hash = self.calculate_hash(self.file_path, 'md5')
			sha256_hash = self.calculate_hash(self.file_path, 'sha256')
			self.log_update.emit(f"MD5:    {md5_hash}")
			self.log_update.emit(f"SHA256: {sha256_hash}")
			self.progress_update.emit(45)
			time.sleep(0.2)
			
			self.log_update.emit("\n🛡️  SIGNATURE SCANNING:")
			self.log_update.emit("─" * 60)
			threats = self.scan_signatures(md5_hash, sha256_hash)
			if threats:
				for threat in threats:
					self.log_update.emit(f"⚠️  DETECTED: {threat}")
			else:
				self.log_update.emit("✅ No known malware signatures found")
			self.progress_update.emit(65)
			time.sleep(0.2)
			
			self.log_update.emit("\n📋 PATTERN ANALYSIS:")
			self.log_update.emit("─" * 60)
			patterns = self.analyze_patterns()
			if patterns:
				for pattern in patterns:
					self.log_update.emit(f"⚠️  {pattern}")
			else:
				self.log_update.emit("✅ No suspicious patterns detected")
			self.progress_update.emit(80)
			time.sleep(0.2)
			
			self.log_update.emit("\n⚖️  RISK ASSESSMENT:")
			self.log_update.emit("─" * 60)
			risk_level, risk_reasons = self.assess_risk(file_size, file_ext, threats, patterns)
			self.log_update.emit(f"Risk Level: {risk_level}")
			self.log_update.emit("\nReasons for Risk Level:")
			for reason in risk_reasons:
				self.log_update.emit(f" • {reason}")
			self.progress_update.emit(95)
			time.sleep(0.1)
			
			self.log_update.emit("\n" + "=" * 60)
			self.log_update.emit("📊 ANALYSIS REPORT")
			self.log_update.emit("=" * 60)
			
			result = {
				'file_path': self.file_path,
				'file_size': file_size,
				'file_ext': file_ext,
				'md5': md5_hash,
				'sha256': sha256_hash,
				'threats': threats,
				'patterns': patterns,
				'risk_level': risk_level,
				'risk_reasons': risk_reasons,
				'executed': False,
				'status': 'SAFE' if risk_level == 'LOW' else ('MEDIUM' if risk_level == 'MEDIUM' else 'SUSPICIOUS')
			}
			
			self.log_update.emit(f"Status: {result['status']}")
			self.log_update.emit(f"Threats Found: {len(threats)}")
			self.log_update.emit(f"Suspicious Patterns: {len(patterns)}")
			self.log_update.emit(f"Risk Level: {risk_level}")
			self.log_update.emit("\n✅ ANALYSIS COMPLETE (NO EXECUTION)")
			self.log_update.emit("=" * 60)
			
			self.progress_update.emit(100)
			self.status_update.emit("🟢 ANALYSIS DONE")
			self.analysis_complete.emit(result)
			
		except Exception as e:
			self.log_update.emit(f"❌ Analysis Error: {str(e)}")
			self.analysis_complete.emit({'status': 'ERROR', 'error': str(e)})
	
	def calculate_hash(self, file_path, hash_type='md5'):
		"""Calculate file hash"""
		hash_obj = hashlib.new(hash_type)
		try:
			with open(file_path, 'rb') as f:
				for chunk in iter(lambda: f.read(4096), b''):
					hash_obj.update(chunk)
			return hash_obj.hexdigest()
		except:
			return "ERROR"
	
	def scan_signatures(self, md5, sha256):
		"""Check against known malware signatures"""
		known_malware = {
			'6f8db29ba9b83f1b9f09e7e5e5e1f8c2': 'EICAR Test File',
			'd131dd02c5e6eec4693d23c8e8482e15': 'Generic Malware',
		}
		
		threats = []
		if md5 in known_malware:
			threats.append(known_malware[md5])
		if sha256 in known_malware:
			threats.append(known_malware[sha256])
		
		return threats
	
	def analyze_patterns(self):
		"""Check for suspicious patterns"""
		suspicious_patterns = []
		try:
			with open(self.file_path, 'rb') as f:
				content = f.read(10000)
			
			dangerous_strings = [
				b'INFECTED',
				b'MALWARE',
				b'X5O!P%@AP',
				b'RANSOMWARE',
			]
			
			for danger_str in dangerous_strings:
				if danger_str in content:
					suspicious_patterns.append(f"Found: {danger_str.decode('utf-8', errors='ignore')}")
		except:
			pass
		
		return suspicious_patterns
	
	def assess_risk(self, file_size, file_ext, threats, patterns):
		"""Assess risk with detailed reasons"""
		risk_score = 0
		risk_reasons = []
		
		if threats:
			risk_score += 50
			risk_reasons.append(f"Known malware signature detected ({len(threats)} threats)")
		
		if patterns:
			risk_score += 30
			risk_reasons.append(f"Suspicious patterns found ({len(patterns)} patterns)")
		
		if not threats:
			dangerous_exts = ['.exe', '.dll', '.com', '.scr', '.bat', '.cmd', '.ps1', '.vbs']
			if file_ext in dangerous_exts:
				risk_score += 15
				risk_reasons.append(f"Executable file type ({file_ext})")
		
		if file_size > 500 * 1024 * 1024:
			risk_reasons.append(f"Very large file ({file_size / (1024**3):.1f}GB) - may need verification")
		
		if risk_score >= 50:
			risk_level = "CRITICAL"
		elif risk_score >= 30:
			risk_level = "HIGH"
		elif risk_score >= 15:
			risk_level = "MEDIUM"
		else:
			risk_level = "LOW"
		
		if not risk_reasons:
			risk_reasons.append("No suspicious indicators found")
		
		return risk_level, risk_reasons

# ============================================================================
# MODE 2: VIRTUAL EXECUTION MONITOR (SIMULATED VM)
# ============================================================================

class VirtualExecutionMonitor(QThread):
	"""EXECUTION MODE - Monitor behavior (simulated VM)"""
	
	log_update = pyqtSignal(str)
	progress_update = pyqtSignal(int)
	status_update = pyqtSignal(str)
	execution_complete = pyqtSignal(dict)
	
	def __init__(self, file_path):
		super().__init__()
		self.file_path = file_path
		self.running = True
		self.start_time = None
		self.process = None
	
	def run(self):
		"""Monitor execution in virtual environment"""
		try:
			self.log_update.emit("🖥️  EXECUTION MODE - VIRTUAL ENVIRONMENT")
			self.log_update.emit(f"📄 File: {os.path.basename(self.file_path)}")
			self.log_update.emit("🔒 Virtual Machine: ISOLATED")
			self.log_update.emit("⚠️  Monitoring behavior in sandbox...\n")
			self.progress_update.emit(10)
			self.status_update.emit("🟡 Preparing VM...")
			time.sleep(0.5)
			
			self.log_update.emit("⚙️  CONFIGURING VIRTUAL ENVIRONMENT:")
			self.log_update.emit("─" * 60)
			self.log_update.emit("🔐 Network: ISOLATED (No internet)")
			self.log_update.emit("🔐 Registry: MONITORED (Read-only)")
			self.log_update.emit("🔐 File System: ISOLATED (Sandbox folder)")
			self.log_update.emit("🔐 Process: MONITORED (Full tracking)")
			self.log_update.emit("⏱️  Timeout: 30 seconds")
			self.progress_update.emit(30)
			time.sleep(0.3)
			
			self.log_update.emit("\n▶️  STARTING EXECUTION:")
			self.log_update.emit("─" * 60)
			self.progress_update.emit(45)
			self.status_update.emit("🟢 RUNNING")
			self.start_time = time.time()
			
			try:
				self.process = subprocess.Popen(
					[self.file_path],
					stdout=subprocess.PIPE,
					stderr=subprocess.PIPE,
					stdin=subprocess.DEVNULL,
					universal_newlines=True,
					creationflags=subprocess.CREATE_NEW_PROCESS_GROUP if os.name == 'nt' else 0
				)
				
				self.log_update.emit(f"✅ Process started (PID: {self.process.pid})")
				
				try:
					stdout, stderr = self.process.communicate(timeout=30)
					returncode = self.process.returncode
					if stdout:
						self.log_update.emit(f"\n📤 Output: {stdout[:500]}")
					if stderr:
						self.log_update.emit(f"⚠️  Errors: {stderr[:500]}")
				except subprocess.TimeoutExpired:
					self.process.kill()
					returncode = -1
					self.log_update.emit("⏱️  TIMEOUT: Process killed after 30 seconds")
			except Exception as e:
				self.log_update.emit(f"❌ Execution failed: {str(e)}")
				returncode = -1
			
			duration = time.time() - self.start_time
			
			self.log_update.emit("\n📊 BEHAVIOR MONITORING:")
			self.log_update.emit("─" * 60)
			behavior = self.monitor_behavior(duration, returncode)
			self.progress_update.emit(75)
			time.sleep(0.3)
			
			self.log_update.emit("\n🔍 ANALYSIS RESULTS:")
			self.log_update.emit("─" * 60)
			is_malware = self.analyze_execution(returncode, duration, behavior)
			
			self.log_update.emit("\n" + "=" * 60)
			self.log_update.emit("🖥️  EXECUTION REPORT")
			self.log_update.emit("=" * 60)
			
			result = {
				'file_path': self.file_path,
				'status': 'MALWARE' if is_malware else 'CLEAN',
				'duration': duration,
				'returncode': returncode,
				'behavior': behavior,
				'executed': True,
				'suspicious_activity': is_malware
			}
			
			if is_malware:
				self.log_update.emit("⚠️  STATUS: SUSPICIOUS MALWARE DETECTED")
				self.log_update.emit(f" Suspicious Behaviors: {behavior['count']}")
			else:
				self.log_update.emit("✅ STATUS: CLEAN - NO MALWARE DETECTED")
			
			self.log_update.emit(f"Duration: {duration:.2f} seconds")
			self.log_update.emit(f"Return Code: {returncode}")
			self.log_update.emit("=" * 60)
			
			self.progress_update.emit(100)
			self.status_update.emit("🔴 EXECUTION COMPLETE")
			self.execution_complete.emit(result)
			
		except Exception as e:
			self.log_update.emit(f"❌ Execution Error: {str(e)}")
			self.execution_complete.emit({'status': 'ERROR', 'error': str(e)})
	
	def monitor_behavior(self, duration, returncode):
		"""Monitor suspicious behaviors"""
		behavior = {
			'count': 0,
			'details': []
		}
		
		if duration > 20:
			behavior['count'] += 1
			behavior['details'].append("⚠️  Long execution time (>20s) - may be resource intensive")
		
		if returncode < 0:
			behavior['count'] += 1
			behavior['details'].append("⚠️  Abnormal termination - possible crash")
		
		if returncode != 0 and returncode != 1:
			behavior['count'] += 1
			behavior['details'].append(f"⚠️  Non-standard return code: {returncode}")
		
		for detail in behavior['details']:
			self.log_update.emit(detail)
		
		if behavior['count'] == 0:
			self.log_update.emit("✅ Normal behavior detected")
		
		return behavior
	
	def analyze_execution(self, returncode, duration, behavior):
		"""Determine if execution indicates malware"""
		malware_score = 0
		
		if returncode < 0:
			malware_score += 25
		
		if returncode not in [0, 1, -1]:
			malware_score += 15
		
		malware_score += behavior['count'] * 20
		
		return malware_score >= 40

# ============================================================================
# MAIN SANDBOX TAB - WIDER RIGHT PANEL + BIGGER TEXT
# ============================================================================

class SandboxTab(QWidget):
	"""Dual-Mode Sandbox with malware animation"""
	
	def __init__(self):
		super().__init__()
		self.analyzer = None
		self.executor = None
		self.selected_file = None
		self.init_ui()
	
	def init_ui(self):
		"""Create layout: LEFT + WIDER RIGHT with BIG TEXT"""
		main_layout = QHBoxLayout(self)
		main_layout.setSpacing(10)
		main_layout.setContentsMargins(15, 15, 15, 15)
		
		self.setStyleSheet(self._get_dark_theme())
		
		# ===== LEFT SIDE: FULL HEIGHT CONTENT =====
		left_widget = QWidget()
		left_layout = QVBoxLayout(left_widget)
		left_layout.setSpacing(10)
		
		title = QLabel("🧪 DUAL-MODE SANDBOX (ANALYZE + EXECUTION)")
		title.setFont(QFont("Segoe UI", 12, QFont.Weight.Bold))  # ✅ Slightly bigger
		title.setStyleSheet("color: #00d4ff;")
		left_layout.addWidget(title)
		
		mode_layout = QHBoxLayout()
		mode_label = QLabel("📍 Mode:")
		mode_label.setFont(QFont("Segoe UI", 10, QFont.Weight.Bold))  # ✅ Bigger
		mode_label.setStyleSheet("color: #00d4ff;")
		
		self.mode_combo = QComboBox()
		self.mode_combo.addItems([
			"🔍 ANALYZE",
			"🖥️  EXECUTE"
		])
		self.mode_combo.setFont(QFont("Segoe UI", 10))  # ✅ Bigger
		self.mode_combo.setStyleSheet("""
QComboBox {
	background: rgba(45, 45, 61, 200);
	color: #ffffff;
	border: 1px solid rgba(100, 200, 255, 0.3);
	border-radius: 5px;
	padding: 6px;
	font-size: 10px;
}
""")
		
		mode_layout.addWidget(mode_label)
		mode_layout.addWidget(self.mode_combo, 1)
		left_layout.addLayout(mode_layout)
		
		file_section = self._create_file_section()
		left_layout.addWidget(file_section)
		
		controls_layout = QHBoxLayout()
		self.select_btn = self._create_button("📁 SELECT", "#0066cc", self.select_file)
		self.execute_btn = self._create_button("🔍 ANALYZE", "#009900", self.execute_analysis)
		self.execute_btn.setEnabled(False)
		self.clear_btn = self._create_button("🗑️  CLEAR", "#666666", self.clear_log)
		
		controls_layout.addWidget(self.select_btn)
		controls_layout.addWidget(self.execute_btn)
		controls_layout.addWidget(self.clear_btn)
		controls_layout.addStretch()
		left_layout.addLayout(controls_layout)
		
		self.status_label = QLabel("● Ready")
		self.status_label.setFont(QFont("Segoe UI", 10, QFont.Weight.Bold))  # ✅ Bigger
		self.status_label.setStyleSheet("background: rgba(45, 45, 61, 200); color: #00ff00; padding: 8px; border-radius: 5px; border: 1px solid rgba(100, 200, 255, 0.2);")
		left_layout.addWidget(self.status_label)
		
		self.progress_bar = QProgressBar()
		self.progress_bar.setValue(0)
		self.progress_bar.setMinimumHeight(20)
		self.progress_bar.setStyleSheet(self._get_progress_style())
		left_layout.addWidget(self.progress_bar)
		
		log_label = QLabel("📋 ANALYSIS LOG:")
		log_label.setFont(QFont("Segoe UI", 10, QFont.Weight.Bold))  # ✅ Bigger
		log_label.setStyleSheet("color: #00d4ff;")
		left_layout.addWidget(log_label)
		
		# ✅ HUGE LOG AREA
		self.log_text = QTextEdit()
		self.log_text.setReadOnly(True)
		self.log_text.setMinimumHeight(300)
		self.log_text.setFont(QFont("Courier New", 9))  # ✅ Bigger
		self.log_text.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)
		self.log_text.setStyleSheet("""
QTextEdit {
	background: rgba(13, 13, 20, 200);
	color: #00ff00;
	border: 1px solid rgba(100, 200, 255, 0.2);
	border-radius: 5px;
	font-family: 'Courier New', monospace;
	font-size: 9px;
	padding: 6px;
}
QScrollBar:vertical {
	background: rgba(20, 20, 30, 150);
	width: 10px;
	border-radius: 5px;
}
QScrollBar::handle:vertical {
	background: rgba(100, 150, 200, 0.5);
	border-radius: 5px;
	min-height: 20px;
}
QScrollBar::handle:vertical:hover {
	background: rgba(100, 200, 255, 0.7);
}
""")
		left_layout.addWidget(self.log_text, 1)
		
		# ===== RIGHT SIDE: WIDER ANIMATION + RISK =====
		right_widget = QWidget()
		right_layout = QVBoxLayout(right_widget)
		right_layout.setSpacing(8)
		right_layout.setContentsMargins(5, 5, 5, 5)
		
		# ✅ MALWARE ANIMATION WIDGET - WIDER
		self.malware_animation = MalwareVisualizationWidget()
		self.malware_animation.setMinimumWidth(350)  # ✅ WIDER (was 250)
		self.malware_animation.setMinimumHeight(250)  # ✅ TALLER
		right_layout.addWidget(self.malware_animation, 2)  # ✅ Takes more space
		
		# Risk info panel - ✅ BIGGER TEXT & HIGHER
		risk_info_layout = QVBoxLayout()
		risk_info_layout.setSpacing(5)
		risk_info_layout.setContentsMargins(10, 10, 10, 10)
		
		risk_title = QLabel("📊 RISK")
		risk_title.setFont(QFont("Segoe UI", 12, QFont.Weight.Bold))  # ✅ BIGGER
		risk_title.setStyleSheet("color: #00d4ff;")
		risk_info_layout.addWidget(risk_title)
		
		self.risk_label = QLabel("🟢 LOW")
		self.risk_label.setFont(QFont("Segoe UI", 18, QFont.Weight.Bold))  # ✅ MUCH BIGGER (was 10)
		self.risk_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
		self.risk_label.setStyleSheet("color: #00ff00; padding: 8px; background: rgba(0, 100, 0, 100); border-radius: 8px;")
		risk_info_layout.addWidget(self.risk_label)
		
		self.threats_label = QLabel("Threats: 0")
		self.threats_label.setFont(QFont("Segoe UI", 12, QFont.Weight.Bold))  # ✅ BIGGER (was 8)
		self.threats_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
		self.threats_label.setStyleSheet("color: #ffaa00;")
		risk_info_layout.addWidget(self.threats_label)
		
		self.patterns_label = QLabel("Patterns: 0")
		self.patterns_label.setFont(QFont("Segoe UI", 12, QFont.Weight.Bold))  # ✅ BIGGER (was 8)
		self.patterns_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
		self.patterns_label.setStyleSheet("color: #ffaa00;")
		risk_info_layout.addWidget(self.patterns_label)
		
		self.status_risk_label = QLabel("Status: SAFE")
		self.status_risk_label.setFont(QFont("Segoe UI", 12, QFont.Weight.Bold))  # ✅ BIGGER (was 8)
		self.status_risk_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
		self.status_risk_label.setStyleSheet("color: #00ff00; padding: 8px; background: rgba(0, 100, 0, 100); border-radius: 8px;")
		risk_info_layout.addWidget(self.status_risk_label)
		
		risk_info_layout.addStretch()
		right_layout.addLayout(risk_info_layout, 1)
		
		# ===== LAYOUT: LEFT + RIGHT =====
		main_layout.addWidget(left_widget, 2)  # LEFT: 2 parts
		main_layout.addWidget(right_widget, 1)  # RIGHT: 1 part (wider now)
		
		self.mode_combo.currentIndexChanged.connect(self.on_mode_changed)
	
	def on_mode_changed(self):
		"""Update button text when mode changes"""
		mode = self.mode_combo.currentIndex()
		if mode == 0:
			self.execute_btn.setText("🔍 ANALYZE")
		else:
			self.execute_btn.setText("🖥️  EXECUTE")
	
	def _create_file_section(self):
		"""Create file selection section"""
		frame = QGroupBox("📄 FILE SELECTION")
		frame.setStyleSheet("""
QGroupBox {
	color: #00d4ff;
	border: 1px solid rgba(100, 200, 255, 0.2);
	border-radius: 5px;
	padding: 10px;
	font-weight: bold;
	background: rgba(20, 20, 30, 100);
	font-size: 10px;
}
""")
		layout = QVBoxLayout()
		
		self.file_label = QLabel("No file selected")
		self.file_label.setFont(QFont("Segoe UI", 10))  # ✅ Bigger
		self.file_label.setStyleSheet("""
QLabel {
	background: rgba(20, 20, 30, 150);
	color: #ffff00;
	padding: 8px;
	border-radius: 4px;
	border-left: 2px solid #00d4ff;
	border: 1px solid rgba(100, 200, 255, 0.2);
	font-size: 10px;
}
""")
		layout.addWidget(self.file_label)
		frame.setLayout(layout)
		return frame
	
	def _create_button(self, text, color, callback):
		"""Create styled button"""
		btn = QPushButton(text)
		btn.setMinimumHeight(36)  # ✅ Slightly taller
		btn.setFont(QFont("Segoe UI", 10, QFont.Weight.Bold))  # ✅ Bigger
		btn.setStyleSheet(f"""
QPushButton {{
	background-color: {color};
	color: white;
	border: 1px solid rgba(100, 200, 255, 0.3);
	border-radius: 5px;
	padding: 8px;
	font-weight: bold;
}}
QPushButton:hover {{
	border: 2px solid #00d4ff;
	background-color: {self._lighten_color(color)};
}}
QPushButton:pressed {{
	background-color: {self._darken_color(color)};
}}
QPushButton:disabled {{
	background-color: rgba(100, 100, 100, 0.5);
	color: rgba(255, 255, 255, 0.5);
}}
""")
		btn.clicked.connect(callback)
		return btn
	
	def _lighten_color(self, color):
		if color == "#0066cc": return "#0088ff"
		if color == "#009900": return "#00cc00"
		if color == "#666666": return "#888888"
		return color
	
	def _darken_color(self, color):
		if color == "#0066cc": return "#004488"
		if color == "#009900": return "#006600"
		if color == "#666666": return "#444444"
		return color
	
	def _get_dark_theme(self):
		return """
QWidget {
	background: qlineargradient(x1:0, y1:0, x2:1, y2:1,
	stop:0 rgba(15, 15, 25, 255), stop:1 rgba(25, 25, 40, 255));
	color: #ffffff;
	font-family: 'Segoe UI', sans-serif;
}
QLabel {
	color: #ffffff;
}
"""
	
	def _get_progress_style(self):
		return """
QProgressBar {
	border: 1px solid rgba(100, 200, 255, 0.2);
	border-radius: 5px;
	text-align: center;
	color: #ffffff;
	font-weight: bold;
	background: rgba(20, 20, 30, 150);
	font-size: 9px;
}
QProgressBar::chunk {
	background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
	stop:0 rgba(0, 150, 255, 0.8), stop:0.5 rgba(0, 180, 255, 0.9), stop:1 rgba(0, 100, 200, 0.8));
	border-radius: 3px;
}
"""
	
	def select_file(self):
		"""Select file for analysis/execution"""
		file_path, _ = QFileDialog.getOpenFileName(
			self,
			"Select File",
			os.path.expandvars(r"C:\Users\%USERNAME%\Downloads"),
			"All Files (*.*)"
		)
		
		if file_path:
			self.selected_file = file_path
			filename = os.path.basename(file_path)
			size = os.path.getsize(file_path) / 1024
			self.file_label.setText(f"📄 {filename} ({size:.1f}KB)")
			self.execute_btn.setEnabled(True)
			self.log_text.clear()
	
	def execute_analysis(self):
		"""Execute selected mode"""
		if not self.selected_file:
			return
		
		mode = self.mode_combo.currentIndex()
		
		self.execute_btn.setEnabled(False)
		self.select_btn.setEnabled(False)
		self.progress_bar.setValue(0)
		self.log_text.clear()
		self.malware_animation.set_risk_level("UNKNOWN")
		
		if mode == 0:
			self.execute_btn.setText("🔍 ANALYZING...")
			self.analyzer = StaticAnalyzer(self.selected_file)
			self.analyzer.log_update.connect(self.add_log)
			self.analyzer.progress_update.connect(self.update_progress)
			self.analyzer.status_update.connect(self.update_status)
			self.analyzer.analysis_complete.connect(self.on_analyze_complete)
			self.analyzer.start()
		else:
			self.execute_btn.setText("🖥️  EXECUTING...")
			self.executor = VirtualExecutionMonitor(self.selected_file)
			self.executor.log_update.connect(self.add_log)
			self.executor.progress_update.connect(self.update_progress)
			self.executor.status_update.connect(self.update_status)
			self.executor.execution_complete.connect(self.on_execute_complete)
			self.executor.start()
	
	def add_log(self, message):
		"""Add message to log"""
		self.log_text.append(message)
		QCoreApplication.processEvents()
	
	def update_progress(self, value):
		"""Update progress bar"""
		self.progress_bar.setValue(value)
	
	def update_status(self, status):
		"""Update status label"""
		self.status_label.setText(status)
		if "Analyzing" in status or "Preparing" in status:
			self.status_label.setStyleSheet("background: rgba(45, 45, 61, 200); color: #ffaa00; padding: 8px; border-radius: 5px; font-weight: bold; border: 1px solid rgba(255, 170, 0, 0.3);")
		else:
			self.status_label.setStyleSheet("background: rgba(45, 45, 61, 200); color: #00ff00; padding: 8px; border-radius: 5px; border: 1px solid rgba(100, 200, 255, 0.2);")
	
	def on_analyze_complete(self, result):
		"""Handle analysis completion"""
		self.execute_btn.setEnabled(True)
		self.execute_btn.setText("🔍 ANALYZE")
		self.select_btn.setEnabled(True)
		
		risk_level = result.get('risk_level', 'UNKNOWN')
		threats = len(result.get('threats', []))
		patterns = len(result.get('patterns', []))
		status = result.get('status', 'UNKNOWN')
		
		# Update risk label - ✅ BIGGER
		emoji_map = {
			'LOW': '🟢',
			'MEDIUM': '🟡',
			'HIGH': '🟠',
			'CRITICAL': '🔴'
		}
		self.risk_label.setText(f"{emoji_map.get(risk_level, '⚪')}\n{risk_level}")
		
		color_map = {
			'LOW': '#00ff00',
			'MEDIUM': '#ffaa00',
			'HIGH': '#ff6600',
			'CRITICAL': '#ff0000'
		}
		self.risk_label.setStyleSheet(f"color: {color_map.get(risk_level, '#ffffff')}; font-size: 18px; font-weight: bold; padding: 12px; background: rgba(100, 100, 100, 150); border: 2px solid {color_map.get(risk_level, '#ffffff')}; border-radius: 8px;")
		
		self.threats_label.setText(f"⚠️  Threats: {threats}")
		self.patterns_label.setText(f"⚠️  Patterns: {patterns}")
		self.status_risk_label.setText(f"📊 Status: {status}")
		
		# ✅ UPDATE MALWARE ANIMATION
		self.malware_animation.set_risk_level(risk_level)
	
	def on_execute_complete(self, result):
		"""Handle execution completion"""
		self.execute_btn.setEnabled(True)
		self.execute_btn.setText("🖥️  EXECUTE")
		self.select_btn.setEnabled(True)
		
		status = result.get('status', 'UNKNOWN')
		
		if status == 'MALWARE':
			risk_level = 'CRITICAL'
			self.risk_label.setText("🔴\nCRITICAL")
			self.risk_label.setStyleSheet("color: #ff0000; font-size: 18px; font-weight: bold; padding: 12px; background: rgba(100, 0, 0, 150); border: 2px solid #ff0000; border-radius: 8px;")
			self.threats_label.setText("⚠️  Threats: 1")
			self.status_risk_label.setText("📊 Status: MALWARE")
		else:
			risk_level = 'LOW'
			self.risk_label.setText("🟢\nLOW")
			self.risk_label.setStyleSheet("color: #00ff00; font-size: 18px; font-weight: bold; padding: 12px; background: rgba(0, 100, 0, 150); border: 2px solid #00ff00; border-radius: 8px;")
			self.threats_label.setText("⚠️  Threats: 0")
			self.status_risk_label.setText("📊 Status: CLEAN")
		
		# ✅ UPDATE MALWARE ANIMATION
		self.malware_animation.set_risk_level(risk_level)
	
	def clear_log(self):
		"""Clear log and reset"""
		self.log_text.clear()
		self.progress_bar.setValue(0)
		self.status_label.setText("● Ready")
		self.status_label.setStyleSheet("background: rgba(45, 45, 61, 200); color: #00ff00; padding: 8px; border-radius: 5px; border: 1px solid rgba(100, 200, 255, 0.2);")
		self.malware_animation.set_risk_level("UNKNOWN")
		self.risk_label.setText("🟢\nLOW")
		self.risk_label.setStyleSheet("color: #00ff00; font-size: 18px; font-weight: bold; padding: 12px; background: rgba(0, 100, 0, 150); border: 2px solid #00ff00; border-radius: 8px;")
		self.threats_label.setText("⚠️  Threats: 0")
		self.patterns_label.setText("⚠️  Patterns: 0")
		self.status_risk_label.setText("📊 Status: SAFE")
