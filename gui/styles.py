# gui/styles.py - Theme Manager & Stylesheet Handler
"""
Theme Manager for Malware Defender v5
Handles all theme switching and CSS styling
"""

class ThemeManager:
    """Central theme management system"""
    
    def __init__(self):
        self.current_theme = "Dark"
        self.available_themes = [
            "Light",
            "Dark",
            "Win11 Dark Blue",
            "Win11 Light",
            "Cyberpunk Dark",
            "Ocean Wave",
            "Forest Green",
            "Sunset Orange"
        ]
    
    def get_theme(self, theme_name):
        """Get theme stylesheet by name"""
        themes = {
            "Light": self.light_theme,
            "Dark": self.dark_theme,
            "Win11 Dark Blue": self.win11_dark,
            "Win11 Light": self.win11_light,
            "Cyberpunk Dark": self.cyberpunk_dark,
            "Ocean Wave": self.ocean_wave,
            "Forest Green": self.forest_green,
            "Sunset Orange": self.sunset_orange
        }
        return themes.get(theme_name, self.dark_theme)
    
    @staticmethod
    def light_theme():
        """Light professional theme"""
        return """
        QMainWindow {
            background: qlineargradient(x1:0, y1:0, x2:1, y2:1, 
                       stop:0 #f8f9fa, stop:1 #e9ecef);
        }
        QWidget { color: #212529; background: transparent; }
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
        QTabBar::tab:hover { background: #dee2e6; }
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
        QPushButton:pressed { background: #003d82; }
        QLineEdit, QTextEdit { 
            background: white; 
            border: 1px solid #dee2e6; 
            border-radius: 4px; 
            padding: 8px; 
            color: #212529; 
        }
        QLineEdit:focus, QTextEdit:focus { border: 2px solid #007bff; }
        QComboBox { 
            background: white; 
            border: 1px solid #dee2e6; 
            border-radius: 4px; 
            padding: 8px; 
            color: #212529; 
        }
        QComboBox:focus { border: 2px solid #007bff; }
        QStatusBar { 
            background: #f8f9fa; 
            border-top: 1px solid #dee2e6; 
        }
        QLabel { color: #495057; }
        """
    
    @staticmethod
    def dark_theme():
        """Modern dark theme"""
        return """
        QMainWindow {
            background: qlineargradient(x1:0, y1:0, x2:1, y2:1, 
                       stop:0 #1a1a1a, stop:1 #2d2d30);
        }
        QWidget { color: #e0e0e0; background: transparent; }
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
        QTabBar::tab:hover { background: #454545; }
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
        QPushButton:pressed { background: #155724; }
        QLineEdit, QTextEdit { 
            background: #3c3c3c; 
            border: 1px solid #555; 
            border-radius: 4px; 
            padding: 8px; 
            color: #e0e0e0; 
        }
        QLineEdit:focus, QTextEdit:focus { border: 2px solid #0078d4; }
        QComboBox { 
            background: #3c3c3c; 
            border: 1px solid #555; 
            border-radius: 4px; 
            padding: 8px; 
            color: #e0e0e0; 
        }
        QComboBox:focus { border: 2px solid #0078d4; }
        QStatusBar { 
            background: #252526; 
            border-top: 1px solid #444; 
        }
        QLabel { color: #e0e0e0; }
        """
    
    @staticmethod
    def win11_dark():
        """Windows 11 Dark official theme"""
        return """
        QMainWindow {
            background: qlineargradient(x1:0, y1:0, x2:1, y2:1, 
                       stop:0 #202020, stop:1 #171717);
        }
        QWidget { color: #e0e0e0; background: transparent; }
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
        QTabBar::tab:hover { background: #3e3e42; }
        QPushButton { 
            background: #0e639c; 
            color: white; 
            border: none; 
            border-radius: 4px; 
            padding: 10px 20px; 
            font-weight: bold; 
            font-size: 11px; 
        }
        QPushButton:hover { background: #1177bb; }
        QPushButton:pressed { background: #0a4668; }
        QLineEdit, QTextEdit { 
            background: #3c3c3c; 
            border: 1px solid #555; 
            border-radius: 4px; 
            padding: 8px; 
            color: #e0e0e0; 
        }
        QLineEdit:focus, QTextEdit:focus { border: 2px solid #0e639c; }
        QComboBox { 
            background: #3c3c3c; 
            border: 1px solid #555; 
            border-radius: 4px; 
            padding: 8px; 
            color: #e0e0e0; 
        }
        QComboBox:focus { border: 2px solid #0e639c; }
        QStatusBar { 
            background: #252526; 
            border-top: 1px solid #3e3e42; 
        }
        """
    
    @staticmethod
    def win11_light():
        """Windows 11 Light official theme"""
        return """
        QMainWindow {
            background: qlineargradient(x1:0, y1:0, x2:1, y2:1, 
                       stop:0 #f3f3f3, stop:1 #e5e5e5);
        }
        QWidget { color: #201f1e; background: transparent; }
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
        QTabBar::tab:hover { background: #e8e7e6; }
        QPushButton { 
            background: #0078d4; 
            color: white; 
            border: none; 
            border-radius: 4px; 
            padding: 10px 20px; 
            font-weight: bold; 
            font-size: 11px; 
        }
        QPushButton:hover { background: #106ebe; }
        QPushButton:pressed { background: #005ba1; }
        QLineEdit, QTextEdit { 
            background: white; 
            border: 1px solid #e1dfdd; 
            border-radius: 4px; 
            padding: 8px; 
            color: #201f1e; 
        }
        QLineEdit:focus, QTextEdit:focus { border: 2px solid #0078d4; }
        QComboBox { 
            background: white; 
            border: 1px solid #e1dfdd; 
            border-radius: 4px; 
            padding: 8px; 
            color: #201f1e; 
        }
        QComboBox:focus { border: 2px solid #0078d4; }
        QStatusBar { 
            background: #f3f3f3; 
            border-top: 1px solid #edebe9; 
        }
        """
    
    @staticmethod
    def cyberpunk_dark():
        """Cyberpunk Dark theme - Neon"""
        return """
        QMainWindow {
            background: qlineargradient(x1:0, y1:0, x2:1, y2:1, 
                       stop:0 #0a0e27, stop:1 #1a0033);
        }
        QWidget { color: #00ff88; background: transparent; }
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
    
    @staticmethod
    def ocean_wave():
        """Ocean Wave theme - Blue & Cyan"""
        return """
        QMainWindow {
            background: qlineargradient(x1:0, y1:0, x2:1, y2:1, 
                       stop:0 #0a2342, stop:1 #1a4d6d);
        }
        QWidget { color: #e0f7ff; background: transparent; }
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
    
    @staticmethod
    def forest_green():
        """Forest Green theme - Natural tones"""
        return """
        QMainWindow {
            background: qlineargradient(x1:0, y1:0, x2:1, y2:1, 
                       stop:0 #1b3d2e, stop:1 #2d5a3d);
        }
        QWidget { color: #d4f1d4; background: transparent; }
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
    
    @staticmethod
    def sunset_orange():
        """Sunset Orange theme - Warm colors"""
        return """
        QMainWindow {
            background: qlineargradient(x1:0, y1:0, x2:1, y2:1, 
                       stop:0 #4d2214, stop:1 #6b3a1f);
        }
        QWidget { color: #ffe6cc; background: transparent; }
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
