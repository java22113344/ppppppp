@echo off
REM Malware Defender v5 Project Structure Creator
REM Run this in your desired project directory

echo Creating Malware Defender v5 directory structure...

REM Root level files
type nul > main.py
type nul > requirements.txt
type nul > README.md
type nul > config.py
type nul > .env

REM GUI folder structure
mkdir gui\tabs
type nul > gui\__init__.py
type nul > gui\main_window.py
type nul > gui\styles.py
type nul > gui\tabs\__init__.py
type nul > gui\tabs\scan_tab.py
type nul > gui\tabs\sandbox_tab.py
type nul > gui\tabs\password_tab.py
type nul > gui\tabs\vpn_tab.py
type nul > gui\tabs\history_tab.py
type nul > gui\tabs\analytics_tab.py
type nul > gui\tabs\hardware_tab.py
type nul > gui\tabs\protection_tab.py
type nul > gui\tabs\parental_tab.py
type nul > gui\tabs\settings_tab.py
type nul > gui\tabs\about_tab.py

REM Core folder structure
mkdir core
type nul > core\__init__.py
type nul > core\scanner.py
type nul > core\file_analyzer.py
type nul > core\signature_engine.py
type nul > core\behavior_monitor.py
type nul > core\registry_monitor.py
type nul > core\memory_analyzer.py
type nul > core\threat_database.py

REM Security folder structure
mkdir security
type nul > security\__init__.py
type nul > security\password_manager.py
type nul > security\encryption.py
type nul > security\vpn_manager.py
type nul > security\firewall.py
type nul > security\usb_controller.py
type nul > security\bluetooth_manager.py

REM Network folder structure
mkdir network
type nul > network\__init__.py
type nul > network\packet_inspector.py
type nul > network\dns_blocker.py
type nul > network\url_scanner.py
type nul > network\connection_monitor.py

REM Detection folder structure
mkdir detection
type nul > detection\__init__.py
type nul > detection\ransomware_detector.py
type nul > detection\rootkit_detector.py
type nul > detection\keylogger_detector.py
type nul > detection\trojan_detector.py
type nul > detection\worm_detector.py

REM Analytics folder structure
mkdir analytics
type nul > analytics\__init__.py
type nul > analytics\threat_analyzer.py
type nul > analytics\usage_tracker.py
type nul > analytics\report_generator.py
type nul > analytics\dashboard.py

REM Database folder structure
mkdir database
type nul > database\__init__.py
type nul > database\db_manager.py
type nul > database\models.py
type nul > database\migrations.py

REM Signatures folder structure
mkdir signatures\yara_rules
type nul > signatures\hashes.db
type nul > signatures\ioc_database.json
type nul > signatures\yara_rules\malware.yar
type nul > signatures\yara_rules\ransomware.yar
type nul > signatures\yara_rules\trojan.yar
type nul > signatures\yara_rules\rootkit.yar
type nul > signatures\yara_rules\browser_hijacker.yar

REM Resources folder structure
mkdir resources\icons
mkdir resources\images
mkdir resources\sounds
mkdir resources\fonts

REM Tests folder structure
mkdir tests
type nul > tests\test_scanner.py
type nul > tests\test_encryption.py
type nul > tests\test_vpn.py
type nul > tests\test_database.py

REM Docs folder structure
mkdir docs
type nul > docs\API.md
type nul > docs\DEPLOYMENT.md
type nul > docs\USER_GUIDE.md

echo.
echo ✓ Malware Defender v5 structure created successfully!
echo.
pause
