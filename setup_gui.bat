@echo off
REM Malware Defender v5 - GUI Setup Script
REM Installs all dependencies and creates GUI files

echo.
echo ====================================
echo  Malware Defender v5 - GUI Setup
echo ====================================
echo.

REM Check Python version
python --version >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Python not found! Please install Python 3.8+
    pause
    exit /b 1
)

echo [✓] Python detected

REM Create virtual environment (optional)
echo.
echo [?] Create virtual environment? (Y/N)
set /p venv_choice=
if /i "%venv_choice%"=="Y" (
    echo [*] Creating virtual environment...
    python -m venv venv
    call venv\Scripts\activate.bat
    echo [✓] Virtual environment activated
)

REM Install dependencies
echo.
echo [*] Installing dependencies...
pip install PyQt6==6.6.0 --quiet
pip install PyQt6-Charts==6.6.0 --quiet
pip install PyQt6-WebEngine==6.6.0 --quiet

if errorlevel 1 (
    echo [ERROR] Failed to install dependencies
    pause
    exit /b 1
)

echo [✓] Dependencies installed

REM Create gui tabs directory if not exists
if not exist "gui\tabs" (
    echo [*] Creating gui/tabs directory...
    mkdir gui\tabs
    type nul > gui\tabs\__init__.py
    echo [✓] Directory created
)

REM Create __init__.py files
if not exist "gui\__init__.py" (
    type nul > gui\__init__.py
    echo [✓] Created gui/__init__.py
)

echo.
echo ====================================
echo  Installation Complete!
echo ====================================
echo.
echo Next steps:
echo 1. Copy main_window.py to gui/
echo 2. Copy styles.py to gui/
echo 3. Copy tab files to gui/tabs/
echo 4. Run: python gui/main_window.py
echo.
echo Happy coding! 🎉
echo.
pause
