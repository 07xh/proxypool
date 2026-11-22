@echo off
setlocal
cd /d "%~dp0"
where py >nul 2>&1
if errorlevel 1 (
  echo [ERROR] Install Python 3.11+ with the Python Launcher first.
  pause
  exit /b 1
)
py -m pip install --upgrade pyinstaller
if errorlevel 1 exit /b 1
py -m PyInstaller --noconfirm --clean --onefile --windowed --name ProxyPoolManager --add-data "pool.json;." manager_gui.py
if errorlevel 1 (
  echo [ERROR] Windows build failed.
  pause
  exit /b 1
)
echo [OK] dist\ProxyPoolManager.exe
pause
