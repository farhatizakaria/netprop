@echo off
setlocal EnableDelayedExpansion

set VENV=.venv
set SCRIPT=netprobe.py
set MIN_PY=38

title NetProbe Setup

echo.
echo  ╔══════════════════════════════════════╗
echo  ║  NetProbe — Network Troubleshooter   ║
echo  ╚══════════════════════════════════════╝
echo.

:: ── Check Python ──────────────────────────────────────────────────────────
python --version >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Python not found in PATH.
    echo         Download Python 3.8+ from https://www.python.org/downloads/
    echo         Make sure to check "Add Python to PATH" during installation.
    pause
    exit /b 1
)

for /f "tokens=2 delims= " %%v in ('python --version 2^>^&1') do set PYVER=%%v
echo  [OK] Python %PYVER% detected.

:: ── Create venv ────────────────────────────────────────────────────────────
if not exist "%VENV%\Scripts\python.exe" (
    echo  [..] Creating virtual environment...
    python -m venv %VENV%
    if errorlevel 1 (
        echo [ERROR] Failed to create venv. Try: pip install virtualenv
        pause
        exit /b 1
    )
    echo  [OK] Virtual environment created.
) else (
    echo  [OK] Virtual environment already exists.
)

:: ── Activate venv ──────────────────────────────────────────────────────────
call %VENV%\Scripts\activate.bat

:: ── Upgrade pip silently ───────────────────────────────────────────────────
echo  [..] Upgrading pip...
python -m pip install --upgrade pip -q

:: ── Install dependencies ───────────────────────────────────────────────────
echo  [..] Installing dependencies...
pip install -r requirements.txt -q
if errorlevel 1 (
    echo [ERROR] Dependency installation failed. Check your internet connection.
    pause
    exit /b 1
)
echo  [OK] Dependencies installed.

:: ── Launch ─────────────────────────────────────────────────────────────────
echo  [OK] Launching NetProbe...
echo.
python %SCRIPT%

:: ── Keep window open on error ─────────────────────────────────────────────
if errorlevel 1 (
    echo.
    echo [ERROR] NetProbe exited with an error (code %errorlevel%).
    pause
)

endlocal
