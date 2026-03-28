@echo off
:: Quick launcher — skips setup, just activates venv and runs
setlocal
set VENV=.venv
set SCRIPT=netprobe.py

if not exist "%VENV%\Scripts\python.exe" (
    echo [!] Virtual environment not found. Run setup.bat first.
    pause
    exit /b 1
)

call %VENV%\Scripts\activate.bat
python %SCRIPT%
endlocal
