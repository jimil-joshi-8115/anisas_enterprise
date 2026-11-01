@echo off
title ANISAS Enterprise Cyber Intelligence Platform
echo =========================================================================
echo               ANISAS Cyber Intelligence Platform Launcher
echo =========================================================================
echo.
cd /d "%~dp0"

echo [1/2] Checking Python dependencies...
python -m pip install -r requirements.txt --quiet --no-warn-script-location

echo [2/2] Starting Local Server on http://localhost:9000 ...
echo.
start "" "http://localhost:9000"
python main.py

pause
