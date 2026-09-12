@echo off
title Chain-Mind Auditor - Web Operations Center
cd /d "%~dp0"
echo Starting Chain-Mind Auditor Web Operations Center (Replit Build)...
echo Dashboard URL: http://127.0.0.1:5000
if exist .venv\Scripts\python.exe (
    .\.venv\Scripts\python.exe main.py web --port 5000 %*
) else (
    python main.py web --port 5000 %*
)
pause
