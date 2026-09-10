@echo off
title Chain-Mind Auditor - Web Operations Center
cd /d "%~dp0"
echo Starting Chain-Mind Auditor Web Operations Center...
.\.venv\Scripts\python.exe main.py web
pause
