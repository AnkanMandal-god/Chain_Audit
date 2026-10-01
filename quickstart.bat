@echo off
title Chain-Mind Auditor - Quickstart Shortcut
cd /d "%~dp0"
echo Starting Chain-Mind Auditor Quickstart Launcher...
if exist .venv\Scripts\activate.bat (
    call .venv\Scripts\activate.bat
)
python quickstart.py %*
pause
