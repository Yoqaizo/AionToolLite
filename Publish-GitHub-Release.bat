@echo off
chcp 65001 >nul
title AionToolLite - GitHub Release and Version Manager
cd /d "%~dp0"
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0Scripts\Release-Manager.ps1"
if errorlevel 1 (
    echo.
    echo [ERROR] Release process stopped with an error.
)
echo.
pause
