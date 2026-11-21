@echo off
chcp 65001 >nul
title AionToolLite 1.2.3 - Launcher

fltmc >nul 2>&1
if errorlevel 1 (
    echo Requesting Administrator privileges...
    powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
    exit /b
)

cd /d "%~dp0"
echo ==========================================================
echo   Launching AionToolLite 1.2.3...
echo ==========================================================
dotnet run --project "AionToolLite\AionToolLite.csproj" -c Release
if errorlevel 1 (
    echo.
    echo [ERROR] Launch failed.
    pause
)
