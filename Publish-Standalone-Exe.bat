@echo off
chcp 65001 >nul
title AionToolLite 1.2.3 - Standalone Publisher
cd /d "%~dp0"
echo ==========================================================
echo   Publishing Standalone Single-File AionToolLite 1.2.3...
echo ==========================================================
dotnet publish "AionToolLite\AionToolLite.csproj" -c Release -r win-x64 --self-contained true /p:PublishSingleFile=true /p:PublishReadyToRun=true /p:EnableCompressionInSingleFile=true /p:DebugType=None /p:DebugSymbols=false
if errorlevel 1 (
    echo.
    echo [ERROR] Publish failed.
    pause
    exit /b 1
)
echo.
echo [OK] Standalone AionToolLite.exe created successfully!
explorer "%~dp0AionToolLite\bin\Release\net8.0-windows\win-x64\publish"
pause
