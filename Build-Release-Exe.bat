@echo off
chcp 65001 >nul
title AionToolLite 1.2.2 - Builder
cd /d "%~dp0"
echo ==========================================================
echo   Compiling AionToolLite 1.2.2...
echo ==========================================================
dotnet build "AionToolLite\AionToolLite.csproj" -c Release --no-incremental
if errorlevel 1 (
    echo.
    echo [ERROR] Build failed.
    pause
    exit /b 1
)
echo.
echo [OK] Build succeeded!
echo Executable: "%~dp0AionToolLite\bin\Release\net8.0-windows\AionToolLite.exe"
explorer "%~dp0AionToolLite\bin\Release\net8.0-windows"
pause
