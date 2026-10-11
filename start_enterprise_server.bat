@echo off
title PolyShield Enterprise Cyber Defense Platform
cls
echo ============================================================================
echo   [#] POLYSHIELD(TM) ENTERPRISE CYBER DEFENSE PLATFORM
echo       Autonomous Multilingual Threat Intelligence & SOC Triage Gateway
echo       Commercial Enterprise Edition v2.4 (Production Ready)
echo ============================================================================
echo.
echo  Starting PolyShield Gateway Server...
echo  Management Console will be available at: http://localhost:8000
echo  Press Ctrl+C to shut down the server.
echo.

where py >nul 2>nul
if %ERRORLEVEL% equ 0 (
    py run.py
) else (
    where python >nul 2>nul
    if %ERRORLEVEL% equ 0 (
        python run.py
    ) else (
        echo [ERROR] Python 3.10+ was not found in PATH!
        echo Please install Python from https://python.org and add it to your PATH.
        pause
    )
)
pause
