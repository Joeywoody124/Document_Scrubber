@echo off
REM ============================================================================
REM Merge Rules - Batch Launcher
REM Merges new_detections.csv back into master_rules.csv
REM Author: Joey M. Woody P.E.
REM Version: 1.0.0
REM ============================================================================

setlocal enabledelayedexpansion

set "SCRIPT_DIR=%~dp0"

if "%~1"=="" (
    echo.
    echo ========================================
    echo   Merge New Detections
    echo ========================================
    echo.
    echo Usage: Drag and drop new_detections.csv onto this .bat
    echo        OR run from command line:
    echo.
    echo   merge_rules.bat "path\to\new_detections.csv"
    echo.
    pause
    exit /b 0
)

set "PS_SCRIPT=%SCRIPT_DIR%merge_rules.ps1"

powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%PS_SCRIPT%" -NewDetectionsPath "%~1"

pause
exit /b 0
