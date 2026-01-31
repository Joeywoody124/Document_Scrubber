@echo off
REM ============================================================================
REM Document Scrubber - Batch Launcher
REM Drag and drop files onto this .bat or run from command line
REM Author: Joey M. Woody P.E.
REM Version: 1.0.0
REM ============================================================================

setlocal enabledelayedexpansion

REM Get the directory where this script lives
set "SCRIPT_DIR=%~dp0"

REM Check if a file was passed as argument
if "%~1"=="" (
    echo.
    echo ========================================
    echo   Document Scrubber - Fast Mode
    echo ========================================
    echo.
    echo Usage: Drag and drop a text file onto this .bat
    echo        OR run from command line:
    echo.
    echo   scrub_batch.bat "path\to\document.txt"
    echo   scrub_batch.bat "path\to\document.txt" -LogNew
    echo.
    echo Options:
    echo   -LogNew    Export new detections to CSV for review
    echo.
    pause
    exit /b 0
)

REM Check if PowerShell is available
where powershell >nul 2>&1
if %errorlevel% neq 0 (
    echo ERROR: PowerShell is required but not found in PATH
    pause
    exit /b 1
)

REM Build the PowerShell command
set "PS_SCRIPT=%SCRIPT_DIR%scrub_core.ps1"
set "INPUT_FILE=%~1"

REM Check for -LogNew flag
set "LOG_FLAG="
if /i "%~2"=="-LogNew" set "LOG_FLAG=-LogNew"
if /i "%~2"=="-lognew" set "LOG_FLAG=-LogNew"

echo.
echo Starting Document Scrubber...
echo.

REM Run PowerShell with execution policy bypass for this script
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%PS_SCRIPT%" -InputFile "%INPUT_FILE%" %LOG_FLAG%

if %errorlevel% neq 0 (
    echo.
    echo Scrubbing encountered an error.
    pause
    exit /b 1
)

echo.
echo Press any key to close...
pause >nul
exit /b 0
