@echo off
REM ============================================================================
REM Test Runner - Process all test files in batch
REM Author: Joey M. Woody P.E.
REM Version: 1.0.1 - Fixed loop issue with _Scrubbed files
REM ============================================================================

setlocal enabledelayedexpansion

set "SCRIPT_DIR=%~dp0"
set "TEST_DIR=%SCRIPT_DIR%test_files"

echo.
echo ========================================
echo   Document Scrubber - Test Runner
echo ========================================
echo.
echo Test files directory: %TEST_DIR%
echo.

REM Check if test directory exists
if not exist "%TEST_DIR%" (
    echo ERROR: Test directory not found!
    pause
    exit /b 1
)

REM Clean up old scrubbed files first
echo Cleaning up old output files...
del "%TEST_DIR%\*_Scrubbed*.txt" 2>nul
del "%TEST_DIR%\new_detections.csv" 2>nul
echo.

REM Count test files (exclude any remaining Scrubbed files)
set count=0
for %%f in ("%TEST_DIR%\test_*.txt") do (
    echo %%~nf | findstr /i "Scrubbed" >nul
    if errorlevel 1 (
        set /a count+=1
    )
)

echo Found %count% test files to process.
echo.
echo ----------------------------------------
echo.

REM Process each test file (exclude Scrubbed files)
for %%f in ("%TEST_DIR%\test_*.txt") do (
    echo %%~nf | findstr /i "Scrubbed" >nul
    if errorlevel 1 (
        echo Processing: %%~nxf
        echo.
        
        powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%SCRIPT_DIR%scrub_core.ps1" -InputFile "%%f" -LogNew
        
        echo.
        echo ----------------------------------------
        echo.
    )
)

echo.
echo ========================================
echo   ALL TESTS COMPLETE
echo ========================================
echo.
echo Check the test_files folder for:
echo   - *_Scrubbed.txt files (scrubbed output)
echo   - new_detections.csv (detected items)
echo.
echo Press any key to close...
pause >nul
exit /b 0
