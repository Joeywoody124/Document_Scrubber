@echo off
REM ============================================================================
REM Document Scrubber GUI Launcher
REM Author: Joey M. Woody P.E.
REM Version: 1.0.0
REM ============================================================================

set "SCRIPT_DIR=%~dp0"

powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%SCRIPT_DIR%scrub_gui.ps1"
