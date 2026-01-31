@echo off
REM Cleanup script for test_files folder
echo.
echo Cleaning up _Scrubbed files and new_detections.csv...
echo.

cd /d "E:\CLAUDE_Workspace\Claude\Report_Files\Projects\Document_Scrubber\batch_branch\test_files"

del /q "*_Scrubbed*.txt" 2>nul
del /q "new_detections.csv" 2>nul

echo Done! Remaining files:
dir /b *.txt *.md *.csv 2>nul

echo.
pause
