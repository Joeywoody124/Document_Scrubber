<#
.SYNOPSIS
    Merge new detections into master_rules.csv

.DESCRIPTION
    After running scrub_core.ps1 with -LogNew, this script merges the
    new_detections.csv back into master_rules.csv, adding any items
    that don't already exist.

.PARAMETER NewDetectionsPath
    Path to new_detections.csv (output from scrub_core.ps1 -LogNew)

.PARAMETER MasterRulesPath
    Path to master_rules.csv. Defaults to parent directory.

.EXAMPLE
    .\merge_rules.ps1 -NewDetectionsPath "C:\docs\new_detections.csv"

.AUTHOR
    Joey M. Woody P.E.

.VERSION
    1.0.0
#>

param(
    [Parameter(Mandatory=$true, Position=0)]
    [string]$NewDetectionsPath,
    
    [Parameter(Mandatory=$false)]
    [string]$MasterRulesPath
)

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$ProjectDir = Split-Path -Parent $ScriptDir

if (-not $MasterRulesPath) {
    $MasterRulesPath = Join-Path $ProjectDir "master_rules.csv"
}

Write-Host ""
Write-Host "======================================" -ForegroundColor Cyan
Write-Host "  Merge New Detections" -ForegroundColor Cyan
Write-Host "======================================" -ForegroundColor Cyan
Write-Host ""

# Validate input
if (-not (Test-Path $NewDetectionsPath)) {
    Write-Host "ERROR: New detections file not found: $NewDetectionsPath" -ForegroundColor Red
    exit 1
}

# Load new detections
$newItems = Import-Csv -Path $NewDetectionsPath -Encoding UTF8
Write-Host "Loaded $($newItems.Count) items from new_detections.csv" -ForegroundColor Cyan

# Load existing master rules (or create empty if doesn't exist)
$existingItems = @()
$existingTexts = @{}

if (Test-Path $MasterRulesPath) {
    $existingItems = @(Import-Csv -Path $MasterRulesPath -Encoding UTF8)
    foreach ($item in $existingItems) {
        $existingTexts[$item.Text] = $true
    }
    Write-Host "Loaded $($existingItems.Count) existing rules from master_rules.csv" -ForegroundColor Cyan
}
else {
    Write-Host "No existing master_rules.csv found - will create new file" -ForegroundColor Yellow
}

# Merge new items
$addedCount = 0
$skippedCount = 0

foreach ($newItem in $newItems) {
    if ($existingTexts.ContainsKey($newItem.Text)) {
        $skippedCount++
        continue
    }
    
    $existingItems += $newItem
    $existingTexts[$newItem.Text] = $true
    $addedCount++
}

# Save merged rules
$existingItems | Export-Csv -Path $MasterRulesPath -NoTypeInformation -Encoding UTF8

Write-Host ""
Write-Host "======================================" -ForegroundColor Green
Write-Host "  MERGE COMPLETE" -ForegroundColor Green
Write-Host "======================================" -ForegroundColor Green
Write-Host ""
Write-Host "  Items added:    $addedCount" -ForegroundColor White
Write-Host "  Items skipped:  $skippedCount (already existed)" -ForegroundColor White
Write-Host "  Total rules:    $($existingItems.Count)" -ForegroundColor White
Write-Host ""

# Optionally delete the new detections file
$response = Read-Host "Delete new_detections.csv? (y/N)"
if ($response -eq "y" -or $response -eq "Y") {
    Remove-Item $NewDetectionsPath -Force
    Write-Host "Deleted: $NewDetectionsPath" -ForegroundColor Yellow
}

exit 0
