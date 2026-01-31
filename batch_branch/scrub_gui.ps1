<#
.SYNOPSIS
    Document Scrubber GUI - PowerShell Windows Forms Interface

.DESCRIPTION
    Provides a graphical interface for the Document Scrubber batch tool.
    Features:
    - Browse for files or folders
    - Batch process multiple files
    - Options for logging new detections
    - Real-time output display
    - Support for EXACT, REGEX, WILDCARD rule types

.AUTHOR
    Joey M. Woody P.E.

.VERSION
    1.1.0 - Added REGEX/WILDCARD support
#>

Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

# ============================================================================
# CONFIGURATION
# ============================================================================

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$ProjectDir = Split-Path -Parent $ScriptDir
$RulesPath = Join-Path $ProjectDir "master_rules.csv"
$JsonPath = Join-Path $ProjectDir "master_rules.json"

# ============================================================================
# HELPER FUNCTIONS
# ============================================================================

function Convert-WildcardToRegex {
    param([string]$Wildcard)
    $escaped = [regex]::Escape($Wildcard)
    $regex = $escaped -replace '\\\*', '.*'
    $regex = $regex -replace '\\\?', '.'
    $regex = $regex -replace '\\#', '\d'
    return "^$regex$"
}

# ============================================================================
# MAIN FORM
# ============================================================================

$form = New-Object System.Windows.Forms.Form
$form.Text = "Document Scrubber - Batch Mode v1.1"
$form.Size = New-Object System.Drawing.Size(700, 600)
$form.StartPosition = "CenterScreen"
$form.Font = New-Object System.Drawing.Font("Segoe UI", 9)
$form.BackColor = [System.Drawing.Color]::FromArgb(240, 240, 240)

# ============================================================================
# INPUT SECTION
# ============================================================================

# Input Label
$lblInput = New-Object System.Windows.Forms.Label
$lblInput.Text = "Files to Scrub:"
$lblInput.Location = New-Object System.Drawing.Point(15, 15)
$lblInput.Size = New-Object System.Drawing.Size(100, 20)
$form.Controls.Add($lblInput)

# File List Box
$lstFiles = New-Object System.Windows.Forms.ListBox
$lstFiles.Location = New-Object System.Drawing.Point(15, 40)
$lstFiles.Size = New-Object System.Drawing.Size(550, 100)
$lstFiles.SelectionMode = "MultiExtended"
$lstFiles.HorizontalScrollbar = $true
$form.Controls.Add($lstFiles)

# Add Files Button
$btnAddFiles = New-Object System.Windows.Forms.Button
$btnAddFiles.Text = "Add Files..."
$btnAddFiles.Location = New-Object System.Drawing.Point(575, 40)
$btnAddFiles.Size = New-Object System.Drawing.Size(100, 30)
$form.Controls.Add($btnAddFiles)

# Add Folder Button
$btnAddFolder = New-Object System.Windows.Forms.Button
$btnAddFolder.Text = "Add Folder..."
$btnAddFolder.Location = New-Object System.Drawing.Point(575, 75)
$btnAddFolder.Size = New-Object System.Drawing.Size(100, 30)
$form.Controls.Add($btnAddFolder)

# Clear Button
$btnClear = New-Object System.Windows.Forms.Button
$btnClear.Text = "Clear List"
$btnClear.Location = New-Object System.Drawing.Point(575, 110)
$btnClear.Size = New-Object System.Drawing.Size(100, 30)
$form.Controls.Add($btnClear)

# ============================================================================
# OPTIONS SECTION
# ============================================================================

# Options Group
$grpOptions = New-Object System.Windows.Forms.GroupBox
$grpOptions.Text = "Options"
$grpOptions.Location = New-Object System.Drawing.Point(15, 150)
$grpOptions.Size = New-Object System.Drawing.Size(660, 80)
$form.Controls.Add($grpOptions)

# Log New Detections Checkbox
$chkLogNew = New-Object System.Windows.Forms.CheckBox
$chkLogNew.Text = "Log new detections to CSV (for review/merge)"
$chkLogNew.Location = New-Object System.Drawing.Point(15, 25)
$chkLogNew.Size = New-Object System.Drawing.Size(300, 20)
$chkLogNew.Checked = $true
$grpOptions.Controls.Add($chkLogNew)

# Open output folder checkbox
$chkOpenFolder = New-Object System.Windows.Forms.CheckBox
$chkOpenFolder.Text = "Open output folder when complete"
$chkOpenFolder.Location = New-Object System.Drawing.Point(15, 50)
$chkOpenFolder.Size = New-Object System.Drawing.Size(300, 20)
$chkOpenFolder.Checked = $false
$grpOptions.Controls.Add($chkOpenFolder)

# Rules Info Label
$lblRules = New-Object System.Windows.Forms.Label
$lblRules.Location = New-Object System.Drawing.Point(330, 20)
$lblRules.Size = New-Object System.Drawing.Size(320, 55)
$lblRules.ForeColor = [System.Drawing.Color]::FromArgb(60, 60, 60)
$grpOptions.Controls.Add($lblRules)

# ============================================================================
# OUTPUT SECTION
# ============================================================================

# Output Label
$lblOutput = New-Object System.Windows.Forms.Label
$lblOutput.Text = "Output:"
$lblOutput.Location = New-Object System.Drawing.Point(15, 240)
$lblOutput.Size = New-Object System.Drawing.Size(100, 20)
$form.Controls.Add($lblOutput)

# Output Text Box
$txtOutput = New-Object System.Windows.Forms.TextBox
$txtOutput.Location = New-Object System.Drawing.Point(15, 265)
$txtOutput.Size = New-Object System.Drawing.Size(660, 240)
$txtOutput.Multiline = $true
$txtOutput.ScrollBars = "Vertical"
$txtOutput.ReadOnly = $true
$txtOutput.BackColor = [System.Drawing.Color]::FromArgb(30, 30, 30)
$txtOutput.ForeColor = [System.Drawing.Color]::FromArgb(200, 255, 200)
$txtOutput.Font = New-Object System.Drawing.Font("Consolas", 9)
$form.Controls.Add($txtOutput)

# ============================================================================
# ACTION BUTTONS
# ============================================================================

# Run Button
$btnRun = New-Object System.Windows.Forms.Button
$btnRun.Text = "Run Scrubber"
$btnRun.Location = New-Object System.Drawing.Point(15, 515)
$btnRun.Size = New-Object System.Drawing.Size(120, 35)
$btnRun.BackColor = [System.Drawing.Color]::FromArgb(0, 120, 60)
$btnRun.ForeColor = [System.Drawing.Color]::White
$btnRun.FlatStyle = "Flat"
$form.Controls.Add($btnRun)

# Merge Rules Button
$btnMerge = New-Object System.Windows.Forms.Button
$btnMerge.Text = "Merge New Rules..."
$btnMerge.Location = New-Object System.Drawing.Point(145, 515)
$btnMerge.Size = New-Object System.Drawing.Size(130, 35)
$form.Controls.Add($btnMerge)

# Open Rules Button
$btnOpenRules = New-Object System.Windows.Forms.Button
$btnOpenRules.Text = "Edit master_rules.csv"
$btnOpenRules.Location = New-Object System.Drawing.Point(285, 515)
$btnOpenRules.Size = New-Object System.Drawing.Size(140, 35)
$form.Controls.Add($btnOpenRules)

# Close Button
$btnClose = New-Object System.Windows.Forms.Button
$btnClose.Text = "Close"
$btnClose.Location = New-Object System.Drawing.Point(555, 515)
$btnClose.Size = New-Object System.Drawing.Size(120, 35)
$form.Controls.Add($btnClose)

# ============================================================================
# HELPER FUNCTIONS
# ============================================================================

function Update-RulesInfo {
    $exactRedact = 0
    $patternRedact = 0
    $exactSkip = 0
    $patternSkip = 0
    
    if (Test-Path $RulesPath) {
        $rules = Import-Csv -Path $RulesPath -Encoding UTF8 -ErrorAction SilentlyContinue
        foreach ($rule in $rules) {
            $type = if ($rule.PSObject.Properties['Type']) { $rule.Type.Trim().ToUpper() } else { "EXACT" }
            if ([string]::IsNullOrWhiteSpace($type)) { $type = "EXACT" }
            
            if ($rule.Action -eq "REDACT") {
                if ($type -eq "EXACT") { $exactRedact++ }
                else { $patternRedact++ }
            }
            if ($rule.Action -eq "SKIP") {
                if ($type -eq "EXACT") { $exactSkip++ }
                else { $patternSkip++ }
            }
        }
    }
    
    $lblRules.Text = "Rules loaded:`n  REDACT: $exactRedact exact, $patternRedact pattern`n  SKIP: $exactSkip exact, $patternSkip pattern"
}

function Write-Output-Log {
    param([string]$Message, [string]$Color = "Green")
    
    $txtOutput.AppendText("$Message`r`n")
    $txtOutput.ScrollToCaret()
    [System.Windows.Forms.Application]::DoEvents()
}

# ============================================================================
# EVENT HANDLERS
# ============================================================================

# Add Files Button Click
$btnAddFiles.Add_Click({
    $openFileDialog = New-Object System.Windows.Forms.OpenFileDialog
    $openFileDialog.Filter = "Text Files (*.txt)|*.txt|Markdown Files (*.md)|*.md|All Files (*.*)|*.*"
    $openFileDialog.Multiselect = $true
    $openFileDialog.Title = "Select Files to Scrub"
    
    if ($openFileDialog.ShowDialog() -eq "OK") {
        foreach ($file in $openFileDialog.FileNames) {
            if (-not $lstFiles.Items.Contains($file)) {
                $lstFiles.Items.Add($file)
            }
        }
    }
})

# Add Folder Button Click
$btnAddFolder.Add_Click({
    $folderDialog = New-Object System.Windows.Forms.FolderBrowserDialog
    $folderDialog.Description = "Select Folder Containing Files to Scrub"
    
    if ($folderDialog.ShowDialog() -eq "OK") {
        $files = Get-ChildItem -Path $folderDialog.SelectedPath -Filter "*.txt" -File
        foreach ($file in $files) {
            if (-not $lstFiles.Items.Contains($file.FullName)) {
                $lstFiles.Items.Add($file.FullName)
            }
        }
        
        $mdFiles = Get-ChildItem -Path $folderDialog.SelectedPath -Filter "*.md" -File
        foreach ($file in $mdFiles) {
            if (-not $lstFiles.Items.Contains($file.FullName)) {
                $lstFiles.Items.Add($file.FullName)
            }
        }
    }
})

# Clear Button Click
$btnClear.Add_Click({
    $lstFiles.Items.Clear()
})

# Run Button Click
$btnRun.Add_Click({
    if ($lstFiles.Items.Count -eq 0) {
        [System.Windows.Forms.MessageBox]::Show("Please add files to scrub first.", "No Files", "OK", "Warning")
        return
    }
    
    $txtOutput.Clear()
    Write-Output-Log "Starting Document Scrubber v1.1.0..."
    Write-Output-Log "Rules file: $RulesPath"
    Write-Output-Log "Files to process: $($lstFiles.Items.Count)"
    Write-Output-Log "----------------------------------------"
    
    $btnRun.Enabled = $false
    $successCount = 0
    $outputFolder = $null
    
    # Load patterns
    . (Join-Path $ScriptDir "patterns.ps1")
    
    # Load rules with type support
    $exactRedact = @{}
    $patternRedact = @()
    $exactSkip = @{}
    $patternSkip = @()
    
    if (Test-Path $RulesPath) {
        $rules = Import-Csv -Path $RulesPath -Encoding UTF8
        foreach ($rule in $rules) {
            if ([string]::IsNullOrWhiteSpace($rule.Text)) { continue }
            
            $type = if ($rule.PSObject.Properties['Type']) { $rule.Type.Trim().ToUpper() } else { "EXACT" }
            if ([string]::IsNullOrWhiteSpace($type)) { $type = "EXACT" }
            
            $regexPattern = $null
            switch ($type) {
                "REGEX" { $regexPattern = $rule.Text }
                "WILDCARD" { $regexPattern = Convert-WildcardToRegex -Wildcard $rule.Text }
            }
            
            if ($rule.Action -eq "REDACT" -and $rule.Alias) {
                if ($type -eq "EXACT") {
                    $exactRedact[$rule.Text] = $rule.Alias
                }
                elseif ($regexPattern) {
                    $patternRedact += @{ Pattern = $regexPattern; Alias = $rule.Alias }
                }
            }
            if ($rule.Action -eq "SKIP") {
                if ($type -eq "EXACT") {
                    $exactSkip[$rule.Text] = $true
                }
                elseif ($regexPattern) {
                    $patternSkip += @{ Pattern = $regexPattern }
                }
            }
        }
    }
    
    Write-Output-Log "Loaded $($exactRedact.Count) exact + $($patternRedact.Count) pattern REDACT rules"
    Write-Output-Log "Loaded $($exactSkip.Count) exact + $($patternSkip.Count) pattern SKIP rules"
    
    foreach ($file in $lstFiles.Items) {
        Write-Output-Log "`nProcessing: $([System.IO.Path]::GetFileName($file))"
        
        try {
            # Read file
            $content = [System.IO.File]::ReadAllText($file, [System.Text.Encoding]::UTF8)
            Write-Output-Log "  File size: $($content.Length) characters"
            
            # Build redaction list
            $allRedactions = @{}
            foreach ($key in $exactRedact.Keys) {
                $allRedactions[$key] = $exactRedact[$key]
            }
            
            # Apply pattern rules from CSV
            foreach ($rule in $patternRedact) {
                try {
                    $found = [regex]::Matches($content, $rule.Pattern, [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
                    foreach ($match in $found) {
                        $matchText = $match.Value.Trim()
                        if ($exactSkip.ContainsKey($matchText)) { continue }
                        $skipMatch = $false
                        foreach ($skip in $patternSkip) {
                            if ($matchText -match $skip.Pattern) { $skipMatch = $true; break }
                        }
                        if ($skipMatch) { continue }
                        if ($matchText.Length -lt 3) { continue }
                        if (-not $allRedactions.ContainsKey($matchText)) {
                            $allRedactions[$matchText] = $rule.Alias
                        }
                    }
                } catch {}
            }
            
            $csvPatternCount = $allRedactions.Count - $exactRedact.Count
            
            # Pattern matching from patterns.ps1
            $newCount = 0
            $newItems = @{}
            
            foreach ($patternName in $script:DETECTION_PATTERNS.Keys) {
                $patternDef = $script:DETECTION_PATTERNS[$patternName]
                $regex = $patternDef.pattern
                $alias = $patternDef.alias
                $caseInsensitive = $patternDef.case_insensitive
                
                $regexOptions = [System.Text.RegularExpressions.RegexOptions]::None
                if ($caseInsensitive) {
                    $regexOptions = [System.Text.RegularExpressions.RegexOptions]::IgnoreCase
                }
                
                try {
                    $found = [regex]::Matches($content, $regex, $regexOptions)
                    foreach ($match in $found) {
                        $matchText = $match.Value.Trim()
                        if ($exactSkip.ContainsKey($matchText)) { continue }
                        $skipMatch = $false
                        foreach ($skip in $patternSkip) {
                            if ($matchText -match $skip.Pattern) { $skipMatch = $true; break }
                        }
                        if ($skipMatch) { continue }
                        if ($matchText.Length -lt 3) { continue }
                        
                        if (-not $allRedactions.ContainsKey($matchText)) {
                            $allRedactions[$matchText] = $alias
                            if (-not $exactRedact.ContainsKey($matchText)) {
                                $newCount++
                                $newItems[$matchText] = @{
                                    Alias = $alias
                                    Category = $patternName
                                }
                            }
                        }
                    }
                } catch {}
            }
            
            Write-Output-Log "  Found $($exactRedact.Count) exact + $csvPatternCount CSV patterns + $newCount new = $($allRedactions.Count) total"
            
            # Apply redactions
            $result = $content
            $sortedKeys = $allRedactions.Keys | Sort-Object { $_.Length } -Descending
            foreach ($key in $sortedKeys) {
                $escapedKey = [regex]::Escape($key)
                $result = $result -replace $escapedKey, $allRedactions[$key]
            }
            
            # Save output
            $baseName = [System.IO.Path]::GetFileNameWithoutExtension($file)
            $extension = [System.IO.Path]::GetExtension($file)
            $directory = [System.IO.Path]::GetDirectoryName($file)
            $outputFile = Join-Path $directory "${baseName}_Scrubbed${extension}"
            
            [System.IO.File]::WriteAllText($outputFile, $result, [System.Text.Encoding]::UTF8)
            Write-Output-Log "  Saved: $([System.IO.Path]::GetFileName($outputFile))"
            
            $outputFolder = $directory
            
            # Export new detections
            if ($chkLogNew.Checked -and $newCount -gt 0) {
                $logPath = Join-Path $directory "new_detections.csv"
                $rows = @()
                foreach ($text in $newItems.Keys) {
                    $item = $newItems[$text]
                    $rows += [PSCustomObject]@{
                        Action = "REDACT"
                        Text = $text
                        Alias = $item.Alias
                        Category = $item.Category
                        Type = "EXACT"
                        Notes = "Auto-detected"
                    }
                }
                $rows | Export-Csv -Path $logPath -NoTypeInformation -Encoding UTF8 -Append
                Write-Output-Log "  Logged $newCount new detections"
            }
            
            $successCount++
            
        } catch {
            Write-Output-Log "  ERROR: $_"
        }
    }
    
    Write-Output-Log "`n----------------------------------------"
    Write-Output-Log "COMPLETE: $successCount of $($lstFiles.Items.Count) files processed"
    
    $btnRun.Enabled = $true
    
    if ($chkOpenFolder.Checked -and $outputFolder) {
        Start-Process "explorer.exe" -ArgumentList $outputFolder
    }
    
    Update-RulesInfo
})

# Merge Rules Button Click
$btnMerge.Add_Click({
    $openFileDialog = New-Object System.Windows.Forms.OpenFileDialog
    $openFileDialog.Filter = "CSV Files (*.csv)|*.csv"
    $openFileDialog.Title = "Select new_detections.csv to Merge"
    
    if ($openFileDialog.ShowDialog() -eq "OK") {
        $newFile = $openFileDialog.FileName
        
        try {
            $newItems = Import-Csv -Path $newFile -Encoding UTF8
            $existingItems = @()
            $existingTexts = @{}
            
            if (Test-Path $RulesPath) {
                $existingItems = @(Import-Csv -Path $RulesPath -Encoding UTF8)
                foreach ($item in $existingItems) {
                    $existingTexts[$item.Text] = $true
                }
            }
            
            $addedCount = 0
            foreach ($newItem in $newItems) {
                if (-not $existingTexts.ContainsKey($newItem.Text)) {
                    # Ensure Type column exists
                    if (-not $newItem.PSObject.Properties['Type']) {
                        $newItem | Add-Member -NotePropertyName 'Type' -NotePropertyValue 'EXACT'
                    }
                    $existingItems += $newItem
                    $existingTexts[$newItem.Text] = $true
                    $addedCount++
                }
            }
            
            $existingItems | Export-Csv -Path $RulesPath -NoTypeInformation -Encoding UTF8
            
            [System.Windows.Forms.MessageBox]::Show(
                "Merged $addedCount new rules into master_rules.csv`nTotal rules: $($existingItems.Count)",
                "Merge Complete",
                "OK",
                "Information"
            )
            
            Update-RulesInfo
            
        } catch {
            [System.Windows.Forms.MessageBox]::Show("Error merging: $_", "Error", "OK", "Error")
        }
    }
})

# Open Rules Button Click
$btnOpenRules.Add_Click({
    if (Test-Path $RulesPath) {
        Start-Process $RulesPath
    } else {
        [System.Windows.Forms.MessageBox]::Show("master_rules.csv not found at:`n$RulesPath", "File Not Found", "OK", "Warning")
    }
})

# Close Button Click
$btnClose.Add_Click({
    $form.Close()
})

# Form Load
$form.Add_Load({
    Update-RulesInfo
})

# ============================================================================
# SHOW FORM
# ============================================================================

[void]$form.ShowDialog()
