<# 
.SYNOPSIS
    Document Scrubber - PowerShell Fast Mode
    Automatically scrubs documents using master_rules.csv and pattern detection

.DESCRIPTION
    This script provides fast, non-interactive document scrubbing:
    1. Loads known rules from master_rules.csv (supports EXACT, REGEX, WILDCARD types)
    2. Applies pattern-based detection for new items
    3. Outputs scrubbed document without stopping for review
    
    New detections are logged but automatically redacted.

.PARAMETER InputFile
    Path to the text file to scrub

.PARAMETER OutputFile
    Optional output path. Defaults to InputFile_Scrubbed.txt

.PARAMETER RulesPath
    Path to master_rules.csv. Defaults to parent directory.

.PARAMETER LogNew
    If specified, exports newly detected items to a CSV for later review

.PARAMETER ShowDetails
    If specified, shows detailed pattern matching information

.EXAMPLE
    .\scrub_core.ps1 -InputFile "C:\docs\report.txt"
    
.EXAMPLE
    .\scrub_core.ps1 -InputFile "report.txt" -LogNew
    
.AUTHOR
    Joey M. Woody P.E.
    
.VERSION
    1.1.0 - Added REGEX and WILDCARD support in master_rules.csv
#>

param(
    [Parameter(Mandatory=$true, Position=0)]
    [string]$InputFile,
    
    [Parameter(Mandatory=$false)]
    [string]$OutputFile,
    
    [Parameter(Mandatory=$false)]
    [string]$RulesPath,
    
    [Parameter(Mandatory=$false)]
    [switch]$LogNew,
    
    [Parameter(Mandatory=$false)]
    [switch]$ShowDetails
)

# ============================================================================
# CONFIGURATION
# ============================================================================

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$ProjectDir = Split-Path -Parent $ScriptDir

# Default rules path is in parent directory (Document_Scrubber folder)
if (-not $RulesPath) {
    $RulesPath = Join-Path $ProjectDir "master_rules.csv"
}

# Load detection patterns
. (Join-Path $ScriptDir "patterns.ps1")

# ============================================================================
# FUNCTIONS
# ============================================================================

function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    $timestamp = Get-Date -Format "HH:mm:ss"
    $color = switch ($Level) {
        "INFO"    { "Cyan" }
        "SUCCESS" { "Green" }
        "WARNING" { "Yellow" }
        "ERROR"   { "Red" }
        default   { "White" }
    }
    Write-Host "[$timestamp] $Level : $Message" -ForegroundColor $color
}

function Convert-WildcardToRegex {
    <#
    .SYNOPSIS
        Convert a simple wildcard pattern to regex
        * = any characters (zero or more)
        ? = single character
        # = single digit
    #>
    param([string]$Wildcard)
    
    # Escape regex special characters except our wildcards
    $escaped = [regex]::Escape($Wildcard)
    
    # Convert our wildcards to regex
    # \* becomes .* (any characters)
    # \? becomes . (single character)
    # \# becomes \d (single digit)
    $regex = $escaped -replace '\\\*', '.*'
    $regex = $regex -replace '\\\?', '.'
    $regex = $regex -replace '\\#', '\d'
    
    return "^$regex$"
}

function Load-MasterRules {
    <#
    .SYNOPSIS
        Load master_rules.csv and return hashtables for REDACT and SKIP rules
        Supports Type column: EXACT (default), REGEX, WILDCARD
    #>
    param([string]$CsvPath)
    
    $exactRedact = @{}      # Exact text matches
    $patternRedact = @()    # Regex/Wildcard patterns (array of objects)
    $exactSkip = @{}        # Exact text to skip
    $patternSkip = @()      # Regex/Wildcard patterns to skip
    
    if (-not (Test-Path $CsvPath)) {
        Write-Log "No master_rules.csv found at $CsvPath - will use pattern detection only" "WARNING"
        return @{ 
            ExactRedact = $exactRedact
            PatternRedact = $patternRedact
            ExactSkip = $exactSkip
            PatternSkip = $patternSkip
        }
    }
    
    try {
        $rules = Import-Csv -Path $CsvPath -Encoding UTF8
        
        foreach ($rule in $rules) {
            $action = $rule.Action.Trim().ToUpper()
            $text = $rule.Text
            $alias = $rule.Alias
            $type = if ($rule.PSObject.Properties['Type']) { $rule.Type.Trim().ToUpper() } else { "EXACT" }
            
            if ([string]::IsNullOrWhiteSpace($text)) { continue }
            if ([string]::IsNullOrWhiteSpace($type)) { $type = "EXACT" }
            
            # Convert pattern based on type
            $regexPattern = $null
            switch ($type) {
                "REGEX" {
                    $regexPattern = $text
                }
                "WILDCARD" {
                    $regexPattern = Convert-WildcardToRegex -Wildcard $text
                }
                default {
                    # EXACT - no pattern conversion needed
                }
            }
            
            switch ($action) {
                "REDACT" {
                    if ($type -eq "EXACT") {
                        if (-not [string]::IsNullOrWhiteSpace($alias)) {
                            $exactRedact[$text] = $alias
                        }
                    }
                    else {
                        if (-not [string]::IsNullOrWhiteSpace($alias) -and $regexPattern) {
                            $patternRedact += @{
                                Pattern = $regexPattern
                                Alias = $alias
                                OriginalText = $text
                                Type = $type
                            }
                        }
                    }
                }
                "SKIP" {
                    if ($type -eq "EXACT") {
                        $exactSkip[$text] = $true
                    }
                    else {
                        if ($regexPattern) {
                            $patternSkip += @{
                                Pattern = $regexPattern
                                OriginalText = $text
                                Type = $type
                            }
                        }
                    }
                }
            }
        }
        
        $totalRedact = $exactRedact.Count + $patternRedact.Count
        $totalSkip = $exactSkip.Count + $patternSkip.Count
        Write-Log "Loaded $totalRedact REDACT rules ($($exactRedact.Count) exact, $($patternRedact.Count) pattern)" "SUCCESS"
        Write-Log "Loaded $totalSkip SKIP rules ($($exactSkip.Count) exact, $($patternSkip.Count) pattern)" "SUCCESS"
    }
    catch {
        Write-Log "Error loading CSV: $_" "ERROR"
    }
    
    return @{ 
        ExactRedact = $exactRedact
        PatternRedact = $patternRedact
        ExactSkip = $exactSkip
        PatternSkip = $patternSkip
    }
}

function Test-ShouldSkip {
    <#
    .SYNOPSIS
        Check if text matches any skip rule (exact or pattern)
    #>
    param(
        [string]$Text,
        [hashtable]$ExactSkip,
        [array]$PatternSkip
    )
    
    # Check exact match first
    if ($ExactSkip.ContainsKey($Text)) { return $true }
    
    # Check pattern matches
    foreach ($skip in $PatternSkip) {
        try {
            if ($Text -match $skip.Pattern) { return $true }
        }
        catch {}
    }
    
    return $false
}

function Find-PatternRuleMatches {
    <#
    .SYNOPSIS
        Find all matches for REGEX and WILDCARD rules from master_rules.csv
    #>
    param(
        [string]$Text,
        [array]$PatternRedact,
        [hashtable]$ExactSkip,
        [array]$PatternSkip
    )
    
    $matches = @{}
    
    foreach ($rule in $PatternRedact) {
        try {
            $found = [regex]::Matches($Text, $rule.Pattern, [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
            
            foreach ($match in $found) {
                $matchText = $match.Value.Trim()
                
                # Skip if in skip rules
                if (Test-ShouldSkip -Text $matchText -ExactSkip $ExactSkip -PatternSkip $PatternSkip) { continue }
                
                # Skip very short matches
                if ($matchText.Length -lt 3) { continue }
                
                # Add to matches
                if (-not $matches.ContainsKey($matchText)) {
                    $matches[$matchText] = $rule.Alias
                }
            }
        }
        catch {
            if ($ShowDetails) {
                Write-Log "Pattern rule error ($($rule.OriginalText)): $_" "WARNING"
            }
        }
    }
    
    return $matches
}

function Find-PatternMatches {
    <#
    .SYNOPSIS
        Scan text for all pattern matches from patterns.ps1
    #>
    param(
        [string]$Text,
        [hashtable]$ExactSkip,
        [array]$PatternSkip
    )
    
    $matches = @{}
    
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
            $found = [regex]::Matches($Text, $regex, $regexOptions)
            
            foreach ($match in $found) {
                $matchText = $match.Value.Trim()
                
                # Skip if in skip rules (exact or pattern)
                if (Test-ShouldSkip -Text $matchText -ExactSkip $ExactSkip -PatternSkip $PatternSkip) { continue }
                
                # Skip very short matches (likely false positives)
                if ($matchText.Length -lt 3) { continue }
                
                # Add to matches if not already present
                if (-not $matches.ContainsKey($matchText)) {
                    $matches[$matchText] = @{
                        Alias = $alias
                        Category = $patternName
                        Count = 1
                    }
                }
                else {
                    $matches[$matchText].Count++
                }
            }
        }
        catch {
            if ($ShowDetails) {
                Write-Log "Pattern error ($patternName): $_" "WARNING"
            }
        }
    }
    
    return $matches
}

function Apply-Redactions {
    <#
    .SYNOPSIS
        Apply all redactions to text
    #>
    param(
        [string]$Text,
        [hashtable]$Redactions
    )
    
    $result = $Text
    
    # Sort by length descending to avoid partial replacements
    $sortedKeys = $Redactions.Keys | Sort-Object { $_.Length } -Descending
    
    foreach ($key in $sortedKeys) {
        $replacement = $Redactions[$key]
        # Escape special regex characters in the key
        $escapedKey = [regex]::Escape($key)
        $result = $result -replace $escapedKey, $replacement
    }
    
    return $result
}

function Export-NewDetections {
    <#
    .SYNOPSIS
        Export newly detected items to CSV for later review
    #>
    param(
        [hashtable]$NewItems,
        [string]$OutputPath
    )
    
    $rows = @()
    foreach ($text in $NewItems.Keys) {
        $item = $NewItems[$text]
        $rows += [PSCustomObject]@{
            Action = "REDACT"
            Text = $text
            Alias = $item.Alias
            Category = $item.Category
            Type = "EXACT"
            Notes = "Auto-detected (count: $($item.Count))"
        }
    }
    
    $rows | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8
    Write-Log "Exported $($rows.Count) new detections to $OutputPath" "INFO"
}

# ============================================================================
# MAIN EXECUTION
# ============================================================================

Write-Host ""
Write-Host "======================================" -ForegroundColor Cyan
Write-Host "  Document Scrubber - Fast Mode" -ForegroundColor Cyan
Write-Host "  PowerShell Edition v1.1.0" -ForegroundColor Cyan
Write-Host "======================================" -ForegroundColor Cyan
Write-Host ""

# Validate input file
if (-not (Test-Path $InputFile)) {
    Write-Log "Input file not found: $InputFile" "ERROR"
    exit 1
}

$InputFile = (Resolve-Path $InputFile).Path
Write-Log "Input file: $InputFile" "INFO"

# Set output file
if (-not $OutputFile) {
    $baseName = [System.IO.Path]::GetFileNameWithoutExtension($InputFile)
    $extension = [System.IO.Path]::GetExtension($InputFile)
    $directory = [System.IO.Path]::GetDirectoryName($InputFile)
    $OutputFile = Join-Path $directory "${baseName}_Scrubbed${extension}"
}

Write-Log "Output file: $OutputFile" "INFO"
Write-Log "Rules file: $RulesPath" "INFO"

# Load master rules
$rules = Load-MasterRules -CsvPath $RulesPath
$exactRedact = $rules.ExactRedact
$patternRedact = $rules.PatternRedact
$exactSkip = $rules.ExactSkip
$patternSkip = $rules.PatternSkip

# Read input file with encoding detection
Write-Log "Reading input file..." "INFO"
$encodings = @(
    [System.Text.Encoding]::UTF8,
    [System.Text.Encoding]::GetEncoding(1252),  # Windows-1252
    [System.Text.Encoding]::GetEncoding(28591)   # ISO-8859-1 (Latin-1)
)

$content = $null
foreach ($encoding in $encodings) {
    try {
        $content = [System.IO.File]::ReadAllText($InputFile, $encoding)
        Write-Log "File read with encoding: $($encoding.EncodingName)" "INFO"
        break
    }
    catch {
        continue
    }
}

if ($null -eq $content) {
    Write-Log "Could not read file with any supported encoding" "ERROR"
    exit 1
}

$originalLength = $content.Length
Write-Log "File size: $originalLength characters" "INFO"

# Build combined redaction list
$allRedactions = @{}

# Add exact master rules (known items)
foreach ($key in $exactRedact.Keys) {
    $allRedactions[$key] = $exactRedact[$key]
}
$exactCount = $allRedactions.Count

# Find pattern rule matches (REGEX/WILDCARD from CSV)
Write-Log "Applying pattern rules from CSV..." "INFO"
$csvPatternMatches = Find-PatternRuleMatches -Text $content -PatternRedact $patternRedact -ExactSkip $exactSkip -PatternSkip $patternSkip
foreach ($text in $csvPatternMatches.Keys) {
    if (-not $allRedactions.ContainsKey($text)) {
        $allRedactions[$text] = $csvPatternMatches[$text]
    }
}
$csvPatternCount = $csvPatternMatches.Count

# Find pattern matches from patterns.ps1 (new items)
Write-Log "Scanning for built-in patterns..." "INFO"
$builtinMatches = Find-PatternMatches -Text $content -ExactSkip $exactSkip -PatternSkip $patternSkip

$newCount = 0
foreach ($text in $builtinMatches.Keys) {
    if (-not $allRedactions.ContainsKey($text)) {
        $allRedactions[$text] = $builtinMatches[$text].Alias
        $newCount++
    }
}

Write-Log "Found $exactCount exact + $csvPatternCount CSV patterns + $newCount new = $($allRedactions.Count) total" "INFO"

# Apply redactions
Write-Log "Applying redactions..." "INFO"
$scrubbedContent = Apply-Redactions -Text $content -Redactions $allRedactions

# Save output
try {
    [System.IO.File]::WriteAllText($OutputFile, $scrubbedContent, [System.Text.Encoding]::UTF8)
    Write-Log "Scrubbed file saved: $OutputFile" "SUCCESS"
}
catch {
    Write-Log "Error saving file: $_" "ERROR"
    exit 1
}

# Export new detections if requested
if ($LogNew -and $newCount -gt 0) {
    $logPath = Join-Path ([System.IO.Path]::GetDirectoryName($OutputFile)) "new_detections.csv"
    
    # Filter to only truly new items (not in master rules)
    $newOnly = @{}
    foreach ($text in $builtinMatches.Keys) {
        if (-not $exactRedact.ContainsKey($text) -and -not $csvPatternMatches.ContainsKey($text)) {
            $newOnly[$text] = $builtinMatches[$text]
        }
    }
    
    Export-NewDetections -NewItems $newOnly -OutputPath $logPath
}

# Summary
Write-Host ""
Write-Host "======================================" -ForegroundColor Green
Write-Host "  SCRUBBING COMPLETE" -ForegroundColor Green
Write-Host "======================================" -ForegroundColor Green
Write-Host ""
Write-Host "  Exact rules applied:    $exactCount" -ForegroundColor White
Write-Host "  CSV pattern matches:    $csvPatternCount" -ForegroundColor White
Write-Host "  New patterns found:     $newCount" -ForegroundColor White
Write-Host "  Total redactions:       $($allRedactions.Count)" -ForegroundColor White
Write-Host ""

if ($newCount -gt 0 -and -not $LogNew) {
    Write-Host "  TIP: Use -LogNew to export new detections for review" -ForegroundColor Yellow
    Write-Host ""
}

exit 0
