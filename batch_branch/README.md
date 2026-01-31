# Document Scrubber - Batch Branch (PowerShell Edition)

**Version:** 1.1.0  
**Author:** Joey M. Woody P.E.  
**Purpose:** Fast, non-interactive document scrubbing using master_rules.csv

---

## Overview

This branch provides a **fast mode** alternative to the Python/QGIS GUI. It automatically applies all known redaction rules and pattern detection without stopping for interactive review.

### When to Use This vs. Python GUI

| Scenario | Use This | Use Python GUI |
|----------|----------|----------------|
| Quick scrub of familiar document types | ✓ | |
| Batch processing multiple files | ✓ | |
| First-time scrub with many unknowns | | ✓ |
| Need to carefully review each detection | | ✓ |
| Running on machine without QGIS | ✓ | |
| Drag-and-drop convenience | ✓ | |

---

## Quick Start Options

### Option 1: GUI (Recommended)
```
Double-click: scrub_gui.bat
```
Features:
- Browse for files or folders
- Batch process multiple files
- Built-in merge rules function
- Real-time output display

### Option 2: Drag and Drop
```
Drag a .txt file onto scrub_batch.bat
```

### Option 3: Command Line
```cmd
scrub_batch.bat "C:\path\to\document.txt"
scrub_batch.bat "C:\path\to\document.txt" -LogNew
```

---

## Files

```
batch_branch/
├── scrub_gui.bat         # GUI launcher (RECOMMENDED)
├── scrub_gui.ps1         # GUI PowerShell script
├── scrub_batch.bat       # Drag-drop entry point
├── scrub_core.ps1        # Core PowerShell logic
├── patterns.ps1          # Detection pattern definitions
├── merge_rules.bat       # Merge new detections into master_rules
├── merge_rules.ps1       # Merge logic
├── run_tests.bat         # Run all test files
├── cleanup_tests.bat     # Clean up test outputs
├── README.md             # This file
├── Handoff.md            # Developer documentation
└── test_files/           # Test documents
```

---

## NEW: Pattern Types in master_rules.csv

**Version 1.1.0** adds support for REGEX and WILDCARD patterns directly in the CSV!

### CSV Format

```csv
Action,Text,Alias,Category,Type,Notes
REDACT,John Smith,[PERSON_NAME],CUSTOM,EXACT,Specific person
REDACT,###-##-##-###,[TMS_REF],CUSTOM,WILDCARD,TMS pattern
REDACT,\d{3}-\d{2}-\d{2}-\d{3},[TMS_REF],CUSTOM,REGEX,TMS regex
SKIP,Planning Department,,CUSTOM,EXACT,Government - keep
SKIP,*Test*,,CUSTOM,WILDCARD,Skip anything with Test
```

### Type Options

| Type | Description | Example Pattern | Matches |
|------|-------------|-----------------|---------|
| `EXACT` | Exact text match (default) | `John Smith` | Only "John Smith" |
| `WILDCARD` | Simple wildcards | `###-##-##-###` | `236-15-08-005` |
| `REGEX` | Full regex pattern | `\d{3}-\d{2}-\d{2}-\d{3}` | `236-15-08-005` |

### Wildcard Characters

| Character | Meaning | Example |
|-----------|---------|---------|
| `*` | Any characters (zero or more) | `*Smith` matches "John Smith", "Jane Smith" |
| `?` | Single character | `Jo?n` matches "John", "Joan" |
| `#` | Single digit | `###-####` matches "843-5551" |

### Example: Match All TMS Numbers

Add this to master_rules.csv:
```csv
REDACT,###-##-##-###,[TMS_REF],CUSTOM,WILDCARD,All TMS numbers
```

This matches: `236-15-08-005`, `145-08-02-015`, etc.

---

## Shared Rules File

Both this batch branch and the Python GUI use the **same** `master_rules.csv`:

```
Document_Scrubber/
├── master_rules.csv      ← SHARED between both tools
├── master_rules.json     ← Used by Python GUI for category settings
├── batch_branch/         ← This tool (reads CSV)
└── qgis_scrub_master.py  ← Python GUI (reads both)
```

**Key point:** Any rules you add via either tool are available to both!

---

## Merge Rules Workflow

When you run with `-LogNew`, new pattern detections are saved to `new_detections.csv`. Here's how to add them to your master rules:

### Using the GUI:
1. Run scrub with "Log new detections" checked
2. Click "Merge New Rules..." button
3. Select the `new_detections.csv` file
4. Rules are added to `master_rules.csv`

### Using Command Line:
```cmd
REM 1. Run scrub with logging
scrub_batch.bat "document.txt" -LogNew

REM 2. (Optional) Review new_detections.csv, change REDACT to SKIP for false positives

REM 3. Merge into master rules
merge_rules.bat "new_detections.csv"
```

### Manual Editing:
Open `master_rules.csv` in Excel and add/edit rows:
```csv
Action,Text,Alias,Category,Type,Notes
REDACT,John Smith,[PERSON_NAME],CUSTOM,EXACT,Project manager
SKIP,Planning Department,,CUSTOM,EXACT,Government - keep visible
REDACT,###-##-##-###,[TMS_REF],CUSTOM,WILDCARD,Match all TMS
```

---

## Detection Patterns

28 built-in patterns are included (same as Python version):

| Category | Examples |
|----------|----------|
| EMAIL | john@example.com |
| PHONE | (843) 555-1234, 843-555-1234 |
| ADDRESS | 123 Main Street, Suite 100 |
| CITY_STATE_ZIP | Charleston, SC 29401 |
| NAMES | Mr. John Smith, Jane Doe P.E. |
| SURVEY | N/F OWNER NAME, Deed Book 123 |
| LICENSES | P.E. #12345, PLS #6789 |
| PARCEL_ID | 1234567890, 123-45-67-890 |
| SSN | 123-45-6789 |
| COORDINATES | 32.7891, -79.9345 |

See `patterns.ps1` for full regex definitions.

**Plus:** You can now add your own patterns via REGEX or WILDCARD in the CSV!

---

## Parameters Reference

### scrub_core.ps1

| Parameter | Required | Description |
|-----------|----------|-------------|
| `-InputFile` | Yes | Path to text file to scrub |
| `-OutputFile` | No | Output path (default: `*_Scrubbed.txt`) |
| `-RulesPath` | No | Path to master_rules.csv |
| `-LogNew` | No | Export new detections to CSV |
| `-ShowDetails` | No | Show detailed pattern errors |

---

## Troubleshooting

### "Execution Policy" Error
```powershell
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```

### GUI Won't Open
Run from command line to see errors:
```cmd
powershell -ExecutionPolicy Bypass -File scrub_gui.ps1
```

### Pattern Not Matching
1. Check if text is in SKIP list in master_rules.csv
2. Test regex at regex101.com
3. Add as REGEX or WILDCARD rule in master_rules.csv

### WILDCARD Pattern Not Working
- Make sure Type column is set to `WILDCARD`
- Use `#` for digits, `*` for any text, `?` for single character
- Pattern is case-insensitive

---

## Related

- **Python GUI:** `../qgis_scrub_master.py` - Full interactive version
- **Main Handoff:** `../Handoff.md` - Project overview
- **Safe_Scrub:** `../Safe_Scrub/` - Prompt injection detection
