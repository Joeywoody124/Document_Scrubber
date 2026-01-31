# Batch Branch - Handoff Documentation

**Project:** Document Scrubber - PowerShell Batch Mode  
**Location:** `E:\CLAUDE_Workspace\Claude\Report_Files\Projects\Document_Scrubber\batch_branch`  
**Author:** Joey M. Woody P.E.  
**Last Updated:** January 2025  
**Status:** STABLE & WORKING

---

## Session Pickup Summary

### Current State: STABLE v1.1.0

The PowerShell batch scrubber is fully functional with REGEX and WILDCARD pattern support in master_rules.csv.

### What Was Completed

1. **Created PowerShell-based fast scrubber** - No QGIS dependency
2. **28 detection patterns** - Mirrors Python version
3. **Batch launcher** - Drag-drop or CLI execution
4. **GUI interface** - File browser, batch processing, merge function
5. **Test suite** - 5 test files covering various document types
6. **Merge utility** - Adds new detections to master_rules.csv
7. **Fixed pattern issues** - PHONE/PARCEL overlap, COMPANY partial matches
8. **NEW: Pattern types** - EXACT, REGEX, WILDCARD support in CSV

### Files in Branch

```
batch_branch/
├── scrub_gui.bat             # GUI launcher (RECOMMENDED)
├── scrub_gui.ps1             # GUI PowerShell script (v1.1.0)
├── scrub_batch.bat           # Drag-drop entry point
├── scrub_core.ps1            # Core PowerShell logic (v1.1.0)
├── patterns.ps1              # 28 detection patterns (v1.0.2)
├── merge_rules.bat           # Merge new detections launcher
├── merge_rules.ps1           # Merge logic
├── run_tests.bat             # Run all test files
├── cleanup_tests.bat         # Delete _Scrubbed files
├── debug_test.bat            # Diagnostic script
├── README.md                 # User documentation
├── Handoff.md                # This file
└── test_files/
    ├── README.md
    ├── test_engineering_report.txt
    ├── test_survey_plat.txt
    ├── test_contact_directory.txt
    ├── test_transmittal_letter.txt
    └── test_edge_cases.txt
```

---

## NEW FEATURE: Pattern Types in CSV (v1.1.0)

### Overview

Users can now add custom patterns directly in `master_rules.csv` without editing `patterns.ps1`.

### CSV Format

```csv
Action,Text,Alias,Category,Type,Notes
REDACT,John Smith,[PERSON_NAME],CUSTOM,EXACT,Specific person
REDACT,###-##-##-###,[TMS_REF],CUSTOM,WILDCARD,TMS pattern
REDACT,\d{3}-\d{2}-\d{2}-\d{3},[TMS_REF],CUSTOM,REGEX,TMS regex
SKIP,Planning Department,,CUSTOM,EXACT,Keep visible
SKIP,*Test*,,CUSTOM,WILDCARD,Skip test files
```

### Type Options

| Type | Description | When to Use |
|------|-------------|-------------|
| `EXACT` | Exact text match (default) | Specific names, addresses |
| `WILDCARD` | Simple pattern with `*`, `?`, `#` | Easy patterns like TMS |
| `REGEX` | Full .NET regex | Complex patterns |

### Wildcard Characters

| Char | Meaning | Example |
|------|---------|---------|
| `*` | Any characters (0+) | `*Smith` → "John Smith" |
| `?` | Single character | `Jo?n` → "John", "Joan" |
| `#` | Single digit | `###-####` → "843-5551" |

### Implementation Details

The `Convert-WildcardToRegex` function converts wildcards to regex:
```powershell
function Convert-WildcardToRegex {
    param([string]$Wildcard)
    $escaped = [regex]::Escape($Wildcard)
    $regex = $escaped -replace '\\\*', '.*'
    $regex = $regex -replace '\\\?', '.'
    $regex = $regex -replace '\\#', '\d'
    return "^$regex$"
}
```

---

## Merge Rules Process

### Step-by-Step

1. **Scrub with logging:** Run with `-LogNew` or check the box in GUI
2. **Files created:**
   - `document_Scrubbed.txt` - Scrubbed output
   - `new_detections.csv` - New patterns found
3. **Review (optional):** Edit `new_detections.csv` in Excel
   - Change `REDACT` to `SKIP` for false positives
   - Adjust aliases if needed
4. **Merge:** Click "Merge New Rules..." in GUI or run `merge_rules.bat`
5. **Done:** Items added to `master_rules.csv` for future runs

### What Gets Merged

- New items not already in master_rules.csv
- Duplicates are skipped
- Type column defaults to `EXACT` if not specified

---

## Test Results Summary

| Pattern | Status | Notes |
|---------|--------|-------|
| EMAIL | ✅ | All formats |
| PHONE | ✅ | Requires separator |
| PARCEL_ID (10-digit) | ✅ | Fixed in v1.0.2 |
| PARCEL_ID (dashed) | ✅ | Working |
| COORDINATES | ✅ | All precision levels |
| Names (all types) | ✅ | Titled, credentialed, middle initial |
| SSN | ✅ | xxx-xx-xxxx |
| Deed/Plat refs | ✅ | Book/Page format |
| TMS | ✅ | TMS# format |
| N/F owners | ✅ | Survey adjoiners |
| COMPANY | ✅ | Requires suffix |
| WILDCARD rules | ✅ | New in v1.1.0 |
| REGEX rules | ✅ | New in v1.1.0 |

---

## Usage

### GUI (Recommended)
```cmd
scrub_gui.bat
```

### Drag-Drop
```
Drag file onto scrub_batch.bat
```

### Command Line
```cmd
scrub_batch.bat "document.txt" -LogNew
```

### Run Tests
```cmd
run_tests.bat
```

---

## Architecture

### Shared Resources
- `../master_rules.csv` - Shared with Python GUI
- Patterns mirror `../qgis_scrub_master.py`

### Data Flow (v1.1.0)
```
1. Load master_rules.csv
   - EXACT rules → exactRedact/exactSkip hashtables
   - REGEX/WILDCARD rules → patternRedact/patternSkip arrays
2. Load patterns.ps1 (28 built-in patterns)
3. Read input file (UTF-8, CP1252, Latin-1)
4. Apply exact REDACT rules
5. Apply CSV pattern rules (REGEX/WILDCARD)
6. Apply built-in pattern matches
7. Check all against SKIP rules (exact + pattern)
8. Apply all redactions (longest first)
9. Save _Scrubbed.txt output
10. Export new_detections.csv (if -LogNew)
```

---

## Bugs Fixed

1. **Export-ModuleMember error** - Removed
2. **-Verbose parameter conflict** - Renamed to -ShowDetails
3. **Infinite loop on _Scrubbed files** - Added exclusion filter
4. **PHONE matching 10-digit parcel IDs** - Require separator
5. **COMPANY partial matches** - Require company suffix
6. **Header false positives** - Require digit after "Parcel"

---

## Known Limitations

1. **Company names without suffix** - Add manually to CSV
2. **Plain names** - Names without indicators won't auto-detect
3. **Multi-line addresses** - Some complex formats may not match
4. **WILDCARD anchored** - Patterns match whole text, not partial

---

## Version History

| Version | Date | Changes |
|---------|------|---------|
| 1.0.0 | Jan 2025 | Initial release |
| 1.0.1 | Jan 2025 | Fixed parameter conflict, loop bug |
| 1.0.2 | Jan 2025 | Fixed PHONE/PARCEL overlap, COMPANY matches |
| 1.1.0 | Jan 2025 | Added REGEX/WILDCARD support in CSV |

---

## Dependencies

- Windows PowerShell 5.1+ (built into Windows)
- No Python required
- No QGIS required
- Shares master_rules.csv with Python version

---

## Related Documentation

- Main project: `../Handoff.md`
- Python GUI: `../qgis_scrub_master.py`
- Word document branch: `../doc_cleaning_branch/Handoff.md`
