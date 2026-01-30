# Document Scrubber - Handoff Documentation

**Project:** Document Scrubber with Master Rules System  
**Location:** `E:\CLAUDE_Workspace\Claude\Report_Files\Projects\Document_Scrubber`  
**Author:** Joey M. Woody P.E.  
**Last Updated:** January 2025

---

## Purpose

A document redaction tool that automatically detects and removes sensitive information from text documents. Designed for civil engineering workflows where documents contain personal names, addresses, survey references, and project-specific data that must be scrubbed before sharing.

The system uses a **"living master list"** that learns from each review session - previously reviewed items are automatically applied in future scans, so users only need to review truly new items.

---

## Key Features

- **Pattern-based detection**: Automatically finds emails, phones, addresses, names with credentials, survey/deed references, etc.
- **Master Rules System**: JSON-based rules that persist across sessions
- **CSV Integration**: Export rules to CSV for easy editing in Excel, auto-merges changes on next run
- **Category Toggles**: Enable/disable entire detection categories (e.g., turn off all phone detection)
- **Incremental Learning**: Only shows NEW items for review; known items auto-applied
- **Multiple Encoding Support**: Handles UTF-8, Windows-1252, Latin-1 encoded files

---

## Files Overview

### Active Files (Keep)

| File | Purpose |
|------|---------|
| `qgis_scrub_master.py` | **PRIMARY TOOL** - QGIS GUI with master rules system |
| `scrub_master.py` | Command-line version of master rules system |
| `master_rules.json` | User's redaction rules (auto-generated, in .gitignore) |
| `master_rules.csv` | Editable CSV version of rules (optional, reconciled on run) |
| `master_rules.template.json` | Template for new users (committed to git) |
| `README.md` | User documentation |
| `Handoff.md` | This file - developer documentation |
| `.gitignore` | Excludes personal rules and output files |
| `LICENSE` | License file |

### Safe_Scrub Folder (Separate Project)

The `Safe_Scrub/` subfolder contains a separate tool for detecting prompt injection attacks. Do not modify or remove.

---

## Architecture

### Detection Flow

```
1. Load master_rules.json (or create from template)
2. If master_rules.csv exists, reconcile changes into JSON
3. Scan document with regex patterns
4. For each match:
   - If in always_redact → auto-apply replacement
   - If in never_redact → skip
   - If unknown → add to "NEW items" list for user review
5. User reviews NEW items (REDACT or SKIP)
6. Apply all redactions to document
7. Save user decisions to master_rules.json
```

### File Relationships

```
master_rules.template.json  →  (copied on first run)  →  master_rules.json
                                                              ↑
master_rules.csv  ────────────────(reconciled on load)────────┘
```

---

## Detection Categories

| Category | Pattern Description | Default Alias |
|----------|---------------------|---------------|
| EMAIL | Email addresses | [EMAIL] |
| PHONE | Phone numbers (xxx) xxx-xxxx | [PHONE] |
| ADDRESS_STREET | Street addresses | [ADDRESS] |
| ADDRESS_HIGHWAY | Highway addresses (1003 Highway 52) | [ADDRESS] |
| ADDRESS_POBOX | PO Box addresses | [PO_BOX] |
| ADDRESS_CITY_STATE_ZIP | City, State ZIP | [CITY_STATE_ZIP] |
| NAME_TITLED | Mr./Mrs./Dr. names | [PERSON_NAME] |
| NAME_CREDENTIALED | Names with PE, PLS, etc. | [PERSON_NAME] |
| NAME_MIDDLE_INITIAL | First M. Last | [PERSON_NAME] |
| NAME_ALLCAPS_CREDENTIAL | ALL CAPS names with credentials | [PERSON_NAME] |
| NAME_CONTACT_PERSON | "Contact Person:" fields | [CONTACT_NAME] |
| SURVEY_NF_OWNER | N/F owner names | [ADJACENT_OWNER] |
| SURVEY_PROPERTY_OF | "Property Of" names | [PROPERTY_OWNER] |
| SURVEY_DEED_BOOK | Deed Book references | [DEED_REF] |
| SURVEY_PLAT_CAB | Plat Cabinet references | [PLAT_REF] |
| SURVEY_TMS | TMS numbers | [TMS_REF] |
| SURVEY_PARCEL_NUM | Long parcel numbers | [PARCEL_ID] |
| SURVEY_SUBDIVISION | Subdivision names | [SUBDIVISION] |
| SURVEY_BLOCK_LOT | Block/Lot references | [BLOCK_LOT] |
| COMPANY_SURVEYING | Surveying/Engineering companies | [COMPANY] |
| COMPANY_PLANNING | Planning/Architecture firms | [COMPANY] |
| PE_LICENSE | PE license numbers | [PE_NUMBER] |
| PLS_LICENSE | PLS license numbers | [PLS_NUMBER] |
| PERMIT_ID | Permit/CAA numbers | [PERMIT_ID] |
| PARCEL_ID | 10-digit parcel IDs | [PARCEL_ID] |
| PARCEL_ID_DASHED | Dashed parcel IDs | [PARCEL_ID] |
| SSN | Social Security Numbers | [SSN_REDACTED] |
| COORDINATES | GPS coordinates | [COORDINATES] |

---

## Configuration

### Hardcoded Path

The rules directory is hardcoded in both scripts:

```python
RULES_DIR = Path(r"E:\CLAUDE_Workspace\Claude\Report_Files\Projects\Document_Scrubber")
```

To change, update this in:
- `qgis_scrub_master.py` (line ~240 in MasterRules class, line ~385 in MasterScrubDialog)
- `scrub_master.py` (line ~30)

### Adding New Patterns

To add a new detection pattern, add to the `DETECTION_PATTERNS` OrderedDict:

```python
('NEW_PATTERN_NAME', {
    'pattern': r'your regex here',
    'flags': re.IGNORECASE,  # or 0 for case-sensitive
    'default_alias': '[ALIAS]',
    'description': 'Human-readable description'
}),
```

Also add to `master_rules.template.json` in the categories section.

---

## Usage

### QGIS GUI (Primary)

1. Open QGIS Python Console: `Ctrl+Alt+P`
2. Click **Show Editor**
3. Load: `qgis_scrub_master.py`
4. Click **Run**
5. Browse to document → Scan → Review NEW items → Apply

### Command Line

```bash
# Scan document
python scrub_master.py document.txt

# Apply reviewed changes
python scrub_master.py document.txt --apply document_REVIEW.csv

# Export rules to CSV
python scrub_master.py --export-rules

# View statistics
python scrub_master.py --stats
```

---

## CSV Editing

Export rules to CSV for bulk editing:

```csv
Action,Text,Alias,Category,Notes
REDACT,John Smith,[PERSON_NAME],CUSTOM,Engineer name
SKIP,Berkeley County Engineering,,CUSTOM,Government dept - keep
DELETE,Old Item,,CUSTOM,Remove from rules
```

**Actions:**
- `REDACT` - Always redact this text with the given alias
- `SKIP` - Never redact this text
- `DELETE` - Remove from master rules entirely

Changes are merged into JSON on next script run.

---

## Git Setup

Files in `.gitignore`:
```
master_rules.json
master_rules.csv
master_rules.json.bak
*_Scrubbed.txt
*_REVIEW.csv
```

New users who clone the repo:
1. Get `master_rules.template.json`
2. On first run, it creates their own `master_rules.json`
3. Their personal rules stay separate

---

## Known Issues / Future Improvements

1. **Plain names without indicators**: Names like "STEPHEN TANNER" without titles or credentials won't be auto-detected. Must be added manually to CSV or via "Add Custom Item" in GUI.

2. **Pattern overlap**: Some patterns may match the same text (e.g., a name with middle initial also matching credentialed name pattern). Duplicates are filtered by text.

3. **Large files**: No progress indicator for large documents. Consider adding for files > 1MB.

4. **Undo**: No undo for "Apply Scrubbing". Original file is not modified, but scrubbed output overwrites previous scrubbed version.

---

## Troubleshooting

### "Could not read file" encoding error
Fixed - script now tries multiple encodings (UTF-8, CP1252, Latin-1).

### Rules not saving to expected location
Fixed - explicit path now hardcoded. Check the path in the script matches your environment.

### Pattern not detecting expected text
1. Check if category is enabled (Settings tab)
2. Test regex at regex101.com
3. Add as custom item if pattern doesn't cover edge case

---

## Contact

For questions about this project, contact the development team or refer to the git history for change context.
