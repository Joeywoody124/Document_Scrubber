# Document Scrubber - Master Rules System

A document redaction tool that automatically detects and removes sensitive information from text documents. Uses a **living master list** that learns from each review session.

## Features

- **Pattern-based detection**: Emails, phones, addresses, names, survey/deed references, companies, permits, and more
- **Living Master List**: Previously reviewed items are auto-applied in future scans
- **Only Review NEW Items**: No need to re-review the same items repeatedly
- **CSV Editing**: Export rules to Excel/CSV for bulk editing
- **Category Toggles**: Enable/disable entire detection types
- **Multiple Encodings**: Handles UTF-8, Windows-1252, and Latin-1 files

---

## Quick Start

### QGIS GUI (Recommended)

1. Open QGIS Python Console: `Ctrl+Alt+P`
2. Click **Show Editor**
3. Load: `qgis_scrub_master.py`
4. Click **Run**

### Command Line

```bash
# Scan a document
python scrub_master.py document.txt

# Review the generated CSV, then apply
python scrub_master.py document.txt --apply document_REVIEW.csv

# Export your rules to CSV for editing
python scrub_master.py --export-rules

# View statistics
python scrub_master.py --stats
```

---

## How It Works

```
First Run:
  Scan doc → Find 50 items → Review ALL 50 → Save to master_rules.json

Second Run:
  Scan doc → Find 60 items → 45 known (auto-applied) → Review 15 NEW → Save

Third Run:
  Scan doc → 55 items → 54 known → Review 1 NEW → Save
```

Your decisions accumulate over time. Eventually, most scans require zero manual review.

---

## Detection Categories

| Category | Example | Alias |
|----------|---------|-------|
| EMAIL | john@example.com | [EMAIL] |
| PHONE | (843) 555-1234 | [PHONE] |
| ADDRESS_STREET | 123 Main Street | [ADDRESS] |
| ADDRESS_HIGHWAY | 1003 Highway 52 | [ADDRESS] |
| ADDRESS_POBOX | P.O. Box 6122 | [PO_BOX] |
| ADDRESS_CITY_STATE_ZIP | Anytown, SC 29401 | [CITY_STATE_ZIP] |
| NAME_TITLED | Mr. John Smith | [PERSON_NAME] |
| NAME_CREDENTIALED | John Smith, PE | [PERSON_NAME] |
| NAME_MIDDLE_INITIAL | John A. Smith | [PERSON_NAME] |
| NAME_CONTACT_PERSON | Contact Person: John Anderson | [CONTACT_NAME] |
| SURVEY_NF_OWNER | N/F JANE DOE | [ADJACENT_OWNER] |
| SURVEY_PROPERTY_OF | PROPERTY OF SMITH JOHN L | [PROPERTY_OWNER] |
| SURVEY_DEED_BOOK | DEED BOOK 4182, PAGE 245 | [DEED_REF] |
| SURVEY_PLAT_CAB | PLAT CAB Q, PAGE 275G | [PLAT_REF] |
| SURVEY_PARCEL_NUM | PARCEL: 1234567890 | [PARCEL_ID] |
| SURVEY_SUBDIVISION | ~OAK GROVE S/D~ | [SUBDIVISION] |
| COMPANY_SURVEYING | ABC Surveying, Inc. | [COMPANY] |
| COMPANY_PLANNING | XYZ Planning & Landscape Architecture | [COMPANY] |
| PE_LICENSE | PE# 12345 | [PE_NUMBER] |
| PLS_LICENSE | SC P.L.S. 12345 | [PLS_NUMBER] |
| PERMIT_ID | CAA-12-34-5678 | [PERMIT_ID] |

---

## Files

| File | Purpose | In Git? |
|------|---------|---------|
| `qgis_scrub_master.py` | **MAIN** - QGIS GUI tool | ✅ |
| `scrub_master.py` | Command line tool | ✅ |
| `master_rules.json` | Your personal redaction rules | ❌ |
| `master_rules.csv` | Editable CSV (merged on run) | ❌ |
| `master_rules.template.json` | Template for new users | ✅ |
| `Handoff.md` | Developer documentation | ✅ |
| `README.md` | This file | ✅ |

---

## CSV Editing

Export your rules to CSV for bulk editing in Excel:

```csv
Action,Text,Alias,Category,Notes
REDACT,John Smith,[PERSON_NAME],CUSTOM,Engineer
SKIP,County Engineering Dept,,CUSTOM,Keep this
DELETE,Old Entry,,CUSTOM,Remove from rules
```

**Actions:**
- `REDACT` - Always replace this text
- `SKIP` - Never redact this text  
- `DELETE` - Remove from master rules

Save the CSV and changes merge automatically on next run.

---

## Adding Custom Items

For text the patterns don't catch (like plain names without titles/credentials):

**Option 1: GUI**
- Use "Add Custom Item" section at bottom of Scan & Review tab

**Option 2: CSV**
- Edit `master_rules.csv` and add rows with Action=REDACT

---

## Git Setup for Teams

The `.gitignore` excludes personal rules:

```
master_rules.json
master_rules.csv
*_Scrubbed.txt
*_REVIEW.csv
```

Each team member builds their own master list. Only the template is shared.

---

## Troubleshooting

**"Could not read file" error**  
The file has special characters. Fixed in latest version - tries multiple encodings.

**Rules not saving**  
Check the hardcoded path in the script matches your folder location.

**Pattern not detecting something**  
1. Check Settings tab - is the category enabled?
2. Add as custom item if it's an edge case

---

**Author:** Joey M. Woody P.E.
