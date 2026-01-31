# Test Files for Document Scrubber Batch Branch

These test files exercise the pattern detection capabilities of the PowerShell scrubber.

## Test Files

| File | Purpose | Key Patterns Tested |
|------|---------|---------------------|
| `test_engineering_report.txt` | Full engineering report | Names w/credentials, emails, phones, addresses, TMS, deed refs, coordinates, PE/PLS licenses |
| `test_survey_plat.txt` | Survey/plat document | Heavy N/F owners, deed books, plat cabinets, TMS, subdivisions, block/lot |
| `test_contact_directory.txt` | Contact list format | Many name formats, emails, phones, company names, addresses |
| `test_transmittal_letter.txt` | Letter/memo format | Mixed content in narrative form, CC lists |
| `test_edge_cases.txt` | Edge cases & false positives | SSN, coordinate variations, items that should NOT match |

## Running Tests

### Option 1: Run All Tests
```cmd
cd E:\CLAUDE_Workspace\Claude\Report_Files\Projects\Document_Scrubber\batch_branch
run_tests.bat
```

### Option 2: Run Single Test
```cmd
scrub_batch.bat "test_files\test_engineering_report.txt" -LogNew
```

## Expected Results

After running, each test file should produce:
- `test_*_Scrubbed.txt` - The redacted output
- `new_detections.csv` - Items detected by patterns (in same folder as input)

## Validation Checklist

For each test file, verify:

- [ ] Emails replaced with `[EMAIL]`
- [ ] Phone numbers replaced with `[PHONE]`
- [ ] Addresses replaced with `[ADDRESS]`
- [ ] City/State/ZIP replaced with `[CITY_STATE_ZIP]`
- [ ] PO Boxes replaced with `[PO_BOX]`
- [ ] Names with titles/credentials replaced with `[PERSON_NAME]`
- [ ] N/F owners replaced with `[ADJACENT_OWNER]`
- [ ] Property Of names replaced with `[PROPERTY_OWNER]`
- [ ] Deed Book refs replaced with `[DEED_REF]`
- [ ] Plat refs replaced with `[PLAT_REF]`
- [ ] TMS numbers replaced with `[TMS_REF]`
- [ ] Parcel IDs replaced with `[PARCEL_ID]`
- [ ] PE/PLS licenses replaced with `[PE_NUMBER]` / `[PLS_NUMBER]`
- [ ] Coordinates replaced with `[COORDINATES]`
- [ ] SSN replaced with `[SSN_REDACTED]`

## False Positive Check (test_edge_cases.txt)

These items should NOT be redacted:
- "Section 404 permit" - not a phone
- "phase 2.1" - not coordinates
- "10-foot setback" - not a parcel ID
- "Drawing sheet C-101" - not sensitive
- "Planning Department" - government, not private company

## Adding to Master Rules

After reviewing `new_detections.csv`:
1. Edit the CSV to mark any false positives as `SKIP`
2. Run: `merge_rules.bat "test_files\new_detections.csv"`
3. Rules added to `master_rules.csv` for future runs
