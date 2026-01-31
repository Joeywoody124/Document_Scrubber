# DOC Cleaning Branch - Handoff Documentation

**Project:** Document Scrubber - Word Document Support  
**Location:** `E:\CLAUDE_Workspace\Claude\Report_Files\Projects\Document_Scrubber\doc_cleaning_branch`  
**Author:** Joey M. Woody P.E.  
**Last Updated:** January 2025  
**Status:** PLACEHOLDER - Planning Phase

---

## Purpose

Extend the Document Scrubber to handle `.doc` and `.docx` files directly, preserving formatting while applying redaction rules from `master_rules.csv`.

---

## Related Projects

### Current Scrubber Tools
- **Python GUI:** `../qgis_scrub_master.py` - Interactive review in QGIS
- **Batch Mode:** `../batch_branch/` - Fast PowerShell scrubbing for .txt files
- **Shared Rules:** `../master_rules.csv` - Central rules file used by all tools

### Markdown-to-Word Workflow
- **Location:** `E:\CLAUDE_Workspace\Claude\Report_Files\Finished_Code\Jbragg_Report_Format`
- **Current Flow:** Write in `.md` → Convert to formatted `.docx`
- **Implication:** If scrubbing happens at the `.md` stage, existing tools work fine. This branch is for when source documents arrive as Word files.

---

## Use Cases

1. **Incoming Word documents** - Client/agency sends .docx that needs scrubbing before AI processing
2. **Legacy .doc files** - Older documents in binary Word format
3. **Round-trip editing** - Scrub a Word doc and return it with formatting intact

---

## Technical Approaches Evaluated

### Option A: Extract Text Only (Lossy)

Extract all text → scrub as plain text → output as .txt

| Pros | Cons |
|------|------|
| Simple implementation | Loses all formatting |
| Fast processing | Output looks unprofessional |
| Works with existing regex engine | Can't round-trip to original format |
| Minimal dependencies | Not suitable for deliverables |

**Verdict:** Only useful for AI ingestion pipelines, not for producing deliverable documents.

---

### Option B: In-Place XML Manipulation (.docx only)

Unzip .docx → parse `word/document.xml` → find/replace text nodes → rezip

| Pros | Cons |
|------|------|
| Preserves all formatting | Complex XML parsing required |
| Round-trips cleanly | Text split across XML nodes |
| No external dependencies | Headers/footers in separate files |
| Works in PowerShell natively | Tables, text boxes need special handling |
| | .doc (legacy) not supported |

**The Text Fragmentation Problem:**
```xml
<!-- "John Smith" might be stored as: -->
<w:r><w:t>Jo</w:t></w:r>
<w:r><w:t>hn Sm</w:t></w:r>
<w:r><w:t>ith</w:t></w:r>
```
Regex for "John Smith" won't match because it's split across XML nodes.

**Verdict:** Viable but edge cases are dangerous for sensitive data.

---

### Option C: Python python-docx Library

Use `python-docx` library to read/modify/save

| Pros | Cons |
|------|------|
| Clean API for paragraphs, tables | Doesn't handle headers/footers well |
| Preserves most formatting | Images/charts can cause issues |
| Active community support | Still has text-run fragmentation |
| | .doc (legacy) not supported |

**Verdict:** Best Python option. Would integrate with existing QGIS tool.

---

### Option D: PowerShell + COM Automation (Word Interop) ⭐ RECOMMENDED

Use Word's own engine via COM to find/replace

| Pros | Cons |
|------|------|
| Handles ALL Word features perfectly | Requires Microsoft Word installed |
| Find/Replace works exactly like in Word | Slow (launches Word process) |
| Supports .doc AND .docx | Can't run on server/headless |
| Handles tracked changes, comments | COM can be flaky/hang |
| No text fragmentation issues | Windows-only |

**Verdict:** Most reliable for quality output. Good for local workstation workflow.

---

### Option E: LibreOffice Headless Conversion

Use LibreOffice CLI to convert to/from formats

| Pros | Cons |
|------|------|
| Free, no MS Office needed | Formatting fidelity varies |
| Can run headless | Large dependency |
| Cross-platform | Conversion artifacts possible |

**Verdict:** Good for server scenarios, not ideal for precision civil engineering work.

---

## Recommended Implementation

Based on the evaluation:

| Format | Method | Notes |
|--------|--------|-------|
| `.txt`, `.md` | Current tools (batch_branch) | Fast, reliable |
| `.docx` | COM Automation via PowerShell | Uses Word's native find/replace |
| `.doc` | COM Automation via PowerShell | Same as above, legacy support |

### Proposed File Structure

```
doc_cleaning_branch/
├── scrub_word.ps1           # Core PowerShell + COM logic
├── scrub_word.bat           # Drag-drop launcher
├── README.md                # Usage documentation
└── Handoff.md               # This file
```

### Integration Points

1. **Read from `master_rules.csv`** - Same rules as other tools
2. **Output to same location** - `filename_Scrubbed.docx`
3. **Optional `-LogNew` flag** - Export new detections for review

---

## Implementation Effort Estimate

| Task | Hours | Notes |
|------|-------|-------|
| COM automation prototype | 3-4 | Basic find/replace working |
| Header/footer handling | 2-3 | Separate document sections in Word |
| Table cell iteration | 2-3 | Word tables have special structure |
| Error handling & cleanup | 2-3 | COM cleanup is critical |
| Testing & edge cases | 3-4 | Various document types |
| **Total** | **12-17** | |

---

## Key Questions Before Implementation

1. **Volume:** How many Word docs per week need scrubbing?
   - 1-2/week: Manual or existing txt workflow may suffice
   - 10+/week: Automation justified

2. **Source vs. Export:** Are Word files the source, or do you export to Word after scrubbing markdown?
   - If export-after: Current workflow works
   - If Word is source: This branch needed

3. **Formatting Complexity:** Do documents have:
   - [ ] Tables
   - [ ] Headers/footers with sensitive data
   - [ ] Text boxes
   - [ ] Comments/tracked changes
   - [ ] Embedded images with text

4. **Deliverable Requirements:** Is scrubbed output for:
   - [ ] Internal AI processing (formatting less critical)
   - [ ] Client deliverable (formatting must be perfect)

---

## Dependencies

- Microsoft Word (Office 365 or standalone)
- PowerShell 5.1+ (built into Windows)
- No additional installs required

---

## Related Documentation

- [python-docx documentation](https://python-docx.readthedocs.io/)
- [Word Object Model Reference](https://docs.microsoft.com/en-us/office/vba/api/overview/word)
- [PowerShell COM Automation Guide](https://docs.microsoft.com/en-us/powershell/scripting/samples/creating-a-custom-input-box)

---

## Next Steps

When ready to implement:

1. Answer the key questions above
2. Create `scrub_word.ps1` with COM automation
3. Test with representative documents
4. Integrate with batch workflow

---

## Session Notes

**January 2025:** Initial planning discussion. Evaluated 5 approaches for handling Word documents. COM Automation (Option D) recommended for local workstation use due to reliability and format support. Created placeholder branch for future implementation.
