# Document Scrubber

A Python utility for removing personal and project-specific data from text documents before sharing or publishing. Features both a command-line interface and a multi-themed graphical interface.

## Features

- **Automatic PII Detection**: Identifies and replaces sensitive information using regex patterns
- **Multi-Themed GUI**: 8 visual themes (Twisty, Enterprise, Cyberpunk, Kinetic, Bauhaus, Academia, Sketch, Playful Geometric)
- **Command Line Interface**: Full-featured CLI with interactive mode
- **Custom Configuration**: JSON config files for project-specific scrubbing rules
- **No External Dependencies**: Uses only Python standard library

## What It Scrubs

### Standard Patterns
| Pattern Type | Example | Replacement |
|-------------|---------|-------------|
| Email | john@example.com | [EMAIL] |
| Phone | (555) 123-4567 | [PHONE] |
| PE License | PE #12345 | [PE_NUMBER] |
| Permit ID | SWP-24-01-0001 | [PERMIT_ID] |
| Address | 123 Main Street | [PROJECT_ADDRESS] |
| Name with title | Mr. John Smith | [PERSON_NAME] |
| Name with credential | John Smith, PE | [PERSON_NAME] |
| Name in parentheses | (Charles R. Hager, PE) | ([PERSON_NAME]) |
| Company | Acme Engineering LLC | [FIRM_NAME] |
| Jurisdiction | Town of Springfield | [LOCAL_JURISDICTION] |
| ZIP Code | 12345 | [ZIP] |
| SSN | 123-45-6789 | [SSN_REDACTED] |
| Coordinates | 32.7767, -96.7970 | [COORDINATES] |
| Parcel ID | R123-45-67-890 | [PARCEL_ID] |

### Line-Based Field Patterns
| Field Label | Example | Replacement |
|-------------|---------|-------------|
| Project Name | Project Name: Oak Hills Development | Project Name: Current_Project |
| Project Location | Site Location: 123 Main St, Anytown | Site Location: TBD |
| Developer | Developer: ABC Development Corp | Developer: [DEVELOPER] |
| Owner | Owner: Smith Family Trust | Owner: [DEVELOPER] |
| Applicant | Applicant: XYZ Holdings LLC | Applicant: [DEVELOPER] |
| Engineer of Record | Engineer of Record: Acme Inc. (John Smith, PE) | Engineer of Record: [FIRM_NAME] |

## Requirements

- Python 3.7 or higher
- No external dependencies (uses standard library only)
- For GUI: Requires tkinter (included with most Python installations)
- For GUI themes: Access to [GUI Design Center Library](https://github.com/Joeywoody124/GUI_Design_Center_Library) styles folder

## Installation

```bash
git clone https://github.com/Joeywoody124/Document_Scrubber.git
cd Document_Scrubber
```

## Quick Start

### GUI Mode (Recommended)

```bash
python scrub_gui.py
```

Features:
- 8 visual themes with runtime switching
- File browser dialogs starting in current directory
- Auto-generates output filename with "_Scrubbed" suffix
- Real-time results display

### Command Line Mode

```bash
# Interactive mode (prompted for file path)
python scrub_document.py

# Direct file processing
python scrub_document.py document.txt

# Specify output file
python scrub_document.py document.txt --output scrubbed.txt

# Interactive confirmation of each replacement
python scrub_document.py document.txt --interactive

# Use custom configuration
python scrub_document.py document.txt --config my_config.json

# Create sample config file
python scrub_document.py --create-config
```

### Batch Mode (Multiple Files)

```bash
# Process all .txt and .md files in a folder
python scrub_batch.py "E:\Documents\Reports"

# Specify custom output folder
python scrub_batch.py "E:\Documents\Reports" --output "E:\Scrubbed"

# Use custom config for project-specific terms
python scrub_batch.py "E:\Documents\Reports" --config my_config.json

# Process additional file types
python scrub_batch.py "E:\Documents\Reports" --extensions .txt .md .log
```

**Batch Output:**
- Creates `_Scrubbed` subfolder (or specified output folder)
- Scrubbed files with `_Scrubbed` suffix
- `SCRUB_REPORT.txt` - Detailed summary with all detected items
- `SCRUB_REPORT.csv` - Spreadsheet-compatible report for analysis

## Custom Configuration

Create a JSON config file for project-specific replacements:

```json
{
  "description": "Project-specific scrubbing rules",
  "patterns": {
    "Specific School Name": "[PROJECT_NAME]",
    "Local River Name": "[RECEIVING_WATER]"
  },
  "replacements": {
    "John Smith": "[ENGINEER_OF_RECORD]",
    "Acme Engineering": "[FIRM_NAME]",
    "123 Project Drive": "[PROJECT_ADDRESS]"
  }
}
```

## GUI Themes

| Theme | Mode | Style |
|-------|------|-------|
| Twisty | Dark | Fintech SaaS, violet-indigo gradients |
| Enterprise | Light | Professional, indigo-violet, elevated cards |
| Cyberpunk | Dark | Neon Matrix green, glitch aesthetic |
| Kinetic | Dark | High-energy brutalism, acid yellow |
| Bauhaus | Light | Geometric, primary colors |
| Academia | Dark | Scholarly, brass and crimson |
| Sketch | Light | Hand-drawn, playful, organic |
| Playful Geometric | Light | Memphis, bouncy, colorful |

## Configuration for GUI Themes

The GUI loads themes from the GUI Design Center Library. Update the `STYLES_BASE_PATH` in `scrub_gui.py` to match your installation:

```python
STYLES_BASE_PATH = Path(r"path/to/GUI_Design_Center_Library/styles")
```

## Supported File Types

- `.txt` - Plain text files
- `.md` - Markdown files

## Best Practices

1. **Always review output manually** - Automated detection is not perfect
2. **Run in interactive mode first** - Learn what the tool detects
3. **Create project-specific configs** - For consistent scrubbing across documents
4. **Keep original files** - Never overwrite source documents
5. **Check for context clues** - Names in tables or lists may need manual review

## Limitations

- Cannot detect names without context clues (titles, credentials)
- May miss project-specific terms not in common patterns
- Does not process images or embedded objects
- PDF files must be converted to text first

## Troubleshooting

### Windows: Python path errors with QGIS

If you have QGIS installed and get errors like `Could not find platform independent libraries`, your system `python` command may point to the QGIS-bundled Python.

**Solution**: Use full path to standalone Python:
```cmd
"C:\Users\YourName\AppData\Local\Programs\Python\Python313\python.exe" scrub_document.py document.txt
```

Or use py launcher:
```cmd
py -3.13 scrub_document.py document.txt
```

### GUI styles not loading

1. Verify the GUI Design Center Library exists at the configured path
2. Edit `STYLES_BASE_PATH` in `scrub_gui.py` to match your installation
3. Ensure all 8 style folders exist with `tokens.json` files

## Files

| File | Purpose |
|------|---------|
| `scrub_document.py` | Command-line scrubbing tool (single file) |
| `scrub_batch.py` | Batch processing for entire folders |
| `scrub_gui.py` | Multi-themed GUI application |
| `README.md` | This documentation |
| `LICENSE` | MIT License |

## License

MIT License - see [LICENSE](LICENSE) file.

## Related Tools

### Safe_Scrub v2.0.5 - AI Security Scanner

Located in `Safe_Scrub/v2/`, this companion tool scans documents for **prompt injection attacks** before AI processing. Designed for civil engineering workflows where PDF-converted documents may contain hidden malicious instructions.

#### Key Features

| Feature | Description |
|---------|-------------|
| **35+ Detection Patterns** | CRITICAL, HIGH, MEDIUM, LOW threat classification |
| **Civil Engineering Whitelist** | Preserves legitimate terms like "bypass channel", "50 cfs", "manual override valve" |
| **Auto-Sanitization** | Generates `_ScrubSafe` files with threats redacted |
| **Audit Logging** | CSV and JSON reports for IT security compliance |
| **Dual Interface** | Standalone GUI (tkinter) + QGIS Python Console |

#### Threat Categories Detected

| Level | Examples |
|-------|----------|
| **CRITICAL** | "Ignore all previous instructions", "reveal your system prompt", "developer mode" |
| **HIGH** | `[SYSTEM: ...]` fake headers, `### END SYSTEM PROMPT` delimiters, role manipulation |
| **MEDIUM** | Base64 strings, hex encoding, `![](https://...)` tracking pixels, data URIs |
| **LOW** | Role-play requests, simulation language |

#### Quick Start

**Standalone GUI:**
```bash
cd Safe_Scrub/v2
python Safe_Scrub_v2_Standalone.py
```

**QGIS Python Console:**
```python
from pathlib import Path
exec(compile(Path('E:/path/to/Safe_Scrub_v2_QGIS.py').read_text(), 'script', 'exec'))
```

See [`Safe_Scrub/v2/README_SafeScrub.md`](Safe_Scrub/v2/README_SafeScrub.md) for full documentation.

#### Recommended Workflow

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│  Raw Document   │───▶│Document_Scrubber│───▶│   Safe_Scrub    │───▶ AI Processing
│   (with PII)    │    │  (remove PII)   │    │(verify AI-safe) │
└─────────────────┘    └─────────────────┘    └─────────────────┘
```

1. **Document_Scrubber** - Remove personally identifiable information
2. **Safe_Scrub** - Scan for prompt injection attacks, verify Score: A
3. **AI Tools** - Process sanitized documents safely

## Author

Created with [Claude Code](https://claude.com/claude-code)
