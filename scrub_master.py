#!/usr/bin/env python3
"""
Document Scrubber - Master Rules System (Command Line)
======================================================
Living document system that learns from each review session.

Features:
- JSON master rules file (code reads this)
- CSV export for easy editing (reconciled on run)
- Category enable/disable toggles
- Consistent aliases (same text = same replacement)
- Only shows NEW items for review

Usage:
    python scrub_master.py document.txt
    python scrub_master.py document.txt --apply document_REVIEW.csv
    python scrub_master.py --export-rules
    python scrub_master.py --stats

Author: Joey M. Woody P.E.
"""

import re
import os
import json
import csv
import shutil
import argparse
from pathlib import Path
from typing import Dict, List, Tuple, Optional
from collections import OrderedDict
from datetime import datetime


# =============================================================================
# CONFIGURATION - Update this path for your environment
# =============================================================================

RULES_DIR = Path(r"E:\CLAUDE_Workspace\Claude\Report_Files\Projects\Document_Scrubber")


# =============================================================================
# DETECTION PATTERNS
# =============================================================================

DETECTION_PATTERNS = OrderedDict([
    # === CONTACT INFO ===
    ('EMAIL', {
        'pattern': r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b',
        'flags': re.IGNORECASE,
        'default_alias': '[EMAIL]',
        'description': 'Email addresses'
    }),
    ('PHONE', {
        'pattern': r'\b(?:\(\d{3}\)\s*|\d{3}[-.\s])\d{3}[-.\s]\d{4}\b',
        'flags': 0,
        'default_alias': '[PHONE]',
        'description': 'Phone numbers'
    }),
    
    # === ADDRESSES ===
    ('ADDRESS_STREET', {
        'pattern': r'\b\d{1,5}\s+(?:[A-Z][a-z]+\.?\s+){1,4}(?:Street|St\.?|Avenue|Ave\.?|Road|Rd\.?|Boulevard|Blvd\.?|Drive|Dr\.?|Lane|Ln\.?|Way|Court|Ct\.?|Circle|Cir\.?|Place|Pl\.?|Parkway|Pkwy\.?|Trail|Trl\.?)\b',
        'flags': re.IGNORECASE,
        'default_alias': '[ADDRESS]',
        'description': 'Street addresses'
    }),
    ('ADDRESS_HIGHWAY', {
        'pattern': r'\b\d{1,5}\s+(?:Highway|Hwy\.?|US\s*-?\s*|State\s+Route|SR\s*-?\s*|Route|Rt\.?|Interstate|I-)\s*\d{1,4}(?:\s*[NSEW])?\b',
        'flags': re.IGNORECASE,
        'default_alias': '[ADDRESS]',
        'description': 'Highway addresses'
    }),
    ('ADDRESS_POBOX', {
        'pattern': r'\bP\.?\s*O\.?\s*Box\s+\d+\b',
        'flags': re.IGNORECASE,
        'default_alias': '[PO_BOX]',
        'description': 'PO Box addresses'
    }),
    ('ADDRESS_CITY_STATE_ZIP', {
        'pattern': r'\b[A-Z][a-z]+(?:\s+[A-Z][a-z]+)?,\s*(?:AL|AK|AZ|AR|CA|CO|CT|DE|FL|GA|HI|ID|IL|IN|IA|KS|KY|LA|ME|MD|MA|MI|MN|MS|MO|MT|NE|NV|NH|NJ|NM|NY|NC|ND|OH|OK|OR|PA|RI|SC|SD|TN|TX|UT|VT|VA|WA|WV|WI|WY)\s+\d{5}(?:-\d{4})?\b',
        'flags': 0,
        'default_alias': '[CITY_STATE_ZIP]',
        'description': 'City, State ZIP'
    }),
    
    # === NAMES - Multiple formats ===
    ('NAME_TITLED', {
        'pattern': r'\b(?:Mr\.?|Mrs\.?|Ms\.?|Dr\.?)\s+[A-Z][a-z]+(?:\s+[A-Z]\.?)?\s+[A-Z][a-z]+\b',
        'flags': 0,
        'default_alias': '[PERSON_NAME]',
        'description': 'Names with titles (Mr./Mrs./Dr.)'
    }),
    ('NAME_CREDENTIALED', {
        'pattern': r'\b[A-Z][a-z]+(?:\s+[A-Z]\.?)?\s+[A-Z][a-z]+\s*[,.]?\s*(?:PE|P\.?E\.?|EI|EIT|PG|RLA|AICP|CFM|PLS|P\.?L\.?S\.?|RA|AIA|SC\s+P\.?L\.?S\.?)\b',
        'flags': 0,
        'default_alias': '[PERSON_NAME]',
        'description': 'Names with credentials (PE, PLS, etc.)'
    }),
    ('NAME_MIDDLE_INITIAL', {
        'pattern': r'\b[A-Z][a-z]+\s+[A-Z]\.\s*[A-Z][a-z]+\b',
        'flags': 0,
        'default_alias': '[PERSON_NAME]',
        'description': 'Names with middle initial (John A. Smith)'
    }),
    ('NAME_ALLCAPS_CREDENTIAL', {
        'pattern': r'\b[A-Z]{2,}\s+[A-Z]\.?\s*[A-Z]{2,}\s*[,.]?\s*(?:PE|P\.?E\.?|PLS|P\.?L\.?S\.?)\b',
        'flags': 0,
        'default_alias': '[PERSON_NAME]',
        'description': 'ALL CAPS names with credentials'
    }),
    ('NAME_CONTACT_PERSON', {
        'pattern': r'CONTACT\s+PERSON\s*:\s*([A-Z][A-Za-z]+(?:\s+[A-Z]\.?)?\s+[A-Z][A-Za-z]+)',
        'flags': re.IGNORECASE,
        'default_alias': '[CONTACT_NAME]',
        'description': 'Contact Person field'
    }),
    
    # === SURVEY/DEED REFERENCES ===
    ('SURVEY_NF_OWNER', {
        'pattern': r'N/F\s+([A-Z][A-Za-z]+(?:\s+[A-Z]\.?)?(?:\s+(?:&|AND)\s+[A-Z][A-Za-z]+)?\s+[A-Z][A-Za-z]+(?:\s+(?:SURVIVORSHIP|JR\.?|SR\.?|III|IV))?)',
        'flags': 0,
        'default_alias': '[ADJACENT_OWNER]',
        'description': 'N/F (Now or Formerly) owner names'
    }),
    ('SURVEY_PROPERTY_OF', {
        'pattern': r'PROPERTY\s+OF\s+([A-Z][A-Za-z]+(?:\s+[A-Z]\.?)?(?:\s+(?:&|AND)\s+[A-Z][A-Za-z]+)?\s+[A-Z][A-Za-z]+(?:\s+(?:JR\.?|SR\.?|III|IV|LLC|INC))?)',
        'flags': 0,
        'default_alias': '[PROPERTY_OWNER]',
        'description': 'Property Of owner names'
    }),
    ('SURVEY_DEED_BOOK', {
        'pattern': r'(?:DEED\s+BOOK|DB\.?)\s*\d+\s*[,.]?\s*(?:PAGE|PG\.?)\s*\d+',
        'flags': re.IGNORECASE,
        'default_alias': '[DEED_REF]',
        'description': 'Deed Book references'
    }),
    ('SURVEY_PLAT_CAB', {
        'pattern': r'PLAT\s+(?:CAB(?:INET)?|BOOK|BK)\.?\s*[A-Z0-9]+\s*[,.]?\s*(?:PAGE|PG\.?)\s*\d+[A-Z]?',
        'flags': re.IGNORECASE,
        'default_alias': '[PLAT_REF]',
        'description': 'Plat Cabinet/Book references'
    }),
    ('SURVEY_TMS', {
        'pattern': r'TMS\s*#?\s*\[?(?:PARCEL_ID|\d{3,}[-\d]*)\]?',
        'flags': re.IGNORECASE,
        'default_alias': '[TMS_REF]',
        'description': 'TMS (Tax Map) references'
    }),
    ('SURVEY_PARCEL_NUM', {
        'pattern': r'PARCEL\s*:?\s*\d{7,}',
        'flags': re.IGNORECASE,
        'default_alias': '[PARCEL_ID]',
        'description': 'Parcel number (long format)'
    }),
    ('SURVEY_SUBDIVISION', {
        'pattern': r'~[A-Z][A-Za-z\s]+(?:S/D|SUBDIVISION|SUBD)~',
        'flags': re.IGNORECASE,
        'default_alias': '[SUBDIVISION]',
        'description': 'Subdivision references'
    }),
    ('SURVEY_BLOCK_LOT', {
        'pattern': r'\b(?:BLOCK|BLK\.?)\s+[A-Z0-9]+(?:\s+(?:LOT|LT\.?)\s+\d+)?',
        'flags': re.IGNORECASE,
        'default_alias': '[BLOCK_LOT]',
        'description': 'Block/Lot references'
    }),
    
    # === COMPANIES ===
    ('COMPANY_SURVEYING', {
        'pattern': r'\b[A-Z][A-Za-z]+(?:\s+[A-Z][A-Za-z]+)*\s+(?:SURVEYING|ENGINEERING|CONSULTING)\s*[,.]?\s*(?:INC\.?|LLC|CO\.?|CORP\.?)?\b',
        'flags': re.IGNORECASE,
        'default_alias': '[COMPANY]',
        'description': 'Surveying/Engineering companies'
    }),
    ('COMPANY_PLANNING', {
        'pattern': r'\b[A-Z][A-Za-z]+(?:\s+[A-Z][A-Za-z]+)*\s+(?:PLANNING|ARCHITECTURE|LANDSCAPE\s+ARCHITECTURE)\b',
        'flags': re.IGNORECASE,
        'default_alias': '[COMPANY]',
        'description': 'Planning/Architecture companies'
    }),
    
    # === IDs & LICENSES ===
    ('PE_LICENSE', {
        'pattern': r'\b(?:PE|P\.E\.?)\s*#?\s*:?\s*\d{4,6}\b',
        'flags': re.IGNORECASE,
        'default_alias': '[PE_NUMBER]',
        'description': 'PE License numbers'
    }),
    ('PLS_LICENSE', {
        'pattern': r'\b(?:PLS|P\.L\.S\.?)\s*#?\s*:?\s*\d{4,6}\b',
        'flags': re.IGNORECASE,
        'default_alias': '[PLS_NUMBER]',
        'description': 'PLS License numbers'
    }),
    ('PERMIT_ID', {
        'pattern': r'\b(?:CAA|SWP|NPDES|SWPPP)[-\s]?(?:No\.?|#)?[-\s:]?\s*\d{2,}[-\d]*\b',
        'flags': re.IGNORECASE,
        'default_alias': '[PERMIT_ID]',
        'description': 'Permit/CAA numbers'
    }),
    ('PARCEL_ID', {
        'pattern': r'\b\d{10}\b',
        'flags': 0,
        'default_alias': '[PARCEL_ID]',
        'description': '10-digit Parcel IDs'
    }),
    ('PARCEL_ID_DASHED', {
        'pattern': r'\b[RT]?\d{3,4}-\d{2,4}-\d{2,4}(?:-\d{3,4})?\b',
        'flags': 0,
        'default_alias': '[PARCEL_ID]',
        'description': 'Dashed Parcel/Tax IDs'
    }),
    ('SSN', {
        'pattern': r'\b\d{3}-\d{2}-\d{4}\b',
        'flags': 0,
        'default_alias': '[SSN_REDACTED]',
        'description': 'Social Security Numbers'
    }),
    ('COORDINATES', {
        'pattern': r'\b-?\d{1,3}\.\d{4,}\s*,\s*-?\d{1,3}\.\d{4,}\b',
        'flags': 0,
        'default_alias': '[COORDINATES]',
        'description': 'GPS coordinates'
    }),
])


# =============================================================================
# MASTER RULES CLASS
# =============================================================================

class MasterRules:
    """Manage the master redaction rules."""
    
    def __init__(self, rules_dir=None):
        if rules_dir is None:
            rules_dir = RULES_DIR
        self.rules_dir = Path(rules_dir)
        
        self.json_path = self.rules_dir / "master_rules.json"
        self.csv_path = self.rules_dir / "master_rules.csv"
        self.template_path = self.rules_dir / "master_rules.template.json"
        
        self.rules = self._load_rules()
    
    def _load_rules(self) -> dict:
        """Load rules from JSON, creating from template if needed."""
        if not self.json_path.exists():
            if self.template_path.exists():
                shutil.copy(self.template_path, self.json_path)
                print(f"Created master_rules.json from template")
            else:
                return self._create_default_rules()
        
        with open(self.json_path, 'r', encoding='utf-8') as f:
            rules = json.load(f)
        
        if self.csv_path.exists():
            rules = self._reconcile_csv(rules)
        
        return rules
    
    def _create_default_rules(self) -> dict:
        """Create default rules structure."""
        rules = {
            "version": "1.0",
            "categories": {},
            "always_redact": {},
            "never_redact": []
        }
        for cat_name, cat_config in DETECTION_PATTERNS.items():
            rules["categories"][cat_name] = {
                "enabled": True,
                "default_alias": cat_config['default_alias'],
                "description": cat_config['description']
            }
        return rules
    
    def _reconcile_csv(self, rules: dict) -> dict:
        """Reconcile rules with CSV edits."""
        print(f"Reconciling with CSV: {self.csv_path}")
        
        try:
            with open(self.csv_path, 'r', encoding='utf-8') as f:
                reader = csv.DictReader(f)
                for row in reader:
                    action = row.get('Action', '').upper().strip()
                    text = row.get('Text', '').strip()
                    alias = row.get('Alias', '').strip()
                    
                    if not text:
                        continue
                    
                    if action == 'REDACT':
                        if alias:
                            rules['always_redact'][text] = alias
                        elif text not in rules['always_redact']:
                            rules['always_redact'][text] = '[REDACTED]'
                        if text in rules['never_redact']:
                            rules['never_redact'].remove(text)
                    elif action == 'SKIP':
                        if text not in rules['never_redact']:
                            rules['never_redact'].append(text)
                        if text in rules['always_redact']:
                            del rules['always_redact'][text]
                    elif action == 'DELETE':
                        if text in rules['always_redact']:
                            del rules['always_redact'][text]
                        if text in rules['never_redact']:
                            rules['never_redact'].remove(text)
            
            print(f"  Reconciled: {len(rules['always_redact'])} redact, {len(rules['never_redact'])} skip")
        except Exception as e:
            print(f"Warning: Could not reconcile CSV: {e}")
        
        return rules
    
    def save(self):
        """Save rules to JSON file."""
        if self.json_path.exists():
            backup_path = self.json_path.with_suffix('.json.bak')
            shutil.copy(self.json_path, backup_path)
        
        with open(self.json_path, 'w', encoding='utf-8') as f:
            json.dump(self.rules, f, indent=2)
        
        print(f"Saved rules to: {self.json_path}")
    
    def export_csv(self) -> str:
        """Export rules to CSV for editing."""
        rows = []
        for text, alias in self.rules.get('always_redact', {}).items():
            rows.append({'Action': 'REDACT', 'Text': text, 'Alias': alias, 'Category': '', 'Notes': ''})
        for text in self.rules.get('never_redact', []):
            rows.append({'Action': 'SKIP', 'Text': text, 'Alias': '', 'Category': '', 'Notes': ''})
        
        rows.sort(key=lambda x: (x['Action'], x['Text'].lower()))
        
        with open(self.csv_path, 'w', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=['Action', 'Text', 'Alias', 'Category', 'Notes'])
            writer.writeheader()
            writer.writerows(rows)
        
        print(f"Exported CSV to: {self.csv_path}")
        return str(self.csv_path)
    
    def is_category_enabled(self, category: str) -> bool:
        return self.rules.get('categories', {}).get(category, {}).get('enabled', True)
    
    def get_default_alias(self, category: str) -> str:
        return self.rules.get('categories', {}).get(category, {}).get('default_alias', f'[{category}]')
    
    def should_redact(self, text: str) -> Tuple[bool, Optional[str]]:
        if text in self.rules.get('never_redact', []):
            return (False, None)
        if text in self.rules.get('always_redact', {}):
            return (True, self.rules['always_redact'][text])
        return (None, None)
    
    def add_redact(self, text: str, alias: str):
        self.rules['always_redact'][text] = alias
        if text in self.rules.get('never_redact', []):
            self.rules['never_redact'].remove(text)
    
    def add_skip(self, text: str):
        if text not in self.rules.get('never_redact', []):
            self.rules['never_redact'].append(text)
        if text in self.rules.get('always_redact', {}):
            del self.rules['always_redact'][text]
    
    def get_stats(self) -> dict:
        return {
            'always_redact': len(self.rules.get('always_redact', {})),
            'never_redact': len(self.rules.get('never_redact', [])),
            'categories_enabled': sum(1 for c in self.rules.get('categories', {}).values() if c.get('enabled', True)),
            'categories_total': len(self.rules.get('categories', {}))
        }


# =============================================================================
# DOCUMENT SCANNER
# =============================================================================

class DocumentScanner:
    """Scan documents using master rules."""
    
    def __init__(self, rules: MasterRules):
        self.rules = rules
    
    def scan(self, text: str) -> dict:
        """Scan document and categorize findings."""
        new_items = []
        auto_redact = []
        auto_skip = []
        seen = set()
        
        for cat_name, cat_config in DETECTION_PATTERNS.items():
            if not self.rules.is_category_enabled(cat_name):
                continue
            
            pattern = cat_config['pattern']
            flags = cat_config.get('flags', 0)
            default_alias = self.rules.get_default_alias(cat_name)
            
            for match in re.finditer(pattern, text, flags):
                match_text = match.group(0)
                if match_text in seen:
                    continue
                seen.add(match_text)
                
                start = max(0, match.start() - 40)
                end = min(len(text), match.end() + 40)
                context = text[start:end].replace('\n', ' ').strip()
                
                item = {
                    'text': match_text,
                    'category': cat_name,
                    'default_alias': default_alias,
                    'context': context
                }
                
                should_redact, alias = self.rules.should_redact(match_text)
                
                if should_redact is True:
                    item['alias'] = alias
                    auto_redact.append(item)
                elif should_redact is False:
                    auto_skip.append(item)
                else:
                    new_items.append(item)
        
        return {
            'new_items': new_items,
            'auto_redact': auto_redact,
            'auto_skip': auto_skip,
            'total_found': len(seen)
        }
    
    def apply_redactions(self, text: str, reviewed_items: List[dict] = None) -> str:
        """Apply redactions to text."""
        replacements = dict(self.rules.rules.get('always_redact', {}))
        
        if reviewed_items:
            for item in reviewed_items:
                if item.get('action') == 'REDACT':
                    replacements[item['text']] = item.get('alias', item.get('default_alias', '[REDACTED]'))
        
        sorted_items = sorted(replacements.items(), key=lambda x: len(x[0]), reverse=True)
        
        result = text
        for match_text, alias in sorted_items:
            pattern = re.escape(match_text)
            result = re.sub(pattern, alias, result, flags=re.IGNORECASE)
        
        return result


# =============================================================================
# HELPER FUNCTIONS
# =============================================================================

def read_file_with_fallback(filepath: str) -> str:
    """Read file with multiple encoding fallbacks."""
    encodings = ['utf-8', 'cp1252', 'latin-1', 'iso-8859-1']
    
    for encoding in encodings:
        try:
            with open(filepath, 'r', encoding=encoding) as f:
                return f.read()
        except UnicodeDecodeError:
            continue
    
    raise ValueError(f"Could not read file with any supported encoding: {filepath}")


def export_review_csv(new_items: List[dict], output_path: str) -> str:
    """Export new items to CSV for review."""
    with open(output_path, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=['Action', 'Text', 'Alias', 'Category', 'Context', 'Notes'])
        writer.writeheader()
        for item in new_items:
            writer.writerow({
                'Action': 'REDACT',
                'Text': item['text'],
                'Alias': item['default_alias'],
                'Category': item['category'],
                'Context': item['context'][:80],
                'Notes': ''
            })
    return output_path


def import_review_csv(csv_path: str) -> List[dict]:
    """Import reviewed items from CSV."""
    items = []
    with open(csv_path, 'r', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        for row in reader:
            items.append({
                'text': row.get('Text', ''),
                'action': row.get('Action', 'REDACT').upper().strip(),
                'alias': row.get('Alias', '[REDACTED]'),
                'category': row.get('Category', '')
            })
    return items


# =============================================================================
# MAIN
# =============================================================================

def main():
    parser = argparse.ArgumentParser(
        description="Document Scrubber with Master Rules System",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
WORKFLOW:
=========

Scan document (generates review CSV for new items only):
  python scrub_master.py document.txt

Review the CSV, then apply:
  python scrub_master.py document.txt --apply document_REVIEW.csv

Export master rules to CSV for editing:
  python scrub_master.py --export-rules

View stats:
  python scrub_master.py --stats
        """
    )
    
    parser.add_argument('input_file', nargs='?', help='Input document to scrub')
    parser.add_argument('--apply', '-a', metavar='CSV', help='Apply reviewed CSV')
    parser.add_argument('--output', '-o', help='Output file path')
    parser.add_argument('--export-rules', action='store_true', help='Export master rules to CSV')
    parser.add_argument('--stats', action='store_true', help='Show rules statistics')
    
    args = parser.parse_args()
    
    # Initialize rules
    rules = MasterRules()
    
    if args.export_rules:
        rules.export_csv()
        return
    
    if args.stats:
        stats = rules.get_stats()
        print("\nMaster Rules Statistics:")
        print(f"  Always redact: {stats['always_redact']} items")
        print(f"  Never redact:  {stats['never_redact']} items")
        print(f"  Categories:    {stats['categories_enabled']}/{stats['categories_total']} enabled")
        print(f"\nRules location: {rules.json_path}")
        return
    
    if not args.input_file:
        parser.print_help()
        return
    
    # Load document
    input_path = Path(args.input_file)
    if not input_path.exists():
        print(f"Error: File not found: {args.input_file}")
        return
    
    print(f"\nLoading: {input_path}")
    content = read_file_with_fallback(str(input_path))
    
    # Scan document
    scanner = DocumentScanner(rules)
    results = scanner.scan(content)
    
    print(f"\nScan Results:")
    print(f"  Total found:    {results['total_found']}")
    print(f"  Auto-redact:    {len(results['auto_redact'])} (in master rules)")
    print(f"  Auto-skip:      {len(results['auto_skip'])} (in skip list)")
    print(f"  NEW for review: {len(results['new_items'])}")
    
    if args.apply:
        print(f"\nLoading review: {args.apply}")
        reviewed = import_review_csv(args.apply)
        
        for item in reviewed:
            if item['action'] == 'REDACT':
                rules.add_redact(item['text'], item['alias'])
            elif item['action'] == 'SKIP':
                rules.add_skip(item['text'])
        
        rules.save()
        scrubbed = scanner.apply_redactions(content, reviewed)
        
        if args.output:
            output_path = Path(args.output)
        else:
            output_path = input_path.parent / f"{input_path.stem}_Scrubbed{input_path.suffix}"
        
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(scrubbed)
        
        print(f"\nScrubbed file saved: {output_path}")
        print(f"Master rules updated with {len(reviewed)} reviewed items")
        
    elif results['new_items']:
        review_path = input_path.parent / f"{input_path.stem}_REVIEW.csv"
        export_review_csv(results['new_items'], str(review_path))
        
        print(f"\nReview CSV created: {review_path}")
        print("\nNext steps:")
        print(f"  1. Edit {review_path.name}")
        print(f"     - Change 'Action' to 'SKIP' for items to keep")
        print(f"     - Edit 'Alias' column for custom replacements")
        print(f"  2. Run: python scrub_master.py \"{args.input_file}\" --apply \"{review_path}\"")
        
    else:
        scrubbed = scanner.apply_redactions(content)
        
        if args.output:
            output_path = Path(args.output)
        else:
            output_path = input_path.parent / f"{input_path.stem}_Scrubbed{input_path.suffix}"
        
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(scrubbed)
        
        print(f"\nNo new items to review!")
        print(f"Applied {len(results['auto_redact'])} redactions from master rules")
        print(f"Scrubbed file saved: {output_path}")


if __name__ == "__main__":
    main()
