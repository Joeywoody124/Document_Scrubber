#!/usr/bin/env python3
"""
Document Scrubber - Remove personal and project-specific data from text documents.

This script identifies and replaces sensitive information including:
- Names (people, companies, jurisdictions)
- Addresses and locations
- Phone numbers and emails
- License and permit numbers
- Project-specific identifiers

Usage:
    python scrub_document.py [input_file] [--output output_file] [--config config.json]
"""

import re
import os
import sys
import json
import argparse
from pathlib import Path
from typing import Dict, List, Tuple
from datetime import datetime


# Default replacement patterns
DEFAULT_PATTERNS = {
    # Email addresses
    r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b': '[EMAIL]',

    # Phone numbers (various formats)
    r'\b\d{3}[-.\s]?\d{3}[-.\s]?\d{4}\b': '[PHONE]',
    r'\(\d{3}\)\s*\d{3}[-.\s]?\d{4}': '[PHONE]',

    # PE License numbers (common formats)
    r'\bPE\s*#?\s*\d{4,6}\b': '[PE_NUMBER]',
    r'\bP\.?E\.?\s*(?:License|Lic\.?|No\.?|#)\s*:?\s*\d{4,6}\b': '[PE_NUMBER]',
    r'(?:License|Lic\.?)\s*(?:No\.?|#)\s*:?\s*\d{4,6}': '[PE_NUMBER]',

    # Permit numbers (SWP-XX-XX-XXXX format and similar)
    r'\b[A-Z]{2,4}-\d{2}-\d{2}-\d{4}\b': '[PERMIT_ID]',
    r'\bSWP-[\dA-Z-]+\b': '[PERMIT_ID]',
    r'\bPermit\s*(?:No\.?|#)\s*:?\s*[\w-]+': '[PERMIT_ID]',

    # Street addresses
    r'\b\d{1,5}\s+(?:[A-Z][a-z]+\s+){1,3}(?:Street|St\.?|Avenue|Ave\.?|Road|Rd\.?|Boulevard|Blvd\.?|Drive|Dr\.?|Lane|Ln\.?|Way|Court|Ct\.?|Circle|Cir\.?|Place|Pl\.?)\b': '[PROJECT_ADDRESS]',

    # ZIP codes
    r'\b\d{5}(?:-\d{4})?\b': '[ZIP]',

    # SSN (if accidentally included)
    r'\b\d{3}-\d{2}-\d{4}\b': '[SSN_REDACTED]',

    # Coordinates (lat/long)
    r'\b-?\d{1,3}\.\d{4,}\s*,\s*-?\d{1,3}\.\d{4,}\b': '[COORDINATES]',

    # Parcel/Tax ID numbers
    r'\b[RT]?\d{3,4}-\d{2,4}-\d{2,4}-\d{3,4}\b': '[PARCEL_ID]',
}

# Common name patterns to detect (will be refined by context)
NAME_INDICATORS = [
    r'(?:Mr\.|Mrs\.|Ms\.|Dr\.)\s+[A-Z][a-z]+\s+[A-Z][a-z]+',
    r'(?:Prepared\s+by|Engineer|Reviewer|Owner|Applicant|Contact)\s*:\s*([A-Z][a-z]+\s+[A-Z][a-z]+)',
    r'([A-Z][a-z]+\s+[A-Z][a-z]+)\s*,\s*(?:PE|P\.E\.|EI|EIT|PG|RLA|AICP)',
]

# Company/Firm indicators - require explicit company suffix with word boundary
COMPANY_INDICATORS = [
    r'(?:prepared\s+by|submitted\s+by|designed\s+by)\s*:?\s*([A-Z][A-Za-z\s&]+(?:LLC|Inc\.?|Corp\.?|Engineering|Consulting|Associates)\b)',
    r'\b([A-Z][A-Za-z]+(?:\s+[A-Z][A-Za-z]+)*\s+(?:LLC|Inc\.?|Corp\.?|Engineering|Consulting|Associates))\b',
]

# Technical terms to exclude from company detection
TECHNICAL_EXCLUSIONS = {
    'Hydrologic Soil Group',
    'Soil Group',
    'Project Group',
    'Working Group',
    'Control Group',
    'Study Group',
}

# Jurisdiction indicators
JURISDICTION_PATTERNS = [
    r'(?:Town|City|County|Village|Borough|Township)\s+of\s+([A-Z][a-z]+(?:\s+[A-Z][a-z]+)?)',
    r'([A-Z][a-z]+(?:\s+[A-Z][a-z]+)?)\s+(?:Town|City|County|Village|Borough|Township)',
]


class DocumentScrubber:
    """Main class for scrubbing sensitive data from documents."""

    def __init__(self, config_path: str = None):
        """Initialize scrubber with optional custom config."""
        self.patterns = DEFAULT_PATTERNS.copy()
        self.custom_replacements: Dict[str, str] = {}
        self.detected_items: Dict[str, List[str]] = {
            'names': [],
            'companies': [],
            'jurisdictions': [],
            'addresses': [],
            'other': []
        }

        if config_path and os.path.exists(config_path):
            self._load_config(config_path)

    def _load_config(self, config_path: str):
        """Load custom configuration from JSON file."""
        try:
            with open(config_path, 'r', encoding='utf-8') as f:
                config = json.load(f)

            # Add custom patterns
            if 'patterns' in config:
                self.patterns.update(config['patterns'])

            # Add exact string replacements
            if 'replacements' in config:
                self.custom_replacements = config['replacements']

            print(f"Loaded configuration from {config_path}")
        except Exception as e:
            print(f"Warning: Could not load config file: {e}")

    def _detect_names(self, text: str) -> List[Tuple[str, str]]:
        """Detect potential names in text."""
        found = []
        for pattern in NAME_INDICATORS:
            matches = re.finditer(pattern, text, re.IGNORECASE)
            for match in matches:
                # Get the captured group if exists, otherwise full match
                name = match.group(1) if match.lastindex else match.group(0)
                name = name.strip()
                if name and len(name) > 3:
                    found.append((name, '[PERSON_NAME]'))
                    if name not in self.detected_items['names']:
                        self.detected_items['names'].append(name)
        return found

    def _detect_companies(self, text: str) -> List[Tuple[str, str]]:
        """Detect company/firm names in text."""
        found = []
        for pattern in COMPANY_INDICATORS:
            matches = re.finditer(pattern, text, re.IGNORECASE)
            for match in matches:
                company = match.group(1) if match.lastindex else match.group(0)
                company = company.strip()
                # Skip technical terms that match company patterns
                if company in TECHNICAL_EXCLUSIONS:
                    continue
                if company and len(company) > 5:
                    found.append((company, '[FIRM_NAME]'))
                    if company not in self.detected_items['companies']:
                        self.detected_items['companies'].append(company)
        return found

    def _detect_jurisdictions(self, text: str) -> List[Tuple[str, str]]:
        """Detect jurisdiction names in text."""
        found = []
        for pattern in JURISDICTION_PATTERNS:
            matches = re.finditer(pattern, text)
            for match in matches:
                full_match = match.group(0)
                found.append((full_match, '[LOCAL_JURISDICTION]'))
                if full_match not in self.detected_items['jurisdictions']:
                    self.detected_items['jurisdictions'].append(full_match)
        return found

    def scrub(self, text: str, interactive: bool = False) -> str:
        """
        Scrub sensitive data from text.

        Args:
            text: Input text to scrub
            interactive: If True, prompt user to confirm each replacement

        Returns:
            Scrubbed text with placeholders
        """
        result = text

        # Apply custom exact replacements first
        for original, replacement in self.custom_replacements.items():
            if original in result:
                result = result.replace(original, replacement)
                print(f"  Replaced: '{original}' -> '{replacement}'")

        # Apply regex patterns
        for pattern, replacement in self.patterns.items():
            matches = list(re.finditer(pattern, result, re.IGNORECASE))
            for match in reversed(matches):  # Reverse to preserve positions
                original_text = match.group(0)
                if interactive:
                    response = input(f"  Replace '{original_text}' with '{replacement}'? [Y/n/custom]: ").strip()
                    if response.lower() == 'n':
                        continue
                    elif response and response.lower() != 'y':
                        replacement = response

                result = result[:match.start()] + replacement + result[match.end():]

        # Detect and replace names
        names = self._detect_names(result)
        for name, replacement in names:
            if interactive:
                response = input(f"  Replace name '{name}' with '{replacement}'? [Y/n/custom]: ").strip()
                if response.lower() == 'n':
                    continue
                elif response and response.lower() != 'y':
                    replacement = response
            result = re.sub(re.escape(name), replacement, result)

        # Detect and replace companies
        companies = self._detect_companies(result)
        for company, replacement in companies:
            if interactive:
                response = input(f"  Replace company '{company}' with '{replacement}'? [Y/n/custom]: ").strip()
                if response.lower() == 'n':
                    continue
                elif response and response.lower() != 'y':
                    replacement = response
            result = re.sub(re.escape(company), replacement, result)

        # Detect and replace jurisdictions
        jurisdictions = self._detect_jurisdictions(result)
        for jurisdiction, replacement in jurisdictions:
            if interactive:
                response = input(f"  Replace jurisdiction '{jurisdiction}' with '{replacement}'? [Y/n/custom]: ").strip()
                if response.lower() == 'n':
                    continue
                elif response and response.lower() != 'y':
                    replacement = response
            result = re.sub(re.escape(jurisdiction), replacement, result)

        return result

    def scrub_file(self, input_path: str, output_path: str = None,
                   interactive: bool = False) -> str:
        """
        Scrub a file and save the result.

        Args:
            input_path: Path to input file
            output_path: Path for output file (default: input_scrubbed.ext)
            interactive: If True, prompt for each replacement

        Returns:
            Path to output file
        """
        input_path = Path(input_path)

        if not input_path.exists():
            raise FileNotFoundError(f"Input file not found: {input_path}")

        # Validate file type
        valid_extensions = {'.txt', '.md', '.markdown'}
        if input_path.suffix.lower() not in valid_extensions:
            print(f"Warning: File type '{input_path.suffix}' may not be fully supported.")

        # Read input file
        print(f"\nReading: {input_path}")
        with open(input_path, 'r', encoding='utf-8') as f:
            content = f.read()

        print(f"Original size: {len(content)} characters")

        # Scrub content
        print("\nScrubbing document...")
        scrubbed = self.scrub(content, interactive=interactive)

        # Determine output path
        if output_path is None:
            output_path = input_path.parent / f"{input_path.stem}_scrubbed{input_path.suffix}"
        else:
            output_path = Path(output_path)

        # Write output file
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(scrubbed)

        print(f"\nScrubbed file saved: {output_path}")
        print(f"Output size: {len(scrubbed)} characters")

        return str(output_path)

    def print_summary(self):
        """Print summary of detected items."""
        print("\n" + "="*50)
        print("SCRUBBING SUMMARY")
        print("="*50)

        for category, items in self.detected_items.items():
            if items:
                print(f"\n{category.upper()} detected ({len(items)}):")
                for item in items[:10]:  # Limit display
                    print(f"  - {item}")
                if len(items) > 10:
                    print(f"  ... and {len(items) - 10} more")


def create_sample_config():
    """Create a sample configuration file."""
    sample_config = {
        "description": "Custom scrubbing configuration",
        "patterns": {
            r"Example School": "[PROJECT_NAME]",
            r"Acme Engineering": "[FIRM_NAME]"
        },
        "replacements": {
            "John Smith": "[ENGINEER_OF_RECORD]",
            "123 Main Street": "[PROJECT_ADDRESS]",
            "Smithville County": "[LOCAL_JURISDICTION]"
        }
    }

    config_path = Path(__file__).parent / "scrub_config_sample.json"
    with open(config_path, 'w', encoding='utf-8') as f:
        json.dump(sample_config, f, indent=2)

    print(f"Sample config created: {config_path}")
    return config_path


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="Scrub personal and project-specific data from documents.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python scrub_document.py document.txt
  python scrub_document.py document.md --output clean.md
  python scrub_document.py document.txt --interactive
  python scrub_document.py document.txt --config my_config.json
  python scrub_document.py --create-config
        """
    )

    parser.add_argument('input_file', nargs='?', help='Input file to scrub (.txt or .md)')
    parser.add_argument('--output', '-o', help='Output file path (default: input_scrubbed.ext)')
    parser.add_argument('--config', '-c', help='Path to custom config JSON file')
    parser.add_argument('--interactive', '-i', action='store_true',
                        help='Interactively confirm each replacement')
    parser.add_argument('--create-config', action='store_true',
                        help='Create a sample configuration file')

    args = parser.parse_args()

    # Create sample config if requested
    if args.create_config:
        create_sample_config()
        return

    # If no input file, prompt for one
    if not args.input_file:
        print("\n" + "="*50)
        print("DOCUMENT SCRUBBER")
        print("="*50)
        print("\nThis tool removes personal and project-specific data from documents.")
        print("Supported file types: .txt, .md\n")

        args.input_file = input("Enter path to document to scrub: ").strip()

        if not args.input_file:
            print("No file specified. Exiting.")
            return

        # Remove quotes if present
        args.input_file = args.input_file.strip('"\'')

        # Ask about interactive mode
        interactive_response = input("Run in interactive mode? [y/N]: ").strip().lower()
        args.interactive = interactive_response == 'y'

    # Validate input file exists
    if not os.path.exists(args.input_file):
        print(f"Error: File not found: {args.input_file}")
        sys.exit(1)

    # Initialize scrubber
    scrubber = DocumentScrubber(config_path=args.config)

    try:
        # Scrub the file
        output_path = scrubber.scrub_file(
            args.input_file,
            output_path=args.output,
            interactive=args.interactive
        )

        # Print summary
        scrubber.print_summary()

        print("\n" + "="*50)
        print("SCRUBBING COMPLETE")
        print("="*50)
        print(f"\nOutput saved to: {output_path}")
        print("\nReview the scrubbed file and manually verify all sensitive")
        print("data has been properly removed before sharing.")

    except Exception as e:
        print(f"\nError: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
