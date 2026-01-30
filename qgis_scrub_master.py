"""
QGIS Document Scrubber - Master Rules GUI
==========================================
Living document system that learns from each review session.

Features:
- Auto-applies known redactions from master rules
- Only shows NEW items for review
- Updates master rules with your decisions
- Consistent aliases (same text = same replacement)
- Category enable/disable toggles

Usage:
    1. Open QGIS Python Console (Ctrl+Alt+P)
    2. Click "Show Editor" button
    3. Load this script
    4. Click "Run Script" (green play button)

Author: Joey M. Woody P.E.
"""

import sys
import os
import json
import csv
import re
import shutil
from pathlib import Path
from collections import OrderedDict
from datetime import datetime

from qgis.PyQt.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QFileDialog, QTableWidget, QTableWidgetItem, QComboBox,
    QLineEdit, QGroupBox, QMessageBox, QHeaderView, QCheckBox,
    QAbstractItemView, QApplication, QTabWidget, QWidget,
    QFormLayout, QSpinBox, QTextEdit, QSplitter, QFrame
)
from qgis.PyQt.QtCore import Qt
from qgis.PyQt.QtGui import QColor, QFont
from qgis.utils import iface


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
            # EXPLICIT PATH - always use the Document_Scrubber folder
            rules_dir = r"E:\CLAUDE_Workspace\Claude\Report_Files\Projects\Document_Scrubber"
        self.rules_dir = Path(rules_dir)
        
        self.json_path = self.rules_dir / "master_rules.json"
        self.csv_path = self.rules_dir / "master_rules.csv"
        self.template_path = self.rules_dir / "master_rules.template.json"
        
        self.rules = self._load_rules()
    
    def _load_rules(self):
        # Create from template if needed
        if not self.json_path.exists():
            if self.template_path.exists():
                shutil.copy(self.template_path, self.json_path)
            else:
                return self._create_default_rules()
        
        with open(self.json_path, 'r', encoding='utf-8') as f:
            rules = json.load(f)
        
        # Reconcile with CSV if exists
        if self.csv_path.exists():
            rules = self._reconcile_csv(rules)
        
        return rules
    
    def _create_default_rules(self):
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
    
    def _reconcile_csv(self, rules):
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
        except Exception as e:
            print(f"CSV reconcile error: {e}")
        return rules
    
    def save(self):
        if self.json_path.exists():
            backup = self.json_path.with_suffix('.json.bak')
            shutil.copy(self.json_path, backup)
        
        with open(self.json_path, 'w', encoding='utf-8') as f:
            json.dump(self.rules, f, indent=2)
    
    def export_csv(self):
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
        
        return str(self.csv_path)
    
    def is_category_enabled(self, category):
        return self.rules.get('categories', {}).get(category, {}).get('enabled', True)
    
    def set_category_enabled(self, category, enabled):
        if category not in self.rules.get('categories', {}):
            self.rules['categories'][category] = {}
        self.rules['categories'][category]['enabled'] = enabled
    
    def get_default_alias(self, category):
        return self.rules.get('categories', {}).get(category, {}).get('default_alias', f'[{category}]')
    
    def should_redact(self, text):
        if text in self.rules.get('never_redact', []):
            return (False, None)
        if text in self.rules.get('always_redact', {}):
            return (True, self.rules['always_redact'][text])
        return (None, None)
    
    def add_redact(self, text, alias):
        self.rules['always_redact'][text] = alias
        if text in self.rules.get('never_redact', []):
            self.rules['never_redact'].remove(text)
    
    def add_skip(self, text):
        if text not in self.rules.get('never_redact', []):
            self.rules['never_redact'].append(text)
        if text in self.rules.get('always_redact', {}):
            del self.rules['always_redact'][text]
    
    def get_stats(self):
        return {
            'always_redact': len(self.rules.get('always_redact', {})),
            'never_redact': len(self.rules.get('never_redact', [])),
            'categories_enabled': sum(1 for c in self.rules.get('categories', {}).values() if c.get('enabled', True)),
            'categories_total': len(self.rules.get('categories', {}))
        }


# =============================================================================
# MAIN DIALOG
# =============================================================================

class MasterScrubDialog(QDialog):
    """Main dialog with master rules system."""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Document Scrubber - Master Rules System")
        self.setMinimumSize(1100, 750)
        
        # EXPLICIT PATH - always use the Document_Scrubber folder
        self.rules_dir = Path(r"E:\CLAUDE_Workspace\Claude\Report_Files\Projects\Document_Scrubber")
        self.rules = MasterRules(self.rules_dir)
        
        self.input_file = None
        self.document_content = None
        self.scan_results = None
        
        self.setup_ui()
        self.update_stats()
    
    def setup_ui(self):
        layout = QVBoxLayout(self)
        
        # Create tabs
        tabs = QTabWidget()
        
        # === SCAN TAB ===
        scan_tab = QWidget()
        scan_layout = QVBoxLayout(scan_tab)
        
        # File selection
        file_group = QGroupBox("Document")
        file_layout = QHBoxLayout(file_group)
        self.file_label = QLabel("No file selected")
        file_layout.addWidget(self.file_label, 1)
        self.browse_btn = QPushButton("Browse...")
        self.browse_btn.clicked.connect(self.browse_file)
        file_layout.addWidget(self.browse_btn)
        self.scan_btn = QPushButton("Scan Document")
        self.scan_btn.clicked.connect(self.scan_document)
        self.scan_btn.setEnabled(False)
        file_layout.addWidget(self.scan_btn)
        scan_layout.addWidget(file_group)
        
        # Stats display
        stats_group = QGroupBox("Master Rules Status")
        stats_layout = QHBoxLayout(stats_group)
        self.stats_label = QLabel()
        stats_layout.addWidget(self.stats_label)
        stats_layout.addStretch()
        scan_layout.addWidget(stats_group)
        
        # Results summary
        self.results_group = QGroupBox("Scan Results")
        results_layout = QVBoxLayout(self.results_group)
        self.results_label = QLabel("Scan a document to see results")
        results_layout.addWidget(self.results_label)
        self.results_group.setVisible(False)
        scan_layout.addWidget(self.results_group)
        
        # New items table
        new_group = QGroupBox("NEW Items for Review (not in master rules)")
        new_layout = QVBoxLayout(new_group)
        
        # Quick actions
        quick_layout = QHBoxLayout()
        quick_layout.addWidget(QLabel("Set all to:"))
        self.all_redact_btn = QPushButton("REDACT")
        self.all_redact_btn.clicked.connect(lambda: self.set_all_action('REDACT'))
        quick_layout.addWidget(self.all_redact_btn)
        self.all_skip_btn = QPushButton("SKIP")
        self.all_skip_btn.clicked.connect(lambda: self.set_all_action('SKIP'))
        quick_layout.addWidget(self.all_skip_btn)
        quick_layout.addStretch()
        self.new_count_label = QLabel("0 new items")
        quick_layout.addWidget(self.new_count_label)
        new_layout.addLayout(quick_layout)
        
        # Table
        self.new_table = QTableWidget()
        self.new_table.setColumnCount(5)
        self.new_table.setHorizontalHeaderLabels(['Action', 'Category', 'Detected Text', 'Alias', 'Context'])
        self.new_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.Fixed)
        self.new_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.Fixed)
        self.new_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.Interactive)
        self.new_table.horizontalHeader().setSectionResizeMode(3, QHeaderView.Interactive)
        self.new_table.horizontalHeader().setSectionResizeMode(4, QHeaderView.Stretch)
        self.new_table.setColumnWidth(0, 80)
        self.new_table.setColumnWidth(1, 140)
        self.new_table.setColumnWidth(2, 200)
        self.new_table.setColumnWidth(3, 150)
        self.new_table.setAlternatingRowColors(True)
        new_layout.addWidget(self.new_table)
        
        scan_layout.addWidget(new_group)
        
        # Add custom item
        custom_group = QGroupBox("Add Custom Item")
        custom_layout = QHBoxLayout(custom_group)
        custom_layout.addWidget(QLabel("Text:"))
        self.custom_text = QLineEdit()
        self.custom_text.setPlaceholderText("Exact text to find and redact...")
        custom_layout.addWidget(self.custom_text, 2)
        custom_layout.addWidget(QLabel("Alias:"))
        self.custom_alias = QLineEdit()
        self.custom_alias.setPlaceholderText("[CUSTOM]")
        custom_layout.addWidget(self.custom_alias, 1)
        self.add_custom_btn = QPushButton("Add")
        self.add_custom_btn.clicked.connect(self.add_custom_item)
        custom_layout.addWidget(self.add_custom_btn)
        scan_layout.addWidget(custom_group)
        
        # Apply button
        apply_layout = QHBoxLayout()
        apply_layout.addStretch()
        self.apply_btn = QPushButton("Apply Scrubbing && Update Master Rules")
        self.apply_btn.setEnabled(False)
        self.apply_btn.clicked.connect(self.apply_scrubbing)
        self.apply_btn.setStyleSheet("background-color: #4CAF50; color: white; font-weight: bold; padding: 10px;")
        apply_layout.addWidget(self.apply_btn)
        scan_layout.addLayout(apply_layout)
        
        tabs.addTab(scan_tab, "Scan && Review")
        
        # === SETTINGS TAB ===
        settings_tab = QWidget()
        settings_layout = QVBoxLayout(settings_tab)
        
        # Categories
        cat_group = QGroupBox("Detection Categories (enable/disable)")
        cat_layout = QVBoxLayout(cat_group)
        
        self.category_checks = {}
        for cat_name, cat_config in DETECTION_PATTERNS.items():
            check = QCheckBox(f"{cat_name}: {cat_config['description']}")
            check.setChecked(self.rules.is_category_enabled(cat_name))
            check.stateChanged.connect(lambda state, c=cat_name: self.toggle_category(c, state))
            self.category_checks[cat_name] = check
            cat_layout.addWidget(check)
        
        settings_layout.addWidget(cat_group)
        
        # Export/Import
        io_group = QGroupBox("Master Rules Management")
        io_layout = QHBoxLayout(io_group)
        
        self.export_csv_btn = QPushButton("Export to CSV")
        self.export_csv_btn.clicked.connect(self.export_rules_csv)
        io_layout.addWidget(self.export_csv_btn)
        
        self.reload_btn = QPushButton("Reload from Files")
        self.reload_btn.clicked.connect(self.reload_rules)
        io_layout.addWidget(self.reload_btn)
        
        io_layout.addStretch()
        settings_layout.addWidget(io_group)
        
        settings_layout.addStretch()
        tabs.addTab(settings_tab, "Settings")
        
        # === MASTER LIST TAB ===
        master_tab = QWidget()
        master_layout = QVBoxLayout(master_tab)
        
        # Always redact list
        redact_group = QGroupBox("Always Redact")
        redact_layout = QVBoxLayout(redact_group)
        self.redact_table = QTableWidget()
        self.redact_table.setColumnCount(3)
        self.redact_table.setHorizontalHeaderLabels(['Text', 'Alias', 'Remove'])
        self.redact_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.Stretch)
        self.redact_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.Interactive)
        self.redact_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.Fixed)
        self.redact_table.setColumnWidth(1, 150)
        self.redact_table.setColumnWidth(2, 70)
        redact_layout.addWidget(self.redact_table)
        master_layout.addWidget(redact_group)
        
        # Never redact list
        skip_group = QGroupBox("Never Redact (Skip)")
        skip_layout = QVBoxLayout(skip_group)
        self.skip_table = QTableWidget()
        self.skip_table.setColumnCount(2)
        self.skip_table.setHorizontalHeaderLabels(['Text', 'Remove'])
        self.skip_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.Stretch)
        self.skip_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.Fixed)
        self.skip_table.setColumnWidth(1, 70)
        skip_layout.addWidget(self.skip_table)
        master_layout.addWidget(skip_group)
        
        # Refresh button
        refresh_layout = QHBoxLayout()
        self.refresh_master_btn = QPushButton("Refresh Lists")
        self.refresh_master_btn.clicked.connect(self.populate_master_lists)
        refresh_layout.addWidget(self.refresh_master_btn)
        refresh_layout.addStretch()
        master_layout.addLayout(refresh_layout)
        
        tabs.addTab(master_tab, "Master List")
        
        layout.addWidget(tabs)
        
        # Bottom buttons
        bottom_layout = QHBoxLayout()
        self.close_btn = QPushButton("Close")
        self.close_btn.clicked.connect(self.close)
        bottom_layout.addStretch()
        bottom_layout.addWidget(self.close_btn)
        layout.addLayout(bottom_layout)
        
        # Populate master lists
        self.populate_master_lists()
    
    def update_stats(self):
        stats = self.rules.get_stats()
        self.stats_label.setText(
            f"Always Redact: {stats['always_redact']} items | "
            f"Never Redact: {stats['never_redact']} items | "
            f"Categories: {stats['categories_enabled']}/{stats['categories_total']} enabled"
        )
    
    def browse_file(self):
        file_path, _ = QFileDialog.getOpenFileName(
            self, "Select Document", str(Path.home()),
            "Text Files (*.txt *.md);;All Files (*.*)"
        )
        if file_path:
            self.input_file = file_path
            self.file_label.setText(file_path)
            self.scan_btn.setEnabled(True)
    
    def scan_document(self):
        if not self.input_file:
            return
        
        # Try multiple encodings
        encodings = ['utf-8', 'cp1252', 'latin-1', 'iso-8859-1']
        self.document_content = None
        
        for encoding in encodings:
            try:
                with open(self.input_file, 'r', encoding=encoding) as f:
                    self.document_content = f.read()
                break  # Success
            except UnicodeDecodeError:
                continue
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Could not read file: {e}")
                return
        
        if self.document_content is None:
            QMessageBox.critical(self, "Error", "Could not read file with any supported encoding")
            return
        
        # Scan
        self.scan_results = {'new': [], 'auto_redact': [], 'auto_skip': []}
        seen = set()
        
        for cat_name, cat_config in DETECTION_PATTERNS.items():
            if not self.rules.is_category_enabled(cat_name):
                continue
            
            pattern = cat_config['pattern']
            flags = cat_config.get('flags', 0)
            default_alias = self.rules.get_default_alias(cat_name)
            
            for match in re.finditer(pattern, self.document_content, flags):
                text = match.group(0)
                if text in seen:
                    continue
                seen.add(text)
                
                start = max(0, match.start() - 40)
                end = min(len(self.document_content), match.end() + 40)
                context = self.document_content[start:end].replace('\n', ' ').strip()
                
                item = {
                    'text': text,
                    'category': cat_name,
                    'default_alias': default_alias,
                    'context': context,
                    'action': 'REDACT',
                    'alias': default_alias
                }
                
                should_redact, alias = self.rules.should_redact(text)
                
                if should_redact is True:
                    item['alias'] = alias
                    self.scan_results['auto_redact'].append(item)
                elif should_redact is False:
                    self.scan_results['auto_skip'].append(item)
                else:
                    self.scan_results['new'].append(item)
        
        # Update UI
        self.results_group.setVisible(True)
        self.results_label.setText(
            f"Found {len(seen)} unique items:\n"
            f"  • Auto-redact (in master): {len(self.scan_results['auto_redact'])}\n"
            f"  • Auto-skip (in skip list): {len(self.scan_results['auto_skip'])}\n"
            f"  • NEW for review: {len(self.scan_results['new'])}"
        )
        
        self.populate_new_table()
        self.new_count_label.setText(f"{len(self.scan_results['new'])} new items")
        self.apply_btn.setEnabled(True)
    
    def populate_new_table(self):
        items = self.scan_results.get('new', [])
        self.new_table.setRowCount(len(items))
        
        for row, item in enumerate(items):
            # Action
            combo = QComboBox()
            combo.addItems(['REDACT', 'SKIP'])
            combo.setCurrentText(item.get('action', 'REDACT'))
            combo.currentTextChanged.connect(lambda t, r=row: self.update_new_action(r, t))
            self.new_table.setCellWidget(row, 0, combo)
            
            # Category
            cat_item = QTableWidgetItem(item['category'])
            cat_item.setFlags(cat_item.flags() & ~Qt.ItemIsEditable)
            self.new_table.setItem(row, 1, cat_item)
            
            # Text
            text_item = QTableWidgetItem(item['text'])
            text_item.setFlags(text_item.flags() & ~Qt.ItemIsEditable)
            self.new_table.setItem(row, 2, text_item)
            
            # Alias (editable)
            alias_item = QTableWidgetItem(item.get('alias', item['default_alias']))
            self.new_table.setItem(row, 3, alias_item)
            
            # Context
            ctx_item = QTableWidgetItem(item['context'][:60])
            ctx_item.setFlags(ctx_item.flags() & ~Qt.ItemIsEditable)
            ctx_item.setToolTip(item['context'])
            self.new_table.setItem(row, 4, ctx_item)
    
    def update_new_action(self, row, action):
        if self.scan_results and row < len(self.scan_results['new']):
            self.scan_results['new'][row]['action'] = action
            color = QColor(255, 220, 220) if action == 'SKIP' else QColor(220, 255, 220)
            for col in range(1, 5):
                item = self.new_table.item(row, col)
                if item:
                    item.setBackground(color)
    
    def set_all_action(self, action):
        for row in range(self.new_table.rowCount()):
            combo = self.new_table.cellWidget(row, 0)
            if combo:
                combo.setCurrentText(action)
    
    def add_custom_item(self):
        text = self.custom_text.text().strip()
        alias = self.custom_alias.text().strip() or '[CUSTOM]'
        
        if not text:
            QMessageBox.warning(self, "Warning", "Enter text to redact")
            return
        
        if self.scan_results is None:
            self.scan_results = {'new': [], 'auto_redact': [], 'auto_skip': []}
        
        # Add to new items
        self.scan_results['new'].append({
            'text': text,
            'category': 'CUSTOM',
            'default_alias': alias,
            'context': '(manually added)',
            'action': 'REDACT',
            'alias': alias
        })
        
        self.populate_new_table()
        self.new_count_label.setText(f"{len(self.scan_results['new'])} new items")
        self.apply_btn.setEnabled(True)
        
        self.custom_text.clear()
        self.custom_alias.clear()
    
    def apply_scrubbing(self):
        if not self.document_content:
            QMessageBox.warning(self, "Warning", "No document loaded")
            return
        
        # Sync table to results
        for row in range(self.new_table.rowCount()):
            if row < len(self.scan_results['new']):
                combo = self.new_table.cellWidget(row, 0)
                if combo:
                    self.scan_results['new'][row]['action'] = combo.currentText()
                
                alias_item = self.new_table.item(row, 3)
                if alias_item:
                    self.scan_results['new'][row]['alias'] = alias_item.text()
        
        # Update master rules with new items
        for item in self.scan_results['new']:
            if item['action'] == 'REDACT':
                self.rules.add_redact(item['text'], item['alias'])
            else:
                self.rules.add_skip(item['text'])
        
        # Save rules
        self.rules.save()
        
        # Build all replacements
        replacements = dict(self.rules.rules.get('always_redact', {}))
        
        # Sort by length
        sorted_items = sorted(replacements.items(), key=lambda x: len(x[0]), reverse=True)
        
        # Apply
        result = self.document_content
        for text, alias in sorted_items:
            pattern = re.escape(text)
            result = re.sub(pattern, alias, result, flags=re.IGNORECASE)
        
        # Get output path
        input_path = Path(self.input_file)
        default_output = input_path.parent / f"{input_path.stem}_Scrubbed{input_path.suffix}"
        
        output_path, _ = QFileDialog.getSaveFileName(
            self, "Save Scrubbed Document", str(default_output),
            "Text Files (*.txt *.md);;All Files (*.*)"
        )
        
        if not output_path:
            return
        
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(result)
        
        # Stats
        redact_count = len([i for i in self.scan_results['new'] if i['action'] == 'REDACT'])
        skip_count = len([i for i in self.scan_results['new'] if i['action'] == 'SKIP'])
        auto_count = len(self.scan_results.get('auto_redact', []))
        
        self.update_stats()
        self.populate_master_lists()
        
        QMessageBox.information(
            self, "Complete",
            f"Scrubbing complete!\n\n"
            f"New items added to master: {redact_count} redact, {skip_count} skip\n"
            f"Auto-redactions applied: {auto_count}\n"
            f"Total replacements: {len(replacements)}\n\n"
            f"Output: {output_path}"
        )
    
    def toggle_category(self, category, state):
        enabled = state == Qt.Checked
        self.rules.set_category_enabled(category, enabled)
        self.rules.save()
        self.update_stats()
    
    def export_rules_csv(self):
        path = self.rules.export_csv()
        QMessageBox.information(self, "Exported", f"Master rules exported to:\n\n{path}\n\nYou can edit this CSV and changes will be merged on next run.")
    
    def reload_rules(self):
        self.rules = MasterRules(self.rules_dir)
        self.update_stats()
        self.populate_master_lists()
        
        # Update category checkboxes
        for cat_name, check in self.category_checks.items():
            check.setChecked(self.rules.is_category_enabled(cat_name))
        
        QMessageBox.information(self, "Reloaded", "Master rules reloaded from files")
    
    def populate_master_lists(self):
        # Redact table
        redact_items = list(self.rules.rules.get('always_redact', {}).items())
        redact_items.sort(key=lambda x: x[0].lower())
        self.redact_table.setRowCount(len(redact_items))
        
        for row, (text, alias) in enumerate(redact_items):
            self.redact_table.setItem(row, 0, QTableWidgetItem(text))
            self.redact_table.setItem(row, 1, QTableWidgetItem(alias))
            
            remove_btn = QPushButton("X")
            remove_btn.setMaximumWidth(50)
            remove_btn.clicked.connect(lambda _, t=text: self.remove_redact(t))
            self.redact_table.setCellWidget(row, 2, remove_btn)
        
        # Skip table
        skip_items = sorted(self.rules.rules.get('never_redact', []), key=str.lower)
        self.skip_table.setRowCount(len(skip_items))
        
        for row, text in enumerate(skip_items):
            self.skip_table.setItem(row, 0, QTableWidgetItem(text))
            
            remove_btn = QPushButton("X")
            remove_btn.setMaximumWidth(50)
            remove_btn.clicked.connect(lambda _, t=text: self.remove_skip(t))
            self.skip_table.setCellWidget(row, 1, remove_btn)
    
    def remove_redact(self, text):
        if text in self.rules.rules.get('always_redact', {}):
            del self.rules.rules['always_redact'][text]
            self.rules.save()
            self.update_stats()
            self.populate_master_lists()
    
    def remove_skip(self, text):
        if text in self.rules.rules.get('never_redact', []):
            self.rules.rules['never_redact'].remove(text)
            self.rules.save()
            self.update_stats()
            self.populate_master_lists()


def run_master_scrub():
    dialog = MasterScrubDialog(iface.mainWindow())
    dialog.exec_()


# Run
run_master_scrub()
