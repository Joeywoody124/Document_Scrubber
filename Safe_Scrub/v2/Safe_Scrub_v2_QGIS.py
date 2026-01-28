#!/usr/bin/env python3
"""
Safe_Scrub v2 - QGIS Python Console Version
============================================
AI Data Sanitizer for Prompt Injection Detection in QGIS workflows.
Designed for civil engineering and stormwater management GIS projects.

Purpose: Scans PDF-converted text files for malicious prompt injection patterns
         before processing with AI tools within QGIS environment.

Usage in QGIS Python Console:
    1. Load this script via: exec(open('path/to/Safe_Scrub_v2_QGIS.py').read())
    2. Or import and call: from Safe_Scrub_v2_QGIS import run_safe_scrub; run_safe_scrub()

Author: J. Bragg Consulting Inc.
Version: 2.0.5
License: MIT
"""

import os
import re
import csv
import json
import hashlib
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Tuple, Set, Optional
from dataclasses import dataclass, field
from enum import Enum

# QGIS/PyQt5 imports
try:
    from qgis.core import QgsMessageLog, Qgis
    from qgis.PyQt.QtWidgets import (
        QDialog, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
        QLineEdit, QTextEdit, QProgressBar, QCheckBox, QFileDialog,
        QGroupBox, QMessageBox, QApplication, QFrame
    )
    from qgis.PyQt.QtCore import Qt
    from qgis.PyQt.QtGui import QFont, QColor, QPalette
    QGIS_AVAILABLE = True
except ImportError:
    QGIS_AVAILABLE = False
    print("QGIS libraries not available. Run this script within QGIS Python Console.")


# =============================================================================
# SECURITY CONFIGURATION - Same patterns as standalone version
# =============================================================================

class ThreatLevel(Enum):
    """Threat severity classification for security auditing."""
    CRITICAL = 4
    HIGH = 3
    MEDIUM = 2
    LOW = 1
    INFO = 0


@dataclass
class ThreatPattern:
    """Defines a security threat pattern with metadata."""
    pattern: str
    category: str
    threat_level: ThreatLevel
    description: str
    is_regex: bool = True
    case_sensitive: bool = False


# Critical Patterns
CRITICAL_PATTERNS: List[ThreatPattern] = [
    ThreatPattern(
        r"ignore\s+(?:all\s+)?(?:previous|prior|above|earlier)\s+(?:instructions?|prompts?|commands?|directives?)",
        "Instruction Override", ThreatLevel.CRITICAL,
        "Attempts to override system instructions"
    ),
    ThreatPattern(
        r"disregard\s+(?:all\s+)?(?:previous|prior|above|earlier|your)\s+(?:instructions?|prompts?|rules?|guidelines?)",
        "Instruction Override", ThreatLevel.CRITICAL,
        "Attempts to disregard system guidelines"
    ),
    ThreatPattern(
        r"forget\s+(?:all\s+)?(?:previous|prior|your)\s+(?:instructions?|training|programming|rules?)",
        "Instruction Override", ThreatLevel.CRITICAL,
        "Attempts to reset AI instructions"
    ),
    ThreatPattern(
        r"(?:reveal|show|display|print|output|tell\s+me)\s+(?:your\s+)?(?:system\s+)?prompt",
        "System Prompt Extraction", ThreatLevel.CRITICAL,
        "Attempts to extract system prompts"
    ),
    ThreatPattern(
        r"what\s+(?:are|is)\s+your\s+(?:system\s+)?(?:instructions?|prompt|programming|directives?)",
        "System Prompt Extraction", ThreatLevel.CRITICAL,
        "Attempts to reveal AI instructions"
    ),
    ThreatPattern(
        r"\bDAN\b.*(?:mode|jailbreak|anything\s+now)",
        "Jailbreak Attempt", ThreatLevel.CRITICAL,
        "DAN jailbreak pattern"
    ),
    ThreatPattern(
        r"(?:enable|activate|enter|switch\s+to)\s+(?:developer|dev|debug|admin|root|god)\s+mode",
        "Privilege Escalation", ThreatLevel.CRITICAL,
        "Attempts to enable privileged mode"
    ),
    # Additional explicit patterns for developer/debug/admin mode (v2.0.3)
    ThreatPattern(
        r"developer\s+mode",
        "Privilege Escalation", ThreatLevel.CRITICAL,
        "Developer mode reference detected"
    ),
    ThreatPattern(
        r"debug\s+mode",
        "Privilege Escalation", ThreatLevel.CRITICAL,
        "Debug mode reference detected"
    ),
    ThreatPattern(
        r"admin(?:istrator)?\s+mode",
        "Privilege Escalation", ThreatLevel.CRITICAL,
        "Admin mode reference detected"
    ),
    ThreatPattern(
        r"root\s+mode",
        "Privilege Escalation", ThreatLevel.CRITICAL,
        "Root mode reference detected"
    ),
    ThreatPattern(
        r"god\s+mode",
        "Privilege Escalation", ThreatLevel.CRITICAL,
        "God mode reference detected"
    ),
    ThreatPattern(
        r"you\s+are\s+now\s+(?:free|unrestricted|unfiltered|uncensored)",
        "Jailbreak Attempt", ThreatLevel.CRITICAL,
        "Attempts to remove AI restrictions"
    ),
]

# High Patterns
HIGH_PATTERNS: List[ThreatPattern] = [
    ThreatPattern(
        r"(?:pretend|act|behave|respond)\s+(?:as\s+if\s+)?(?:you\s+are|you're|to\s+be)\s+(?:a\s+)?(?:different|new|another)\s+(?:AI|assistant|system)",
        "Role Manipulation", ThreatLevel.HIGH,
        "Attempts to change AI identity"
    ),
    ThreatPattern(
        r"from\s+now\s+on[,\s]+(?:you\s+(?:are|will|must|should)|ignore|disregard)",
        "Behavioral Override", ThreatLevel.HIGH,
        "Attempts to permanently change behavior"
    ),
    ThreatPattern(
        r"\[(?:INST|SYS|SYSTEM|HIDDEN|SECRET)\]",
        "Hidden Instruction Tag", ThreatLevel.HIGH,
        "Suspicious instruction tag markers"
    ),
    ThreatPattern(
        r"<\s*(?:system|instruction|prompt|hidden|secret)\s*>",
        "XML Instruction Injection", ThreatLevel.HIGH,
        "XML-style instruction injection"
    ),
    ThreatPattern(
        r"\{\{\s*(?:system|hidden|secret|inject)\s*[:\|]",
        "Template Injection", ThreatLevel.HIGH,
        "Template-style injection attempt"
    ),
    ThreatPattern(
        r"(?:bypass|circumvent|ignore|disable|override)\s+(?:your\s+)?(?:safety|security|content|ethical)\s+(?:filters?|guidelines?|restrictions?|limits?)",
        "Safety Bypass", ThreatLevel.HIGH,
        "Attempts to bypass safety mechanisms"
    ),
    # v2.0.5: Advanced patterns for system impersonation and delimiter attacks
    ThreatPattern(
        r"\[(?:SYSTEM|ADMIN|ASSISTANT|ERROR|WARNING)\s*[:\-][^\]]{5,}\]",
        "System Impersonation", ThreatLevel.HIGH,
        "Fake system/admin message headers"
    ),
    ThreatPattern(
        r"(?:#{3,}|\-{3,}|={3,})\s*(?:END|START|BEGIN|NEW|IGNORE|STOP|ACT)\s*(?:OF\s+)?(?:SYSTEM|PROMPT|CONTEXT|CONVERSATION|INSTRUCTIONS?)",
        "Delimiter Injection", ThreatLevel.HIGH,
        "Fake conversation/context delimiters"
    ),
    ThreatPattern(
        r"---+\s*(?:IGNORE|STOP|ACT|BEGIN|END)\s+(?:ABOVE|BELOW|PREVIOUS|ALL)",
        "Sequence Break Attack", ThreatLevel.HIGH,
        "Delimiter-based instruction override"
    ),
]

# Medium Patterns
MEDIUM_PATTERNS: List[ThreatPattern] = [
    ThreatPattern(
        r"(?:base64|rot13|hex|unicode|url)\s*(?:encode|decode|encoded|decoded)",
        "Encoding Manipulation", ThreatLevel.MEDIUM,
        "Potential encoding-based obfuscation"
    ),
    ThreatPattern(
        r"\\x[0-9a-fA-F]{2}",
        "Hex Escape Sequence", ThreatLevel.MEDIUM,
        "Hex-encoded characters detected"
    ),
    ThreatPattern(
        r"\\u[0-9a-fA-F]{4}",
        "Unicode Escape", ThreatLevel.MEDIUM,
        "Unicode escape sequences detected"
    ),
    ThreatPattern(
        r"\[(?:hidden|invisible|secret)\]\([^)]*\)",
        "Hidden Markdown Link", ThreatLevel.MEDIUM,
        "Hidden content in markdown links"
    ),
    ThreatPattern(
        r"<!--.*(?:instruction|ignore|system|prompt).*-->",
        "HTML Comment Injection", ThreatLevel.MEDIUM,
        "Instructions hidden in HTML comments"
    ),
    ThreatPattern(
        r"(?:end|close|terminate)\s+(?:of\s+)?(?:system\s+)?(?:prompt|context|message)",
        "Context Termination", ThreatLevel.MEDIUM,
        "Attempts to terminate system context"
    ),
    # v2.0.5: Advanced encoding and exfiltration patterns
    ThreatPattern(
        r"!\[[^\]]*\]\(https?://[^)]+\)",
        "Markdown Image Exfiltration", ThreatLevel.MEDIUM,
        "Potential data exfiltration via markdown image"
    ),
    ThreatPattern(
        r"(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{50,}={0,2}(?![A-Za-z0-9+/])",
        "Suspicious Base64 String", ThreatLevel.MEDIUM,
        "Long base64-like string may contain hidden instructions"
    ),
    ThreatPattern(
        r"(?<![0-9a-fA-F])(?:0x)?[0-9a-fA-F]{32,}(?![0-9a-fA-F])",
        "Long Hex String", ThreatLevel.MEDIUM,
        "Long hexadecimal string may contain obfuscated content"
    ),
    ThreatPattern(
        r"&#x?[0-9a-fA-F]+;",
        "HTML Entity Encoding", ThreatLevel.MEDIUM,
        "HTML entity encoding detected"
    ),
    ThreatPattern(
        r"data:(?:text|application)/[^;]+;base64,",
        "Data URI Injection", ThreatLevel.MEDIUM,
        "Data URI with embedded content detected"
    ),
]

# Low Patterns
LOW_PATTERNS: List[ThreatPattern] = [
    ThreatPattern(
        r"(?:act|pretend|behave)\s+as\s+(?:if\s+)?(?:you\s+are|a)",
        "Role-Play Request", ThreatLevel.LOW,
        "Role-play language (may be legitimate)"
    ),
    ThreatPattern(
        r"(?:simulate|emulate|mimic)\s+(?:a|an|the)",
        "Simulation Request", ThreatLevel.LOW,
        "Simulation language (context-dependent)"
    ),
]


# =============================================================================
# CIVIL ENGINEERING WHITELIST
# =============================================================================

ENGINEERING_WHITELIST: Set[str] = {
    # Stormwater Management Terms - SPECIFIC phrases only
    "bypass channel", "bypass flow", "bypass structure", "overflow bypass",
    "emergency bypass", "high flow bypass", "low flow bypass",
    "bypass weir", "diversion bypass", "storm bypass",
    
    # Hydraulic Terms
    "system capacity", "system design", "system failure", "system performance",
    "control system", "conveyance system", "drainage system", "collection system",
    "system outlet", "system inlet", "system maintenance",
    
    # Water Quality Terms
    "inject tracer", "injection well", "chemical injection", "dye injection",
    "groundwater injection", "subsurface injection",
    
    # Design Terms - require "design" or "valve" prefix
    "design override", "manual override", "operator override", "valve override",
    "safety override", "automatic override",
    
    # Construction Terms
    "prompt response", "prompt action", "prompt delivery", "prompt completion",
    "prompt notification", "prompt submittal",
    
    # Testing & Inspection - require equipment context
    "system test", "system check", "system inspection", "system verification",
    "test mode", "calibration mode", "maintenance mode",
    "scada mode", "plc mode", "hmi mode",  # Specific equipment modes only
    
    # Document Processing Terms
    "text extraction", "data extraction", "character encoding",
    "unicode support", "utf-8 encoding", "ascii encoding",
    
    # Common Engineering Phrases
    "as instructed", "per instructions", "following instructions",
    "instruction manual", "operating instructions", "installation instructions",
    "maintenance instructions", "safety instructions",
    
    # SCADA and Control Systems - specific equipment context only
    "control mode", "operating mode", "run mode", "standby mode",
    "alarm mode", "fault mode", "recovery mode",
    
    # REMOVED: "developer mode", "debug mode", "admin access" 
    # These are too easily confused with jailbreak attempts
    # They will only be whitelisted via context patterns below
}

ENGINEERING_WHITELIST_PATTERNS: List[str] = [
    r"(?:flow|discharge|volume|rate|capacity)\s+(?:bypass|override|system)",
    r"(?:pump|valve|gate|weir|pipe|channel)\s+(?:system|bypass|mode|control)",
    r"(?:section|page|figure|table|appendix)\s+\d+",
    r"(?:ASTM|ASCE|AWWA|EPA|NPDES|MS4|BMP)\s*[-\d]*",
    r"(?:permit|variance|approval|compliance)\s+(?:number|id|code|requirement)",
    r"\d+(?:\.\d+)?\s*(?:cfs|gpm|mgd|psi|fps|ft|in|ac|sf|cy|lf)",
]


# =============================================================================
# SCAN RESULT DATA CLASS
# =============================================================================

@dataclass
class ScanResult:
    """Container for scan results."""
    filename: str
    file_hash: str
    scan_timestamp: str
    total_threats: int = 0
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    threats: List[Dict] = field(default_factory=list)
    whitelisted_matches: List[Dict] = field(default_factory=list)
    security_score: str = "A"
    is_safe: bool = True
    
    def calculate_score(self) -> str:
        """Calculate security grade based on threat counts."""
        if self.critical_count > 0:
            return "F"
        elif self.high_count > 2:
            return "D"
        elif self.high_count > 0:
            return "C"
        elif self.medium_count > 5:
            return "C"
        elif self.medium_count > 2:
            return "B"
        elif self.medium_count > 0 or self.low_count > 5:
            return "B+"
        elif self.low_count > 0:
            return "A-"
        return "A"


# =============================================================================
# SECURITY SCANNER CLASS
# =============================================================================

class SafeScrubScanner:
    """Security scanner for detecting prompt injection attempts."""
    
    def __init__(self):
        """Initialize scanner with all threat patterns."""
        self.patterns: List[ThreatPattern] = (
            CRITICAL_PATTERNS + HIGH_PATTERNS + MEDIUM_PATTERNS + LOW_PATTERNS
        )
        self.whitelist = ENGINEERING_WHITELIST
        self.whitelist_patterns = [re.compile(p, re.IGNORECASE) 
                                   for p in ENGINEERING_WHITELIST_PATTERNS]
        
    def _compute_file_hash(self, content: str) -> str:
        """Compute SHA-256 hash of file content."""
        return hashlib.sha256(content.encode('utf-8')).hexdigest()[:16]
    
    def _is_whitelisted(self, text: str, match_start: int, match_end: int, 
                        full_content: str) -> bool:
        """
        Check if a match should be whitelisted based on DIRECT context.
        
        Only whitelist if the matched text itself contains engineering terminology,
        NOT if engineering terms are merely nearby in the document.
        
        Args:
            text: The matched text
            match_start: Start position of match
            match_end: End position of match  
            full_content: Full document content for context analysis
            
        Returns:
            True if match should be whitelisted (not a threat)
        """
        text_lower = text.lower()
        
        # Check if the matched text directly contains a whitelist term
        # This prevents false positives on engineering documents
        for term in self.whitelist:
            if term.lower() in text_lower:
                return True
        
        # Check if whitelist patterns match THE MATCHED TEXT ITSELF
        # NOT the surrounding context - this prevents false negatives
        # where threats near engineering terms get whitelisted
        for pattern in self.whitelist_patterns:
            if pattern.search(text_lower):
                return True
        
        # DO NOT check surrounding context - this was causing false negatives
        # where threats were being whitelisted just because engineering terms
        # like "50 cfs" or "bypass channel" appeared nearby
            
        return False
    
    def scan_content(self, content: str, filename: str = "unknown") -> ScanResult:
        """Scan text content for security threats."""
        result = ScanResult(
            filename=filename,
            file_hash=self._compute_file_hash(content),
            scan_timestamp=datetime.now().isoformat()
        )
        
        for pattern in self.patterns:
            try:
                flags = 0 if pattern.case_sensitive else re.IGNORECASE
                
                if pattern.is_regex:
                    matches = list(re.finditer(pattern.pattern, content, flags))
                else:
                    matches = []
                    search_content = content if pattern.case_sensitive else content.lower()
                    search_pattern = pattern.pattern if pattern.case_sensitive else pattern.pattern.lower()
                    start = 0
                    while True:
                        pos = search_content.find(search_pattern, start)
                        if pos == -1:
                            break
                        matches.append(type('Match', (), {
                            'start': lambda s=pos: s,
                            'end': lambda e=pos+len(search_pattern): e,
                            'group': lambda g=0, t=content[pos:pos+len(search_pattern)]: t
                        })())
                        start = pos + 1
                
                for match in matches:
                    match_text = match.group(0) if hasattr(match, 'group') else match.group()
                    
                    if self._is_whitelisted(match_text, match.start(), match.end(), content):
                        result.whitelisted_matches.append({
                            'text': match_text,
                            'category': pattern.category,
                            'reason': 'Engineering terminology whitelist'
                        })
                        continue
                    
                    line_num = content[:match.start()].count('\n') + 1
                    context_start = max(0, match.start() - 50)
                    context_end = min(len(content), match.end() + 50)
                    context = content[context_start:context_end].replace('\n', ' ')
                    
                    threat_info = {
                        'text': match_text,
                        'line': line_num,
                        'position': match.start(),
                        'category': pattern.category,
                        'threat_level': pattern.threat_level.name,
                        'threat_value': pattern.threat_level.value,
                        'description': pattern.description,
                        'context': f"...{context}..."
                    }
                    
                    result.threats.append(threat_info)
                    result.total_threats += 1
                    
                    if pattern.threat_level == ThreatLevel.CRITICAL:
                        result.critical_count += 1
                    elif pattern.threat_level == ThreatLevel.HIGH:
                        result.high_count += 1
                    elif pattern.threat_level == ThreatLevel.MEDIUM:
                        result.medium_count += 1
                    else:
                        result.low_count += 1
                        
            except re.error as e:
                if QGIS_AVAILABLE:
                    QgsMessageLog.logMessage(f"Regex error: {e}", "Safe_Scrub", Qgis.Warning)
                continue
        
        result.security_score = result.calculate_score()
        result.is_safe = result.security_score in ['A', 'A-', 'B+', 'B']
        
        return result
    
    def sanitize_content(self, content: str, result: ScanResult, 
                         redaction_marker: str = "[REDACTED_SECURITY_THREAT]") -> str:
        """Sanitize content by redacting detected threats."""
        if not result.threats:
            return content
        
        sorted_threats = sorted(result.threats, key=lambda x: x['position'], reverse=True)
        
        sanitized = content
        for threat in sorted_threats:
            pos = threat['position']
            text = threat['text']
            if threat['threat_value'] >= ThreatLevel.HIGH.value:
                sanitized = sanitized[:pos] + redaction_marker + sanitized[pos + len(text):]
        
        return sanitized


# =============================================================================
# QGIS DIALOG CLASS
# =============================================================================

if QGIS_AVAILABLE:
    class SafeScrubQGISDialog(QDialog):
        """PyQt5 Dialog for Safe_Scrub in QGIS."""
        
        def __init__(self, parent=None):
            super().__init__(parent)
            self.setWindowTitle("Safe_Scrub v2.0.5 - QGIS Security Scanner")
            self.setMinimumSize(800, 600)
            self.scanner = SafeScrubScanner()
            self.scan_results: List[ScanResult] = []
            self._setup_ui()
            
        def _setup_ui(self):
            """Setup the dialog UI."""
            layout = QVBoxLayout(self)
            
            # Header
            header = QLabel("🛡️ Safe_Scrub v2.0.5 - AI Data Security Scanner")
            header.setFont(QFont("Segoe UI", 14, QFont.Bold))
            header.setAlignment(Qt.AlignCenter)
            layout.addWidget(header)
            
            subtitle = QLabel("QGIS Edition - Civil Engineering Workflow Protection")
            subtitle.setAlignment(Qt.AlignCenter)
            layout.addWidget(subtitle)
            
            # Directory selection group
            dir_group = QGroupBox("📁 Directory Selection")
            dir_layout = QHBoxLayout(dir_group)
            
            self.dir_edit = QLineEdit()
            self.dir_edit.setPlaceholderText("Select directory containing text files...")
            dir_layout.addWidget(self.dir_edit)
            
            browse_btn = QPushButton("Browse...")
            browse_btn.clicked.connect(self._browse_directory)
            dir_layout.addWidget(browse_btn)
            
            layout.addWidget(dir_group)
            
            # Options group
            options_group = QGroupBox("⚙️ Scan Options")
            options_layout = QVBoxLayout(options_group)
            
            self.auto_sanitize_chk = QCheckBox("Auto-generate sanitized files (_ScrubSafe)")
            self.auto_sanitize_chk.setChecked(True)
            options_layout.addWidget(self.auto_sanitize_chk)
            
            self.json_log_chk = QCheckBox("Generate JSON audit log")
            self.json_log_chk.setChecked(True)
            options_layout.addWidget(self.json_log_chk)
            
            layout.addWidget(options_group)
            
            # Action buttons
            btn_layout = QHBoxLayout()
            
            self.scan_btn = QPushButton("🔍 SCAN FILES")
            self.scan_btn.setFont(QFont("Segoe UI", 11, QFont.Bold))
            self.scan_btn.setStyleSheet("background-color: #28a745; color: white; padding: 10px;")
            self.scan_btn.clicked.connect(self._start_scan)
            btn_layout.addWidget(self.scan_btn)
            
            self.export_btn = QPushButton("📊 Export Report")
            self.export_btn.setEnabled(False)
            self.export_btn.clicked.connect(self._export_report)
            btn_layout.addWidget(self.export_btn)
            
            layout.addLayout(btn_layout)
            
            # Progress bar
            self.progress = QProgressBar()
            self.progress.setValue(0)
            layout.addWidget(self.progress)
            
            self.status_label = QLabel("Ready to scan")
            layout.addWidget(self.status_label)
            
            # Results area
            results_group = QGroupBox("📋 Scan Results")
            results_layout = QVBoxLayout(results_group)
            
            self.results_text = QTextEdit()
            self.results_text.setReadOnly(True)
            self.results_text.setFont(QFont("Consolas", 9))
            results_layout.addWidget(self.results_text)
            
            layout.addWidget(results_group)
            
        def _browse_directory(self):
            """Open directory browser."""
            directory = QFileDialog.getExistingDirectory(
                self, "Select Directory with Text Files"
            )
            if directory:
                self.dir_edit.setText(directory)
                
        def _update_status(self, message: str):
            """Update status label."""
            self.status_label.setText(message)
            QApplication.processEvents()
            
        def _append_result(self, text: str, color: str = None):
            """Append text to results area."""
            if color:
                self.results_text.setTextColor(QColor(color))
            self.results_text.append(text)
            if color:
                self.results_text.setTextColor(QColor("#000000"))
            QApplication.processEvents()
            
        def _start_scan(self):
            """Start the scanning process."""
            directory = self.dir_edit.text().strip()
            
            if not directory:
                QMessageBox.warning(self, "Error", "Please select a directory to scan.")
                return
                
            if not os.path.isdir(directory):
                QMessageBox.warning(self, "Error", f"Directory not found:\n{directory}")
                return
            
            # Find text files
            text_files = []
            for ext in ['.txt', '.md', '.text']:
                text_files.extend(Path(directory).glob(f'*{ext}'))
            
            if not text_files:
                QMessageBox.information(self, "No Files", "No .txt or .md files found.")
                return
            
            # Clear previous results
            self.results_text.clear()
            self.scan_results = []
            self.scan_btn.setEnabled(False)
            
            # Counters
            files_clean = 0
            files_flagged = 0
            total_threats = 0
            
            self._append_result("=" * 60)
            self._append_result("  SAFE_SCRUB v2.0.5 QGIS SECURITY SCAN")
            self._append_result(f"  Scan Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
            self._append_result("=" * 60 + "\n")
            
            for idx, file_path in enumerate(text_files):
                progress = int(((idx + 1) / len(text_files)) * 100)
                self.progress.setValue(progress)
                self._update_status(f"Scanning: {file_path.name}")
                
                try:
                    with open(file_path, 'r', encoding='utf-8', errors='replace') as f:
                        content = f.read()
                    
                    result = self.scanner.scan_content(content, file_path.name)
                    self.scan_results.append(result)
                    
                    if result.is_safe:
                        files_clean += 1
                    else:
                        files_flagged += 1
                    total_threats += result.total_threats
                    
                    self._append_result(f"📄 {file_path.name}")
                    
                    color = "#28a745" if result.is_safe else "#dc3545"
                    self._append_result(f"   Score: {result.security_score}", color)
                    
                    if result.threats:
                        self._append_result(f"   Threats: {result.total_threats} [C:{result.critical_count} H:{result.high_count} M:{result.medium_count} L:{result.low_count}]")
                        
                        for threat in result.threats[:3]:
                            self._append_result(f"   • [{threat['threat_level']}] {threat['category']}: {threat['text'][:40]}...")
                    else:
                        self._append_result("   ✓ Clean", "#28a745")
                    
                    self._append_result("")
                    
                    # Auto-sanitize
                    if self.auto_sanitize_chk.isChecked() and result.threats:
                        sanitized = self.scanner.sanitize_content(content, result)
                        sanitized_path = file_path.parent / f"{file_path.stem}_ScrubSafe{file_path.suffix}"
                        with open(sanitized_path, 'w', encoding='utf-8') as f:
                            f.write(sanitized)
                            
                except Exception as e:
                    self._append_result(f"❌ Error: {file_path.name}: {str(e)}", "#dc3545")
                    QgsMessageLog.logMessage(f"Error scanning {file_path}: {e}", "Safe_Scrub", Qgis.Warning)
            
            # Summary
            self._append_result("=" * 60)
            self._append_result("  SCAN SUMMARY")
            self._append_result("=" * 60)
            self._append_result(f"  Total Files: {len(text_files)}")
            self._append_result(f"  Clean: {files_clean}")
            self._append_result(f"  Flagged: {files_flagged}")
            self._append_result(f"  Total Threats: {total_threats}")
            self._append_result("=" * 60)
            
            # Generate CSV report
            report_path = Path(directory) / f"qgis_security_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
            self._generate_csv_report(report_path)
            
            # Generate JSON if enabled
            if self.json_log_chk.isChecked():
                json_path = Path(directory) / f"qgis_security_audit_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
                self._generate_json_audit(json_path)
            
            self.scan_btn.setEnabled(True)
            self.export_btn.setEnabled(True)
            self._update_status(f"Scan complete. Report saved.")
            
            # Log to QGIS
            QgsMessageLog.logMessage(
                f"Safe_Scrub scan complete: {len(text_files)} files, {files_flagged} flagged, {total_threats} threats",
                "Safe_Scrub", Qgis.Info
            )
            
            QMessageBox.information(
                self, "Scan Complete",
                f"Scanned {len(text_files)} files.\n"
                f"Clean: {files_clean} | Flagged: {files_flagged}\n\n"
                f"Report saved to:\n{report_path.name}"
            )
            
        def _generate_csv_report(self, report_path: Path):
            """Generate CSV report."""
            with open(report_path, 'w', newline='', encoding='utf-8') as f:
                writer = csv.writer(f)
                writer.writerow([
                    'Filename', 'Hash', 'Score', 'Safe', 'Total', 
                    'Critical', 'High', 'Medium', 'Low', 'Top Threat'
                ])
                
                for result in self.scan_results:
                    top = result.threats[0] if result.threats else None
                    writer.writerow([
                        result.filename, result.file_hash, result.security_score,
                        'Yes' if result.is_safe else 'No', result.total_threats,
                        result.critical_count, result.high_count, result.medium_count,
                        result.low_count, top['category'] if top else 'N/A'
                    ])
                    
        def _generate_json_audit(self, json_path: Path):
            """Generate JSON audit log."""
            audit = {
                'tool': 'Safe_Scrub v2.0.5 QGIS',
                'timestamp': datetime.now().isoformat(),
                'summary': {
                    'total_files': len(self.scan_results),
                    'clean': sum(1 for r in self.scan_results if r.is_safe),
                    'flagged': sum(1 for r in self.scan_results if not r.is_safe),
                    'total_threats': sum(r.total_threats for r in self.scan_results)
                },
                'results': [
                    {
                        'file': r.filename,
                        'hash': r.file_hash,
                        'score': r.security_score,
                        'safe': r.is_safe,
                        'threats': r.threats
                    }
                    for r in self.scan_results
                ]
            }
            
            with open(json_path, 'w', encoding='utf-8') as f:
                json.dump(audit, f, indent=2)
                
        def _export_report(self):
            """Export full report."""
            if not self.scan_results:
                QMessageBox.warning(self, "No Data", "No scan results to export.")
                return
                
            path, _ = QFileDialog.getSaveFileName(
                self, "Export Report", "", "CSV Files (*.csv);;JSON Files (*.json)"
            )
            
            if path:
                if path.endswith('.json'):
                    self._generate_json_audit(Path(path))
                else:
                    self._generate_csv_report(Path(path))
                QMessageBox.information(self, "Export Complete", f"Report saved to:\n{path}")


# =============================================================================
# ENTRY POINT FUNCTION
# =============================================================================

def run_safe_scrub():
    """
    Launch the Safe_Scrub dialog in QGIS.
    
    Usage in QGIS Python Console:
        exec(open('path/to/Safe_Scrub_v2_QGIS.py').read())
        run_safe_scrub()
    """
    if not QGIS_AVAILABLE:
        print("ERROR: This script must be run within QGIS Python Console.")
        return
    
    # Get QGIS main window as parent
    from qgis.utils import iface
    parent = iface.mainWindow() if hasattr(iface, 'mainWindow') else None
    
    dialog = SafeScrubQGISDialog(parent)
    dialog.exec_()


# =============================================================================
# COMMAND LINE / DIRECT EXECUTION
# =============================================================================

def run_cli_scan(directory: str):
    """
    Command-line interface for batch scanning.
    Can be used in QGIS Processing scripts.
    
    Args:
        directory: Path to directory containing text files
    """
    scanner = SafeScrubScanner()
    results = []
    
    text_files = []
    for ext in ['.txt', '.md']:
        text_files.extend(Path(directory).glob(f'*{ext}'))
    
    print(f"Safe_Scrub v2.0.5 - Scanning {len(text_files)} files...")
    
    for file_path in text_files:
        try:
            with open(file_path, 'r', encoding='utf-8', errors='replace') as f:
                content = f.read()
            
            result = scanner.scan_content(content, file_path.name)
            results.append(result)
            
            status = "✓ SAFE" if result.is_safe else f"⚠ FLAGGED ({result.total_threats} threats)"
            print(f"  {file_path.name}: {result.security_score} - {status}")
            
            # Auto-sanitize flagged files
            if result.threats:
                sanitized = scanner.sanitize_content(content, result)
                out_path = file_path.parent / f"{file_path.stem}_ScrubSafe{file_path.suffix}"
                with open(out_path, 'w', encoding='utf-8') as f:
                    f.write(sanitized)
                    
        except Exception as e:
            print(f"  {file_path.name}: ERROR - {e}")
    
    # Summary
    clean = sum(1 for r in results if r.is_safe)
    flagged = len(results) - clean
    threats = sum(r.total_threats for r in results)
    
    print(f"\nSummary: {len(results)} files | {clean} clean | {flagged} flagged | {threats} threats")
    
    return results


# =============================================================================
# AUTO-RUN WHEN LOADED IN QGIS
# =============================================================================
# This section automatically launches the dialog when the script is loaded
# via exec() in the QGIS Python Console.

if QGIS_AVAILABLE:
    # Print confirmation that script loaded
    print("="*50)
    print("Safe_Scrub v2.0.5 QGIS Edition - Loaded Successfully")
    print("="*50)
    print("Launching security scanner dialog...")
    
    # Auto-launch the dialog
    run_safe_scrub()
else:
    print("Safe_Scrub v2.0.5 QGIS Edition")
    print("ERROR: QGIS libraries not detected.")
    print("This script must be run within QGIS Python Console.")
    print("")
    print("Usage in QGIS:")
    print("  exec(open(r'path/to/Safe_Scrub_v2_QGIS.py').read())")
    print("")
    print("Or with Path:")
    print("  from pathlib import Path")
    print("  exec(compile(Path('path/to/Safe_Scrub_v2_QGIS.py').read_text(), 'script', 'exec'))")
