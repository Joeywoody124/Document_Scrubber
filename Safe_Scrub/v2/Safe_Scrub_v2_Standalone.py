#!/usr/bin/env python3
"""
Safe_Scrub v2 - AI Data Sanitizer for Prompt Injection Detection
================================================================
Professional-grade security tool for scanning text files before AI ingestion.
Designed for civil engineering and stormwater management workflows.

Purpose: Scans PDF-converted text files for malicious prompt injection patterns,
         hidden instructions, and AI manipulation attempts while preserving
         legitimate technical terminology.

Author: J. Bragg Consulting Inc.
Version: 2.0.5
License: MIT

Security Rating Target: A-grade for third-party IT security audits
"""

import os
import re
import csv
import json
import hashlib
import tkinter as tk
from tkinter import filedialog, messagebox, ttk, scrolledtext
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Tuple, Set, Optional
from dataclasses import dataclass, field
from enum import Enum


# =============================================================================
# SECURITY CONFIGURATION - INJECTION DETECTION PATTERNS
# =============================================================================

class ThreatLevel(Enum):
    """Threat severity classification for security auditing."""
    CRITICAL = 4  # Direct prompt override attempts
    HIGH = 3      # Manipulation or jailbreak attempts  
    MEDIUM = 2    # Suspicious patterns or encoding
    LOW = 1       # Potential indicators, may be false positives
    INFO = 0      # Informational only


@dataclass
class ThreatPattern:
    """Defines a security threat pattern with metadata."""
    pattern: str
    category: str
    threat_level: ThreatLevel
    description: str
    is_regex: bool = True
    case_sensitive: bool = False


# -----------------------------------------------------------------------------
# CRITICAL THREAT PATTERNS - Direct AI Manipulation Attempts
# -----------------------------------------------------------------------------
CRITICAL_PATTERNS: List[ThreatPattern] = [
    # Direct instruction override
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
    
    # System prompt extraction
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
        r"(?:copy|paste|repeat)\s+(?:your\s+)?(?:entire\s+)?(?:system\s+)?(?:prompt|instructions?)",
        "System Prompt Extraction", ThreatLevel.CRITICAL,
        "Attempts to extract full prompt"
    ),
    
    # Jailbreak keywords
    ThreatPattern(
        r"\bDAN\b.*(?:mode|jailbreak|anything\s+now)",
        "Jailbreak Attempt", ThreatLevel.CRITICAL,
        "DAN (Do Anything Now) jailbreak pattern"
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

# -----------------------------------------------------------------------------
# HIGH THREAT PATTERNS - Manipulation and Social Engineering
# -----------------------------------------------------------------------------
HIGH_PATTERNS: List[ThreatPattern] = [
    # Role manipulation
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
        r"(?:new\s+)?(?:persona|character|role|identity)\s*[:\-]\s*",
        "Role Assignment", ThreatLevel.HIGH,
        "Attempts to assign new persona"
    ),
    
    # Hidden instruction injection
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
    
    # Constraint bypass
    ThreatPattern(
        r"(?:bypass|circumvent|ignore|disable|override)\s+(?:your\s+)?(?:safety|security|content|ethical)\s+(?:filters?|guidelines?|restrictions?|limits?)",
        "Safety Bypass", ThreatLevel.HIGH,
        "Attempts to bypass safety mechanisms"
    ),
    ThreatPattern(
        r"(?:without|no)\s+(?:safety|security|content)\s+(?:filters?|checks?|restrictions?)",
        "Filter Removal", ThreatLevel.HIGH,
        "Requests to remove safety filters"
    ),
    
    # Hypothetical framing for bypass
    ThreatPattern(
        r"(?:hypothetically|theoretically|imagine\s+if|what\s+if)\s+(?:you\s+)?(?:could|were\s+able\s+to|had\s+no)\s+(?:ignore|bypass|override)",
        "Hypothetical Bypass", ThreatLevel.HIGH,
        "Hypothetical framing to bypass restrictions"
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

# -----------------------------------------------------------------------------
# MEDIUM THREAT PATTERNS - Suspicious Indicators
# -----------------------------------------------------------------------------
MEDIUM_PATTERNS: List[ThreatPattern] = [
    # Encoding manipulation
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
        r"&#x?[0-9a-fA-F]+;",
        "HTML Entity Encoding", ThreatLevel.MEDIUM,
        "HTML entity encoding detected"
    ),
    
    # Markdown/formatting tricks
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
        r"\u200b|\u200c|\u200d|\ufeff",
        "Zero-Width Characters", ThreatLevel.MEDIUM,
        "Invisible Unicode characters detected"
    ),
    
    # Context manipulation
    ThreatPattern(
        r"(?:end|close|terminate)\s+(?:of\s+)?(?:system\s+)?(?:prompt|context|message)",
        "Context Termination", ThreatLevel.MEDIUM,
        "Attempts to terminate system context"
    ),
    ThreatPattern(
        r"---+\s*(?:NEW|END|BEGIN)\s+(?:CONVERSATION|CONTEXT|PROMPT)\s*---+",
        "Context Boundary Injection", ThreatLevel.MEDIUM,
        "Fake context boundaries"
    ),
    
    # Social engineering patterns
    ThreatPattern(
        r"(?:trust\s+me|believe\s+me|i\s+promise)[,\s]+(?:this\s+is|you\s+can|it's)\s+(?:safe|okay|fine|allowed)",
        "Social Engineering", ThreatLevel.MEDIUM,
        "Trust manipulation language"
    ),
    ThreatPattern(
        r"(?:emergency|urgent|critical)[:\s]+(?:override|bypass|ignore)",
        "Urgency Manipulation", ThreatLevel.MEDIUM,
        "Urgency-based manipulation"
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
        r"data:(?:text|application)/[^;]+;base64,",
        "Data URI Injection", ThreatLevel.MEDIUM,
        "Data URI with embedded content detected"
    ),
]

# -----------------------------------------------------------------------------
# LOW THREAT PATTERNS - Potential Indicators (May Have Legitimate Uses)
# -----------------------------------------------------------------------------
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
    ThreatPattern(
        r"(?:no|without)\s+(?:warnings?|disclaimers?|caveats?)",
        "Disclaimer Removal", ThreatLevel.LOW,
        "Requests to remove safety disclaimers"
    ),
    ThreatPattern(
        r"don't\s+(?:tell|inform|warn|notify)\s+(?:anyone|the\s+user)",
        "Secrecy Request", ThreatLevel.LOW,
        "Secrecy or concealment language"
    ),
]


# =============================================================================
# CIVIL ENGINEERING & STORMWATER WHITELIST
# =============================================================================
# These patterns should NOT be flagged as threats - they are legitimate
# technical terminology used in civil engineering and stormwater documents.

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
    "safety override", "emergency override", "automatic override",
    
    # Construction Terms
    "prompt response", "prompt action", "prompt delivery", "prompt completion",
    "prompt notification", "prompt submittal",
    
    # Regulatory Terms - only specific variance contexts
    "ignore setbacks", "ignore buffer",  # In context of variance requests
    
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
    
    # REMOVED from direct whitelist (v2.0.1 -> v2.0.2):
    # "developer mode", "debug mode", "admin access" 
    # These are too easily confused with jailbreak attempts.
    # They will only be whitelisted via ENGINEERING_WHITELIST_PATTERNS
    # when preceded by equipment identifiers like "SCADA", "PLC", etc.
}

# Regex patterns for context-aware whitelisting
ENGINEERING_WHITELIST_PATTERNS: List[str] = [
    # Measurement and calculations
    r"(?:flow|discharge|volume|rate|capacity)\s+(?:bypass|override|system)",
    
    # Equipment references  
    r"(?:pump|valve|gate|weir|pipe|channel)\s+(?:system|bypass|mode|control)",
    
    # Document references
    r"(?:section|page|figure|table|appendix)\s+\d+",
    
    # Standard references
    r"(?:ASTM|ASCE|AWWA|EPA|NPDES|MS4|BMP)\s*[-\d]*",
    
    # Permit and regulatory
    r"(?:permit|variance|approval|compliance)\s+(?:number|id|code|requirement)",
    
    # Technical specifications
    r"\d+(?:\.\d+)?\s*(?:cfs|gpm|mgd|psi|fps|ft|in|ac|sf|cy|lf)",
]


# =============================================================================
# SECURITY SCANNER CLASS
# =============================================================================

@dataclass
class ScanResult:
    """Container for scan results with detailed threat information."""
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


class SafeScrubScanner:
    """
    Security scanner for detecting prompt injection and AI manipulation attempts.
    Designed for civil engineering document workflows.
    """
    
    def __init__(self):
        """Initialize scanner with all threat patterns."""
        self.patterns: List[ThreatPattern] = (
            CRITICAL_PATTERNS + HIGH_PATTERNS + MEDIUM_PATTERNS + LOW_PATTERNS
        )
        self.whitelist = ENGINEERING_WHITELIST
        self.whitelist_patterns = [re.compile(p, re.IGNORECASE) 
                                   for p in ENGINEERING_WHITELIST_PATTERNS]
        
    def _compute_file_hash(self, content: str) -> str:
        """Compute SHA-256 hash of file content for audit trail."""
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
        
        # Check if the matched text DIRECTLY contains a whitelist term
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
        """
        Scan text content for security threats.
        
        Args:
            content: Text content to scan
            filename: Source filename for reporting
            
        Returns:
            ScanResult with detailed threat analysis
        """
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
                    # Simple string matching
                    search_content = content if pattern.case_sensitive else content.lower()
                    search_pattern = pattern.pattern if pattern.case_sensitive else pattern.pattern.lower()
                    matches = []
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
                    
                    # Check whitelist
                    if self._is_whitelisted(match_text, match.start(), match.end(), content):
                        result.whitelisted_matches.append({
                            'text': match_text,
                            'pattern': pattern.pattern,
                            'category': pattern.category,
                            'reason': 'Engineering terminology whitelist'
                        })
                        continue
                    
                    # Record threat
                    # Get line number
                    line_num = content[:match.start()].count('\n') + 1
                    
                    # Get context (surrounding text)
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
                    
                    # Update counts by severity
                    if pattern.threat_level == ThreatLevel.CRITICAL:
                        result.critical_count += 1
                    elif pattern.threat_level == ThreatLevel.HIGH:
                        result.high_count += 1
                    elif pattern.threat_level == ThreatLevel.MEDIUM:
                        result.medium_count += 1
                    else:
                        result.low_count += 1
                        
            except re.error as e:
                print(f"Regex error in pattern '{pattern.pattern}': {e}")
                continue
        
        # Calculate final security score
        result.security_score = result.calculate_score()
        result.is_safe = result.security_score in ['A', 'A-', 'B+', 'B']
        
        return result
    
    def sanitize_content(self, content: str, result: ScanResult, 
                         redaction_marker: str = "[REDACTED_SECURITY_THREAT]") -> str:
        """
        Sanitize content by redacting detected threats.
        
        Args:
            content: Original content
            result: Scan result with threat locations
            redaction_marker: Text to replace threats with
            
        Returns:
            Sanitized content
        """
        if not result.threats:
            return content
        
        # Sort threats by position (descending) to preserve positions during replacement
        sorted_threats = sorted(result.threats, key=lambda x: x['position'], reverse=True)
        
        sanitized = content
        for threat in sorted_threats:
            pos = threat['position']
            text = threat['text']
            # Only redact CRITICAL and HIGH threats by default
            if threat['threat_value'] >= ThreatLevel.HIGH.value:
                sanitized = sanitized[:pos] + redaction_marker + sanitized[pos + len(text):]
        
        return sanitized


# =============================================================================
# GUI APPLICATION
# =============================================================================

class SafeScrubGUI:
    """Professional GUI for Safe_Scrub security scanner."""
    
    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title("Safe_Scrub v2.0.5 - AI Data Security Scanner")
        self.root.geometry("950x750")
        self.root.minsize(800, 600)
        
        # Initialize scanner
        self.scanner = SafeScrubScanner()
        
        # Theme colors (Professional Dark Theme)
        self.colors = {
            'bg': '#1a1a2e',
            'bg_secondary': '#16213e',
            'fg': '#eaeaea',
            'accent': '#0f3460',
            'accent_light': '#e94560',
            'success': '#00d26a',
            'warning': '#ffc107',
            'danger': '#dc3545',
            'info': '#17a2b8',
            'card': '#0f3460',
            'border': '#533483'
        }
        
        # Configure root
        self.root.configure(bg=self.colors['bg'])
        
        # Build GUI
        self._create_header()
        self._create_main_content()
        self._create_footer()
        
    def _create_header(self):
        """Create header section with title and description."""
        header = tk.Frame(self.root, bg=self.colors['bg_secondary'], pady=15)
        header.pack(fill=tk.X)
        
        title = tk.Label(
            header,
            text="🛡️ Safe_Scrub v2.0.5",
            font=('Segoe UI', 20, 'bold'),
            fg=self.colors['accent_light'],
            bg=self.colors['bg_secondary']
        )
        title.pack()
        
        subtitle = tk.Label(
            header,
            text="AI Data Security Scanner for Civil Engineering Workflows",
            font=('Segoe UI', 10),
            fg=self.colors['fg'],
            bg=self.colors['bg_secondary']
        )
        subtitle.pack()
        
    def _create_main_content(self):
        """Create main content area with controls and results."""
        main = tk.Frame(self.root, bg=self.colors['bg'], padx=20, pady=15)
        main.pack(fill=tk.BOTH, expand=True)
        
        # Left column - Controls
        left_frame = tk.Frame(main, bg=self.colors['bg'])
        left_frame.pack(side=tk.LEFT, fill=tk.Y, padx=(0, 10))
        
        # Directory selection
        dir_frame = tk.LabelFrame(
            left_frame, 
            text=" 📁 Directory Selection ",
            font=('Segoe UI', 10, 'bold'),
            fg=self.colors['fg'],
            bg=self.colors['card'],
            padx=10, pady=10
        )
        dir_frame.pack(fill=tk.X, pady=(0, 10))
        
        self.dir_var = tk.StringVar()
        dir_entry = tk.Entry(
            dir_frame, 
            textvariable=self.dir_var,
            font=('Consolas', 9),
            width=35,
            bg=self.colors['bg'],
            fg=self.colors['fg'],
            insertbackground=self.colors['fg']
        )
        dir_entry.pack(side=tk.LEFT, fill=tk.X, expand=True)
        
        browse_btn = tk.Button(
            dir_frame,
            text="Browse",
            font=('Segoe UI', 9),
            bg=self.colors['accent'],
            fg=self.colors['fg'],
            activebackground=self.colors['accent_light'],
            command=self._browse_directory,
            cursor='hand2'
        )
        browse_btn.pack(side=tk.RIGHT, padx=(5, 0))
        
        # Options frame
        options_frame = tk.LabelFrame(
            left_frame,
            text=" ⚙️ Scan Options ",
            font=('Segoe UI', 10, 'bold'),
            fg=self.colors['fg'],
            bg=self.colors['card'],
            padx=10, pady=10
        )
        options_frame.pack(fill=tk.X, pady=(0, 10))
        
        self.auto_sanitize_var = tk.BooleanVar(value=True)
        auto_chk = tk.Checkbutton(
            options_frame,
            text="Auto-generate sanitized files",
            variable=self.auto_sanitize_var,
            font=('Segoe UI', 9),
            fg=self.colors['fg'],
            bg=self.colors['card'],
            selectcolor=self.colors['bg'],
            activebackground=self.colors['card']
        )
        auto_chk.pack(anchor=tk.W)
        
        self.include_low_var = tk.BooleanVar(value=False)
        low_chk = tk.Checkbutton(
            options_frame,
            text="Include LOW-level threats in report",
            variable=self.include_low_var,
            font=('Segoe UI', 9),
            fg=self.colors['fg'],
            bg=self.colors['card'],
            selectcolor=self.colors['bg'],
            activebackground=self.colors['card']
        )
        low_chk.pack(anchor=tk.W)
        
        self.generate_json_var = tk.BooleanVar(value=True)
        json_chk = tk.Checkbutton(
            options_frame,
            text="Generate JSON audit log",
            variable=self.generate_json_var,
            font=('Segoe UI', 9),
            fg=self.colors['fg'],
            bg=self.colors['card'],
            selectcolor=self.colors['bg'],
            activebackground=self.colors['card']
        )
        json_chk.pack(anchor=tk.W)
        
        # Action buttons
        btn_frame = tk.Frame(left_frame, bg=self.colors['bg'])
        btn_frame.pack(fill=tk.X, pady=10)
        
        self.scan_btn = tk.Button(
            btn_frame,
            text="🔍 SCAN FILES",
            font=('Segoe UI', 12, 'bold'),
            bg=self.colors['success'],
            fg='white',
            activebackground='#00b359',
            command=self._start_scan,
            cursor='hand2',
            height=2
        )
        self.scan_btn.pack(fill=tk.X, pady=(0, 5))
        
        self.export_btn = tk.Button(
            btn_frame,
            text="📊 Export Full Report",
            font=('Segoe UI', 10),
            bg=self.colors['info'],
            fg='white',
            activebackground='#138496',
            command=self._export_report,
            cursor='hand2',
            state=tk.DISABLED
        )
        self.export_btn.pack(fill=tk.X)
        
        # Statistics panel
        stats_frame = tk.LabelFrame(
            left_frame,
            text=" 📈 Scan Statistics ",
            font=('Segoe UI', 10, 'bold'),
            fg=self.colors['fg'],
            bg=self.colors['card'],
            padx=10, pady=10
        )
        stats_frame.pack(fill=tk.X, pady=(10, 0))
        
        self.stats_labels = {}
        stats_items = [
            ('files_scanned', 'Files Scanned:', '0'),
            ('files_clean', 'Clean Files:', '0'),
            ('files_flagged', 'Flagged Files:', '0'),
            ('total_threats', 'Total Threats:', '0'),
            ('avg_score', 'Average Score:', '-')
        ]
        
        for key, label, default in stats_items:
            row = tk.Frame(stats_frame, bg=self.colors['card'])
            row.pack(fill=tk.X, pady=2)
            
            lbl = tk.Label(
                row, text=label,
                font=('Segoe UI', 9),
                fg=self.colors['fg'],
                bg=self.colors['card'],
                width=15, anchor=tk.W
            )
            lbl.pack(side=tk.LEFT)
            
            val = tk.Label(
                row, text=default,
                font=('Segoe UI', 9, 'bold'),
                fg=self.colors['accent_light'],
                bg=self.colors['card']
            )
            val.pack(side=tk.LEFT)
            self.stats_labels[key] = val
        
        # Progress bar
        self.progress_var = tk.DoubleVar()
        self.progress = ttk.Progressbar(
            left_frame,
            variable=self.progress_var,
            maximum=100,
            mode='determinate'
        )
        self.progress.pack(fill=tk.X, pady=(10, 0))
        
        self.status_label = tk.Label(
            left_frame,
            text="Ready to scan",
            font=('Segoe UI', 9),
            fg=self.colors['fg'],
            bg=self.colors['bg']
        )
        self.status_label.pack(pady=(5, 0))
        
        # Right column - Results
        right_frame = tk.Frame(main, bg=self.colors['bg'])
        right_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True)
        
        results_frame = tk.LabelFrame(
            right_frame,
            text=" 📋 Scan Results ",
            font=('Segoe UI', 10, 'bold'),
            fg=self.colors['fg'],
            bg=self.colors['card'],
            padx=10, pady=10
        )
        results_frame.pack(fill=tk.BOTH, expand=True)
        
        # Results text area
        self.results_text = scrolledtext.ScrolledText(
            results_frame,
            font=('Consolas', 9),
            bg=self.colors['bg'],
            fg=self.colors['fg'],
            insertbackground=self.colors['fg'],
            wrap=tk.WORD,
            state=tk.DISABLED
        )
        self.results_text.pack(fill=tk.BOTH, expand=True)
        
        # Configure text tags for coloring
        self.results_text.tag_configure('critical', foreground='#ff4444')
        self.results_text.tag_configure('high', foreground='#ff8800')
        self.results_text.tag_configure('medium', foreground='#ffcc00')
        self.results_text.tag_configure('low', foreground='#88ccff')
        self.results_text.tag_configure('safe', foreground='#00dd66')
        self.results_text.tag_configure('header', foreground='#e94560', font=('Consolas', 10, 'bold'))
        self.results_text.tag_configure('filename', foreground='#17a2b8', font=('Consolas', 9, 'bold'))
        
        # Store results for export
        self.scan_results: List[ScanResult] = []
        
    def _create_footer(self):
        """Create footer with version and help info."""
        footer = tk.Frame(self.root, bg=self.colors['bg_secondary'], pady=8)
        footer.pack(fill=tk.X, side=tk.BOTTOM)
        
        info = tk.Label(
            footer,
            text="Safe_Scrub v2.0.5 | J. Bragg Consulting Inc. | Target: A-Grade IT Security Compliance",
            font=('Segoe UI', 8),
            fg=self.colors['fg'],
            bg=self.colors['bg_secondary']
        )
        info.pack()
        
    def _browse_directory(self):
        """Open directory browser."""
        directory = filedialog.askdirectory(
            title="Select Directory with Text Files to Scan"
        )
        if directory:
            self.dir_var.set(directory)
            
    def _update_status(self, message: str):
        """Update status label."""
        self.status_label.config(text=message)
        self.root.update_idletasks()
        
    def _append_result(self, text: str, tag: str = None):
        """Append text to results area."""
        self.results_text.config(state=tk.NORMAL)
        if tag:
            self.results_text.insert(tk.END, text, tag)
        else:
            self.results_text.insert(tk.END, text)
        self.results_text.see(tk.END)
        self.results_text.config(state=tk.DISABLED)
        self.root.update_idletasks()
        
    def _clear_results(self):
        """Clear results area."""
        self.results_text.config(state=tk.NORMAL)
        self.results_text.delete(1.0, tk.END)
        self.results_text.config(state=tk.DISABLED)
        
    def _start_scan(self):
        """Start the scanning process."""
        directory = self.dir_var.get().strip()
        
        if not directory:
            messagebox.showerror("Error", "Please select a directory to scan.")
            return
            
        if not os.path.isdir(directory):
            messagebox.showerror("Error", f"Directory not found:\n{directory}")
            return
        
        # Find text files
        text_files = []
        for ext in ['.txt', '.md', '.text']:
            text_files.extend(Path(directory).glob(f'*{ext}'))
        
        if not text_files:
            messagebox.showinfo("No Files", "No .txt or .md files found in the directory.")
            return
        
        # Clear previous results
        self._clear_results()
        self.scan_results = []
        
        # Disable scan button during processing
        self.scan_btn.config(state=tk.DISABLED)
        
        # Initialize counters
        files_clean = 0
        files_flagged = 0
        total_threats = 0
        total_score = 0
        
        self._append_result("=" * 70 + "\n", 'header')
        self._append_result("  SAFE_SCRUB v2.0.5 SECURITY SCAN REPORT\n", 'header')
        self._append_result(f"  Scan Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n", 'header')
        self._append_result("=" * 70 + "\n\n")
        
        for idx, file_path in enumerate(text_files):
            # Update progress
            progress = ((idx + 1) / len(text_files)) * 100
            self.progress_var.set(progress)
            self._update_status(f"Scanning: {file_path.name}")
            
            try:
                # Read file content
                with open(file_path, 'r', encoding='utf-8', errors='replace') as f:
                    content = f.read()
                
                # Scan content
                result = self.scanner.scan_content(content, file_path.name)
                self.scan_results.append(result)
                
                # Update counters
                if result.is_safe:
                    files_clean += 1
                else:
                    files_flagged += 1
                total_threats += result.total_threats
                
                # Convert score to number for averaging
                score_map = {'A': 100, 'A-': 95, 'B+': 90, 'B': 85, 'C': 75, 'D': 65, 'F': 50}
                total_score += score_map.get(result.security_score, 50)
                
                # Display result
                self._append_result(f"📄 {file_path.name}\n", 'filename')
                
                score_tag = 'safe' if result.is_safe else 'critical'
                self._append_result(f"   Security Score: {result.security_score}\n", score_tag)
                
                if result.threats:
                    self._append_result(f"   Threats Found: {result.total_threats}\n")
                    self._append_result(f"   [CRITICAL: {result.critical_count} | ")
                    self._append_result(f"HIGH: {result.high_count} | ")
                    self._append_result(f"MEDIUM: {result.medium_count} | ")
                    self._append_result(f"LOW: {result.low_count}]\n")
                    
                    # Show top threats
                    for threat in result.threats[:3]:
                        level = threat['threat_level'].lower()
                        self._append_result(f"   • [{level.upper()}] ", level)
                        self._append_result(f"{threat['category']}: {threat['text'][:50]}...\n")
                    
                    if len(result.threats) > 3:
                        self._append_result(f"   ... and {len(result.threats) - 3} more threats\n")
                else:
                    self._append_result("   ✓ No threats detected\n", 'safe')
                
                self._append_result("\n")
                
                # Auto-sanitize if enabled
                if self.auto_sanitize_var.get() and result.threats:
                    sanitized = self.scanner.sanitize_content(content, result)
                    sanitized_path = file_path.parent / f"{file_path.stem}_ScrubSafe{file_path.suffix}"
                    with open(sanitized_path, 'w', encoding='utf-8') as f:
                        f.write(sanitized)
                        
            except Exception as e:
                self._append_result(f"❌ Error scanning {file_path.name}: {str(e)}\n", 'critical')
        
        # Generate summary
        avg_score = total_score / len(text_files) if text_files else 0
        avg_grade = 'A' if avg_score >= 95 else 'A-' if avg_score >= 90 else 'B+' if avg_score >= 85 else 'B' if avg_score >= 80 else 'C' if avg_score >= 70 else 'D' if avg_score >= 60 else 'F'
        
        self._append_result("=" * 70 + "\n", 'header')
        self._append_result("  SCAN SUMMARY\n", 'header')
        self._append_result("=" * 70 + "\n")
        self._append_result(f"  Total Files Scanned: {len(text_files)}\n")
        self._append_result(f"  Clean Files: {files_clean}\n", 'safe')
        self._append_result(f"  Flagged Files: {files_flagged}\n", 'critical' if files_flagged else 'safe')
        self._append_result(f"  Total Threats Detected: {total_threats}\n")
        self._append_result(f"  Average Security Score: {avg_grade}\n", 'safe' if avg_grade in ['A', 'A-'] else 'medium')
        self._append_result("=" * 70 + "\n")
        
        # Update statistics
        self.stats_labels['files_scanned'].config(text=str(len(text_files)))
        self.stats_labels['files_clean'].config(text=str(files_clean))
        self.stats_labels['files_flagged'].config(text=str(files_flagged))
        self.stats_labels['total_threats'].config(text=str(total_threats))
        self.stats_labels['avg_score'].config(text=avg_grade)
        
        # Generate CSV report
        report_path = Path(directory) / f"security_scan_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
        self._generate_csv_report(report_path)
        
        # Generate JSON audit log if enabled
        if self.generate_json_var.get():
            json_path = Path(directory) / f"security_audit_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
            self._generate_json_audit(json_path)
        
        # Re-enable buttons
        self.scan_btn.config(state=tk.NORMAL)
        self.export_btn.config(state=tk.NORMAL)
        self._update_status(f"Scan complete. Report saved to {report_path.name}")
        
        messagebox.showinfo(
            "Scan Complete",
            f"Scanned {len(text_files)} files.\n"
            f"Clean: {files_clean} | Flagged: {files_flagged}\n"
            f"Average Score: {avg_grade}\n\n"
            f"Report saved to:\n{report_path.name}"
        )
        
    def _generate_csv_report(self, report_path: Path):
        """Generate CSV report of scan results."""
        with open(report_path, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow([
                'Filename', 'File Hash', 'Scan Time', 'Security Score', 'Is Safe',
                'Total Threats', 'Critical', 'High', 'Medium', 'Low',
                'Top Threat Category', 'Top Threat Description'
            ])
            
            for result in self.scan_results:
                top_threat = result.threats[0] if result.threats else None
                writer.writerow([
                    result.filename,
                    result.file_hash,
                    result.scan_timestamp,
                    result.security_score,
                    'Yes' if result.is_safe else 'No',
                    result.total_threats,
                    result.critical_count,
                    result.high_count,
                    result.medium_count,
                    result.low_count,
                    top_threat['category'] if top_threat else 'N/A',
                    top_threat['description'] if top_threat else 'N/A'
                ])
                
    def _generate_json_audit(self, json_path: Path):
        """Generate detailed JSON audit log."""
        audit_data = {
            'scan_metadata': {
                'tool_name': 'Safe_Scrub',
                'version': '2.0.5',
                'scan_timestamp': datetime.now().isoformat(),
                'total_files': len(self.scan_results),
                'scanner_patterns': len(self.scanner.patterns)
            },
            'summary': {
                'files_clean': sum(1 for r in self.scan_results if r.is_safe),
                'files_flagged': sum(1 for r in self.scan_results if not r.is_safe),
                'total_threats': sum(r.total_threats for r in self.scan_results),
                'threat_breakdown': {
                    'critical': sum(r.critical_count for r in self.scan_results),
                    'high': sum(r.high_count for r in self.scan_results),
                    'medium': sum(r.medium_count for r in self.scan_results),
                    'low': sum(r.low_count for r in self.scan_results)
                }
            },
            'file_results': []
        }
        
        for result in self.scan_results:
            file_data = {
                'filename': result.filename,
                'file_hash': result.file_hash,
                'scan_timestamp': result.scan_timestamp,
                'security_score': result.security_score,
                'is_safe': result.is_safe,
                'threat_counts': {
                    'total': result.total_threats,
                    'critical': result.critical_count,
                    'high': result.high_count,
                    'medium': result.medium_count,
                    'low': result.low_count
                },
                'threats': result.threats,
                'whitelisted_matches': result.whitelisted_matches
            }
            audit_data['file_results'].append(file_data)
        
        with open(json_path, 'w', encoding='utf-8') as f:
            json.dump(audit_data, f, indent=2)
            
    def _export_report(self):
        """Export full detailed report."""
        if not self.scan_results:
            messagebox.showwarning("No Data", "No scan results to export.")
            return
            
        export_path = filedialog.asksaveasfilename(
            defaultextension='.txt',
            filetypes=[
                ('Text Files', '*.txt'),
                ('JSON Files', '*.json'),
                ('CSV Files', '*.csv')
            ],
            title="Export Scan Report"
        )
        
        if not export_path:
            return
            
        ext = Path(export_path).suffix.lower()
        
        if ext == '.json':
            self._generate_json_audit(Path(export_path))
        elif ext == '.csv':
            self._generate_csv_report(Path(export_path))
        else:
            # Text report
            with open(export_path, 'w', encoding='utf-8') as f:
                f.write("SAFE_SCRUB v2.0.5 SECURITY SCAN REPORT\n")
                f.write("=" * 70 + "\n")
                f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
                
                for result in self.scan_results:
                    f.write(f"File: {result.filename}\n")
                    f.write(f"Hash: {result.file_hash}\n")
                    f.write(f"Score: {result.security_score}\n")
                    f.write(f"Safe: {'Yes' if result.is_safe else 'No'}\n")
                    f.write(f"Threats: {result.total_threats}\n")
                    
                    if result.threats:
                        f.write("\nDetected Threats:\n")
                        for threat in result.threats:
                            f.write(f"  [{threat['threat_level']}] {threat['category']}\n")
                            f.write(f"    Line {threat['line']}: {threat['text']}\n")
                            f.write(f"    Context: {threat['context']}\n")
                    
                    f.write("\n" + "-" * 70 + "\n\n")
                    
        messagebox.showinfo("Export Complete", f"Report exported to:\n{export_path}")


# =============================================================================
# MAIN ENTRY POINT
# =============================================================================

def main():
    """Application entry point."""
    root = tk.Tk()
    app = SafeScrubGUI(root)
    
    # Center window
    root.update_idletasks()
    width = root.winfo_width()
    height = root.winfo_height()
    x = (root.winfo_screenwidth() // 2) - (width // 2)
    y = (root.winfo_screenheight() // 2) - (height // 2)
    root.geometry(f"+{x}+{y}")
    
    root.mainloop()


if __name__ == "__main__":
    main()
