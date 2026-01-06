#!/usr/bin/env python3
"""
Document Scrubber GUI with Multiple Themes
===========================================
A graphical interface for scrubbing personal and project-specific data
from text documents. Features runtime GUI style switching with 8 built-in
themes inspired by the GUI Design Center Library.

Author: Generated with Claude Code
Created: 2025-01-06
"""

import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import json
import os
import sys
from pathlib import Path
from typing import Dict, Any, Optional, List, Tuple
import re

# Import the core scrubbing functionality
from scrub_document import DocumentScrubber, DEFAULT_PATTERNS


# ============================================================================
# EMBEDDED THEME DEFINITIONS (No external files required)
# ============================================================================
EMBEDDED_THEMES = {
    "Twisty (Dark)": {
        "name": "Twisty",
        "background": "#0D0D12",
        "foreground": "#FFFFFF",
        "accent": "#8B5CF6",
        "accent_secondary": "#6366F1",
        "muted": "#1A1A24",
        "muted_fg": "#6B6B7B",
        "border": "#2A2A38",
        "card": "#1A1A24",
        "button_bg": "#8B5CF6",
        "button_fg": "#FFFFFF",
        "input_bg": "#1A1A24",
        "success": "#22C55E",
        "error": "#EF4444",
        "is_dark": True,
    },
    "Enterprise (Light)": {
        "name": "Enterprise",
        "background": "#F8FAFC",
        "foreground": "#0F172A",
        "accent": "#4F46E5",
        "accent_secondary": "#7C3AED",
        "muted": "#F1F5F9",
        "muted_fg": "#64748B",
        "border": "#E2E8F0",
        "card": "#FFFFFF",
        "button_bg": "#4F46E5",
        "button_fg": "#FFFFFF",
        "input_bg": "#FFFFFF",
        "success": "#10B981",
        "error": "#EF4444",
        "is_dark": False,
    },
    "Cyberpunk (Dark)": {
        "name": "Cyberpunk",
        "background": "#0a0a0f",
        "foreground": "#e0e0e0",
        "accent": "#00ff88",
        "accent_secondary": "#ff00ff",
        "muted": "#1c1c2e",
        "muted_fg": "#6b7280",
        "border": "#2a2a3a",
        "card": "#12121a",
        "button_bg": "#00ff88",
        "button_fg": "#0a0a0f",
        "input_bg": "#12121a",
        "success": "#00ff88",
        "error": "#ff3366",
        "is_dark": True,
    },
    "Kinetic (Dark)": {
        "name": "Kinetic",
        "background": "#09090B",
        "foreground": "#FAFAFA",
        "accent": "#DFE104",
        "accent_secondary": "#A1A1AA",
        "muted": "#27272A",
        "muted_fg": "#A1A1AA",
        "border": "#3F3F46",
        "card": "#18181B",
        "button_bg": "#DFE104",
        "button_fg": "#09090B",
        "input_bg": "#27272A",
        "success": "#22C55E",
        "error": "#EF4444",
        "is_dark": True,
    },
    "Bauhaus (Light)": {
        "name": "Bauhaus",
        "background": "#F0F0F0",
        "foreground": "#121212",
        "accent": "#D02020",
        "accent_secondary": "#1040C0",
        "muted": "#E0E0E0",
        "muted_fg": "#666666",
        "border": "#121212",
        "card": "#FFFFFF",
        "button_bg": "#D02020",
        "button_fg": "#FFFFFF",
        "input_bg": "#FFFFFF",
        "success": "#22C55E",
        "error": "#D02020",
        "is_dark": False,
    },
    "Academia (Dark)": {
        "name": "Academia",
        "background": "#1C1714",
        "foreground": "#E8DFD4",
        "accent": "#C9A962",
        "accent_secondary": "#8B2635",
        "muted": "#251E19",
        "muted_fg": "#9C8B7A",
        "border": "#4A3F35",
        "card": "#251E19",
        "button_bg": "#C9A962",
        "button_fg": "#1C1714",
        "input_bg": "#251E19",
        "success": "#22C55E",
        "error": "#8B2635",
        "is_dark": True,
    },
    "Sketch (Light)": {
        "name": "Sketch",
        "background": "#fdfbf7",
        "foreground": "#2d2d2d",
        "accent": "#ff4d4d",
        "accent_secondary": "#2d5da1",
        "muted": "#e5e0d8",
        "muted_fg": "#7a7a7a",
        "border": "#2d2d2d",
        "card": "#ffffff",
        "button_bg": "#ff4d4d",
        "button_fg": "#ffffff",
        "input_bg": "#ffffff",
        "success": "#22C55E",
        "error": "#ff4d4d",
        "is_dark": False,
    },
    "Playful Geometric (Light)": {
        "name": "Playful Geometric",
        "background": "#FFFDF5",
        "foreground": "#1E293B",
        "accent": "#8B5CF6",
        "accent_secondary": "#F472B6",
        "muted": "#F1F5F9",
        "muted_fg": "#64748B",
        "border": "#1E293B",
        "card": "#FFFFFF",
        "button_bg": "#8B5CF6",
        "button_fg": "#FFFFFF",
        "input_bg": "#FFFFFF",
        "success": "#34D399",
        "error": "#EF4444",
        "is_dark": False,
    },
}

# Optional: Path to external GUI Design Center Library for additional customization
# Set to None to use only embedded themes
STYLES_BASE_PATH = None  # or Path(r"path/to/GUI_Design_Center_Library/styles")

STYLE_MAP = {
    "Twisty (Dark)": "twisty/tokens.json",
    "Enterprise (Light)": "enterprise/tokens.json",
    "Cyberpunk (Dark)": "cyberpunk/tokens.json",
    "Kinetic (Dark)": "kinetic/tokens.json",
    "Bauhaus (Light)": "bauhaus/tokens.json",
    "Academia (Dark)": "academia/tokens.json",
    "Sketch (Light)": "sketch/tokens.json",
    "Playful Geometric (Light)": "playful-geometric/tokens.json",
}


# ============================================================================
# STYLE LOADER CLASS
# ============================================================================
class StyleLoader:
    """Loads and normalizes style tokens from JSON files or embedded themes."""

    def __init__(self, styles_base_path: Optional[Path]):
        self.base_path = styles_base_path
        self.cache: Dict[str, Dict[str, Any]] = {}

    def load_style(self, style_key: str) -> Optional[Dict[str, Any]]:
        """Load a style from embedded themes or JSON file, with caching."""
        if style_key in self.cache:
            return self.cache[style_key]

        # First, try embedded themes (always available)
        if style_key in EMBEDDED_THEMES:
            self.cache[style_key] = EMBEDDED_THEMES[style_key]
            return self.cache[style_key]

        # Fall back to external JSON files if path is configured
        if self.base_path is None or style_key not in STYLE_MAP:
            return None

        token_path = self.base_path / STYLE_MAP[style_key]

        if not token_path.exists():
            print(f"Warning: Style file not found: {token_path}")
            return None

        try:
            with open(token_path, "r", encoding="utf-8") as f:
                tokens = json.load(f)
            normalized = self._normalize_tokens(tokens)
            self.cache[style_key] = normalized
            return normalized
        except (json.JSONDecodeError, IOError) as e:
            print(f"Error loading style {style_key}: {e}")
            return None

    def _normalize_tokens(self, tokens: Dict[str, Any]) -> Dict[str, Any]:
        """Normalize token structure to a consistent format."""
        normalized = {
            "name": tokens.get("name", "Unknown"),
            "background": self._extract_color(tokens, "background"),
            "foreground": self._extract_color(tokens, "foreground"),
            "accent": self._extract_color(tokens, "accent", "primary"),
            "accent_secondary": self._extract_color(tokens, "accentSecondary", "secondary"),
            "muted": self._extract_color(tokens, "muted", "surface"),
            "muted_fg": self._extract_color(tokens, "mutedForeground", "textMuted"),
            "border": self._extract_color(tokens, "border"),
            "card": self._extract_color(tokens, "card", "surface"),
            "button_bg": self._extract_button_bg(tokens),
            "button_fg": self._extract_button_fg(tokens),
            "input_bg": self._extract_input_bg(tokens),
            "success": self._extract_color(tokens, "accent", fallback="#22C55E"),
            "error": self._extract_color(tokens, "destructive", "accentRed", fallback="#EF4444"),
            "is_dark": self._is_dark_mode(tokens),
        }
        return normalized

    def _extract_color(self, tokens: Dict, *keys, fallback: str = "#808080") -> str:
        """Extract a color value from tokens, trying multiple keys."""
        colors = tokens.get("colors", {})

        for key in keys:
            if key in colors:
                val = colors[key]
                if isinstance(val, str):
                    return val
                if isinstance(val, dict):
                    return val.get("hex", fallback)

        return fallback

    def _extract_button_bg(self, tokens: Dict) -> str:
        """Extract button background color."""
        components = tokens.get("components", {})
        button = components.get("button", {})
        primary = button.get("primary", {})

        if isinstance(primary, dict):
            bg = primary.get("background", "")
            if isinstance(bg, str) and bg.startswith("#"):
                return bg

        return self._extract_color(tokens, "accent", "primary", fallback="#4F46E5")

    def _extract_button_fg(self, tokens: Dict) -> str:
        """Extract button foreground/text color."""
        components = tokens.get("components", {})
        button = components.get("button", {})
        primary = button.get("primary", {})

        if isinstance(primary, dict):
            text = primary.get("text", "")
            if isinstance(text, str) and text.startswith("#"):
                return text

        return "#ffffff"

    def _extract_input_bg(self, tokens: Dict) -> str:
        """Extract input field background color."""
        components = tokens.get("components", {})
        inp = components.get("input", {})

        if isinstance(inp, dict):
            bg = inp.get("background", "")
            if isinstance(bg, str) and bg.startswith("#"):
                return bg

        return self._extract_color(tokens, "card", "surface", fallback="#ffffff")

    def _is_dark_mode(self, tokens: Dict) -> bool:
        """Determine if the style is dark mode based on background color."""
        bg = self._extract_color(tokens, "background")
        if bg.startswith("#"):
            try:
                r = int(bg[1:3], 16)
                g = int(bg[3:5], 16)
                b = int(bg[5:7], 16)
                luminance = (0.299 * r + 0.587 * g + 0.114 * b) / 255
                return luminance < 0.5
            except ValueError:
                pass
        return True


# ============================================================================
# DOCUMENT SCRUBBER GUI APPLICATION
# ============================================================================
class ScrubberGUI:
    """
    Main application window for document scrubbing.
    Supports runtime style switching between multiple GUI themes.
    """

    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title("Document Scrubber - Multi-Style GUI")
        self.root.geometry("800x750")
        self.root.minsize(700, 650)

        # Initialize components
        self.style_loader = StyleLoader(STYLES_BASE_PATH)
        self.current_style: Dict[str, Any] = {}
        self.scrubber = DocumentScrubber()

        # File path variables
        self.input_file_path = tk.StringVar()
        self.output_file_path = tk.StringVar()

        # Track current working directory for file dialogs
        self.current_dir = Path.cwd()

        # Create widgets
        self._create_widgets()

        # Set default style
        self.style_var.set("Twisty (Dark)")
        self._apply_style("Twisty (Dark)")

    def _create_widgets(self):
        """Create all application widgets."""
        # Main container
        self.main_frame = tk.Frame(self.root)
        self.main_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)

        # ----------------------------------------------------------------
        # STYLE SELECTOR
        # ----------------------------------------------------------------
        self.style_frame = tk.Frame(self.main_frame)
        self.style_frame.pack(fill=tk.X, pady=(0, 15))

        self.style_label = tk.Label(
            self.style_frame,
            text="THEME:",
            font=("Arial", 10, "bold")
        )
        self.style_label.pack(side=tk.LEFT, padx=(0, 10))

        self.style_var = tk.StringVar()
        self.style_dropdown = ttk.Combobox(
            self.style_frame,
            textvariable=self.style_var,
            values=list(STYLE_MAP.keys()),
            state="readonly",
            width=25
        )
        self.style_dropdown.pack(side=tk.LEFT)
        self.style_dropdown.bind("<<ComboboxSelected>>", self._on_style_change)

        # ----------------------------------------------------------------
        # HEADER
        # ----------------------------------------------------------------
        self.header_frame = tk.Frame(self.main_frame)
        self.header_frame.pack(fill=tk.X, pady=(0, 20))

        self.title_label = tk.Label(
            self.header_frame,
            text="DOCUMENT SCRUBBER",
            font=("Arial", 24, "bold")
        )
        self.title_label.pack(anchor=tk.W)

        self.subtitle_label = tk.Label(
            self.header_frame,
            text="Remove personal and project-specific data from documents",
            font=("Arial", 11)
        )
        self.subtitle_label.pack(anchor=tk.W, pady=(5, 0))

        # ----------------------------------------------------------------
        # FILE SELECTION SECTION
        # ----------------------------------------------------------------
        self.file_frame = tk.Frame(self.main_frame)
        self.file_frame.pack(fill=tk.X, pady=(0, 15))

        # Input file row
        self.input_row = tk.Frame(self.file_frame)
        self.input_row.pack(fill=tk.X, pady=5)

        self.input_label = tk.Label(
            self.input_row,
            text="Input File:",
            font=("Arial", 10),
            width=12,
            anchor=tk.W
        )
        self.input_label.pack(side=tk.LEFT)

        self.input_entry = tk.Entry(
            self.input_row,
            textvariable=self.input_file_path,
            font=("Arial", 10),
            relief=tk.FLAT,
            bd=0
        )
        self.input_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, ipady=8, padx=(0, 10))

        self.browse_input_btn = tk.Button(
            self.input_row,
            text="Browse...",
            font=("Arial", 10),
            cursor="hand2",
            command=self._browse_input
        )
        self.browse_input_btn.pack(side=tk.RIGHT, ipadx=10, ipady=4)

        # Output file row
        self.output_row = tk.Frame(self.file_frame)
        self.output_row.pack(fill=tk.X, pady=5)

        self.output_label = tk.Label(
            self.output_row,
            text="Output File:",
            font=("Arial", 10),
            width=12,
            anchor=tk.W
        )
        self.output_label.pack(side=tk.LEFT)

        self.output_entry = tk.Entry(
            self.output_row,
            textvariable=self.output_file_path,
            font=("Arial", 10),
            relief=tk.FLAT,
            bd=0
        )
        self.output_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, ipady=8, padx=(0, 10))

        self.browse_output_btn = tk.Button(
            self.output_row,
            text="Browse...",
            font=("Arial", 10),
            cursor="hand2",
            command=self._browse_output
        )
        self.browse_output_btn.pack(side=tk.RIGHT, ipadx=10, ipady=4)

        # ----------------------------------------------------------------
        # SCRUB BUTTON
        # ----------------------------------------------------------------
        self.button_frame = tk.Frame(self.main_frame)
        self.button_frame.pack(fill=tk.X, pady=(10, 15))

        self.scrub_button = tk.Button(
            self.button_frame,
            text="SCRUB DOCUMENT",
            font=("Arial", 12, "bold"),
            cursor="hand2",
            command=self._scrub_document
        )
        self.scrub_button.pack(fill=tk.X, ipady=12)

        # ----------------------------------------------------------------
        # RESULTS SECTION
        # ----------------------------------------------------------------
        self.results_frame = tk.Frame(self.main_frame, relief=tk.RIDGE, bd=2)
        self.results_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 10))

        self.results_header = tk.Frame(self.results_frame)
        self.results_header.pack(fill=tk.X, padx=15, pady=(15, 5))

        self.results_title = tk.Label(
            self.results_header,
            text="SCRUBBING RESULTS",
            font=("Arial", 14, "bold")
        )
        self.results_title.pack(side=tk.LEFT)

        # Status indicator
        self.status_label = tk.Label(
            self.results_header,
            text="",
            font=("Arial", 10)
        )
        self.status_label.pack(side=tk.RIGHT)

        # Results text with scrollbar
        self.results_container = tk.Frame(self.results_frame)
        self.results_container.pack(fill=tk.BOTH, expand=True, padx=15, pady=(0, 15))

        self.results_scrollbar = tk.Scrollbar(self.results_container)
        self.results_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        self.results_text = tk.Text(
            self.results_container,
            height=15,
            font=("Consolas", 10),
            wrap=tk.WORD,
            state=tk.DISABLED,
            relief=tk.FLAT,
            padx=10,
            pady=10,
            yscrollcommand=self.results_scrollbar.set
        )
        self.results_text.pack(fill=tk.BOTH, expand=True)
        self.results_scrollbar.config(command=self.results_text.yview)

        # ----------------------------------------------------------------
        # FOOTER
        # ----------------------------------------------------------------
        self.footer_frame = tk.Frame(self.main_frame)
        self.footer_frame.pack(fill=tk.X, pady=(5, 0))

        self.style_info_label = tk.Label(
            self.footer_frame,
            text="Current Theme: Twisty",
            font=("Arial", 9)
        )
        self.style_info_label.pack(side=tk.LEFT)

        self.version_label = tk.Label(
            self.footer_frame,
            text="v1.0.0",
            font=("Arial", 9)
        )
        self.version_label.pack(side=tk.RIGHT)

    def _browse_input(self):
        """Open file dialog for input file selection."""
        filetypes = [
            ("Text Files", "*.txt"),
            ("Markdown Files", "*.md"),
            ("All Files", "*.*")
        ]

        filename = filedialog.askopenfilename(
            title="Select Document to Scrub",
            initialdir=self.current_dir,
            filetypes=filetypes
        )

        if filename:
            self.input_file_path.set(filename)
            # Update current directory
            self.current_dir = Path(filename).parent
            # Auto-generate output filename
            input_path = Path(filename)
            output_name = f"{input_path.stem}_Scrubbed{input_path.suffix}"
            output_path = input_path.parent / output_name
            self.output_file_path.set(str(output_path))

    def _browse_output(self):
        """Open file dialog for output file selection."""
        filetypes = [
            ("Text Files", "*.txt"),
            ("Markdown Files", "*.md"),
            ("All Files", "*.*")
        ]

        # Determine initial filename from input if available
        initial_file = ""
        if self.input_file_path.get():
            input_path = Path(self.input_file_path.get())
            initial_file = f"{input_path.stem}_Scrubbed{input_path.suffix}"

        filename = filedialog.asksaveasfilename(
            title="Save Scrubbed Document As",
            initialdir=self.current_dir,
            initialfile=initial_file,
            filetypes=filetypes,
            defaultextension=".txt"
        )

        if filename:
            self.output_file_path.set(filename)
            self.current_dir = Path(filename).parent

    def _scrub_document(self):
        """Perform the document scrubbing operation."""
        input_path = self.input_file_path.get().strip()
        output_path = self.output_file_path.get().strip()

        # Validate inputs
        if not input_path:
            messagebox.showerror("Error", "Please select an input file.")
            return

        if not os.path.exists(input_path):
            messagebox.showerror("Error", f"Input file not found:\n{input_path}")
            return

        if not output_path:
            # Auto-generate output path
            input_p = Path(input_path)
            output_path = str(input_p.parent / f"{input_p.stem}_Scrubbed{input_p.suffix}")
            self.output_file_path.set(output_path)

        try:
            # Read input file
            with open(input_path, 'r', encoding='utf-8') as f:
                content = f.read()

            original_size = len(content)

            # Create fresh scrubber instance
            self.scrubber = DocumentScrubber()

            # Scrub content
            scrubbed = self.scrubber.scrub(content, interactive=False)

            # Write output file
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(scrubbed)

            scrubbed_size = len(scrubbed)

            # Build results summary
            results = self._build_results_summary(
                input_path, output_path,
                original_size, scrubbed_size
            )

            # Display results
            self._display_results(results, success=True)

            # Update status
            self._update_status("Scrubbing complete!", success=True)

        except Exception as e:
            self._display_results(f"Error during scrubbing:\n\n{str(e)}", success=False)
            self._update_status("Scrubbing failed", success=False)

    def _build_results_summary(self, input_path: str, output_path: str,
                                original_size: int, scrubbed_size: int) -> str:
        """Build a formatted results summary."""
        detected = self.scrubber.detected_items

        lines = [
            "=" * 55,
            "  SCRUBBING COMPLETE",
            "=" * 55,
            "",
            f"  Input:  {Path(input_path).name}",
            f"  Output: {Path(output_path).name}",
            "",
            f"  Original size:  {original_size:,} characters",
            f"  Scrubbed size:  {scrubbed_size:,} characters",
            f"  Difference:     {original_size - scrubbed_size:,} characters",
            "",
            "-" * 55,
            "  DETECTED ITEMS",
            "-" * 55,
            ""
        ]

        # Add detected items by category
        for category, items in detected.items():
            if items:
                lines.append(f"  {category.upper()} ({len(items)}):")
                for item in items[:5]:  # Show first 5
                    display_item = item[:40] + "..." if len(item) > 40 else item
                    lines.append(f"    - {display_item}")
                if len(items) > 5:
                    lines.append(f"    ... and {len(items) - 5} more")
                lines.append("")

        if not any(detected.values()):
            lines.append("  No items detected by pattern matching.")
            lines.append("  (Standard regex patterns were still applied)")
            lines.append("")

        lines.extend([
            "-" * 55,
            "",
            "  Review the scrubbed file and manually verify",
            "  all sensitive data has been properly removed.",
            ""
        ])

        return "\n".join(lines)

    def _display_results(self, text: str, success: bool = True):
        """Display text in the results area."""
        self.results_text.configure(state=tk.NORMAL)
        self.results_text.delete(1.0, tk.END)
        self.results_text.insert(tk.END, text)
        self.results_text.configure(state=tk.DISABLED)

    def _update_status(self, text: str, success: bool = True):
        """Update the status indicator."""
        style = self.current_style
        if success:
            color = style.get("success", "#22C55E")
        else:
            color = style.get("error", "#EF4444")

        self.status_label.configure(text=text, fg=color)

    def _on_style_change(self, event=None):
        """Handle style dropdown change event."""
        selected_style = self.style_var.get()
        self._apply_style(selected_style)

    def _apply_style(self, style_key: str):
        """Apply the selected style to all widgets."""
        style = self.style_loader.load_style(style_key)

        if not style:
            messagebox.showerror(
                "Style Error",
                f"Could not load style: {style_key}\n\n"
                f"Check that the styles folder exists at:\n{STYLES_BASE_PATH}"
            )
            return

        self.current_style = style

        # Extract colors
        bg = style["background"]
        fg = style["foreground"]
        accent = style["accent"]
        accent_sec = style["accent_secondary"]
        muted = style["muted"]
        muted_fg = style["muted_fg"]
        border = style["border"]
        card = style["card"]
        btn_bg = style["button_bg"]
        btn_fg = style["button_fg"]
        input_bg = style["input_bg"]
        is_dark = style["is_dark"]

        # Entry text color
        entry_fg = fg if is_dark else "#1a1a1a"

        # Apply styles to all widgets
        self.root.configure(bg=bg)
        self.main_frame.configure(bg=bg)

        # Style selector
        self.style_frame.configure(bg=bg)
        self.style_label.configure(bg=bg, fg=accent)

        # Configure ttk style
        ttk_style = ttk.Style()
        ttk_style.theme_use("clam")
        ttk_style.configure(
            "TCombobox",
            fieldbackground=input_bg,
            background=input_bg,
            foreground=entry_fg,
            arrowcolor=accent
        )

        # Header
        self.header_frame.configure(bg=bg)
        self.title_label.configure(bg=bg, fg=accent)
        self.subtitle_label.configure(bg=bg, fg=muted_fg)

        # File selection
        self.file_frame.configure(bg=bg)
        self.input_row.configure(bg=bg)
        self.output_row.configure(bg=bg)

        self.input_label.configure(bg=bg, fg=fg)
        self.output_label.configure(bg=bg, fg=fg)

        for entry in [self.input_entry, self.output_entry]:
            entry.configure(
                bg=input_bg,
                fg=entry_fg,
                insertbackground=accent,
                highlightthickness=2,
                highlightbackground=border,
                highlightcolor=accent
            )

        for btn in [self.browse_input_btn, self.browse_output_btn]:
            btn.configure(
                bg=muted,
                fg=fg,
                activebackground=accent,
                activeforeground=btn_fg,
                highlightthickness=0,
                bd=0
            )

        # Scrub button
        self.button_frame.configure(bg=bg)
        self.scrub_button.configure(
            bg=btn_bg,
            fg=btn_fg,
            activebackground=accent_sec if accent_sec else accent,
            activeforeground=btn_fg,
            highlightthickness=0,
            bd=0
        )

        # Results
        results_bg = card if card else bg
        self.results_frame.configure(bg=results_bg, highlightbackground=border)
        self.results_header.configure(bg=results_bg)
        self.results_title.configure(bg=results_bg, fg=accent)
        self.status_label.configure(bg=results_bg)
        self.results_container.configure(bg=results_bg)

        results_text_fg = fg if is_dark else "#1a1a1a"
        self.results_text.configure(
            bg=results_bg,
            fg=results_text_fg,
            insertbackground=accent
        )

        self.results_scrollbar.configure(
            bg=muted,
            troughcolor=bg,
            activebackground=accent
        )

        # Footer
        self.footer_frame.configure(bg=bg)
        self.style_info_label.configure(
            bg=bg,
            fg=muted_fg,
            text=f"Current Theme: {style['name']}"
        )
        self.version_label.configure(bg=bg, fg=muted_fg)

        # Force refresh
        self.root.update_idletasks()


# ============================================================================
# MAIN ENTRY POINT
# ============================================================================
def main():
    """Application entry point."""
    root = tk.Tk()

    app = ScrubberGUI(root)

    # Center window on screen
    root.update_idletasks()
    width = root.winfo_width()
    height = root.winfo_height()
    x = (root.winfo_screenwidth() // 2) - (width // 2)
    y = (root.winfo_screenheight() // 2) - (height // 2)
    root.geometry(f"+{x}+{y}")

    root.mainloop()


if __name__ == "__main__":
    main()
