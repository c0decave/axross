#!/usr/bin/env python3
"""
Natural Language & Secret Scanner for OTI Dashboard.

Detects natural language content (strings, comments, docstrings, template text)
and security-sensitive content (secrets, PII) in source code files.

Uses only Python stdlib — no external dependencies required.
"""

import argparse
import ast
import io
import json
import math
import os
import re
import sys
import tokenize
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from fnmatch import fnmatch
from pathlib import Path

VERSION = "1.0.0"

# =============================================================================
# Data Model
# =============================================================================


@dataclass
class Finding:
    file: str
    line: int
    category: str  # string_literal, comment, docstring, template_text,
    # html_content, secret, pii, env_value
    content: str
    severity: str  # info, low, medium, high, critical
    context: str = ""
    detector: str = ""
    is_natural_language: bool = False


SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]

# =============================================================================
# Common Word List for NL Detection (English + German, ~200 words)
# =============================================================================

COMMON_WORDS = {
    # English function words + common verbs/nouns
    "the",
    "is",
    "are",
    "was",
    "were",
    "been",
    "being",
    "have",
    "has",
    "had",
    "do",
    "does",
    "did",
    "will",
    "would",
    "could",
    "should",
    "may",
    "might",
    "must",
    "shall",
    "can",
    "need",
    "this",
    "that",
    "these",
    "those",
    "with",
    "from",
    "for",
    "not",
    "but",
    "and",
    "or",
    "if",
    "then",
    "else",
    "when",
    "all",
    "each",
    "every",
    "both",
    "few",
    "more",
    "most",
    "other",
    "some",
    "such",
    "only",
    "own",
    "same",
    "than",
    "too",
    "very",
    "just",
    "because",
    "about",
    "into",
    "through",
    "during",
    "before",
    "after",
    "above",
    "below",
    "between",
    "under",
    "again",
    "further",
    "once",
    "here",
    "there",
    "where",
    "why",
    "how",
    "what",
    "which",
    "who",
    "whom",
    "your",
    "their",
    "its",
    "error",
    "failed",
    "please",
    "click",
    "select",
    "enter",
    "display",
    "show",
    "hide",
    "enable",
    "disable",
    "warning",
    "success",
    "account",
    "user",
    "password",
    "login",
    "logout",
    "settings",
    "configuration",
    "file",
    "data",
    "name",
    "value",
    "type",
    "list",
    "number",
    "text",
    "page",
    "view",
    "table",
    "field",
    "default",
    "required",
    "optional",
    "true",
    "false",
    "yes",
    "no",
    "none",
    "null",
    "empty",
    "invalid",
    "save",
    "delete",
    "update",
    "create",
    "read",
    "write",
    "open",
    "close",
    "start",
    "stop",
    "run",
    "check",
    "test",
    "found",
    "missing",
    "available",
    # German function words + common terms
    "der",
    "die",
    "das",
    "ein",
    "eine",
    "einer",
    "einem",
    "einen",
    "ist",
    "sind",
    "war",
    "wird",
    "werden",
    "haben",
    "hat",
    "wurde",
    "nicht",
    "auch",
    "auf",
    "mit",
    "dem",
    "den",
    "von",
    "zu",
    "und",
    "oder",
    "aber",
    "wenn",
    "dass",
    "als",
    "nach",
    "bei",
    "aus",
    "vor",
    "noch",
    "nur",
    "wie",
    "alle",
    "kann",
    "schon",
    "durch",
    "ohne",
    "aktiviert",
    "deaktiviert",
    "anzeigen",
    "zeigt",
    "erlaubt",
    "benutzer",
    "einstellung",
    "einstellungen",
    "maximum",
    "minimum",
    "zeitraum",
    "standard",
    "maximale",
    "anzahl",
    "seite",
    "spalte",
    "tabelle",
    "fehler",
    "bitte",
    "konfiguration",
    "modus",
    "gesamt",
    "letzter",
}

# =============================================================================
# Secret Detection Patterns
# =============================================================================

SECRET_PATTERNS = [
    # Actual hardcoded credentials: quoted literal values, not function calls.
    (
        re.compile(r"(?i)(password|passwd|pwd)\s*[=:]\s*[\"'][^\"']{3,}[\"']"),
        "Hardcoded password",
        "critical",
    ),
    (
        re.compile(r"(?i)(api[_-]?key|apikey)\s*[=:]\s*[\"'][^\"']{3,}[\"']"),
        "Hardcoded API key",
        "critical",
    ),
    (
        re.compile(r"(?i)(secret[_-]?key|secret)\s*[=:]\s*[\"'][^\"']{3,}[\"']"),
        "Hardcoded secret",
        "critical",
    ),
    (
        re.compile(r"(?i)(token|auth[_-]?token|access[_-]?token)\s*[=:]\s*[\"'][^\"']{10,}[\"']"),
        "Hardcoded token",
        "high",
    ),
    # .env file style: KEY=VALUE (no quotes needed)
    (
        re.compile(r"^(?:SECRET_KEY|DB_PASSWORD|API_KEY|AUTH_TOKEN)\s*=\s*(\S{5,})$", re.MULTILINE),
        "Env secret value",
        "critical",
    ),
    # Bearer tokens, AWS keys, private keys
    (re.compile(r"Bearer\s+[A-Za-z0-9_\-\.]{20,}"), "Bearer token", "critical"),
    (re.compile(r"AKIA[0-9A-Z]{16}"), "AWS Access Key ID", "critical"),
    (re.compile(r"-----BEGIN\s+(RSA\s+)?PRIVATE\s+KEY-----"), "Private key", "critical"),
    (
        re.compile(r"(?i)(mysql|postgres|postgresql|mongodb|redis)://\S+:\S+@"),
        "DB connection string with credentials",
        "critical",
    ),
    # Docker/YAML style: PASSWORD: value, POSTGRES_PASSWORD: value
    (re.compile(r"(?i)(PASSWORD|SECRET|TOKEN|API_KEY):\s+\S{3,}"), "Config file secret", "high"),
]

# Patterns that indicate a placeholder, not a real secret
SECRET_PLACEHOLDERS = re.compile(
    r"(?i)(your[-_]|change[-_]?me|example|placeholder|xxx|replace|dummy|"
    r"generate[-_]a[-_]|set[-_]this|todo|fixme|<[^>]+>|\{\{|\$\{|"
    r"hier[-_]|einfuegen|passwort[-_]?hier|sicher)"
)

# Patterns that indicate the line reads a secret from env/config (not hardcoded)
SECRET_SAFE_PATTERNS = re.compile(
    r"(?i)(os\.environ|getenv|config\[|\.get\(|request\.(POST|GET)|"
    r"def\s+\w+.*password\s*[:=]|sha256-|sha384-|sha512-)"
)

# =============================================================================
# PII Detection Patterns
# =============================================================================

PII_PATTERNS = [
    (re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"), "Email address", "medium"),
    (re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"), "IP address", "low"),
    # Phone numbers: require + prefix or separators (dash/space/dot between groups)
    (
        re.compile(r"(?:\+\d{1,3}[\s-])?\(?\d{2,4}\)?[\s-]\d{3,4}[\s-]\d{3,4}\b"),
        "Phone number",
        "medium",
    ),
]

# IPs that are not PII
SAFE_IPS = {
    "127.0.0.1",
    "0.0.0.0",
    "255.255.255.255",
    "255.255.255.0",
    "192.168.0.0",
    "10.0.0.0",
    "172.16.0.0",
}

# =============================================================================
# Default Exclusions
# =============================================================================

DEFAULT_EXCLUDES = [
    "*/.venv/*",
    "*/venv/*",
    "*/.env.example",
    "*/node_modules/*",
    "*/staticfiles/*",
    "*/__pycache__/*",
    "*/vendor/*",
    "*/.git/*",
    "*/release/*",
    "*.min.js",
    "*.min.css",
    "*.pyc",
    "*.mo",
    "*.svg",
    "*/svg_tests/*",
    "*/security/reports/*",
    "*/migrations/*",
    "*/.claude/*",
    "*/mtd-logos/*",
    "*.woff",
    "*.woff2",
    "*.ttf",
    "*.eot",
    "*.png",
    "*.jpg",
    "*.jpeg",
    "*.gif",
    "*.webp",
    "*.ico",
    "*.pdf",
    "*.zip",
    "*.gz",
    "*.tar",
]

TEXT_EXTENSIONS = {
    ".py",
    ".html",
    ".htm",
    ".js",
    ".ts",
    ".css",
    ".scss",
    ".json",
    ".yml",
    ".yaml",
    ".toml",
    ".cfg",
    ".ini",
    ".conf",
    ".md",
    ".txt",
    ".rst",
    ".po",
    ".env",
    ".sh",
    ".bash",
    ".dockerfile",
    ".xml",
    ".csv",
}

# =============================================================================
# NL Detection Heuristic
# =============================================================================


def is_natural_language(text: str) -> bool:
    """Check if text appears to be natural language (not code identifiers)."""
    words = re.findall(r"[a-zA-ZäöüÄÖÜß]+", text.lower())
    if len(words) < 3:
        return False
    matches = sum(1 for w in words if w in COMMON_WORDS)
    return matches / len(words) >= 0.3


def shannon_entropy(text: str) -> float:
    """Calculate Shannon entropy of a string."""
    if not text:
        return 0.0
    freq = {}
    for c in text:
        freq[c] = freq.get(c, 0) + 1
    length = len(text)
    return -sum((count / length) * math.log2(count / length) for count in freq.values())


# =============================================================================
# Parsers
# =============================================================================


class PythonParser:
    """Extract NL content from Python files using AST + tokenize."""

    @staticmethod
    def parse(filepath: str, source: str) -> list[Finding]:
        findings = []
        findings.extend(PythonParser._extract_via_ast(filepath, source))
        findings.extend(PythonParser._extract_comments(filepath, source))
        return findings

    @staticmethod
    def _extract_via_ast(filepath: str, source: str) -> list[Finding]:
        findings = []
        try:
            tree = ast.parse(source, filename=filepath)
        except SyntaxError:
            return PythonParser._extract_strings_regex(filepath, source)

        # Extract docstrings
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Module)):
                docstring = ast.get_docstring(node)
                if docstring and len(docstring.strip()) > 10:
                    line = node.body[0].lineno if node.body else getattr(node, "lineno", 0)
                    findings.append(
                        Finding(
                            file=filepath,
                            line=line,
                            category="docstring",
                            content=docstring.strip()[:200],
                            severity="info",
                            detector="python_ast",
                            is_natural_language=is_natural_language(docstring),
                        )
                    )

        # Extract string literals (skip docstrings already found)
        docstring_lines = {f.line for f in findings}
        for node in ast.walk(tree):
            if isinstance(node, ast.Constant) and isinstance(node.value, str):
                val = node.value.strip()
                if len(val) < 5:
                    continue
                if node.lineno in docstring_lines:
                    continue
                # Skip import-like paths
                if re.match(r"^[a-zA-Z_][\w.]*$", val):
                    continue
                # Skip URL patterns
                if re.match(r"^[/^]", val) and "/" in val and " " not in val:
                    continue
                findings.append(
                    Finding(
                        file=filepath,
                        line=node.lineno,
                        category="string_literal",
                        content=val[:200],
                        severity="info",
                        detector="python_ast",
                        is_natural_language=is_natural_language(val),
                    )
                )

        return findings

    @staticmethod
    def _extract_comments(filepath: str, source: str) -> list[Finding]:
        findings = []
        try:
            tokens = tokenize.generate_tokens(io.StringIO(source).readline)
            for tok_type, tok_string, start, _end, _line in tokens:
                if tok_type == tokenize.COMMENT:
                    text = tok_string.lstrip("#").strip()
                    if len(text) < 5:
                        continue
                    # Skip shebangs, coding declarations, noqa
                    if text.startswith("!") or "coding:" in text or "noqa" in text:
                        continue
                    findings.append(
                        Finding(
                            file=filepath,
                            line=start[0],
                            category="comment",
                            content=text[:200],
                            severity="info",
                            detector="python_tokenize",
                            is_natural_language=is_natural_language(text),
                        )
                    )
        except tokenize.TokenError:
            pass
        return findings

    @staticmethod
    def _extract_strings_regex(filepath: str, source: str) -> list[Finding]:
        """Fallback for files that fail AST parsing."""
        findings = []
        for i, line in enumerate(source.splitlines(), 1):
            for match in re.finditer(r"""(?:['"])(.{5,}?)(?:['"])""", line):
                val = match.group(1)
                if is_natural_language(val):
                    findings.append(
                        Finding(
                            file=filepath,
                            line=i,
                            category="string_literal",
                            content=val[:200],
                            severity="info",
                            detector="regex_fallback",
                            is_natural_language=True,
                        )
                    )
        return findings


class HtmlTemplateParser:
    """Extract NL content from HTML/Django template files."""

    @staticmethod
    def parse(filepath: str, source: str) -> list[Finding]:
        findings = []
        findings.extend(HtmlTemplateParser._extract_trans_tags(filepath, source))
        findings.extend(HtmlTemplateParser._extract_text_content(filepath, source))
        findings.extend(HtmlTemplateParser._extract_nl_attributes(filepath, source))
        return findings

    @staticmethod
    def _extract_trans_tags(filepath: str, source: str) -> list[Finding]:
        findings = []
        for i, line in enumerate(source.splitlines(), 1):
            for match in re.finditer(r"""\{%\s*trans\s+['"](.*?)['"]\s*%\}""", line):
                text = match.group(1)
                if len(text) >= 3:
                    findings.append(
                        Finding(
                            file=filepath,
                            line=i,
                            category="template_text",
                            content=text[:200],
                            severity="info",
                            detector="django_trans",
                            is_natural_language=True,
                        )
                    )
        # blocktrans
        for match in re.finditer(
            r"\{%\s*blocktrans.*?%\}(.*?)\{%\s*endblocktrans\s*%\}", source, re.DOTALL
        ):
            text = match.group(1).strip()
            if len(text) >= 5:
                line = source[: match.start()].count("\n") + 1
                findings.append(
                    Finding(
                        file=filepath,
                        line=line,
                        category="template_text",
                        content=text[:200],
                        severity="info",
                        detector="django_blocktrans",
                        is_natural_language=True,
                    )
                )
        return findings

    @staticmethod
    def _extract_text_content(filepath: str, source: str) -> list[Finding]:
        findings = []
        for i, line in enumerate(source.splitlines(), 1):
            # Text between tags
            for match in re.finditer(r">([^<]{5,})<", line):
                text = match.group(1).strip()
                # Skip template-only content
                if not text or re.match(r"^\s*\{\{.*\}\}\s*$", text):
                    continue
                if is_natural_language(text):
                    findings.append(
                        Finding(
                            file=filepath,
                            line=i,
                            category="html_content",
                            content=text[:200],
                            severity="info",
                            detector="html_text",
                            is_natural_language=True,
                        )
                    )
        return findings

    @staticmethod
    def _extract_nl_attributes(filepath: str, source: str) -> list[Finding]:
        findings = []
        for i, line in enumerate(source.splitlines(), 1):
            for match in re.finditer(
                r"""(?:title|alt|placeholder|aria-label)\s*=\s*["']([^"']{5,})["']""",
                line,
                re.IGNORECASE,
            ):
                text = match.group(1)
                if is_natural_language(text):
                    findings.append(
                        Finding(
                            file=filepath,
                            line=i,
                            category="html_content",
                            content=text[:200],
                            severity="info",
                            detector="html_attribute",
                            is_natural_language=True,
                        )
                    )
        return findings


class JavaScriptParser:
    """Extract NL content from JavaScript files."""

    @staticmethod
    def parse(filepath: str, source: str) -> list[Finding]:
        findings = []
        for i, line in enumerate(source.splitlines(), 1):
            # Single-line comments
            match = re.search(r"//\s*(.{5,})$", line)
            if match:
                text = match.group(1).strip()
                if is_natural_language(text):
                    findings.append(
                        Finding(
                            file=filepath,
                            line=i,
                            category="comment",
                            content=text[:200],
                            severity="info",
                            detector="js_comment",
                            is_natural_language=True,
                        )
                    )
            # String literals with spaces (likely NL)
            for match in re.finditer(r"""(?:['"`])(.{10,}?)(?:['"`])""", line):
                text = match.group(1)
                if " " in text and is_natural_language(text):
                    findings.append(
                        Finding(
                            file=filepath,
                            line=i,
                            category="string_literal",
                            content=text[:200],
                            severity="info",
                            detector="js_string",
                            is_natural_language=True,
                        )
                    )
        return findings


class EnvFileParser:
    """Extract secrets and values from .env files."""

    SENSITIVE_KEYS = re.compile(
        r"(?i)(secret|password|passwd|pwd|token|key|auth|credential|private)"
    )

    @staticmethod
    def parse(filepath: str, source: str) -> list[Finding]:
        findings = []
        for i, line in enumerate(source.splitlines(), 1):
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                if stripped.startswith("#") and len(stripped) > 3:
                    findings.append(
                        Finding(
                            file=filepath,
                            line=i,
                            category="comment",
                            content=stripped[1:].strip()[:200],
                            severity="info",
                            detector="env_comment",
                            is_natural_language=is_natural_language(stripped),
                        )
                    )
                continue
            match = re.match(r"^([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)", stripped)
            if not match:
                continue
            key, value = match.group(1), match.group(2).strip().strip("'\"")
            if not value:
                continue

            severity = "info"
            category = "env_value"

            if EnvFileParser.SENSITIVE_KEYS.search(key):
                if SECRET_PLACEHOLDERS.search(value):
                    severity = "info"
                elif len(value) > 5:
                    severity = "critical"
                    category = "secret"

            findings.append(
                Finding(
                    file=filepath,
                    line=i,
                    category=category,
                    content=f"{key}={value[:60]}{'...' if len(value) > 60 else ''}",
                    severity=severity,
                    detector="env_parser",
                    is_natural_language=False,
                )
            )
        return findings


class GenericTextParser:
    """Extract NL content from text files (.md, .txt, .yml, .json, .css)."""

    @staticmethod
    def parse(filepath: str, source: str) -> list[Finding]:
        ext = Path(filepath).suffix.lower()
        if ext == ".json":
            return GenericTextParser._parse_json(filepath, source)
        if ext in (".yml", ".yaml"):
            return GenericTextParser._parse_yaml(filepath, source)
        if ext == ".css":
            return GenericTextParser._parse_css(filepath, source)
        if ext == ".po":
            return GenericTextParser._parse_po(filepath, source)
        # .md, .txt, .rst, .sh, etc.
        return GenericTextParser._parse_text(filepath, source)

    @staticmethod
    def _parse_json(filepath: str, source: str) -> list[Finding]:
        findings = []
        try:
            data = json.loads(source)
            GenericTextParser._walk_json(filepath, data, findings)
        except json.JSONDecodeError:
            pass
        return findings

    @staticmethod
    def _walk_json(filepath: str, obj, findings: list, depth: int = 0):
        if depth > 10:
            return
        if isinstance(obj, str) and len(obj) >= 10 and is_natural_language(obj):
            findings.append(
                Finding(
                    file=filepath,
                    line=0,
                    category="string_literal",
                    content=obj[:200],
                    severity="info",
                    detector="json_string",
                    is_natural_language=True,
                )
            )
        elif isinstance(obj, dict):
            for v in obj.values():
                GenericTextParser._walk_json(filepath, v, findings, depth + 1)
        elif isinstance(obj, list):
            for item in obj:
                GenericTextParser._walk_json(filepath, item, findings, depth + 1)

    @staticmethod
    def _parse_yaml(filepath: str, source: str) -> list[Finding]:
        findings = []
        for i, line in enumerate(source.splitlines(), 1):
            match = re.match(r"^\s*[\w-]+:\s+(.{5,})", line)
            if match:
                val = match.group(1).strip().strip("'\"")
                if is_natural_language(val):
                    findings.append(
                        Finding(
                            file=filepath,
                            line=i,
                            category="string_literal",
                            content=val[:200],
                            severity="info",
                            detector="yaml_value",
                            is_natural_language=True,
                        )
                    )
        return findings

    @staticmethod
    def _parse_css(filepath: str, source: str) -> list[Finding]:
        findings = []
        for match in re.finditer(r"/\*(.*?)\*/", source, re.DOTALL):
            text = match.group(1).strip()
            if len(text) >= 5 and is_natural_language(text):
                line = source[: match.start()].count("\n") + 1
                findings.append(
                    Finding(
                        file=filepath,
                        line=line,
                        category="comment",
                        content=text[:200],
                        severity="info",
                        detector="css_comment",
                        is_natural_language=True,
                    )
                )
        return findings

    @staticmethod
    def _parse_po(filepath: str, source: str) -> list[Finding]:
        findings = []
        for i, line in enumerate(source.splitlines(), 1):
            match = re.match(r'^(msgid|msgstr)\s+"(.{3,})"', line)
            if match:
                text = match.group(2)
                findings.append(
                    Finding(
                        file=filepath,
                        line=i,
                        category="template_text",
                        content=text[:200],
                        severity="info",
                        detector="po_string",
                        is_natural_language=True,
                    )
                )
        return findings

    @staticmethod
    def _parse_text(filepath: str, source: str) -> list[Finding]:
        findings = []
        for i, line in enumerate(source.splitlines(), 1):
            text = line.strip()
            if len(text) >= 10 and is_natural_language(text):
                findings.append(
                    Finding(
                        file=filepath,
                        line=i,
                        category="string_literal",
                        content=text[:200],
                        severity="info",
                        detector="text_line",
                        is_natural_language=True,
                    )
                )
        return findings


# =============================================================================
# Security Detectors (run on all source lines, independent of parsers)
# =============================================================================


def detect_secrets(filepath: str, source: str) -> list[Finding]:
    """Scan source for hardcoded secrets."""
    findings = []
    for i, line in enumerate(source.splitlines(), 1):
        for pattern, description, severity in SECRET_PATTERNS:
            match = pattern.search(line)
            if match:
                content = line.strip()[:200]
                # A9k boundary-trust: placeholder & safe-pattern
                # filters must scope to the matched assignment expression
                # (`match.group(0)`), NOT the full line. Otherwise an
                # attacker hides a hardcoded credential behind a one-token
                # comment (e.g. `password = "REAL..."  # TODO: rotate` or
                # `... # also from cfg.get('pw')`) and the comment text
                # matches a safe/placeholder token, silently dropping the
                # real-secret finding. Same structural defect class as
                # PATTERN-001 (a security decision computed over a wider
                # scope than the bytes the decision is about).
                scope = match.group(0)
                # Check if it's a placeholder (template/example value)
                if SECRET_PLACEHOLDERS.search(scope):
                    continue
                # Skip comments that discuss secrets (e.g. "# set a strong SECRET_KEY")
                stripped = line.lstrip()
                if stripped.startswith("#") or stripped.startswith("//"):
                    continue
                # Skip lines that read from env/config (not hardcoded)
                if SECRET_SAFE_PATTERNS.search(scope):
                    continue
                findings.append(
                    Finding(
                        file=filepath,
                        line=i,
                        category="secret",
                        content=content,
                        severity=severity,
                        detector="secret_pattern",
                        is_natural_language=False,
                    )
                )
    # High-entropy strings
    for i, line in enumerate(source.splitlines(), 1):
        for match in re.finditer(r"""[=:]\s*['"]([A-Za-z0-9+/=_\-]{20,})['"]""", line):
            val = match.group(1)
            if shannon_entropy(val) > 4.5:
                if SECRET_PLACEHOLDERS.search(val):
                    continue
                # Skip SRI integrity hashes
                if re.match(r"sha(256|384|512)-", val):
                    continue
                findings.append(
                    Finding(
                        file=filepath,
                        line=i,
                        category="secret",
                        content=f"High-entropy string: {val[:40]}...",
                        severity="high",
                        detector="entropy_check",
                        is_natural_language=False,
                    )
                )
    return findings


def detect_pii(filepath: str, source: str) -> list[Finding]:
    """Scan source for PII (emails, IPs, phone numbers)."""
    findings = []
    for i, line in enumerate(source.splitlines(), 1):
        for pattern, description, severity in PII_PATTERNS:
            for match in pattern.finditer(line):
                val = match.group(0)
                # Filter safe IPs and version numbers
                if description == "IP address":
                    if val in SAFE_IPS:
                        continue
                    # Version-number-like: preceded by "v" or followed by more digits
                    before = line[: match.start()]
                    if re.search(r"[vV]$", before) or re.search(r"^\.?\d", line[match.end() :]):
                        continue
                # Filter noreply@example emails
                if description == "Email address":
                    if "example" in val or "noreply" in val or "localhost" in val:
                        continue
                findings.append(
                    Finding(
                        file=filepath,
                        line=i,
                        category="pii",
                        content=f"{description}: {val}",
                        severity=severity,
                        detector="pii_pattern",
                        is_natural_language=False,
                    )
                )
    return findings


# =============================================================================
# Main Scanner
# =============================================================================


class NaturalLanguageScanner:
    """Orchestrates file collection, parsing, and detection."""

    def __init__(
        self, root_dir: str, exclude_patterns: list[str] = None, secrets_only: bool = False
    ):
        self.root_dir = os.path.abspath(root_dir)
        self.exclude_patterns = exclude_patterns or DEFAULT_EXCLUDES
        self.secrets_only = secrets_only

    def scan(self) -> list[Finding]:
        files = self._collect_files()
        all_findings = []
        for filepath in files:
            all_findings.extend(self._scan_file(filepath))
        # Deduplicate by (file, line, category, content)
        seen = set()
        unique = []
        for f in all_findings:
            key = (f.file, f.line, f.category, f.content[:50])
            if key not in seen:
                seen.add(key)
                unique.append(f)
        return sorted(unique, key=lambda f: (SEVERITY_ORDER.index(f.severity), f.file, f.line))

    def _collect_files(self) -> list[str]:
        files = []
        for dirpath, dirnames, filenames in os.walk(self.root_dir):
            # Skip excluded directories
            dirnames[:] = [
                d
                for d in dirnames
                if not any(fnmatch(os.path.join(dirpath, d, ""), p) for p in self.exclude_patterns)
            ]
            for fname in filenames:
                fpath = os.path.join(dirpath, fname)
                rel = os.path.relpath(fpath, self.root_dir)
                if any(fnmatch(fpath, p) or fnmatch(rel, p) for p in self.exclude_patterns):
                    continue
                ext = Path(fname).suffix.lower()
                # Include files with known extensions or no extension (Dockerfile, Makefile)
                if ext in TEXT_EXTENSIONS or fname in ("Dockerfile", "Makefile", ".env"):
                    files.append(fpath)
        return sorted(files)

    def _scan_file(self, filepath: str) -> list[Finding]:
        try:
            source = Path(filepath).read_text(encoding="utf-8", errors="replace")
        except (OSError, UnicodeDecodeError):
            return []

        rel_path = os.path.relpath(filepath, self.root_dir)
        findings = []

        # Always run security detectors
        findings.extend(detect_secrets(rel_path, source))
        findings.extend(detect_pii(rel_path, source))

        if self.secrets_only:
            return findings

        # Route to appropriate parser
        ext = Path(filepath).suffix.lower()
        fname = Path(filepath).name

        if ext == ".py":
            findings.extend(PythonParser.parse(rel_path, source))
        elif ext in (".html", ".htm"):
            findings.extend(HtmlTemplateParser.parse(rel_path, source))
        elif ext == ".js":
            findings.extend(JavaScriptParser.parse(rel_path, source))
        elif fname.startswith(".env") or fname == ".env":
            findings.extend(EnvFileParser.parse(rel_path, source))
        elif ext in TEXT_EXTENSIONS:
            findings.extend(GenericTextParser.parse(rel_path, source))

        return findings


# =============================================================================
# Reporters
# =============================================================================


class CliReporter:
    """Colored terminal output grouped by severity."""

    COLORS = {
        "critical": "\033[91m",  # Red
        "high": "\033[93m",  # Yellow
        "medium": "\033[33m",  # Orange
        "low": "\033[36m",  # Cyan
        "info": "\033[90m",  # Gray
        "reset": "\033[0m",
        "bold": "\033[1m",
        "green": "\033[92m",
        "white": "\033[97m",
    }

    def __init__(self, no_color: bool = False, min_severity: str = "info", quiet: bool = False):
        self.min_severity = min_severity
        self.quiet = quiet
        if no_color or not sys.stdout.isatty():
            self.COLORS = {k: "" for k in self.COLORS}

    def report(self, findings: list[Finding], files_scanned: int):
        c = self.COLORS
        min_idx = SEVERITY_ORDER.index(self.min_severity)

        # Filter by severity
        filtered = [f for f in findings if SEVERITY_ORDER.index(f.severity) <= min_idx]

        print(f"\n{c['bold']}{'=' * 60}{c['reset']}")
        print(f"{c['bold']}  Natural Language Scanner - OTI Dashboard{c['reset']}")
        print(f"{c['bold']}{'=' * 60}{c['reset']}")
        print(f"\nFiles scanned: {files_scanned}")
        print(f"Total findings: {len(filtered)}")

        if not self.quiet:
            for severity in SEVERITY_ORDER:
                sev_findings = [f for f in filtered if f.severity == severity]
                if not sev_findings:
                    continue
                color = c.get(severity, "")
                print(f"\n{c['bold']}{'=' * 60}{c['reset']}")
                print(f"{c['bold']}  {severity.upper()} FINDINGS ({len(sev_findings)}){c['reset']}")
                print(f"{c['bold']}{'=' * 60}{c['reset']}")
                for f in sev_findings:
                    print(
                        f"\n{color}[{f.severity.upper()}]{c['reset']} "
                        f"{c['white']}{f.file}:{f.line}{c['reset']}  "
                        f"({f.category})"
                    )
                    content = f.content.replace("\n", " ")[:120]
                    print(f"  {content}")
                    print(f"  {c['info']}Detector: {f.detector}{c['reset']}")

        # Summary
        print(f"\n{c['bold']}{'=' * 60}{c['reset']}")
        print(f"{c['bold']}  SUMMARY{c['reset']}")
        print(f"{c['bold']}{'=' * 60}{c['reset']}")

        cats = {}
        for f in filtered:
            cats[f.category] = cats.get(f.category, 0) + 1
        print(f"\n{'Category':<25} {'Count':>6}")
        print("-" * 32)
        for cat in sorted(cats.keys()):
            print(f"  {cat:<23} {cats[cat]:>6}")
        print("-" * 32)
        print(f"  {'Total':<23} {len(filtered):>6}")

        print(f"\n{'Severity':<25} {'Count':>6}")
        print("-" * 32)
        sevs = {}
        for f in filtered:
            sevs[f.severity] = sevs.get(f.severity, 0) + 1
        for sev in SEVERITY_ORDER:
            if sev in sevs:
                color = c.get(sev, "")
                print(f"  {color}{sev:<23}{c['reset']} {sevs[sev]:>6}")
        print()


class JsonReporter:
    """Structured JSON report output."""

    @staticmethod
    def report(findings: list[Finding], files_scanned: int, output_path: str):
        cats = {}
        sevs = {}
        for f in findings:
            cats[f.category] = cats.get(f.category, 0) + 1
            sevs[f.severity] = sevs.get(f.severity, 0) + 1

        report_data = {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "scanner": "scan_natural_language",
            "version": VERSION,
            "statistics": {
                "files_scanned": files_scanned,
                "total_findings": len(findings),
                "by_category": cats,
                "by_severity": sevs,
            },
            "findings": [asdict(f) for f in findings],
        }

        Path(output_path).parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, "w", encoding="utf-8") as fp:
            json.dump(report_data, fp, indent=2, ensure_ascii=False)


class TxtReporter:
    """Plain text report output (for piping / non-terminal use)."""

    @staticmethod
    def report(findings: list[Finding], files_scanned: int, output_path: str):
        lines = []
        lines.append("Natural Language Scanner - OTI Dashboard")
        lines.append(f"Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}")
        lines.append(f"Files scanned: {files_scanned}")
        lines.append(f"Total findings: {len(findings)}")
        lines.append("=" * 60)

        for severity in SEVERITY_ORDER:
            sev_findings = [f for f in findings if f.severity == severity]
            if not sev_findings:
                continue
            lines.append(f"\n{severity.upper()} FINDINGS ({len(sev_findings)})")
            lines.append("-" * 40)
            for f in sev_findings:
                content = f.content.replace("\n", " ")[:120]
                lines.append(f"[{f.severity.upper()}] {f.file}:{f.line} ({f.category})")
                lines.append(f"  {content}")
                lines.append(f"  Detector: {f.detector}")

        Path(output_path).parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, "w", encoding="utf-8") as fp:
            fp.write("\n".join(lines) + "\n")


# =============================================================================
# CLI
# =============================================================================


def main():
    parser = argparse.ArgumentParser(
        description="Natural Language & Secret Scanner for source code."
    )
    parser.add_argument("--root", default=".", help="Project root directory")
    parser.add_argument("--json-output", help="JSON report output path")
    parser.add_argument("--txt-output", help="Text report output path")
    parser.add_argument(
        "--severity",
        default="info",
        choices=SEVERITY_ORDER,
        help="Minimum severity to display (default: info)",
    )
    parser.add_argument("--no-color", action="store_true", help="Disable colored output")
    parser.add_argument("--secrets-only", action="store_true", help="Only report secrets and PII")
    parser.add_argument(
        "--quiet", action="store_true", help="Only show summary, not individual findings"
    )
    parser.add_argument(
        "--exclude", action="append", default=[], help="Additional glob patterns to exclude"
    )
    args = parser.parse_args()

    excludes = DEFAULT_EXCLUDES + args.exclude

    scanner = NaturalLanguageScanner(
        root_dir=args.root,
        exclude_patterns=excludes,
        secrets_only=args.secrets_only,
    )

    findings = scanner.scan()
    files_scanned = len(scanner._collect_files())

    # CLI output
    cli = CliReporter(no_color=args.no_color, min_severity=args.severity, quiet=args.quiet)
    cli.report(findings, files_scanned)

    # Auto-generate report paths if not specified
    timestamp = datetime.now().strftime("%Y-%m-%d_%H%M%S")
    reports_dir = os.path.join(args.root, "security", "reports")

    json_path = args.json_output or os.path.join(reports_dir, f"natural_language_{timestamp}.json")
    txt_path = args.txt_output or os.path.join(reports_dir, f"natural_language_{timestamp}.txt")

    try:
        JsonReporter.report(findings, files_scanned, json_path)
        TxtReporter.report(findings, files_scanned, txt_path)
        print("Reports saved to:")
        print(f"  {json_path}")
        print(f"  {txt_path}")
    except OSError as e:
        print(f"Warning: Could not write reports: {e}", file=sys.stderr)

    # Exit code: 1 if critical/high findings
    critical_high = [f for f in findings if f.severity in ("critical", "high")]
    sys.exit(1 if critical_high else 0)


if __name__ == "__main__":
    main()
