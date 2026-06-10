"""Central redaction helpers for logs, journals and diagnostics."""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

SENSITIVE_KEYS = frozenset(
    {
        "access_key",
        "accesskeyid",
        "api_key",
        "authorization",
        "azure_connection_string",
        "azure_sas_token",
        "awsaccesskeyid",
        "client_secret",
        "conn_string",
        "credential",
        "cookie",
        "dropbox_app_secret",
        "gdrive_client_secret",
        "key_passphrase",
        "password",
        "proxy_password",
        "refresh_token",
        "sas_token",
        "secret",
        "secret_key",
        "security_token",
        "session_token",
        "sig",
        "signature",
        "token",
        "x_amz_credential",
        "x_amz_security_token",
        "x_amz_signature",
    }
)
_COMPACT_SENSITIVE_KEYS = frozenset(re.sub(r"[^a-z0-9]", "", key) for key in SENSITIVE_KEYS)

_ASSIGNMENT_RE = re.compile(
    r"(?i)\b("
    r"password|passwd|pwd|token|secret|access[_-]?key|"
    r"secret[_-]?key|client[_-]?secret|sig|signature"
    r")\s*[:=]\s*([^&\s;]+)"
)
_CLI_SECRET_OPTION_RE = re.compile(
    r"(?i)(\s--(?:password|passwd|token|secret|api-key|access-key|"
    r"secret-key|client-secret)(?:\s+|=))([^\s]+)"
)
_SSHPASS_RE = re.compile(r"(?i)(\bsshpass\s+-p\s+)([^\s]+)")
_AUTH_TOKEN_RE = re.compile(r"(?i)\b(Basic|Bearer)\s+[A-Za-z0-9+/=._~:-]+")
_GENERIC_AUTH_HEADER_RE = re.compile(r"(?i)\bAuthorization\s*:\s*(?!(?:Basic|Bearer)\b)[^\s,;]+")
_URL_RE = re.compile(r"\b[a-z][a-z0-9+.-]*://[^\s<>'\"]+", re.IGNORECASE)
_TRAILING_URL_PUNCT = ".,;)"


def _is_sensitive_key(key: object) -> bool:
    text = str(key).strip().lower().replace("-", "_")
    compact = re.sub(r"[^a-z0-9]", "", text)
    return (
        text in SENSITIVE_KEYS
        or compact in _COMPACT_SENSITIVE_KEYS
        or any(part in text for part in SENSITIVE_KEYS)
        or any(part in compact for part in _COMPACT_SENSITIVE_KEYS)
    )


def redact_url(value: str) -> str:
    """Redact credentials and sensitive query fields from a URL-like string."""
    try:
        parts = urlsplit(value)
    except ValueError:
        return value
    if not parts.scheme or not parts.netloc:
        return value

    netloc = parts.netloc
    if "@" in netloc:
        host = netloc.rsplit("@", 1)[1]
        netloc = f"<redacted>@{host}"

    query_pairs = []
    for key, val in parse_qsl(parts.query, keep_blank_values=True):
        query_pairs.append((key, "<redacted>" if _is_sensitive_key(key) else val))
    query = urlencode(query_pairs, doseq=True)
    return urlunsplit((parts.scheme, netloc, parts.path, query, parts.fragment))


def redact_text(value: str) -> str:
    """Best-effort redaction for human log strings."""
    text = _AUTH_TOKEN_RE.sub(lambda m: f"{m.group(1)} <redacted>", value)
    text = _GENERIC_AUTH_HEADER_RE.sub("Authorization: <redacted>", text)
    urls: list[str] = []

    def replace_url(match: re.Match[str]) -> str:
        url = match.group(0)
        suffix = ""
        while url and url[-1] in _TRAILING_URL_PUNCT:
            suffix = url[-1] + suffix
            url = url[:-1]
        urls.append(redact_url(url) + suffix)
        return f"__AXROSS_REDACTED_URL_{len(urls) - 1}__"

    text = _URL_RE.sub(replace_url, text)
    text = _ASSIGNMENT_RE.sub(lambda m: f"{m.group(1)}=<redacted>", text)
    text = _CLI_SECRET_OPTION_RE.sub(lambda m: f"{m.group(1)}<redacted>", text)
    text = _SSHPASS_RE.sub(lambda m: f"{m.group(1)}<redacted>", text)
    for idx, url in enumerate(urls):
        text = text.replace(f"__AXROSS_REDACTED_URL_{idx}__", url)
    return text


def redact(value):
    """Recursively redact common secret shapes while preserving structure."""
    if value is None or isinstance(value, (bool, int, float)):
        return value
    if isinstance(value, bytes):
        try:
            return redact_text(value.decode("utf-8", errors="replace"))
        except Exception:
            return "<bytes>"
    if isinstance(value, str):
        return redact_text(value)
    if isinstance(value, Mapping):
        out = {}
        for key, item in value.items():
            out[key] = "<redacted>" if _is_sensitive_key(key) else redact(item)
        return out
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        return [redact(item) for item in value]
    return redact_text(str(value))


__all__ = [
    "SENSITIVE_KEYS",
    "redact",
    "redact_text",
    "redact_url",
]
