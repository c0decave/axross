"""Central redaction helpers for logs, journals and diagnostics."""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from functools import lru_cache
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

# ``\b`` is not a boundary between ``_`` and a letter, so the key may
# carry ``snake_case`` / ``kebab-case`` prefixes (``access_token``,
# ``AWS_SECRET_ACCESS_KEY``). Quoted keys and values (JSON, repr) are
# matched too; a quoted value may contain spaces.
_ASSIGNMENT_RE = re.compile(
    r"(?i)(?<![a-z0-9])((?:[a-z0-9]+[_-])*(?:"
    r"password|passwd|passphrase|pwd|token|secret|access[_-]?key|"
    r"secret[_-]?key|client[_-]?secret|api[_-]?key|sig|signature"
    r"))([\"']?\s*[:=]\s*)(\"[^\"]*\"|'[^']*'|[^&\s;\"',}]+)"
)
_CLI_SECRET_OPTION_RE = re.compile(
    r"(?i)(?:^|(?<=\s))(--(?:password|passwd|token|secret|api-key|access-key|"
    r"secret-key|client-secret)(?:\s+|=))([^\s]+)"
)
_SSHPASS_RE = re.compile(r"(?i)(\bsshpass\s+-p\s+)([^\s]+)")
_AUTH_TOKEN_RE = re.compile(r"(?i)\b(Basic|Bearer)\s+[A-Za-z0-9+/=._~:-]+")
# A header value is everything up to the line end (raw HTTP dumps) or up
# to the closing quote (dict / JSON repr). Schemes other than Basic and
# Bearer (NTLM, Negotiate, Digest, AWS4-HMAC-SHA256, ...) carry their
# credential after the scheme name, possibly as several comma-separated
# parameters, so the whole value is replaced; only the scheme name stays.
_HEADER_VALUE = r"([\"']?[ \t]*[:=][ \t]*)(?:([\"'])(.*?)\3|([^\r\n]*))"
_GENERIC_AUTH_HEADER_RE = re.compile(
    r"(?i)(?<![a-z0-9_-])((?:proxy-)?authorization)" + _HEADER_VALUE
)
_COOKIE_HEADER_RE = re.compile(r"(?i)(?<![a-z0-9_-])((?:set-)?cookie)" + _HEADER_VALUE)
_AUTH_SCHEME_RE = re.compile(r"([A-Za-z][A-Za-z0-9._-]*)\s+\S")
_PEM_PRIVATE_KEY_RE = re.compile(
    r"(-----BEGIN ((?:[A-Z0-9]+ )*PRIVATE KEY(?: BLOCK)?)-----)(.*?)(-----END \2-----|\Z)",
    re.DOTALL,
)
_URL_RE = re.compile(r"\b[a-z][a-z0-9+.-]*://[^\s<>'\"]+", re.IGNORECASE)
_TRAILING_URL_PUNCT = ".,;)"


# Every pattern above needs whitespace, ':' or '=' to match (the URL one
# through '://', the PEM one through the space in "BEGIN ... KEY"); text
# without any of them cannot change.
_NEEDS_SCAN_RE = re.compile(r"[\s:=]")


def _is_sensitive_key(key: object) -> bool:
    return _is_sensitive_key_text(str(key))


@lru_cache(maxsize=4096)
def _is_sensitive_key_text(key: str) -> bool:
    text = key.strip().lower().replace("-", "_")
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


def _redact_assignment(match: re.Match[str]) -> str:
    key, sep, value = match.group(1), match.group(2), match.group(3)
    if value[:1] in ("'", '"'):
        return f"{key}{sep}{value[0]}<redacted>{value[0]}"
    if sep.startswith(("'", '"')):
        return f"{key}{sep}<redacted>"
    return f"{key}=<redacted>"


def _redact_header(match: re.Match[str], *, keep_scheme: bool) -> str:
    name, sep, quote = match.group(1), match.group(2), match.group(3) or ""
    value = match.group(4) if quote else match.group(5)
    if not value.strip():
        return match.group(0)
    scheme = _AUTH_SCHEME_RE.match(value) if keep_scheme else None
    hidden = f"{scheme.group(1)} <redacted>" if scheme else "<redacted>"
    return f"{name}{sep}{quote}{hidden}{quote}"


def redact_text(value: str) -> str:
    """Best-effort redaction for human log strings."""
    if not _NEEDS_SCAN_RE.search(value):
        return value
    return _scan_text(value)


def _scan_text(value: str) -> str:
    """Every redaction pass of :func:`redact_text`, without the fast path."""
    text = _PEM_PRIVATE_KEY_RE.sub(lambda m: f"{m.group(1)}<redacted>{m.group(4)}", value)
    text = _AUTH_TOKEN_RE.sub(lambda m: f"{m.group(1)} <redacted>", text)
    text = _GENERIC_AUTH_HEADER_RE.sub(lambda m: _redact_header(m, keep_scheme=True), text)
    text = _COOKIE_HEADER_RE.sub(lambda m: _redact_header(m, keep_scheme=False), text)
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
    text = _ASSIGNMENT_RE.sub(_redact_assignment, text)
    text = _CLI_SECRET_OPTION_RE.sub(lambda m: f"{m.group(1)}<redacted>", text)
    text = _SSHPASS_RE.sub(lambda m: f"{m.group(1)}<redacted>", text)
    for idx, url in enumerate(urls):
        text = text.replace(f"__AXROSS_REDACTED_URL_{idx}__", url)
    return text


def redact_path(value: str) -> str:
    """Redact a file path: only the credentials of a URL-shaped path
    (``user:pass@`` and sensitive query fields). Every other character is
    part of a real file name - "Basic Course" or "Signature: scan.pdf" is a
    folder or a file, not an auth header - and a caller that has to find
    the file again (undo) needs it unchanged."""
    if "://" not in value:
        return value
    return redact_url(value)


def redact(value):
    """Recursively redact common secret shapes while preserving structure."""
    # Exact-type fast paths for the common shapes; the generic checks
    # below give the same result for them, only slower (ABC isinstance).
    cls = type(value)
    if cls is str:
        return redact_text(value)
    if cls is dict:
        return {
            key: "<redacted>" if _is_sensitive_key(key) else redact(item)
            for key, item in value.items()
        }
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
    "redact_path",
    "redact_text",
    "redact_url",
]
