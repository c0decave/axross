"""TLS verification against the host's CA certificates, also in the one-file binary.

The binary's OpenSSL comes from the build machine (AlmaLinux) and looks for
RHEL's /etc/pki/tls/cert.pem and /etc/pki/tls/certs. Debian, Ubuntu,
Gentoo, Arch and openSUSE keep their bundle elsewhere: measured on the
0.13.121 binary on Arch, ssl.create_default_context() loaded 0 CA
certificates, and every stdlib TLS client failed with
CERTIFICATE_VERIFY_FAILED (voice model downloads, FTPS, IMAPS, NNTP,
Gopher, the STT client; requests worked only through certifi).

:func:`apply_ca_bundle` runs at the start (main.py): when the default
store is empty and the user set neither SSL_CERT_FILE nor SSL_CERT_DIR,
SSL_CERT_FILE points at the host's bundle - so a CA the administrator
installed is trusted - or at certifi's when the host has none. OpenSSL
reads the variable whenever a context loads its default paths, so every
later context sees it. Host programs started from axross do not inherit
it (core.subprocess_env.clean_child_env); axross's own workers do.
"""

from __future__ import annotations

import os
import ssl
from collections.abc import Callable, Iterable

#: Where systems keep their PEM bundle, most common first.
HOST_CA_FILES = (
    "/etc/ssl/certs/ca-certificates.crt",                 # Debian, Ubuntu, Gentoo, Arch, Alpine
    "/etc/pki/tls/certs/ca-bundle.crt",                   # RHEL, Fedora, Alma, Rocky
    "/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem",  # RHEL, Fedora (the source)
    "/etc/ssl/ca-bundle.pem",                             # openSUSE
    "/etc/ssl/cert.pem",                                  # Arch, Alpine, macOS, the BSDs
    "/etc/pki/tls/cacert.pem",                            # OpenELEC
)
FILE_VAR, DIR_VAR = "SSL_CERT_FILE", "SSL_CERT_DIR"

#: What this process set itself (not the user).
_SET_BY_AXROSS: set[str] = set()


def default_store_count() -> int:
    """The CA certificates a default client context loads."""
    return int(ssl.create_default_context().cert_store_stats().get("x509_ca", 0))


def _certifi() -> str:
    try:
        import certifi
    except ImportError:
        return ""
    return certifi.where()


def _usable(path: str) -> bool:
    try:
        return os.path.isfile(path) and os.path.getsize(path) > 0 and os.access(path, os.R_OK)
    except OSError:
        return False


def apply_ca_bundle(environ: dict | None = None, *, candidates: Iterable[str] = HOST_CA_FILES,
                    count: Callable[[], int] = default_store_count,
                    certifi_path: str | None = None) -> str | None:
    """Point SSL_CERT_FILE in *environ* (default ``os.environ``) at a CA
    bundle when the default store is empty; return the path set, None
    when nothing was (a working store, the user's own variable, or no
    bundle anywhere)."""
    environ = os.environ if environ is None else environ
    if FILE_VAR in environ or DIR_VAR in environ:
        return None
    if count() > 0:
        return None
    chosen = next((p for p in candidates if _usable(p)), "")
    if not chosen:
        fallback = _certifi() if certifi_path is None else certifi_path
        chosen = fallback if fallback and _usable(fallback) else ""
    if not chosen:
        return None
    environ[FILE_VAR] = chosen
    _SET_BY_AXROSS.add(FILE_VAR)
    return chosen


def set_by_axross() -> frozenset[str]:
    """The names :func:`apply_ca_bundle` set in this process."""
    return frozenset(_SET_BY_AXROSS)


__all__ = ["DIR_VAR", "FILE_VAR", "HOST_CA_FILES", "apply_ca_bundle", "default_store_count",
           "set_by_axross"]
