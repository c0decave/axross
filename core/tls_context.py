"""Verified TLS client contexts for protocols whose stdlib client does not verify.

``imaplib.IMAP4_SSL`` and ``poplib.POP3_SSL`` fall back to
``ssl._create_stdlib_context()``, which is ``_create_unverified_context``:
no certificate check, no hostname check. A passive MITM then reads the
login. Every such constructor gets the context from here instead.
"""
from __future__ import annotations

import logging
import ssl

log = logging.getLogger(__name__)


def client_tls_context(verify: bool = True, *, label: str = "TLS") -> ssl.SSLContext:
    """Default-verifying context; ``verify=False`` is an explicit, logged opt-out."""
    if verify:
        return ssl.create_default_context()
    log.warning(
        "%s: certificate verification DISABLED by profile option; "
        "credentials are exposed to an active man-in-the-middle",
        label,
    )
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx
