"""IMAP / POP3 / LDAP must verify server certificates unless told otherwise."""
from __future__ import annotations

import ssl
import unittest
from unittest import mock

from core import imap_client, pop3_client
from core.tls_context import client_tls_context


class ContextTest(unittest.TestCase):
    def test_default_verifies(self) -> None:
        ctx = client_tls_context()
        self.assertEqual(ctx.verify_mode, ssl.CERT_REQUIRED)
        self.assertTrue(ctx.check_hostname)

    def test_opt_out_is_explicit_and_logged(self) -> None:
        with self.assertLogs("core.tls_context", level="WARNING"):
            ctx = client_tls_context(verify=False, label="IMAP")
        self.assertEqual(ctx.verify_mode, ssl.CERT_NONE)
        self.assertFalse(ctx.check_hostname)


class ImapTest(unittest.TestCase):
    def _session(self, **kw):
        session = imap_client.ImapSession.__new__(imap_client.ImapSession)
        session._host, session._port = "mail.example", 993
        session._username = session._password = ""
        session._use_ssl = True
        session._proxy = None
        session._verify_tls = kw.get("verify_tls", True)
        return session

    def test_ssl_context_is_passed_and_verifying(self) -> None:
        session = self._session()
        with mock.patch.object(imap_client.imaplib, "IMAP4_SSL") as ctor:
            ctor.return_value.login.return_value = ("OK", [b""])
            try:
                session._connect()
            except Exception:  # noqa: BLE001 - only the constructor call matters
                pass
        ctx = ctor.call_args.kwargs.get("ssl_context")
        self.assertIsNotNone(ctx)
        self.assertEqual(ctx.verify_mode, ssl.CERT_REQUIRED)

    def test_opt_out_reaches_constructor(self) -> None:
        session = self._session(verify_tls=False)
        with mock.patch.object(imap_client.imaplib, "IMAP4_SSL") as ctor:
            try:
                session._connect()
            except Exception:  # noqa: BLE001
                pass
        self.assertEqual(ctor.call_args.kwargs["ssl_context"].verify_mode, ssl.CERT_NONE)


class Pop3Test(unittest.TestCase):
    def test_context_is_passed_and_verifying(self) -> None:
        session = pop3_client.Pop3Session.__new__(pop3_client.Pop3Session)
        session._host, session._port = "pop.example", 995
        session._username = session._password = ""
        session._use_ssl = True
        session._proxy = mock.Mock(enabled=False)
        session._verify_tls = True
        with mock.patch.object(pop3_client.poplib, "POP3_SSL") as ctor:
            try:
                session._connect()
            except Exception:  # noqa: BLE001
                pass
        ctx = ctor.call_args.kwargs.get("context")
        self.assertIsNotNone(ctx)
        self.assertEqual(ctx.verify_mode, ssl.CERT_REQUIRED)


class LdapTest(unittest.TestCase):
    """ldap3 is optional; its names are replaced so the code path runs anyway."""

    class _FakeTls:
        def __init__(self, validate=None):
            self.validate = validate

    def _build(self, **kw):
        from core import ldap_fs_client as L

        with mock.patch.object(L, "ldap3", object(), create=True), mock.patch.object(
            L, "Tls", self._FakeTls, create=True
        ), mock.patch.object(L, "Server", create=True) as server, mock.patch.object(
            L, "Connection", create=True
        ), mock.patch.object(L, "ALL", "ALL", create=True):
            try:
                L.LdapFsSession(host="ldap.example", **kw)
            except Exception:  # noqa: BLE001 - only the Server() call matters
                pass
        return server.call_args.kwargs

    def test_ldaps_gets_a_validating_tls_object(self) -> None:
        kwargs = self._build(port=636, use_tls=True)
        self.assertEqual(kwargs["tls"].validate, ssl.CERT_REQUIRED)

    def test_opt_out(self) -> None:
        kwargs = self._build(port=636, use_tls=True, verify_tls=False)
        self.assertEqual(kwargs["tls"].validate, ssl.CERT_NONE)

    def test_plain_ldap_has_no_tls_object(self) -> None:
        self.assertIsNone(self._build(port=389, use_tls=False)["tls"])


if __name__ == "__main__":
    unittest.main()
