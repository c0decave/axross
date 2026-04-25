"""End-to-end integration tests for the Windows-protocol backends.

There is no practical Linux emulator for WinRM / WMI-DCOM / DFS-N, so
these tests require a real Windows target (Windows Server 2019+ with
WinRM / DCOM / DFS-N enabled). See ``docs/WINDOWS_TESTING.md`` for
how to stand up a throwaway target.

Configuration lives in environment variables; each test class skips
cleanly when the vars it needs are missing, so a developer running
``pytest`` locally sees "skipped" rather than a failure.

Env vars
--------
* ``AXROSS_WIN_HOST``          — hostname / IP of the Windows target
* ``AXROSS_WIN_USER``          — username for WinRM + SMB + DCOM auth
* ``AXROSS_WIN_PASSWORD``      — password
* ``AXROSS_WIN_WINRM_HTTPS``   — "1" to use HTTPS/5986 (default), else HTTP/5985
* ``AXROSS_WIN_WINRM_PORT``    — WinRM port override
* ``AXROSS_WIN_WINRM_VERIFY``  — "0" to skip TLS cert validation (self-signed setups)
* ``AXROSS_WIN_SMB_SHARE``     — SMB share name (default "TestShare")
* ``AXROSS_WIN_DFSN_NAMESPACE`` — DFS-N namespace name (share, not full UNC)

Run with:

    .venv/bin/python -m pytest tests/test_windows_integration.py -v

Timing: the WinRM round-trips are SLOW (~1-3 s each) compared to
mock tests. The suite is meant for opt-in verification, not CI.
"""
from __future__ import annotations

import os
import unittest


def _env(name: str) -> str | None:
    val = os.environ.get(name)
    return val.strip() if val and val.strip() else None


def _required(*names: str) -> bool:
    """True iff every one of *names* is set to a non-empty value."""
    return all(_env(n) for n in names)


# --------------------------------------------------------------------------
# WinRM
# --------------------------------------------------------------------------

@unittest.skipUnless(
    _required("AXROSS_WIN_HOST", "AXROSS_WIN_USER", "AXROSS_WIN_PASSWORD"),
    "WinRM integration test requires AXROSS_WIN_HOST / USER / PASSWORD",
)
class WinRMIntegrationTests(unittest.TestCase):
    """Drives the real WinRM backend against an env-configured target."""

    @classmethod
    def setUpClass(cls) -> None:
        try:
            import winrm  # noqa: F401 — verify dep available
        except ImportError:  # pragma: no cover
            raise unittest.SkipTest("pywinrm not installed")
        from core.winrm_client import WinRMSession
        cls.WinRMSession = WinRMSession
        cls.host = _env("AXROSS_WIN_HOST")
        cls.user = _env("AXROSS_WIN_USER")
        cls.password = _env("AXROSS_WIN_PASSWORD")
        https_env = (_env("AXROSS_WIN_WINRM_HTTPS") or "1").lower()
        cls.use_https = https_env in ("1", "true", "yes", "on")
        cls.port = int(_env("AXROSS_WIN_WINRM_PORT") or
                       (5986 if cls.use_https else 5985))
        cls.verify_ssl = (_env("AXROSS_WIN_WINRM_VERIFY") or "1") != "0"

    def _session(self):
        return self.WinRMSession(
            host=self.host, username=self.user, password=self.password,
            port=self.port, use_https=self.use_https,
            verify_ssl=self.verify_ssl,
        )

    def test_winrm_stat_root(self) -> None:
        """Sanity: stat of the root returns a directory item. If this
        fails, every other WinRM test would fail with the same cause
        — keeping it first makes triage obvious."""
        sess = self._session()
        item = sess.stat("\\")
        self.assertTrue(item.is_dir)

    def test_winrm_listing_contains_expected_entries(self) -> None:
        sess = self._session()
        entries = sess.list_dir("\\Windows")
        names = {e.name.lower() for e in entries}
        self.assertIn("system32", names)

    def test_winrm_small_file_roundtrip(self) -> None:
        """Write a tiny file via open_write, read it back, delete it."""
        sess = self._session()
        tmp_path = f"\\Users\\{self.user}\\axx_roundtrip.txt"
        payload = b"hello winrm integration\r\n"
        try:
            with sess.open_write(tmp_path) as fh:
                fh.write(payload)
            with sess.open_read(tmp_path) as fh:
                read_back = fh.read()
            self.assertEqual(read_back, payload)
        finally:
            try:
                sess.remove(tmp_path)
            except Exception:
                pass


# --------------------------------------------------------------------------
# WMI / DCOM
# --------------------------------------------------------------------------

@unittest.skipUnless(
    _required("AXROSS_WIN_HOST", "AXROSS_WIN_USER", "AXROSS_WIN_PASSWORD"),
    "WMI integration test requires AXROSS_WIN_HOST / USER / PASSWORD",
)
class WMIIntegrationTests(unittest.TestCase):
    """Drives the real WMI/DCOM backend for metadata enumeration."""

    @classmethod
    def setUpClass(cls) -> None:
        try:
            import impacket  # noqa: F401
        except ImportError:  # pragma: no cover
            raise unittest.SkipTest("impacket not installed")
        from core.wmi_client import WMISession
        cls.WMISession = WMISession
        cls.host = _env("AXROSS_WIN_HOST")
        cls.user = _env("AXROSS_WIN_USER")
        cls.password = _env("AXROSS_WIN_PASSWORD")

    def test_wmi_enumerates_windows_dir(self) -> None:
        sess = self.WMISession(
            host=self.host, username=self.user, password=self.password,
        )
        try:
            entries = sess.list_dir("C:\\Windows")
            # "Windows" always contains at least a handful of subdirs.
            self.assertGreater(len(entries), 0)
            names = {e.name.lower() for e in entries}
            # These are universal across Windows editions.
            self.assertTrue({"system32", "syswow64"} & names,
                            f"expected system32/syswow64 in {names}")
        finally:
            sess.close()


# --------------------------------------------------------------------------
# DFS-N
# --------------------------------------------------------------------------

@unittest.skipUnless(
    _required(
        "AXROSS_WIN_HOST", "AXROSS_WIN_USER", "AXROSS_WIN_PASSWORD",
        "AXROSS_WIN_DFSN_NAMESPACE",
    ),
    "DFS-N test requires AXROSS_WIN_HOST + DFSN_NAMESPACE",
)
class DFSNIntegrationTests(unittest.TestCase):
    """Drives the real DFS-N backend against a stand-alone namespace."""

    @classmethod
    def setUpClass(cls) -> None:
        try:
            import smbprotocol  # noqa: F401
        except ImportError:  # pragma: no cover
            raise unittest.SkipTest("smbprotocol not installed")
        from core.dfsn_client import DFSNamespaceSession
        cls.DFSNamespaceSession = DFSNamespaceSession
        cls.host = _env("AXROSS_WIN_HOST")
        cls.user = _env("AXROSS_WIN_USER")
        cls.password = _env("AXROSS_WIN_PASSWORD")
        cls.namespace = _env("AXROSS_WIN_DFSN_NAMESPACE")

    def test_dfsn_namespace_is_listable(self) -> None:
        sess = self.DFSNamespaceSession(
            host=self.host, namespace=self.namespace,
            username=self.user, password=self.password,
        )
        try:
            entries = sess.list_dir("/")
            # A namespace with folders should yield at least one.
            # (Tests in this file assume docs/WINDOWS_TESTING.md's
            # recipe which creates an "inner" folder.)
            self.assertTrue(
                any(e.is_dir for e in entries),
                f"expected ≥1 folder in namespace {self.namespace!r}",
            )
        finally:
            sess.close()


if __name__ == "__main__":  # pragma: no cover — manual runner
    unittest.main(verbosity=2)
