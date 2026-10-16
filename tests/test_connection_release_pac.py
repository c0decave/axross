"""release() gives back the session connect() handed out, whatever the PAC says now.

Before: ``release(profile)`` recomputed the session key through
``effective_profile`` -> ``proxy_settings.resolve_for_profile`` -> the PAC.
When the PAC answer changed between connect and release (a new PAC file
after the 300 s cache TTL, a time-based rule), the key no longer matched,
``release`` returned silently and the session was never disconnected.
When the PAC could no longer be read at all, ``release`` raised
``ProxyResolutionError`` into the caller (a pane close). The terminal
pane's extra reference (``MainWindow._embed_terminal_pane``) and
``get_session`` recomputed the key the same way.

Now the manager remembers the key each connect used for that profile
object and release / acquire / get_session use it.
"""

from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core import proxy_settings as PS  # noqa: E402
from core.connection_manager import ConnectionManager  # noqa: E402
from core.profiles import ConnectionProfile  # noqa: E402


def _pac(proxy_host: str) -> str:
    return f'function FindProxyForURL(url, host) {{ return "PROXY {proxy_host}:3128"; }}\n'


class _FakeSession:
    def __init__(self, profile) -> None:
        self.connected = True
        self.proxy_host = profile.proxy_host
        self.disconnects = 0

    def disconnect(self) -> None:
        self.disconnects += 1
        self.connected = False


class _Base(unittest.TestCase):
    def setUp(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.tmp = Path(tmp.name)
        self.pac_file = self.tmp / "proxy.pac"
        self.pac_file.write_text(_pac("first.proxy"))
        for patcher in (
            mock.patch.object(PS, "SETTINGS_PATH", self.tmp / "proxy.json"),
            mock.patch.dict(PS._PAC_CACHE, clear=True),
        ):
            patcher.start()
            self.addCleanup(patcher.stop)
        PS.save(PS.ProxyDefaults(proxy_type="http", pac_url=str(self.pac_file), bypass=[]))
        self.created: list[_FakeSession] = []

        def create(_self, resolved, *_args, **_kw):
            session = _FakeSession(resolved)
            self.created.append(session)
            return session

        patcher = mock.patch.object(ConnectionManager, "_create_session", create)
        patcher.start()
        self.addCleanup(patcher.stop)
        self.cm = ConnectionManager()
        self.profile = ConnectionProfile(
            name="p", protocol="sftp", host="files.example", port=22, proxy_mode="default"
        )

    def _pac_now_says(self, proxy_host: str | None) -> None:
        """The PAC answer changes and the 300 s cache has run out."""
        if proxy_host is None:
            self.pac_file.unlink()
        else:
            self.pac_file.write_text(_pac(proxy_host))
        PS._PAC_CACHE.clear()


class ReleaseTest(_Base):
    def test_happy_release_disconnects_after_the_pac_answer_changed(self) -> None:
        session = self.cm.connect(self.profile)
        self.assertEqual(session.proxy_host, "first.proxy")
        self._pac_now_says("second.proxy")
        self.cm.release(self.profile)
        self.assertEqual(session.disconnects, 1)
        self.assertEqual(self.cm.active_sessions(), [])

    def test_happy_unchanged_pac_still_refcounts(self) -> None:
        first = self.cm.connect(self.profile)
        second = self.cm.connect(self.profile)
        self.assertIs(first, second)
        self.cm.release(self.profile)
        self.assertEqual(first.disconnects, 0)
        self.cm.release(self.profile)
        self.assertEqual(first.disconnects, 1)

    def test_sad_release_with_an_unreadable_pac_neither_raises_nor_leaks(self) -> None:
        session = self.cm.connect(self.profile)
        self._pac_now_says(None)
        self.cm.release(self.profile)  # no ProxyResolutionError
        self.assertEqual(session.disconnects, 1)

    def test_sad_release_of_a_never_connected_profile_is_a_no_op(self) -> None:
        session = self.cm.connect(self.profile)
        other = ConnectionProfile(name="q", protocol="sftp", host="other.example", port=22)
        self.cm.release(other)
        self.assertEqual(session.disconnects, 0)

    def test_edge_two_connects_across_a_pac_change_release_both_sessions(self) -> None:
        first = self.cm.connect(self.profile)
        self._pac_now_says("second.proxy")
        second = self.cm.connect(self.profile)
        self.assertIsNot(first, second)
        self.cm.release(self.profile)
        self.cm.release(self.profile)
        self.assertEqual((first.disconnects, second.disconnects), (1, 1))
        self.assertEqual(self.cm.active_sessions(), [])

    def test_edge_equal_copy_of_the_profile_releases_too(self) -> None:
        import dataclasses

        session = self.cm.connect(self.profile)
        self._pac_now_says("second.proxy")
        self.cm.release(dataclasses.replace(self.profile))
        self.assertEqual(session.disconnects, 1)


class ExtraReferenceTest(_Base):
    def test_happy_terminal_reference_keeps_the_session_until_both_release(self) -> None:
        session = self.cm.connect(self.profile)
        self._pac_now_says("second.proxy")
        self.cm.acquire(self.profile)  # what _embed_terminal_pane takes
        self.assertIs(self.cm.get_session(self.profile), session)
        self.cm.release(self.profile)
        self.assertEqual(session.disconnects, 0)
        self.cm.release(self.profile)
        self.assertEqual(session.disconnects, 1)

    def test_edge_get_session_with_an_unreadable_pac_returns_the_live_session(self) -> None:
        session = self.cm.connect(self.profile)
        self._pac_now_says(None)
        self.assertIs(self.cm.get_session(self.profile), session)

    def test_edge_disconnect_all_forgets_the_remembered_keys(self) -> None:
        session = self.cm.connect(self.profile)
        self.cm.disconnect_all()
        self.assertEqual(session.disconnects, 1)
        self.cm.release(self.profile)  # nothing left to give back
        self.assertEqual(session.disconnects, 1)


if __name__ == "__main__":
    unittest.main()
