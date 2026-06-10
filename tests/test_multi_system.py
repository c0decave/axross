"""Tests for the multi-system / daily-driver feature batch:
visit_history, conn_health, safety_tarpit, inspect, multi_view,
search_federation, adaptive_io, copy_resume, trail, dashboard,
reverse_serve.

No network. Two strategies for the file-backend dependency:

* ``core.ram_fs.RamFsSession`` — real, in-process backend that
  satisfies the FileBackend protocol. Used wherever the tests need
  realistic behaviour (read/write/stat/list).
* Tiny fake-backend dataclasses — used where a test wants to inject a
  specific ``backend.list_dir`` response or simulate timing.
"""

from __future__ import annotations

import hashlib
import io
import json
import os
import socket
import sys
import tempfile
import threading
import time
import unittest
import urllib.request
from datetime import datetime
from pathlib import Path
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from core import (
    adaptive_io,
    conn_health,
    copy_resume,
    dashboard,
    inspect,
    multi_view,
    reverse_serve,
    safety_tarpit,
    scripting,
    search_federation,
    trail,
    visit_history,
)
from core.ram_fs import RamFsSession
from models.file_item import FileItem

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _ramfs() -> RamFsSession:
    """Fresh RamFS — every test gets its own. The session is
    in-process so cleanup is automatic when the reference drops."""
    return RamFsSession()


def _make_file_item(
    name: str,
    *,
    size: int = 0,
    is_dir: bool = False,
    mtime: float | None = None,
) -> FileItem:
    return FileItem(
        name=name,
        is_dir=is_dir,
        is_link=False,
        size=size,
        modified=datetime.fromtimestamp(mtime or time.time()),
        permissions=0o644,
    )


class _StaticBackend:
    """Tiny FileBackend look-alike whose ``list_dir`` returns fixed
    entries. Enough to drive ``inspect.summarize`` /
    ``inspect.explain`` / ``search_federation`` tests."""

    def __init__(self, name: str, listings: dict[str, list[FileItem]]):
        self.name = name
        self._listings = listings

    def home(self) -> str:
        return "/"

    def join(self, *parts: str) -> str:
        cleaned = [p.strip("/") for p in parts if p]
        return "/" + "/".join(cleaned)

    def list_dir(self, path: str) -> list[FileItem]:
        if path not in self._listings:
            raise OSError(f"no listing for {path!r}")
        return list(self._listings[path])

    def stat(self, path: str) -> FileItem:
        if path == "/":
            return _make_file_item("/", is_dir=True)
        # Best effort — synthesise from name.
        return _make_file_item(path.rsplit("/", 1)[-1], size=42)

    def open_read(self, path: str, mode: str = "rb"):
        return io.BytesIO(b"")


# ---------------------------------------------------------------------------
# visit_history
# ---------------------------------------------------------------------------


class VisitHistoryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        # Redirect the storage location for the duration of the test.
        self._orig = visit_history.HISTORY_FILE
        visit_history.HISTORY_FILE = Path(self.tmp.name) / "visit_history.json"

    def tearDown(self) -> None:
        visit_history.HISTORY_FILE = self._orig
        self.tmp.cleanup()

    def test_record_and_recall(self) -> None:
        visit_history.record_visit(
            "sftp",
            "prod-db-04",
            "alice",
            path="/var/log/postgres/",
            verb="list_dir",
            desc="postgres logs",
        )
        v = visit_history.where_was_i("prod-db-04")
        assert v is not None
        self.assertEqual(v.host, "prod-db-04")
        self.assertEqual(v.last_path, "/var/log/postgres/")
        self.assertEqual(v.visit_count, 1)
        self.assertEqual(len(v.recent_ops), 1)

    def test_substring_match(self) -> None:
        visit_history.record_visit("sftp", "prod-db-04.internal", "alice")
        v = visit_history.where_was_i("prod-db")
        assert v is not None
        self.assertIn("prod-db", v.host)

    def test_visits_sorted_by_recency(self) -> None:
        visit_history.record_visit("sftp", "h1", "u")
        visit_history.record_visit("sftp", "h2", "u")
        all_visits = visit_history.where_was_i()
        assert isinstance(all_visits, list)
        self.assertEqual(all_visits[0].host, "h2")
        self.assertEqual(all_visits[1].host, "h1")

    def test_recent_ops_capped(self) -> None:
        for i in range(visit_history.MAX_OPS_PER_HOST + 5):
            visit_history.record_visit(
                "sftp",
                "h",
                "u",
                verb="op",
                desc=f"op-{i}",
            )
        v = visit_history.where_was_i("h")
        assert v is not None
        self.assertEqual(len(v.recent_ops), visit_history.MAX_OPS_PER_HOST)
        # Newest op first.
        self.assertIn(
            f"op-{visit_history.MAX_OPS_PER_HOST + 4}",
            v.recent_ops[0]["desc"],
        )

    def test_clear_one(self) -> None:
        visit_history.record_visit("sftp", "h1", "u")
        visit_history.record_visit("sftp", "h2", "u")
        dropped = visit_history.clear("h1")
        self.assertEqual(dropped, 1)
        self.assertIsNone(visit_history.where_was_i("h1"))
        self.assertIsNotNone(visit_history.where_was_i("h2"))

    def test_clear_all(self) -> None:
        visit_history.record_visit("sftp", "h1", "u")
        visit_history.record_visit("sftp", "h2", "u")
        dropped = visit_history.clear()
        self.assertEqual(dropped, 2)

    def test_empty_host_lookup_does_not_match_everything(self) -> None:
        visit_history.record_visit("sftp", "h1", "u")
        self.assertIsNone(visit_history.where_was_i(""))

    def test_scripting_file_ops_record_path_and_verb(self) -> None:
        from core.profiles import ConnectionProfile

        b = _ramfs()
        b._axross_profile = ConnectionProfile(
            name="vh",
            protocol="sftp",
            host="vh-host",
            username="alice",
        )
        b._axross_profile_key = "vh-session"
        scripting.write_bytes(b, "/note.txt", b"hello")
        v = visit_history.where_was_i("vh-host")
        assert v is not None
        self.assertEqual(v.last_path, "/note.txt")
        self.assertEqual(v.recent_ops[0]["verb"], "write")

    def test_record_swallows_disk_failure(self) -> None:
        # Point at an unwritable path; record_visit must not raise.
        visit_history.HISTORY_FILE = Path("/proc/1/no-such-place/visit.json")
        visit_history.record_visit("sftp", "h", "u")  # must not raise

    def test_record_visit_serializes_concurrent_load_mutate_save(self) -> None:
        stored: dict[str, visit_history.HostVisit] = {}
        store_guard = threading.Lock()
        active_guard = threading.Lock()
        active_loads = 0
        max_active_loads = 0
        start = threading.Event()

        def clone_visits(
            visits: dict[str, visit_history.HostVisit],
        ) -> dict[str, visit_history.HostVisit]:
            return {
                key: visit_history.HostVisit(
                    protocol=v.protocol,
                    host=v.host,
                    username=v.username,
                    last_path=v.last_path,
                    last_seen=v.last_seen,
                    visit_count=v.visit_count,
                    recent_ops=[dict(op) for op in v.recent_ops],
                )
                for key, v in visits.items()
            }

        def slow_load() -> dict[str, visit_history.HostVisit]:
            nonlocal active_loads, max_active_loads
            with active_guard:
                active_loads += 1
                max_active_loads = max(max_active_loads, active_loads)
            try:
                time.sleep(0.01)
                with store_guard:
                    return clone_visits(stored)
            finally:
                with active_guard:
                    active_loads -= 1

        def slow_save(visits: dict[str, visit_history.HostVisit]) -> None:
            snapshot = clone_visits(visits)
            time.sleep(0.005)
            with store_guard:
                stored.clear()
                stored.update(snapshot)

        def worker(i: int) -> None:
            start.wait()
            visit_history.record_visit(
                "sftp",
                f"h{i}",
                "u",
                path=f"/tmp/{i}",
                verb="list_dir",
                desc=f"op-{i}",
            )

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(8)]
        with mock.patch.object(visit_history, "_load", side_effect=slow_load), mock.patch.object(
            visit_history, "_save", side_effect=slow_save
        ):
            for thread in threads:
                thread.start()
            start.set()
            for thread in threads:
                thread.join(timeout=2.0)

        self.assertFalse(any(thread.is_alive() for thread in threads))
        self.assertEqual(max_active_loads, 1)
        self.assertEqual({v.host for v in stored.values()}, {f"h{i}" for i in range(8)})

    def test_humanize_age(self) -> None:
        self.assertEqual(visit_history.humanize_age(10), "just now")
        self.assertEqual(visit_history.humanize_age(120), "2 min ago")
        self.assertIn("h", visit_history.humanize_age(7200))
        self.assertIn("d", visit_history.humanize_age(86400 * 3))


# ---------------------------------------------------------------------------
# conn_health
# ---------------------------------------------------------------------------


class FakeSession:
    """Test double matching the duck-typed surface conn_health probes.

    ``_probe_pop3`` drills into ``session._pop`` and calls ``noop()``
    on that handle — so we expose ``_pop`` pointing back to self.
    """

    def __init__(self, *, fail: bool = False) -> None:
        self.fail = fail
        self.connected = True
        self._pop = self  # so getattr(session, "_pop").noop() works

    def noop(self) -> None:  # POP3 / IMAP probe
        if self.fail:
            raise OSError("noop boom")


class ConnHealthTests(unittest.TestCase):
    def setUp(self) -> None:
        self.mgr = conn_health.HealthManager(interval_s=conn_health.MIN_INTERVAL_S)

    def tearDown(self) -> None:
        self.mgr.stop()

    def test_enroll_and_probe_success(self) -> None:
        session = FakeSession()
        record = self.mgr.enroll("k1", session, protocol="pop3", label="alice@h")
        self.mgr.probe_now("k1")
        self.assertTrue(record.healthy)
        self.assertIsNotNone(record.last_latency_s)
        self.assertEqual(record.consecutive_failures, 0)

    def test_two_failures_marks_stale(self) -> None:
        session = FakeSession(fail=True)
        record = self.mgr.enroll("k2", session, protocol="pop3", label="x")
        self.mgr.probe_now("k2")
        self.assertEqual(record.consecutive_failures, 1)
        self.assertFalse(record.stale)
        self.mgr.probe_now("k2")
        self.assertEqual(record.consecutive_failures, 2)
        self.assertTrue(record.stale)

    def test_unenroll_drops_record(self) -> None:
        self.mgr.enroll("k3", FakeSession(), protocol="pop3", label="x")
        self.mgr.unenroll("k3")
        self.assertIsNone(self.mgr.get("k3"))

    def test_generic_fallback_uses_connected_attr(self) -> None:
        # Protocol with no registered probe → falls back to connected.
        session = FakeSession()
        session.connected = True
        record = self.mgr.enroll(
            "k4",
            session,
            protocol="exotic",
            label="x",
        )
        self.mgr.probe_now("k4")
        self.assertTrue(record.healthy)

        session.connected = False
        self.mgr.probe_now("k4")
        self.assertEqual(record.consecutive_failures, 1)

    def test_unknown_protocol_without_connected_state_fails_closed(self) -> None:
        session = object()
        record = self.mgr.enroll("k5", session, protocol="exotic", label="x")
        self.mgr.probe_now("k5")
        self.mgr.probe_now("k5")
        self.assertTrue(record.stale)
        self.assertIn("no health probe", record.history[-1].error)


class ConnectionManagerHookTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self._orig_history = visit_history.HISTORY_FILE
        visit_history.HISTORY_FILE = Path(self.tmp.name) / "visit_history.json"
        conn_health._GLOBAL = None

    def tearDown(self) -> None:
        visit_history.HISTORY_FILE = self._orig_history
        mgr = conn_health.get_manager()
        mgr.stop()
        conn_health._GLOBAL = None
        self.tmp.cleanup()

    def test_connect_decorates_session_and_wires_health_and_visits(self) -> None:
        from core.connection_manager import ConnectionManager
        from core.profiles import ConnectionProfile

        class FakeCM(ConnectionManager):
            def _create_session(self, profile, password, key_passphrase, on_unknown_host):
                return FakeSession()

        profile = ConnectionProfile(
            name="hooked",
            protocol="pop3",
            host="hook-host",
            port=110,
            username="alice",
        )
        cm = FakeCM()
        session = cm.connect(profile)
        self.assertIs(getattr(session, "_axross_profile"), profile)
        self.assertTrue(getattr(session, "_axross_profile_key"))
        self.assertEqual(len(conn_health.health_pulse()), 1)
        self.assertIsNotNone(visit_history.where_was_i("hook-host"))
        profile.production = True
        reused = cm.connect(profile)
        self.assertIs(reused, session)
        self.assertTrue(getattr(reused, "_axross_profile").production)
        cm.release(profile)
        cm.release(profile)
        self.assertEqual(conn_health.health_pulse(), [])


# ---------------------------------------------------------------------------
# safety_tarpit
# ---------------------------------------------------------------------------


class SafetyTarpitTests(unittest.TestCase):
    def setUp(self) -> None:
        safety_tarpit.reset_all()
        # Replace the renderer with an instant-pass stub so the tests
        # don't sleep for 3 seconds each.
        self._orig = safety_tarpit._COUNTDOWN_RENDERER
        self.calls: list[tuple[float, str, str]] = []

        def fake(seconds, *, label, op_desc):
            self.calls.append((seconds, label, op_desc))
            return True

        safety_tarpit.set_countdown_renderer(fake)

    def tearDown(self) -> None:
        safety_tarpit.set_countdown_renderer(self._orig)
        safety_tarpit.reset_all()
        os.environ.pop(safety_tarpit.ENV_DISABLE, None)

    def _profile(self, *, production: bool = True):
        from core.profiles import ConnectionProfile

        return ConnectionProfile(
            name="prod-db-04",
            protocol="sftp",
            host="prod-db-04.internal",
            production=production,
        )

    def test_no_op_when_profile_not_production(self) -> None:
        with safety_tarpit.production_gate(
            self._profile(production=False),
            "rm /a",
            session_id="s1",
        ):
            pass
        self.assertEqual(self.calls, [])

    def test_fires_on_first_op_per_session(self) -> None:
        prof = self._profile()
        with safety_tarpit.production_gate(prof, "rm /a", session_id="s1"):
            pass
        with safety_tarpit.production_gate(prof, "rm /b", session_id="s1"):
            pass
        # Only the FIRST op should have triggered the renderer.
        self.assertEqual(len(self.calls), 1)
        self.assertIn("/a", self.calls[0][2])

    def test_per_session_isolation(self) -> None:
        prof = self._profile()
        with safety_tarpit.production_gate(prof, "rm", session_id="s1"):
            pass
        with safety_tarpit.production_gate(prof, "rm", session_id="s2"):
            pass
        self.assertEqual(len(self.calls), 2)

    def test_env_disable_short_circuits(self) -> None:
        os.environ[safety_tarpit.ENV_DISABLE] = "1"
        with safety_tarpit.production_gate(
            self._profile(),
            "rm",
            session_id="s1",
        ):
            pass
        self.assertEqual(self.calls, [])

    def test_keyboard_interrupt_propagates(self) -> None:
        def boom(seconds, *, label, op_desc):
            raise KeyboardInterrupt("user bailed")

        safety_tarpit.set_countdown_renderer(boom)
        with self.assertRaises(KeyboardInterrupt):
            with safety_tarpit.production_gate(
                self._profile(),
                "rm",
                session_id="s1",
            ):
                self.fail("body should not execute on abort")

    def test_scripting_write_hits_production_tarpit(self) -> None:
        b = _ramfs()
        prof = self._profile(production=True)
        b._axross_profile = prof
        b._axross_profile_key = "prod-session"
        scripting.write_bytes(b, "/danger.txt", b"payload")
        self.assertEqual(len(self.calls), 1)
        self.assertIn("write", self.calls[0][2])
        # Same opened session has paid the toll; a second write proceeds
        # without another countdown.
        scripting.write_bytes(b, "/danger2.txt", b"payload")
        self.assertEqual(len(self.calls), 1)


# ---------------------------------------------------------------------------
# inspect (summarize + explain)
# ---------------------------------------------------------------------------


class InspectTests(unittest.TestCase):
    def test_summarize_counts_and_histogram(self) -> None:
        b = _ramfs()
        b.mkdir("/x")
        for i in range(3):
            fh = b.open_write(f"/x/log-{i}.log")
            fh.write(b"line\n" * 10)
            fh.close()
        fh = b.open_write("/x/note.txt")
        fh.write(b"x")
        fh.close()
        s = inspect.summarize(b, "/x")
        self.assertEqual(s.file_count, 4)
        self.assertEqual(s.dir_count, 0)
        self.assertEqual(s.extensions[".log"], 3)
        self.assertEqual(s.extensions[".txt"], 1)
        self.assertGreaterEqual(s.total_bytes, 4 * 5)

    def test_summarize_handles_oserror(self) -> None:
        b = _ramfs()
        s = inspect.summarize(b, "/no-such-dir")
        self.assertTrue(s.error)
        self.assertEqual(s.file_count, 0)

    def test_explain_recognises_git(self) -> None:
        listings = {
            "/repo": [
                _make_file_item("HEAD", size=20),
                _make_file_item("config", size=42),
                _make_file_item("refs", is_dir=True),
                _make_file_item("objects", is_dir=True),
                _make_file_item("packed-refs", size=100),
            ],
        }
        backend = _StaticBackend("test", listings)
        r = inspect.explain(backend, "/repo")
        self.assertEqual(r.label, "Git repository")
        self.assertGreaterEqual(r.confidence, 0.5)

    def test_explain_recognises_postgres(self) -> None:
        listings = {
            "/pg": [
                _make_file_item("PG_VERSION", size=4),
                _make_file_item("postgresql.conf", size=2048),
                _make_file_item("pg_hba.conf", size=512),
                _make_file_item("base", is_dir=True),
                _make_file_item("global", is_dir=True),
                _make_file_item("postmaster.pid", size=64),
            ],
        }
        backend = _StaticBackend("test", listings)
        r = inspect.explain(backend, "/pg")
        self.assertEqual(r.label, "PostgreSQL data directory")

    def test_explain_returns_empty_for_random_dir(self) -> None:
        listings = {
            "/random": [
                _make_file_item("foo.txt", size=10),
                _make_file_item("bar.dat", size=20),
            ],
        }
        backend = _StaticBackend("test", listings)
        r = inspect.explain(backend, "/random")
        self.assertEqual(r.label, "")

    def test_explain_recognises_systemd_units(self) -> None:
        listings = {
            "/sysd": [
                _make_file_item("nginx.service", size=100),
                _make_file_item("backup.timer", size=80),
                _make_file_item("api.socket", size=70),
            ],
        }
        backend = _StaticBackend("test", listings)
        r = inspect.explain(backend, "/sysd")
        self.assertEqual(r.label, "systemd unit drop-in directory")


# ---------------------------------------------------------------------------
# multi_view
# ---------------------------------------------------------------------------


class MultiViewTests(unittest.TestCase):
    def test_compare_file_all_equal(self) -> None:
        b1 = _ramfs()
        b2 = _ramfs()
        for b in (b1, b2):
            fh = b.open_write("/foo")
            fh.write(b"hello")
            fh.close()
        rep = multi_view.compare_file([b1, b2], "/foo")
        self.assertEqual(len(rep.probes), 2)
        for p in rep.probes:
            self.assertTrue(p.exists)
            self.assertEqual(p.size, 5)
            self.assertEqual(p.sha256, rep.probes[0].sha256)
        self.assertTrue(rep.all_equal())

    def test_compare_file_diverges(self) -> None:
        b1 = _ramfs()
        b2 = _ramfs()
        b1.open_write("/foo").write(b"hello")
        # close happens via reference drop in RamFS
        fh = b1.open_write("/foo")
        fh.write(b"hello")
        fh.close()
        fh = b2.open_write("/foo")
        fh.write(b"goodbye")
        fh.close()
        rep = multi_view.compare_file([b1, b2], "/foo")
        self.assertFalse(rep.all_equal())
        # A unified diff was generated against the second backend.
        self.assertIn(rep.probes[1].label, rep.content_diff)

    def test_compare_file_handles_missing(self) -> None:
        b1 = _ramfs()
        b2 = _ramfs()
        fh = b1.open_write("/foo")
        fh.write(b"hi")
        fh.close()
        rep = multi_view.compare_file([b1, b2], "/foo")
        self.assertTrue(rep.probes[0].exists)
        self.assertFalse(rep.probes[1].exists)

    def test_inspect_targets_alignment(self) -> None:
        b1 = _ramfs()
        b2 = _ramfs()
        fh = b1.open_write("/a")
        fh.write(b"alpha")
        fh.close()
        fh = b2.open_write("/b")
        fh.write(b"beta-payload")
        fh.close()
        rep = multi_view.inspect_targets([(b1, "/a"), (b2, "/b")])
        self.assertEqual(len(rep.targets), 2)
        self.assertEqual(rep.targets[0].size, 5)
        self.assertEqual(rep.targets[1].size, 12)
        self.assertFalse(rep.hashes_consistent())

    def test_compare_file_accepts_label_override_pairs(self) -> None:
        b1 = _ramfs()
        b2 = _ramfs()
        for b in (b1, b2):
            fh = b.open_write("/foo")
            fh.write(b"hello")
            fh.close()
        rep = multi_view.compare_file([(b1, "left"), (b2, "right")], "/foo")
        self.assertEqual([p.label for p in rep.probes], ["left", "right"])

    def test_timeout_returns_error_probe_instead_of_hanging(self) -> None:
        class SlowBackend(_StaticBackend):
            def stat(self, path: str) -> FileItem:
                time.sleep(0.2)
                return super().stat(path)

        started = time.monotonic()
        rep = multi_view.compare_file(
            [SlowBackend("slow", {"/": []})],
            "/foo",
            per_target_timeout_s=0.02,
        )
        self.assertLess(time.monotonic() - started, 0.15)
        self.assertIn("TimeoutError", rep.probes[0].error)

    def test_truncated_hashes_are_not_reported_as_identical(self) -> None:
        b1 = _ramfs()
        b2 = _ramfs()
        fh = b1.open_write("/foo")
        fh.write(b"ab")
        fh.close()
        fh = b2.open_write("/foo")
        fh.write(b"ac")
        fh.close()
        rep = multi_view.compare_file(
            [b1, b2],
            "/foo",
            content_cap_bytes=1,
        )
        self.assertTrue(all(p.truncated for p in rep.probes))
        self.assertFalse(rep.all_equal())

    def test_content_cap_rejects_negative_and_excessive_values(self) -> None:
        b = _ramfs()
        fh = b.open_write("/foo")
        fh.write(b"payload")
        fh.close()

        with self.assertRaisesRegex(ValueError, "content_cap_bytes"):
            multi_view.compare_file([b], "/foo", content_cap_bytes=-1)
        with self.assertRaisesRegex(ValueError, "safety limit"):
            multi_view.inspect_targets(
                [(b, "/foo")],
                content_cap_bytes=multi_view.MAX_CONTENT_CAP_BYTES + 1,
            )

    def test_parallelism_and_timeout_reject_bad_values(self) -> None:
        b = _ramfs()
        fh = b.open_write("/foo")
        fh.write(b"payload")
        fh.close()

        with self.assertRaisesRegex(ValueError, "parallelism"):
            multi_view.compare_file([b], "/foo", parallelism=0)
        with self.assertRaisesRegex(ValueError, "per_target_timeout_s"):
            multi_view.inspect_targets([(b, "/foo")], per_target_timeout_s=-0.1)

    def test_per_target_timeout_is_not_a_shared_queue_budget(self) -> None:
        # When parallelism is lower than the number of targets and the
        # per-target budget is set to comfortably exceed any single
        # probe's runtime, queued probes must still get their full
        # budget when they actually start executing — they should not
        # share one global deadline with the first probe.
        class SlowStat(_StaticBackend):
            def stat(self, path: str) -> FileItem:
                time.sleep(0.05)
                return _make_file_item(path.rsplit("/", 1)[-1], size=1)

        for b in (b1 := SlowStat("seq-a", {"/": []}),
                  b2 := SlowStat("seq-b", {"/": []})):
            b._listings["/foo"] = []

        rep = multi_view.inspect_targets(
            [(b1, "/foo"), (b2, "/foo")],
            parallelism=1,
            per_target_timeout_s=0.08,
        )
        self.assertEqual(len(rep.targets), 2)
        for probe in rep.targets:
            self.assertEqual(
                probe.error, "",
                f"{probe.label}: {probe.error!r}",
            )
            self.assertTrue(probe.exists)


# ---------------------------------------------------------------------------
# search_federation
# ---------------------------------------------------------------------------


class SearchFederationTests(unittest.TestCase):
    def test_generic_walker_name_glob(self) -> None:
        b = _ramfs()
        b.mkdir("/etc")
        for name in ("nginx.conf", "apache.conf", "hosts"):
            fh = b.open_write(f"/etc/{name}")
            fh.write(b"data")
            fh.close()
        q = search_federation.SearchQuery(name="*.conf", roots=["/etc"])
        rep = search_federation.federated_search([b], q)
        names = {h.path.split("/")[-1] for h in rep.hits}
        self.assertEqual(names, {"nginx.conf", "apache.conf"})

    def test_generic_walker_size_filter(self) -> None:
        b = _ramfs()
        for size, name in ((10, "small"), (200, "big")):
            fh = b.open_write(f"/{name}")
            fh.write(b"x" * size)
            fh.close()
        q = search_federation.SearchQuery(min_size=100, roots=["/"])
        rep = search_federation.federated_search([b], q)
        names = {h.path.lstrip("/") for h in rep.hits}
        self.assertEqual(names, {"big"})

    def test_generic_walker_contains_substring(self) -> None:
        b = _ramfs()
        b.mkdir("/logs")
        fh = b.open_write("/logs/access.log")
        fh.write(b"GET /index.html\n200 OK\n")
        fh.close()
        fh = b.open_write("/logs/error.log")
        fh.write(b"500 internal server error\n")
        fh.close()
        q = search_federation.SearchQuery(
            name="*.log",
            contains="500",
            roots=["/logs"],
        )
        rep = search_federation.federated_search([b], q)
        names = [h.path for h in rep.hits]
        self.assertEqual(names, ["/logs/error.log"])
        self.assertIn("500", rep.hits[0].snippet)

    def test_register_adapter_takes_priority(self) -> None:
        # Custom protocol → a registered adapter should run instead of
        # the generic walker.
        called = {"adapter": False}

        def my_adapter(backend, query, max_hits):
            called["adapter"] = True
            return [
                search_federation.SearchHit(
                    backend_label="x",
                    path="/from-adapter",
                    size=1,
                )
            ]

        backend = _StaticBackend("test", {"/": []})
        backend.search_protocol = "exotic"
        search_federation.register_adapter("exotic", my_adapter)
        try:
            rep = search_federation.federated_search(
                [backend],
                search_federation.SearchQuery(),
            )
            self.assertTrue(called["adapter"])
            self.assertEqual(len(rep.hits), 1)
        finally:
            search_federation._ADAPTERS.pop("exotic", None)

    def test_backend_timeout_returns_error_instead_of_hanging(self) -> None:
        backend = _StaticBackend("slow-search", {"/": []})
        backend.search_protocol = "slowproto"

        def slow_adapter(_backend, _query, _max_hits):
            time.sleep(0.2)
            return []

        search_federation.register_adapter("slowproto", slow_adapter)
        try:
            started = time.monotonic()
            rep = search_federation.federated_search(
                [backend],
                search_federation.SearchQuery(),
                per_backend_timeout_s=0.02,
            )
            self.assertLess(time.monotonic() - started, 0.15)
            self.assertIn("TimeoutError", rep.errors["slow-search"])
        finally:
            search_federation._ADAPTERS.pop("slowproto", None)

    def test_timeout_budget_is_per_backend_not_global_queue_time(self) -> None:
        backends = [
            _StaticBackend("seq-a", {"/": []}),
            _StaticBackend("seq-b", {"/": []}),
        ]
        for backend in backends:
            backend.search_protocol = "sequential-slow"

        def slow_but_within_budget(backend, _query, _max_hits):
            time.sleep(0.05)
            return [
                search_federation.SearchHit(
                    backend_label=backend.name,
                    path="/ok",
                )
            ]

        search_federation.register_adapter("sequential-slow", slow_but_within_budget)
        try:
            rep = search_federation.federated_search(
                backends,
                search_federation.SearchQuery(),
                parallelism=1,
                per_backend_timeout_s=0.08,
            )
            self.assertEqual({h.backend_label for h in rep.hits}, {"seq-a", "seq-b"})
            self.assertEqual(rep.errors, {})
        finally:
            search_federation._ADAPTERS.pop("sequential-slow", None)

    def test_duplicate_backend_submissions_have_independent_timeouts(self) -> None:
        # When the same backend object is queued twice with
        # parallelism below the duplicate count, the queued duplicate
        # must NOT inherit the first duplicate's start time. Each
        # submission gets its own timeout budget.
        class _Counter(_StaticBackend):
            def __init__(self, name: str) -> None:
                super().__init__(name, {"/": []})
                self.calls = 0

        backend = _Counter("dup-target")
        backend.search_protocol = "dup-proto"

        def slow_then_fast(b, _query, _max_hits):
            b.calls += 1
            if b.calls == 1:
                time.sleep(0.2)
            else:
                time.sleep(0.01)
            return [
                search_federation.SearchHit(
                    backend_label=b.name,
                    path=f"/r{b.calls}",
                )
            ]

        search_federation.register_adapter("dup-proto", slow_then_fast)
        try:
            rep = search_federation.federated_search(
                [backend, backend],
                search_federation.SearchQuery(),
                parallelism=1,
                per_backend_timeout_s=0.05,
            )
            # First duplicate times out; second duplicate must still run
            # and produce a hit within its own 0.05s budget.
            self.assertEqual(backend.calls, 2)
            self.assertEqual(len(rep.hits), 1)
            self.assertEqual(rep.hits[0].path, "/r2")
            self.assertIn("TimeoutError", rep.errors.get("dup-target", ""))
        finally:
            search_federation._ADAPTERS.pop("dup-proto", None)

    def test_invalid_name_regex_returns_query_error_without_workers(self) -> None:
        class NoReadBackend(_StaticBackend):
            def list_dir(self, path: str) -> list[FileItem]:
                raise AssertionError("worker should not be started")

        backend = NoReadBackend("no-worker", {"/": []})
        q = search_federation.SearchQuery(regex="[")
        rep = search_federation.federated_search([backend], q)
        self.assertEqual(rep.hits, [])
        self.assertIn("query", rep.errors)
        self.assertIn("invalid", rep.errors["query"])

    def test_dangerous_contains_regex_is_rejected_before_content_read(self) -> None:
        class NoReadBackend(_StaticBackend):
            def open_read(self, path: str, mode: str = "rb"):
                raise AssertionError("unsafe regex should fail before read")

        backend = NoReadBackend(
            "no-read",
            {
                "/": [_make_file_item("payload.txt", size=20)],
            },
        )
        q = search_federation.SearchQuery(
            contains="(a+)+$",
            contains_is_regex=True,
            roots=["/"],
        )
        rep = search_federation.federated_search([backend], q)
        self.assertEqual(rep.hits, [])
        self.assertIn("query", rep.errors)
        self.assertIn("unsafe", rep.errors["query"])

    def test_query_bounds_reject_impossible_ranges(self) -> None:
        b = _ramfs()
        q = search_federation.SearchQuery(min_size=100, max_size=1)
        rep = search_federation.federated_search([b], q)
        self.assertIn("query", rep.errors)
        self.assertIn("min_size", rep.errors["query"])


# ---------------------------------------------------------------------------
# adaptive_io
# ---------------------------------------------------------------------------


class AdaptiveChunkerTests(unittest.TestCase):
    def test_initial_size_picked_after_warmup(self) -> None:
        c = adaptive_io.AdaptiveChunker()
        # Synthesise 4 fast samples; the chunker should propose a
        # different chunk size on the 4th record() call.
        hints = []
        for _ in range(4):
            h = c.record(adaptive_io.PROBE_CHUNK, 0.001)  # ~32 MB/s
            hints.append(h)
        # Some non-empty hint must have appeared.
        self.assertTrue(any(hints), msg=f"no hint emitted; got {hints}")

    def test_grow_on_rising_throughput(self) -> None:
        c = adaptive_io.AdaptiveChunker()
        # Warm up.
        for _ in range(4):
            c.record(adaptive_io.PROBE_CHUNK, 0.01)
        size_after_warmup = c.current
        # Pump 32 high-throughput samples → trigger the reassess.
        for _ in range(adaptive_io.REASSESS_INTERVAL):
            c.record(c.current, 0.001)
        self.assertGreaterEqual(c.current, size_after_warmup)

    def test_chunk_clamped_to_bounds(self) -> None:
        # Direct exercise of the clamp logic.
        self.assertEqual(adaptive_io._clamp_chunk(1), adaptive_io.MIN_CHUNK)
        self.assertEqual(
            adaptive_io._clamp_chunk(adaptive_io.MAX_CHUNK * 100),
            adaptive_io.MAX_CHUNK,
        )

    def test_adaptive_copy_moves_all_bytes(self) -> None:
        src = io.BytesIO(b"x" * (5 * 1024 * 1024))
        dst = io.BytesIO()
        moved = adaptive_io.adaptive_copy(src, dst, total_bytes=src.getbuffer().nbytes)
        self.assertEqual(moved, 5 * 1024 * 1024)
        self.assertEqual(len(dst.getvalue()), 5 * 1024 * 1024)

    def test_adaptive_copy_detects_short_write(self) -> None:
        class ShortWriter:
            def write(self, data):
                return max(0, len(data) - 1)

        with self.assertRaises(OSError):
            adaptive_io.adaptive_copy(io.BytesIO(b"abc"), ShortWriter())


# ---------------------------------------------------------------------------
# copy_resume
# ---------------------------------------------------------------------------


class CopyResumeTests(unittest.TestCase):
    def setUp(self) -> None:
        self.src = _ramfs()
        self.dst = _ramfs()
        # 9 MiB source so we get multiple segments at the default 4 MiB.
        self.payload = bytes(range(256)) * (36 * 1024)  # 9 MiB
        fh = self.src.open_write("/big.bin")
        fh.write(self.payload)
        fh.close()
        self.tmp = tempfile.TemporaryDirectory()
        self.manifest = Path(self.tmp.name) / "resume.json"

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_full_copy_completes(self) -> None:
        rep = copy_resume.resumable_copy(
            self.src,
            "/big.bin",
            self.dst,
            "/big.bin",
            manifest_path=self.manifest,
        )
        self.assertTrue(rep.completed)
        self.assertEqual(rep.bytes_transferred, len(self.payload))
        # Destination matches the payload byte-for-byte.
        fh = self.dst.open_read("/big.bin")
        try:
            self.assertEqual(fh.read(), self.payload)
        finally:
            fh.close()
        # Manifest is removed on successful completion.
        self.assertFalse(self.manifest.exists())

    def test_overwrite_refused_without_flag(self) -> None:
        # Pre-existing destination — refuse without overwrite=True.
        fh = self.dst.open_write("/big.bin")
        fh.write(b"existing")
        fh.close()
        with self.assertRaises(FileExistsError):
            copy_resume.resumable_copy(
                self.src,
                "/big.bin",
                self.dst,
                "/big.bin",
                manifest_path=self.manifest,
            )

    def test_partial_segment_destination_restarts_without_corruption(self) -> None:
        seg_size = copy_resume.MIN_SEGMENT_SIZE
        first = self.payload[:seg_size]
        fh = self.dst.open_write("/big.bin")
        fh.write(first + b"partial-next-segment")
        fh.close()
        manifest = {
            "src_label": self.src.name,
            "src_path": "/big.bin",
            "dst_label": self.dst.name,
            "dst_path": "/big.bin",
            "total_bytes": len(self.payload),
            "segment_size": seg_size,
            "started_at": time.time(),
            "updated_at": time.time(),
            "segments": [],
        }
        for i, off in enumerate(range(0, len(self.payload), seg_size)):
            length = min(seg_size, len(self.payload) - off)
            done = i == 0
            manifest["segments"].append(
                {
                    "index": i,
                    "offset": off,
                    "length": length,
                    "sha256": hashlib.sha256(first).hexdigest() if done else "",
                    "done": done,
                }
            )
        self.manifest.write_text(json.dumps(manifest), encoding="utf-8")

        rep = copy_resume.resumable_copy(
            self.src,
            "/big.bin",
            self.dst,
            "/big.bin",
            segment_size=seg_size,
            manifest_path=self.manifest,
        )
        self.assertTrue(rep.completed)
        with self.dst.open_read("/big.bin") as fh:
            self.assertEqual(fh.read(), self.payload)

    def test_corrupt_manifested_prefix_is_reverified_before_append(self) -> None:
        seg_size = copy_resume.MIN_SEGMENT_SIZE
        first = self.payload[:seg_size]
        fh = self.dst.open_write("/big.bin")
        fh.write(b"X" * seg_size)
        fh.close()
        manifest = {
            "src_label": self.src.name,
            "src_path": "/big.bin",
            "dst_label": self.dst.name,
            "dst_path": "/big.bin",
            "total_bytes": len(self.payload),
            "segment_size": seg_size,
            "started_at": time.time(),
            "updated_at": time.time(),
            "segments": [],
        }
        for i, off in enumerate(range(0, len(self.payload), seg_size)):
            length = min(seg_size, len(self.payload) - off)
            manifest["segments"].append(
                {
                    "index": i,
                    "offset": off,
                    "length": length,
                    "sha256": hashlib.sha256(first).hexdigest() if i == 0 else "",
                    "done": i == 0,
                }
            )
        self.manifest.write_text(json.dumps(manifest), encoding="utf-8")

        rep = copy_resume.resumable_copy(
            self.src,
            "/big.bin",
            self.dst,
            "/big.bin",
            segment_size=seg_size,
            manifest_path=self.manifest,
        )
        self.assertTrue(rep.completed)
        with self.dst.open_read("/big.bin") as fh:
            self.assertEqual(fh.read(), self.payload)

    def test_resume_restarts_when_source_bytes_change_same_size(self) -> None:
        seg_size = copy_resume.MIN_SEGMENT_SIZE
        old_payload = b"A" * seg_size + b"B" * seg_size
        new_payload = b"C" * seg_size + b"D" * seg_size

        with self.src.open_write("/big.bin") as fh:
            fh.write(old_payload)
        with self.dst.open_write("/big.bin") as fh:
            fh.write(old_payload[:seg_size])

        manifest = {
            "src_label": self.src.name,
            "src_path": "/big.bin",
            "dst_label": self.dst.name,
            "dst_path": "/big.bin",
            "total_bytes": len(old_payload),
            "segment_size": seg_size,
            "started_at": time.time(),
            "updated_at": time.time(),
            "segments": [
                {
                    "index": 0,
                    "offset": 0,
                    "length": seg_size,
                    "sha256": hashlib.sha256(old_payload[:seg_size]).hexdigest(),
                    "done": True,
                },
                {
                    "index": 1,
                    "offset": seg_size,
                    "length": seg_size,
                    "sha256": "",
                    "done": False,
                },
            ],
        }
        self.manifest.write_text(json.dumps(manifest), encoding="utf-8")

        with self.src.open_write("/big.bin") as fh:
            fh.write(new_payload)

        rep = copy_resume.resumable_copy(
            self.src,
            "/big.bin",
            self.dst,
            "/big.bin",
            segment_size=seg_size,
            manifest_path=self.manifest,
        )
        self.assertTrue(rep.completed)
        with self.dst.open_read("/big.bin") as fh:
            self.assertEqual(fh.read(), new_payload)


# ---------------------------------------------------------------------------
# trail
# ---------------------------------------------------------------------------


class TrailTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self._orig = trail.DB_FILE
        trail.DB_FILE = Path(self.tmp.name) / "trail.db"

    def tearDown(self) -> None:
        trail.DB_FILE = self._orig
        self.tmp.cleanup()

    def test_snapshot_creates_record(self) -> None:
        b = _ramfs()
        b.mkdir("/etc")
        fh = b.open_write("/etc/config")
        fh.write(b"hello")
        fh.close()
        snap = trail.snapshot_now(b, "/etc")
        self.assertEqual(snap.file_count, 1)
        self.assertGreater(snap.total_bytes, 0)
        self.assertTrue(snap.tree_hash)

    def test_walk_collect_caps_directory_only_trees(self) -> None:
        class EndlessDirs:
            name = "endless-dirs"

            def __init__(self) -> None:
                self.calls = 0

            def list_dir(self, _path: str) -> list[FileItem]:
                self.calls += 1
                if self.calls > 25:
                    raise AssertionError("directory walk is not bounded")
                return [_make_file_item(f"d{self.calls}", is_dir=True)]

            def join(self, *parts: str) -> str:
                cleaned = [part.strip("/") for part in parts if part]
                return "/" + "/".join(cleaned)

        backend = EndlessDirs()
        rows, truncated = trail._walk_collect(
            backend,
            "/",
            max_files=3,
            head_hash=False,
        )
        self.assertEqual(rows, [])
        self.assertTrue(truncated)
        self.assertLessEqual(backend.calls, 25)

    def test_diff_detects_added_file(self) -> None:
        b = _ramfs()
        b.mkdir("/etc")
        fh = b.open_write("/etc/a")
        fh.write(b"x")
        fh.close()
        snap1 = trail.snapshot_now(b, "/etc")
        fh = b.open_write("/etc/b")
        fh.write(b"y")
        fh.close()
        snap2 = trail.snapshot_now(b, "/etc")
        diff = trail.diff_snapshots(snap1.snapshot_id, snap2.snapshot_id)
        self.assertEqual(diff.added, ["/etc/b"])
        self.assertEqual(diff.removed, [])
        self.assertEqual(diff.unchanged, 1)

    def test_diff_detects_modified_file(self) -> None:
        b = _ramfs()
        b.mkdir("/etc")
        fh = b.open_write("/etc/a")
        fh.write(b"x")
        fh.close()
        snap1 = trail.snapshot_now(b, "/etc")
        time.sleep(1.1)  # advance mtime granularity
        fh = b.open_write("/etc/a")
        fh.write(b"yy")
        fh.close()
        snap2 = trail.snapshot_now(b, "/etc")
        diff = trail.diff_snapshots(snap1.snapshot_id, snap2.snapshot_id)
        self.assertEqual(diff.modified, ["/etc/a"])

    def test_list_trails_after_snapshot(self) -> None:
        b = _ramfs()
        trail.snapshot_now(b, "/", name="my-trail")
        trails = trail.list_trails()
        names = [t["name"] for t in trails]
        self.assertIn("my-trail", names)

    def test_export_jsonl(self) -> None:
        b = _ramfs()
        trail.snapshot_now(b, "/", name="my-trail")
        out = Path(self.tmp.name) / "trail.jsonl"
        n = trail.export_trail_jsonl("my-trail", out)
        self.assertEqual(n, 1)
        self.assertTrue(out.exists())
        # 0o600 file mode.
        self.assertEqual(out.stat().st_mode & 0o777, 0o600)

    def test_export_jsonl_refuses_symlink_destination(self) -> None:
        if not hasattr(os, "symlink"):
            self.skipTest("symlink not supported on this platform")
        b = _ramfs()
        trail.snapshot_now(b, "/", name="my-trail")
        target = Path(self.tmp.name) / "target.jsonl"
        target.write_text("keep\n", encoding="utf-8")
        link = Path(self.tmp.name) / "linked.jsonl"
        try:
            os.symlink(target, link)
        except OSError as exc:
            self.skipTest(f"symlink unavailable: {exc}")
        with self.assertRaises(OSError):
            trail.export_trail_jsonl("my-trail", link)
        self.assertEqual(target.read_text(encoding="utf-8"), "keep\n")


# ---------------------------------------------------------------------------
# dashboard
# ---------------------------------------------------------------------------


class DashboardTests(unittest.TestCase):
    def setUp(self) -> None:
        # Reset the conn_health singleton for isolation.
        conn_health._GLOBAL = None

    def test_empty_snapshot_renders(self) -> None:
        snap = dashboard.snapshot()
        text = dashboard.render_text(snap)
        self.assertIn("federation status", text)
        self.assertIn("0 connection", text)

    def test_snapshot_picks_up_health_records(self) -> None:
        mgr = conn_health.get_manager()
        try:
            mgr.enroll("k1", FakeSession(), protocol="pop3", label="alice@h:995")
            mgr.probe_now("k1")
            snap = dashboard.snapshot()
            self.assertEqual(len(snap.rows), 1)
            self.assertEqual(snap.rows[0].label, "alice@h:995")
            self.assertTrue(snap.rows[0].healthy)
        finally:
            mgr.stop()
            conn_health._GLOBAL = None

    def test_render_markdown_table_when_rows_present(self) -> None:
        mgr = conn_health.get_manager()
        try:
            mgr.enroll("k", FakeSession(), protocol="pop3", label="alice@h:995")
            mgr.probe_now("k")
            snap = dashboard.snapshot()
            md = dashboard.render_markdown(snap)
            self.assertIn("federation status", md)
            # With at least one row a markdown table appears.
            self.assertIn("|", md)
            self.assertIn("alice@h:995", md)
        finally:
            mgr.stop()
            conn_health._GLOBAL = None

    def test_render_json_parses(self) -> None:
        import json as _json

        snap = dashboard.snapshot()
        data = _json.loads(dashboard.render_json(snap))
        self.assertIn("captured_at", data)
        self.assertIn("rows", data)

    def test_snapshot_with_backends_capacity_timeout(self) -> None:
        class SlowCapacity:
            name = "slow-cap"

            def home(self) -> str:
                return "/"

            def disk_usage(self, root: str):
                time.sleep(0.2)
                return (100, 50, 50)

        old = dashboard.CAPACITY_TIMEOUT_S
        dashboard.CAPACITY_TIMEOUT_S = 0.02
        try:
            started = time.monotonic()
            snap = dashboard.snapshot_with_backends([SlowCapacity()])
            self.assertLess(time.monotonic() - started, 0.15)
            row = next(r for r in snap.rows if r.label == "slow-cap")
            self.assertEqual(row.capacity_total, 0)
        finally:
            dashboard.CAPACITY_TIMEOUT_S = old

    def test_disk_usage_capacity_probe_saturation_fails_closed(self) -> None:
        release = threading.Event()

        class StuckCapacity:
            name = "stuck-cap"

            def disk_usage(self, root: str):
                release.wait(timeout=1.0)
                return (100, 50, 50)

        old = dashboard._CAPACITY_SEMAPHORE
        dashboard._CAPACITY_SEMAPHORE = threading.BoundedSemaphore(1)
        try:
            with self.assertRaisesRegex(TimeoutError, "exceeded"):
                dashboard._disk_usage_with_timeout(
                    StuckCapacity(),
                    "/",
                    timeout_s=0.01,
                )
            with self.assertRaisesRegex(TimeoutError, "saturated"):
                dashboard._disk_usage_with_timeout(
                    StuckCapacity(),
                    "/",
                    timeout_s=0.01,
                )
        finally:
            release.set()
            time.sleep(0.05)
            dashboard._CAPACITY_SEMAPHORE = old


# ---------------------------------------------------------------------------
# reverse_serve — full HTTP round-trips against a localhost server
# ---------------------------------------------------------------------------


class ReverseS3Tests(unittest.TestCase):
    def setUp(self) -> None:
        self.b = _ramfs()
        self.b.mkdir("/mybucket")
        fh = self.b.open_write("/mybucket/hello.txt")
        fh.write(b"hello s3 from axross")
        fh.close()
        self.srv = reverse_serve.serve_s3(
            self.b,
            bind="127.0.0.1",
            port=0,
            root_path="/",
        )

    def tearDown(self) -> None:
        self.srv.shutdown()

    def _url(self, path: str) -> str:
        return f"{self.srv.base_url}{path}"

    def test_get_object(self) -> None:
        with urllib.request.urlopen(self._url("/mybucket/hello.txt")) as r:
            self.assertEqual(r.status, 200)
            self.assertEqual(r.read(), b"hello s3 from axross")

    def test_list_buckets(self) -> None:
        with urllib.request.urlopen(self._url("/")) as r:
            body = r.read().decode()
        self.assertIn("<Name>mybucket</Name>", body)

    def test_list_objects(self) -> None:
        with urllib.request.urlopen(self._url("/mybucket")) as r:
            body = r.read().decode()
        self.assertIn("<Key>hello.txt</Key>", body)
        self.assertIn("<IsTruncated>false</IsTruncated>", body)

    def test_list_objects_reports_truncated_when_walk_cap_stops_before_max_keys(self) -> None:
        class ManyDirsBackend:
            def join(self, *parts: str) -> str:
                cleaned = [p.strip("/") for p in parts if p.strip("/")]
                return "/" + "/".join(cleaned)

            def list_dir(self, path: str) -> list[FileItem]:
                if path == "/":
                    return [_make_file_item("mybucket", is_dir=True)]
                if path == "/mybucket":
                    return [
                        _make_file_item(f"d{i}", is_dir=True)
                        for i in range(reverse_serve.MIN_WALK_DIR_VISITS + 2)
                    ]
                if path.startswith("/mybucket/d"):
                    return []
                raise OSError(path)

            def stat(self, path: str) -> FileItem:
                return _make_file_item(path.rsplit("/", 1)[-1] or "/", is_dir=True)

        srv = reverse_serve.serve_s3(
            ManyDirsBackend(),
            bind="127.0.0.1",
            port=0,
            root_path="/",
        )
        try:
            with urllib.request.urlopen(f"{srv.base_url}/mybucket?max-keys=1") as r:
                body = r.read().decode()
        finally:
            srv.shutdown()

        self.assertIn("<IsTruncated>true</IsTruncated>", body)
        self.assertNotIn("<Contents>", body)

    def test_put_then_get(self) -> None:
        req = urllib.request.Request(
            self._url("/mybucket/upload.txt"),
            data=b"new content",
            method="PUT",
            headers={"Content-Length": "11"},
        )
        with urllib.request.urlopen(req) as r:
            self.assertEqual(r.status, 200)
        with urllib.request.urlopen(self._url("/mybucket/upload.txt")) as r:
            self.assertEqual(r.read(), b"new content")

    def test_delete(self) -> None:
        # Ensure the file exists, then DELETE it.
        req = urllib.request.Request(
            self._url("/mybucket/hello.txt"),
            method="DELETE",
        )
        with urllib.request.urlopen(req) as r:
            self.assertEqual(r.status, 204)
        # GET now returns 404.
        with self.assertRaises(urllib.error.HTTPError) as ctx:
            urllib.request.urlopen(self._url("/mybucket/hello.txt"))
        self.assertEqual(ctx.exception.code, 404)

    def test_path_traversal_rejected(self) -> None:
        with self.assertRaises(urllib.error.HTTPError) as ctx:
            urllib.request.urlopen(self._url("/mybucket/../other"))
        self.assertEqual(ctx.exception.code, 400)

    def test_invalid_max_keys_returns_400(self) -> None:
        with self.assertRaises(urllib.error.HTTPError) as ctx:
            urllib.request.urlopen(self._url("/mybucket?max-keys=wat"))
        self.assertEqual(ctx.exception.code, 400)

    def test_short_put_body_is_not_reported_as_success(self) -> None:
        host = "127.0.0.1"
        with socket.create_connection((host, self.srv.port), timeout=2.0) as s:
            s.sendall(
                b"PUT /mybucket/short.txt HTTP/1.1\r\n"
                b"Host: 127.0.0.1\r\n"
                b"Content-Length: 10\r\n"
                b"Connection: close\r\n"
                b"\r\n"
                b"abc"
            )
            s.shutdown(socket.SHUT_WR)
            data = s.recv(4096)
        self.assertIn(b" 400 ", data.split(b"\r\n", 1)[0])

    def test_public_bind_without_auth_is_refused(self) -> None:
        b = _ramfs()
        with self.assertRaises(PermissionError):
            reverse_serve.serve_s3(b, bind="0.0.0.0", port=0)

    def test_root_path_traversal_is_refused(self) -> None:
        b = _ramfs()
        with self.assertRaises(PermissionError):
            reverse_serve.serve_s3(
                b,
                bind="127.0.0.1",
                port=0,
                root_path="/safe/../oops",
            )


class ReverseS3WalkKeysBoundsTests(unittest.TestCase):
    """Regression tests for ``_walk_keys``: it did not bound how
    many directories it visits during a single ``ListBucket`` call. A
    hostile remote backend (threat T1) that reports an endlessly
    recursive directory tree — e.g. a symlink loop on an SMB share or
    a malicious SFTP server — drives the reverse-S3 ListBucket loop to
    descend without limit, growing the ``visited`` set and per-entry
    path strings until the process runs out of memory."""

    def test_walk_keys_recurses_applies_prefix_and_max_keys(self) -> None:
        from core.reverse_serve import _walk_keys

        backend = _StaticBackend(
            "s3-walk",
            {
                "/root": [
                    _make_file_item("docs", is_dir=True),
                    _make_file_item("root.txt", size=10),
                ],
                "/root/docs": [
                    _make_file_item("alpha.txt", size=20, mtime=1_700_000_000),
                    _make_file_item("beta.txt", size=30, mtime=1_700_000_100),
                    _make_file_item("deep", is_dir=True),
                ],
                "/root/docs/deep": [
                    _make_file_item("gamma.txt", size=40),
                ],
            },
        )

        got, truncated = _walk_keys(backend, "/root", "docs/", 2)

        self.assertEqual(
            [
                ("docs/alpha.txt", {"size": 20, "mtime": 1_700_000_000.0}),
                ("docs/beta.txt", {"size": 30, "mtime": 1_700_000_100.0}),
            ],
            got,
        )
        self.assertTrue(truncated)

    def test_walk_keys_zero_max_keys_does_not_probe_backend(self) -> None:
        from core.reverse_serve import _walk_keys

        class CountingBackend:
            def __init__(self) -> None:
                self.calls = 0

            def list_dir(self, _path: str) -> list:
                self.calls += 1
                return [_make_file_item("unexpected.txt", size=1)]

            def join(self, *parts: str) -> str:
                cleaned = [p.strip("/") for p in parts if p]
                return "/" + "/".join(cleaned)

        backend = CountingBackend()

        self.assertEqual(([], False), _walk_keys(backend, "/root", "", 0))
        self.assertEqual(0, backend.calls)

    def test_walk_keys_bounds_directory_visits_on_loop_backend(self) -> None:
        from core.reverse_serve import _walk_keys

        # Safety cap inside the test backend so the test cannot hang
        # the suite. The bug is "no bound at all" — if the walk stops
        # only because the *test* gives up at SAFETY_CAP, the production
        # code is still unbounded and DoS-able.
        SAFETY_CAP = 1000

        class LoopBackend:
            """Every directory reports a single subdirectory ``sub`` and
            no files. Mimics a symlink loop / recursive SMB share."""

            def __init__(self) -> None:
                self.calls = 0

            def list_dir(self, _path: str) -> list:
                self.calls += 1
                if self.calls > SAFETY_CAP:
                    return []
                return [
                    _make_file_item("sub", is_dir=True),
                ]

            def join(self, *parts: str) -> str:
                cleaned = [p.strip("/") for p in parts if p]
                return "/" + "/".join(cleaned)

        backend = LoopBackend()
        entries, truncated = _walk_keys(backend, "/root", "", 100)
        # A correctly-bounded walk should visit at most O(max_keys)
        # directories (here max_keys=100). Without a depth or visit
        # cap, the current code descends until the test backend gives
        # up at SAFETY_CAP.
        self.assertEqual([], entries)
        self.assertTrue(truncated)
        self.assertLess(
            backend.calls,
            200,
            f"_walk_keys called list_dir {backend.calls} times for "
            "max_keys=100 on a loop backend; production code lacks a "
            "depth or visit cap, making reverse-S3 ListBucket DoS-able "
            "by a hostile remote backend.",
        )


class ReverseS3ListingCapsTests(unittest.TestCase):
    """Defense-in-depth: the security/reverse_s3_limits helper
    enforces a second, independent body-byte cap on the listing
    returned by _walk_keys before it is serialised into XML."""

    def test_under_cap_returns_all_entries_unchanged(self) -> None:
        from security.reverse_s3_limits import enforce_listing_caps

        entries = [(f"k{i}", {"size": 1, "mtime": 0.0}) for i in range(50)]
        capped, truncated = enforce_listing_caps(entries)
        self.assertEqual(len(capped), 50)
        self.assertFalse(truncated)
        self.assertEqual(capped[0][0], "k0")

    def test_empty_input_returns_empty_no_truncation(self) -> None:
        from security.reverse_s3_limits import enforce_listing_caps

        capped, truncated = enforce_listing_caps([])
        self.assertEqual(capped, [])
        self.assertFalse(truncated)

    def test_oversize_rel_path_is_skipped_and_marked_truncated(self) -> None:
        from security.reverse_s3_limits import (
            MAX_ENTRY_PATH_BYTES,
            enforce_listing_caps,
        )

        good = ("ok.txt", {"size": 1, "mtime": 0.0})
        bad = ("x" * (MAX_ENTRY_PATH_BYTES + 1), {"size": 1, "mtime": 0.0})
        capped, truncated = enforce_listing_caps([good, bad, good])
        # Both good entries survive; the pathological one is dropped.
        self.assertEqual([rel for rel, _ in capped], ["ok.txt", "ok.txt"])
        self.assertTrue(truncated)

    def test_running_body_cap_truncates_list(self) -> None:
        from security.reverse_s3_limits import enforce_listing_caps

        # 1 KiB-ish rel paths with a tight body cap → only a few fit.
        big = ("a" * 1024, {"size": 1, "mtime": 0.0})
        entries = [big] * 100
        capped, truncated = enforce_listing_caps(
            entries, max_body_bytes=4096
        )
        self.assertTrue(truncated)
        self.assertLess(len(capped), 100)
        # At least one entry should still fit so the response is useful.
        self.assertGreaterEqual(len(capped), 1)

    def test_negative_cap_raises_value_error(self) -> None:
        from security.reverse_s3_limits import enforce_listing_caps

        with self.assertRaises(ValueError):
            enforce_listing_caps([], max_body_bytes=-1)
        with self.assertRaises(ValueError):
            enforce_listing_caps([], max_entry_path_bytes=-1)

    def test_unicode_rel_paths_counted_by_utf8_bytes(self) -> None:
        from security.reverse_s3_limits import enforce_listing_caps

        # A 3-byte (UTF-8) emoji per char; verify byte-counting (not
        # codepoint-counting) is what the cap measures.
        rel = "⚡" * 100  # 300 UTF-8 bytes
        capped, truncated = enforce_listing_caps(
            [(rel, {"size": 1, "mtime": 0.0})],
            max_entry_path_bytes=200,
        )
        self.assertEqual(capped, [])
        self.assertTrue(truncated)


class ReverseS3AuthTests(unittest.TestCase):
    def setUp(self) -> None:
        self.b = _ramfs()
        self.b.mkdir("/mybucket")
        fh = self.b.open_write("/mybucket/hello.txt")
        fh.write(b"secret")
        fh.close()
        self.srv = reverse_serve.serve_s3(
            self.b,
            bind="127.0.0.1",
            port=0,
            auth_token="s3kret-token",
        )

    def tearDown(self) -> None:
        self.srv.shutdown()

    def test_unauthed_get_rejected(self) -> None:
        with self.assertRaises(urllib.error.HTTPError) as ctx:
            urllib.request.urlopen(f"{self.srv.base_url}/mybucket/hello.txt")
        self.assertEqual(ctx.exception.code, 403)

    def test_authed_get_succeeds(self) -> None:
        req = urllib.request.Request(
            f"{self.srv.base_url}/mybucket/hello.txt",
            headers={"Authorization": "Bearer s3kret-token"},
        )
        with urllib.request.urlopen(req) as r:
            self.assertEqual(r.read(), b"secret")


class ReverseS3ReadOnlyTests(unittest.TestCase):
    def setUp(self) -> None:
        self.b = _ramfs()
        self.b.mkdir("/mybucket")
        self.srv = reverse_serve.serve_s3(
            self.b,
            bind="127.0.0.1",
            port=0,
            read_only=True,
        )

    def tearDown(self) -> None:
        self.srv.shutdown()

    def test_put_rejected_when_read_only(self) -> None:
        req = urllib.request.Request(
            f"{self.srv.base_url}/mybucket/upload.txt",
            data=b"forbidden",
            method="PUT",
            headers={"Content-Length": "9"},
        )
        with self.assertRaises(urllib.error.HTTPError) as ctx:
            urllib.request.urlopen(req)
        self.assertEqual(ctx.exception.code, 403)


class ReverseWebDAVTests(unittest.TestCase):
    def setUp(self) -> None:
        self.b = _ramfs()
        self.b.mkdir("/dir")
        fh = self.b.open_write("/dir/file.txt")
        fh.write(b"webdav content")
        fh.close()
        self.srv = reverse_serve.serve_webdav(
            self.b,
            bind="127.0.0.1",
            port=0,
            root_path="/",
        )

    def tearDown(self) -> None:
        self.srv.shutdown()

    def _url(self, path: str) -> str:
        return f"{self.srv.base_url}{path}"

    def test_get_file(self) -> None:
        with urllib.request.urlopen(self._url("/dir/file.txt")) as r:
            self.assertEqual(r.read(), b"webdav content")

    def test_options_allows_dav(self) -> None:
        req = urllib.request.Request(self._url("/"), method="OPTIONS")
        with urllib.request.urlopen(req) as r:
            self.assertIn("DAV", dict(r.getheaders()))

    def test_propfind_returns_207(self) -> None:
        req = urllib.request.Request(
            self._url("/dir"),
            method="PROPFIND",
            headers={"Depth": "1"},
        )
        with urllib.request.urlopen(req) as r:
            self.assertEqual(r.status, 207)
            body = r.read().decode()
        self.assertIn("file.txt", body)
        self.assertIn("multistatus", body)

    def test_put_then_delete(self) -> None:
        req = urllib.request.Request(
            self._url("/dir/new.txt"),
            data=b"x",
            method="PUT",
            headers={"Content-Length": "1"},
        )
        with urllib.request.urlopen(req) as r:
            self.assertEqual(r.status, 201)
        with urllib.request.urlopen(self._url("/dir/new.txt")) as r:
            self.assertEqual(r.read(), b"x")
        req = urllib.request.Request(self._url("/dir/new.txt"), method="DELETE")
        with urllib.request.urlopen(req) as r:
            self.assertEqual(r.status, 204)

    def test_encoded_path_traversal_rejected_cleanly(self) -> None:
        with self.assertRaises(urllib.error.HTTPError) as ctx:
            urllib.request.urlopen(self._url("/dir/%2e%2e/file.txt"))
        self.assertEqual(ctx.exception.code, 400)


class ReverseWebDAVAuthTests(unittest.TestCase):
    def setUp(self) -> None:
        self.b = _ramfs()
        self.srv = reverse_serve.serve_webdav(
            self.b,
            bind="127.0.0.1",
            port=0,
            auth_token="dav-token",
        )

    def tearDown(self) -> None:
        self.srv.shutdown()

    def test_lock_requires_auth(self) -> None:
        req = urllib.request.Request(
            f"{self.srv.base_url}/",
            method="LOCK",
        )
        with self.assertRaises(urllib.error.HTTPError) as ctx:
            urllib.request.urlopen(req)
        self.assertEqual(ctx.exception.code, 401)


class ScriptingStoreHardeningTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_load_script_refuses_symlink_file(self) -> None:
        if not hasattr(os, "symlink"):
            self.skipTest("symlink not supported on this platform")
        with mock.patch.dict(os.environ, {"HOME": self.tmp.name}):
            scripts = Path(scripting.script_dir())
            target = scripts / "target.py"
            target.write_text("x = 1\n", encoding="utf-8")
            link = scripts / "linked.py"
            try:
                os.symlink(target, link)
            except OSError as exc:
                self.skipTest(f"symlink unavailable: {exc}")
            with self.assertRaises(OSError):
                scripting.load_script("linked")


if __name__ == "__main__":
    unittest.main()
