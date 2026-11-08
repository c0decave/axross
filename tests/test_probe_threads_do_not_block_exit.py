"""A probe that timed out no longer keeps the process from exiting.

Before: ``federated_search`` and core.multi_view's ``inspect_targets`` /
``compare_file`` ran their per-backend work on a ThreadPoolExecutor and,
on a timeout, called ``pool.shutdown(wait=False)``. Python's exit hook
joins every ThreadPoolExecutor worker anyway, so a script whose search
or comparison hit one dead host got its answer after the timeout - and
then its process hung at exit until the hung call ended (forever, on a
host that never answers).

Now the probes run on daemon threads (search_federation.DaemonPool);
the results, the error texts and the timeouts are as they were.
"""

from __future__ import annotations

import subprocess
import sys
import textwrap
import threading
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core import multi_view as MV  # noqa: E402
from core import search_federation as SF  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
HANG_S = 60


def _run(code: str) -> tuple[float, str]:
    started = time.monotonic()
    run = subprocess.run([sys.executable, "-c", textwrap.dedent(code)], cwd=ROOT,
                         capture_output=True, text=True, timeout=HANG_S + 60)
    took = time.monotonic() - started
    assert run.returncode == 0, run.stderr[-2000:]
    return took, run.stdout


def test_happy_a_script_with_a_hung_search_backend_exits_after_the_timeout():
    took, out = _run(f"""
        import time
        from core import search_federation as SF
        SF.register_adapter("hungproto", lambda b, q, n: time.sleep({HANG_S}) or [])
        SF._backend_protocol = lambda b: "hungproto"
        class Hung: name = "hung"
        r = SF.federated_search([Hung()], SF.SearchQuery(), per_backend_timeout_s=0.5)
        print(r.errors)
    """)
    assert "TimeoutError: exceeded 0.5s" in out
    assert took < HANG_S / 2, f"the process took {took:.1f} s to exit"


def test_sad_a_script_with_a_hung_target_exits_after_inspect_and_compare():
    took, out = _run(f"""
        import time
        from core import multi_view as MV
        class Hung:
            name = "hung"
            def stat(self, path): time.sleep({HANG_S})
        r = MV.inspect_targets([(Hung(), "/x")], per_target_timeout_s=0.5)
        print([p.error for p in r.targets])
        c = MV.compare_file([Hung()], "/x", per_target_timeout_s=0.5)
        print([p.error for p in c.probes])
    """)
    assert out.count("TimeoutError: exceeded 0.5s") == 2, out
    assert took < HANG_S / 2, f"the process took {took:.1f} s to exit"


def test_edge_results_errors_and_timeouts_are_kept_and_the_threads_are_daemons(monkeypatch):
    gate = threading.Event()
    seen: list[threading.Thread] = []

    def adapter(backend, query, n):
        seen.append(threading.current_thread())
        if backend.name == "hung":
            gate.wait(10)
            return []
        if backend.name == "broken":
            raise OSError("no route")
        return [SF.SearchHit(backend_label=backend.name, path="/a")]

    monkeypatch.setitem(SF._ADAPTERS, "testproto", adapter)
    monkeypatch.setattr(SF, "_backend_protocol", lambda b: "testproto")
    backends = [type("B", (), {"name": n})() for n in ("ok", "hung", "broken")]
    try:
        r = SF.federated_search(backends, SF.SearchQuery(), per_backend_timeout_s=0.5)
    finally:
        gate.set()
    assert [h.path for h in r.hits] == ["/a"] and r.per_backend == {"ok": 1}
    assert r.errors == {"hung": "TimeoutError: exceeded 0.5s", "broken": "OSError: no route"}
    assert seen and all(t.daemon for t in seen)
    # One worker, three probes: the queued ones get their own clock.
    gate.clear()
    slow = [type("B", (), {"name": f"slow{i}"})() for i in range(3)]

    def take_a_while(backend, query, n):
        time.sleep(0.3)
        return [SF.SearchHit(backend_label=backend.name, path="/s")]

    monkeypatch.setitem(SF._ADAPTERS, "testproto", take_a_while)
    r = SF.federated_search(slow, SF.SearchQuery(), parallelism=1, per_backend_timeout_s=0.6)
    assert r.errors == {} and len(r.hits) == 3


def test_edge_a_daemon_pool_cancels_what_has_not_started_and_never_waits():
    pool = SF.DaemonPool(1, name="t")
    gate = threading.Event()
    first = pool.submit(gate.wait, 5)
    queued = pool.submit(lambda: "never")
    while not first.running():
        time.sleep(0.005)
    started = time.monotonic()
    pool.shutdown()
    assert time.monotonic() - started < 0.5
    assert queued.cancelled()
    gate.set()
    assert first.result(timeout=5) is True


def test_edge_inspect_keeps_errors_and_order_on_daemon_threads():
    seen: list[threading.Thread] = []

    class Gone:
        name = "gone"

        def stat(self, path):
            seen.append(threading.current_thread())
            raise FileNotFoundError(path)

    report = MV.inspect_targets([(Gone(), "/x"), (Gone(), "/y")], per_target_timeout_s=2)
    assert [p.path for p in report.targets] == ["/x", "/y"]
    assert all(p.error.startswith("FileNotFoundError") for p in report.targets)
    assert seen and all(t.daemon for t in seen)
