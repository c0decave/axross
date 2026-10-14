"""Backend availability is checked when it is first read, not at start-up.

Measured before the change: ``init_registry`` took 0.7-0.9 s of a ~1 s GUI
start, almost all of it importing optional SDKs only to learn whether they
are installed (exchangelib 136 ms, boto3 115 ms, dropbox 75 ms, redis 75 ms,
azure 61 ms ...). The check is still a real import — an installed but broken
package still counts as unavailable — it just runs on first use.
"""

from __future__ import annotations

import os
import subprocess
import sys
import tempfile
import textwrap
import threading
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from core import backend_registry as BR  # noqa: E402

HEAVY = ("boto3", "exchangelib", "dropbox", "redis", "azure.storage.blob")


def _run(code: str) -> str:
    env = dict(os.environ, PYTHONPATH=str(ROOT))
    out = subprocess.run(
        [sys.executable, "-c", textwrap.dedent(code)],
        capture_output=True,
        text=True,
        env=env,
        cwd=str(ROOT),
        timeout=120,
    )
    assert out.returncode == 0, out.stderr
    return out.stdout.strip()


class _TempModules(unittest.TestCase):
    def setUp(self) -> None:
        self.dir = tempfile.mkdtemp()
        sys.path.insert(0, self.dir)
        self.addCleanup(sys.path.remove, self.dir)
        self.saved = dict(BR._registry)
        self.addCleanup(self._restore)

    def _restore(self) -> None:
        BR._registry.clear()
        BR._registry.update(self.saved)

    def module(self, name: str, body: str) -> str:
        Path(self.dir, f"{name}.py").write_text(body)
        self.addCleanup(sys.modules.pop, name, None)
        return name

    def info(self, probe, pid: str = "zz-test") -> BR.BackendInfo:
        info = BR.BackendInfo(
            protocol_id=pid, display_name="ZZ", module="x", class_name="Y", available=probe
        )
        BR.register(info)
        return info


class StartupTest(unittest.TestCase):
    def test_init_registry_imports_no_optional_sdk(self) -> None:
        loaded = _run(
            f"""
            import sys
            from core.backend_registry import init_registry
            init_registry()
            print(",".join(m for m in {HEAVY!r} if m in sys.modules))
            """
        )
        self.assertEqual(loaded, "")

    def test_listing_capabilities_does_not_import_either(self) -> None:
        # atomic_io / elevated_io walk all_backends() for class names.
        loaded = _run(
            f"""
            import sys
            from core import backend_registry as BR
            BR.init_registry()
            [(b.class_name, b.capabilities) for b in BR.all_backends()]
            print(",".join(m for m in {HEAVY!r} if m in sys.modules))
            """
        )
        self.assertEqual(loaded, "")

    def test_same_availability_as_an_eager_import_check(self) -> None:
        # A/B: lazy answers equal what importing each probe right away gives.
        got = _run(
            """
            from core import backend_registry as BR
            BR.init_registry()
            print(sorted((b.protocol_id, b.available) for b in BR.all_backends()))
            """
        )
        eager = _run(
            """
            import builtins
            from core import backend_registry as BR
            BR._check_available = lambda name: _eager(name)
            def _eager(name):
                try:
                    __import__(name)
                    return True
                except ImportError:
                    return False
            BR.init_registry()
            print(sorted((b.protocol_id, b.available) for b in BR.all_backends()))
            """
        )
        self.assertEqual(got, eager)


class ProbeTest(_TempModules):
    def test_happy_an_installed_module_is_available_and_a_real_bool(self) -> None:
        name = self.module("zz_present_mod", "X = 1\n")
        info = self.info(BR._check_available(name))
        self.assertIs(info.available, True)
        self.assertIs(BR.get("zz-test").available, True)

    def test_sad_a_missing_module_is_unavailable(self) -> None:
        info = self.info(BR._check_available("zz_definitely_missing_mod"))
        self.assertIs(info.available, False)
        self.assertNotIn("zz-test", [b.protocol_id for b in BR.available_backends()])
        with self.assertRaises(ImportError):
            BR.load_backend_class("zz-test")

    def test_sad_an_installed_but_broken_package_is_still_unavailable(self) -> None:
        name = self.module("zz_broken_mod", "raise ImportError('native lib missing')\n")
        self.assertIs(self.info(BR._check_available(name)).available, False)

    def test_edge_the_import_runs_once(self) -> None:
        name = self.module(
            "zz_counted_mod",
            "import builtins\nbuiltins.zz_count = getattr(builtins, 'zz_count', 0) + 1\n",
        )
        import builtins

        self.addCleanup(lambda: hasattr(builtins, "zz_count") and delattr(builtins, "zz_count"))
        info = self.info(BR._check_available(name))
        for _ in range(3):
            self.assertTrue(info.available)
        self.assertEqual(builtins.zz_count, 1)

    def test_edge_plain_booleans_still_work(self) -> None:
        self.assertIs(self.info(False).available, False)
        self.assertIs(self.info(True, "zz-2").available, True)

    def test_edge_concurrent_first_reads_agree(self) -> None:
        name = self.module("zz_slow_mod", "import time\ntime.sleep(0.2)\n")
        info = self.info(BR._check_available(name))
        results = []
        threads = [
            threading.Thread(target=lambda: results.append(info.available)) for _ in range(5)
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual(results, [True] * 5)


if __name__ == "__main__":
    unittest.main()
