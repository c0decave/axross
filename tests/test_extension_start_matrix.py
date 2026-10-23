"""Every bundled extension switched on: the real app still opens its window.

Reported: axross-full showed no window on a laptop with the NVIDIA driver -
the Media Player extension created its audio engine while the main window
was built, and Qt Multimedia hung in the driver's cuInit. The extension's
unit tests inject a fake engine and no smoke run switched an extension on,
so nothing ever started the real app with it. scripts/extension_matrix.py
does: each extension alone, all together, and all together under a stand-in
NVIDIA driver whose cuInit never returns (tests/hanging_gpu_driver.py).
"""

from __future__ import annotations

import importlib.util
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "extension_matrix.py"
_spec = importlib.util.spec_from_file_location("extension_matrix", SCRIPT)
XM = importlib.util.module_from_spec(_spec)
sys.modules["extension_matrix"] = XM  # dataclasses look their module up there
_spec.loader.exec_module(XM)

APP = [sys.executable, str(ROOT / "main.py")]
IDS = XM.bundled_ids()

_HANGS = """\
import time
EXTENSION = {"name": "Hangs"}
def activate(api):
    while True:
        time.sleep(1)
"""
_RAISES = """\
EXTENSION = {"name": "Raises"}
def activate(api):
    raise RuntimeError("broken on purpose")
"""


def _assert_clean(result):
    assert result.problems() == [], "\n".join(result.problems())


# -- happy -------------------------------------------------------------------

@pytest.mark.parametrize("ext_id", IDS)
def test_happy_each_bundled_extension_alone_opens_the_window(ext_id):
    result = XM.start(APP, [ext_id])
    _assert_clean(result)
    assert ext_id in result.loaded


def test_happy_all_bundled_extensions_together_open_the_window():
    result = XM.start(APP, IDS)
    _assert_clean(result)
    assert result.loaded == set(IDS)


def test_happy_all_extensions_under_a_hanging_nvidia_driver(tmp_path):
    """The report itself: the driver's cuInit never returns."""
    try:
        wrap = XM.hanging_gpu_wrap(tmp_path)
    except RuntimeError as exc:
        pytest.skip(str(exc))
    result = XM.start(APP, IDS, wrap=wrap)
    _assert_clean(result)


def test_happy_the_ids_come_from_the_folder_not_a_list():
    files = sorted(p.stem for p in (ROOT / "resources" / "extensions").glob("*.py")
                   if not p.name.startswith("_"))
    assert IDS == [f"bundled:{name}" for name in files]
    assert "bundled:media_player" in IDS


# -- sad: the matrix must catch what went wrong --------------------------------

def test_sad_an_extension_that_hangs_in_activate_is_reported_as_hung():
    """Negative control: the report's failure shape - the window never comes."""
    result = XM.start(APP, ["user:hangs"], timeout=10, user_extensions={"hangs": _HANGS})
    assert result.returncode is None
    assert not result.window
    assert "hung" in result.problems()[0]


def test_sad_an_extension_that_raises_in_activate_is_reported():
    result = XM.start(APP, ["user:raises"], user_extensions={"raises": _RAISES})
    assert result.window  # the app survives it ...
    assert "broken on purpose" in result.failed.get("user:raises", "")
    assert any("user:raises failed" in p for p in result.problems())  # ... the matrix fails


def test_sad_an_id_that_does_not_load_is_reported():
    result = XM.start(APP, ["bundled:no_such_extension"])
    assert result.window
    assert result.problems() == [
        "bundled:no_such_extension: bundled:no_such_extension was switched on but did not load"
    ]


def test_sad_the_cli_refuses_a_folder_without_a_binary(tmp_path):
    r = subprocess.run([sys.executable, str(SCRIPT), str(tmp_path)], capture_output=True,
                       text=True, timeout=60)
    assert r.returncode == 2 and "no axross-full or axross-slim" in r.stderr


def test_sad_the_cli_wants_exactly_one_target():
    r = subprocess.run([sys.executable, str(SCRIPT)], capture_output=True, text=True, timeout=60)
    assert r.returncode == 2 and "Usage" in r.stderr


# -- edge --------------------------------------------------------------------

def test_edge_no_extension_switched_on_is_the_baseline():
    result = XM.start(APP, [])
    _assert_clean(result)
    assert result.loaded == set()


def test_edge_the_plan_is_each_alone_then_all_and_only_all_under_the_driver():
    assert XM.plan(["a", "b"], hanging_gpu=False) == [["a"], ["b"], ["a", "b"]]
    assert XM.plan(["a", "b"], hanging_gpu=True) == [["a", "b"]]
    assert XM.plan([], hanging_gpu=False) == [[]]


def test_happy_all_extensions_under_a_hanging_driver_that_qt_really_calls(tmp_path):
    """The GPU-probe switch off: Qt calls the hanging cuInit; the probe in a
    child (core.multimedia_probe) must keep the window coming and the Media
    Player must say why it is off."""
    try:
        wrap = XM.hanging_gpu_wrap(tmp_path)
    except RuntimeError as exc:
        pytest.skip(str(exc))
    result = XM.start(APP, IDS, wrap=wrap, extra_env={"AXROSS_MULTIMEDIA_GPU_PROBE": "1"})
    _assert_clean(result)


def test_edge_the_driver_runs_both_variants_the_plain_run_one():
    assert XM.variants(hanging_gpu=False) == [("", {})]
    assert [extra for _s, extra in XM.variants(hanging_gpu=True)] == [
        {}, {"AXROSS_MULTIMEDIA_GPU_PROBE": "1"}]


def test_edge_the_binary_prefers_full_over_slim(tmp_path):
    (tmp_path / "axross-slim").write_text("")
    assert XM.find_binary(tmp_path).name == "axross-slim"
    (tmp_path / "axross-full").write_text("")
    assert XM.find_binary(tmp_path).name == "axross-full"


def test_edge_a_log_line_of_another_logger_is_not_counted():
    result = XM.StartResult(ids=["bundled:x"])
    XM._parse_log("2026 [INFO] other: Extension loaded: X (bundled:x)\n", result)
    assert result.loaded == set()
    XM._parse_log("2026 [INFO] ui.extension_host: Extension loaded: X (bundled:x)\n", result)
    assert result.loaded == {"bundled:x"}


def test_edge_a_killed_start_leaves_no_unpacked_binary_behind(tmp_path):
    """A one-file binary unpacks itself into TMPDIR (673 MB for axross-full)
    and only removes that on a normal exit: a start killed after the
    timeout must unpack into the start's own temporary folder."""
    exe = tmp_path / "fake"
    exe.write_text("#!/bin/sh\nmkdir \"$TMPDIR/_MEIfake\"\nsleep 600\n")
    exe.chmod(0o755)
    seen = []
    real = XM.tempfile.TemporaryDirectory

    class Spy(real):
        def __init__(self, *a, **k):
            super().__init__(*a, **k)
            seen.append(Path(self.name))

    XM.tempfile.TemporaryDirectory = Spy
    try:
        result = XM.start([str(exe)], [], timeout=3)
    finally:
        XM.tempfile.TemporaryDirectory = real
    assert result.returncode is None
    assert seen and not seen[0].exists()
    assert not list(Path(XM.tempfile.gettempdir()).glob("_MEIfake"))


def test_edge_the_environment_points_tmpdir_into_the_start_folder(tmp_path):
    env = XM._env(tmp_path / "home", None)
    assert Path(env["TMPDIR"]).parent == tmp_path


def test_edge_the_loaded_line_may_carry_the_activation_time():
    result = XM.StartResult(ids=["bundled:x", "bundled:y"])
    XM._parse_log("2026 [INFO] ui.extension_host: Extension loaded: X (bundled:x) in 0.012 s\n"
                  "2026 [INFO] ui.extension_host: Extension loaded: Y (b) (bundled:y)\n", result)
    assert result.loaded == {"bundled:x", "bundled:y"}
