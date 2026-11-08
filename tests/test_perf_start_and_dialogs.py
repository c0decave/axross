"""The start and dialog costs the performance review found, held down by
counts rather than wall-clock budgets:

* Matrix and XMPP no longer import nio / OMEMO when they are switched on
  (only a connect does); the equalizer's numpy waits for the first sound.
* Extension code is kept by the SHA-256 of its source (core.extension_code_cache):
  an unchanged source is not compiled again, a changed one never finds the
  old code, and an entry that is not private to the user is never run.
* A switched-off extension whose namespace something still holds is used
  again when switched on with an unchanged source (no second copy per cycle);
  Reload still runs every module anew.
* The activation marker is written without fsync.
* The Connection dialog no longer searches PATH on every open
  (core.backend_registry._CommandProbe); a changed PATH is noticed.
* Window flags set before a window is shown do not reparent it
  (ui.viewer_window.set_window_flag).
* Picking the theme in use does not repolish every widget again.
"""

from __future__ import annotations

import gc
import os
import stat
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

pytest.importorskip("PyQt6.QtWidgets", reason="PyQt6 not installed")

from PyQt6.QtCore import QEvent, Qt  # noqa: E402
from PyQt6.QtWidgets import QApplication, QDialog, QLineEdit, QMainWindow, QVBoxLayout  # noqa: E402

from core import extension_code_cache as ECC  # noqa: E402
from core import extensions as EX  # noqa: E402

APP = QApplication.instance() or QApplication([])


@pytest.fixture(autouse=True)
def own_home(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path / "cache"))
    EX.clear_manifest_cache()
    monkeypatch.setattr(EX, "_SAFE_MODE", False)
    ECC.clear_memory()
    yield
    ECC.clear_memory()


def _run(code: str) -> str:
    env = dict(os.environ, QT_QPA_PLATFORM="offscreen", PYTHONPATH=str(ROOT))
    out = subprocess.run([sys.executable, "-c", textwrap.dedent(code)], cwd=str(ROOT), env=env,
                         capture_output=True, text=True, timeout=240)
    assert out.returncode == 0, out.stderr[-3000:]
    return out.stdout.strip().splitlines()[-1]


# -- heavy libraries wait for their first use ---------------------------------------------


def test_happy_switching_matrix_and_xmpp_on_imports_no_chat_library(tmp_path):
    line = _run(f"""
        import os, sys
        os.environ["HOME"] = {str(tmp_path / "h")!r}
        os.environ["XDG_CACHE_HOME"] = {str(tmp_path / "c")!r}
        from PyQt6.QtWidgets import QApplication, QMainWindow
        app = QApplication([])
        from core import extensions as EX
        EX.set_safe_mode(False)
        from ui.extension_host import ExtensionHost
        win = QMainWindow()
        host = ExtensionHost(win, win.menuBar().addMenu("Extensions"))
        for info in EX.discover():
            if info.ext_id in ("bundled:matrix", "bundled:xmpp"):
                assert host.load(info), host.error(info.ext_id)
        print(sorted(m for m in ("nio", "vodozemac", "omemo", "twomemo", "slixmpp", "aiohttp")
                     if m in sys.modules))
    """)
    assert line == "[]"


def test_happy_the_quick_check_agrees_with_the_import_check():
    from core import chat_matrix, chat_xmpp

    assert (chat_matrix.nio_missing(load=False) is None) == (chat_matrix.nio_missing() is None)
    assert (chat_xmpp.libraries_missing(load=False) is None) == (chat_xmpp.libraries_missing() is None)


def test_sad_a_missing_chat_library_is_named_without_importing(monkeypatch):
    from core import chat_matrix, chat_xmpp

    monkeypatch.setitem(sys.modules, "nio", None)
    monkeypatch.setitem(sys.modules, "twomemo", None)
    assert "Help > Features…" in chat_matrix.nio_missing(load=False)
    assert "Help > Features…" in chat_xmpp.libraries_missing(load=False)


def test_edge_the_equalizer_imports_numpy_with_its_first_sound():
    line = _run("""
        import sys
        from core import audio_eq as AEQ
        ok = AEQ.available()
        before = "numpy" in sys.modules
        if ok:
            pcm = bytes(range(256)) * 64
            out = AEQ.equalize_int16(pcm, 16000, AEQ.PRESETS["Bass boost"])
            assert len(out) == len(pcm) and out != pcm
        print(before, ok == ("numpy" in sys.modules))
    """)
    assert line == "False True"


# -- the code cache --------------------------------------------------------------------------


def _exec(code) -> dict:
    ns: dict = {}
    exec(code, ns)  # noqa: S102 - the test's own source
    return ns


def test_happy_an_unchanged_source_is_compiled_once(tmp_path):
    src, path = b"VALUE = 1\n", str(tmp_path / "ext.py")
    before = dict(ECC.stats)
    assert _exec(ECC.compile_source(src, path))["VALUE"] == 1
    assert _exec(ECC.compile_source(src, path))["VALUE"] == 1  # this process
    ECC.clear_memory()
    assert _exec(ECC.compile_source(src, path))["VALUE"] == 1  # the next start
    assert ECC.stats["compiled"] - before["compiled"] == 1
    assert ECC.stats["memory"] - before["memory"] == 1
    if ECC._disk_allowed():
        assert ECC.stats["disk"] - before["disk"] == 1
        folder = ECC.cache_dir()
        assert stat.S_IMODE(folder.stat().st_mode) == 0o700
        assert all(stat.S_IMODE(f.stat().st_mode) == 0o600 for f in folder.iterdir())


def test_sad_a_changed_source_never_finds_the_old_code(tmp_path):
    path = str(tmp_path / "ext.py")
    assert _exec(ECC.compile_source(b"VALUE = 1\n", path))["VALUE"] == 1
    ECC.clear_memory()
    # Same size, same file: only the content differs.
    assert _exec(ECC.compile_source(b"VALUE = 2\n", path))["VALUE"] == 2


needs_posix = pytest.mark.skipif(not ECC._disk_allowed(), reason="the disk cache is POSIX only")


def _entry(src: bytes, path: str) -> Path:
    return ECC.cache_dir() / (ECC.source_key(src, path) + ".code")


@needs_posix
def test_sad_an_entry_others_may_write_is_never_run(tmp_path):
    src, path = b"VALUE = 1\n", str(tmp_path / "ext.py")
    ECC.compile_source(src, path)
    ECC.clear_memory()
    entry = _entry(src, path)
    planted = ECC.compile_source(b"VALUE = 666\n", path)  # what an attacker would put there
    ECC.clear_memory()
    data = entry.read_bytes()
    import hashlib
    import marshal

    payload = marshal.dumps(planted)
    entry.write_bytes(data[:len(ECC._MAGIC) + 65] + hashlib.sha256(payload).digest() + payload)
    os.chmod(entry, 0o666)
    assert _exec(ECC.compile_source(src, path))["VALUE"] == 1
    os.chmod(entry, 0o600)
    os.chmod(ECC.cache_dir(), 0o777)
    ECC.clear_memory()
    try:
        assert _exec(ECC.compile_source(src, path))["VALUE"] == 1
    finally:
        os.chmod(ECC.cache_dir(), 0o700)


@needs_posix
def test_sad_a_damaged_entry_is_compiled_anew(tmp_path):
    src, path = b"VALUE = 1\n", str(tmp_path / "ext.py")
    ECC.compile_source(src, path)
    ECC.clear_memory()
    entry = _entry(src, path)
    data = bytearray(entry.read_bytes())
    data[-3] ^= 0xFF
    entry.write_bytes(bytes(data))
    before = ECC.stats["compiled"]
    assert _exec(ECC.compile_source(src, path))["VALUE"] == 1
    assert ECC.stats["compiled"] == before + 1


@needs_posix
def test_edge_a_symlinked_entry_or_folder_is_ignored(tmp_path):
    src, path = b"VALUE = 1\n", str(tmp_path / "ext.py")
    ECC.compile_source(src, path)
    ECC.clear_memory()
    entry = _entry(src, path)
    elsewhere = tmp_path / "elsewhere.code"
    entry.rename(elsewhere)
    entry.symlink_to(elsewhere)
    before = ECC.stats["compiled"]
    assert _exec(ECC.compile_source(src, path))["VALUE"] == 1
    assert ECC.stats["compiled"] == before + 1


@needs_posix
def test_edge_the_folder_keeps_at_most_max_entries(tmp_path, monkeypatch):
    monkeypatch.setattr(ECC, "MAX_ENTRIES", 3)
    for i in range(6):
        ECC.compile_source(f"VALUE = {i}\n".encode(), str(tmp_path / "ext.py"))
    assert len(list(ECC.cache_dir().glob("*.code"))) == 3


# -- the host: compile once, namespaces used again ------------------------------------------


@pytest.fixture
def host():
    from ui.extension_host import ExtensionHost

    window = QMainWindow()
    yield ExtensionHost(window, window.menuBar().addMenu("Extensions"))
    window.deleteLater()
    APP.sendPostedEvents(None, QEvent.Type.DeferredDelete)


def _write_ext(name: str, body: str) -> None:
    folder = EX.extensions_dir()
    folder.mkdir(parents=True, exist_ok=True)
    (folder / f"{name}.py").write_text(
        f'EXTENSION = {{"name": "{name.title()}"}}\n' + textwrap.dedent(body))


def _settle() -> None:
    APP.processEvents()
    APP.sendPostedEvents(None, QEvent.Type.DeferredDelete)
    gc.collect()


HELD = """
    RUNS = []
    RUNS.append(1)
    def activate(api):
        pass
"""


def test_happy_a_held_namespace_is_used_again_with_an_unchanged_source(host):
    _write_ext("held", HELD)
    host.set_enabled("user:held", True)
    first = host.module("user:held")
    keep = first.activate  # something still holds the namespace (a Qt class, a thread)
    host.set_enabled("user:held", False)
    _settle()
    compiled = ECC.stats["compiled"]
    host.set_enabled("user:held", True)
    again = host.module("user:held")
    assert again is first and again.RUNS == [1]  # not run (nor compiled) a second time
    assert ECC.stats["compiled"] == compiled
    assert keep is again.activate


def test_sad_a_changed_source_runs_anew_even_when_held(host):
    _write_ext("held", HELD)
    host.set_enabled("user:held", True)
    first = host.module("user:held")
    host.set_enabled("user:held", False)
    _write_ext("held", HELD.replace("RUNS = []", "RUNS = [0]"))
    host.set_enabled("user:held", True)
    again = host.module("user:held")
    assert again is not first and again.RUNS == [0, 1]


def test_sad_reload_runs_every_module_anew(host):
    _write_ext("held", HELD)
    EX.set_enabled("user:held", True)
    host.load_enabled()
    first = host.module("user:held")
    host.reload()
    assert host.module("user:held") is not first


def test_edge_a_namespace_nothing_holds_is_freed_and_run_anew(host):
    _write_ext("held", HELD)
    host.set_enabled("user:held", True)
    first_id = id(host.module("user:held").RUNS)
    host.set_enabled("user:held", False)
    host.set_enabled("user:held", True)  # the batch collects first: never a stale reuse
    assert host.module("user:held").RUNS == [1]
    import ui.extension_host as EH

    assert "axross_extension_user_held" not in EH._SPARE
    del first_id


BLOCKED = """
    import threading
    GATE = threading.Event()
    class Panel:
        def done(self, _value):
            pass
    def activate(api):
        panel = Panel()
        # Like the Media Player's audio probe: work still running after the
        # switch-off holds the callbacks, and with them the namespace.
        api.run_in_background(lambda: GATE.wait(30), on_done=panel.done)
"""


def test_edge_on_off_cycles_while_work_still_runs_keep_one_copy(host, monkeypatch):
    _write_ext("blocked", BLOCKED)
    gates = []
    try:
        for _ in range(4):
            host.set_enabled("user:blocked", True)
            gates.append(host.module("user:blocked").GATE)
            host.set_enabled("user:blocked", False)
            _settle()
        alive = [o for o in gc.get_objects()
                 if isinstance(o, dict) and o.get("__name__") == "axross_extension_user_blocked"]
        assert len(alive) == 1
        assert len({id(g) for g in gates}) == 1  # the one namespace, used again
    finally:
        for gate in gates:
            gate.set()


def test_happy_the_activation_marker_is_written_without_fsync(monkeypatch):
    calls = []
    monkeypatch.setattr(os, "fsync", lambda fd: calls.append(fd))
    info = EX.ExtensionInfo(ext_id="user:probe", name="Probe", module_name="probe",
                            path="/nonexistent/probe.py", source="user")
    marker = EX.begin_activation(info)
    try:
        assert marker is not None and '"user:probe"' in marker.read_text()
        if os.name == "posix":
            assert stat.S_IMODE(marker.stat().st_mode) == 0o600
    finally:
        EX.end_activation(marker)
    assert calls == [] and not marker.exists()


# -- the backend registry: PATH searched once ------------------------------------------------


def test_happy_the_connection_dialog_searches_path_once(monkeypatch, tmp_path):
    from core import backend_registry as BR
    from core.profiles import ProfileManager
    from ui.connection_dialog import ConnectionDialog

    BR.init_registry()
    calls = []
    real = BR.shutil.which
    monkeypatch.setattr(BR.shutil, "which", lambda c, *a, **k: calls.append(c) or real(c, *a, **k))
    manager = ProfileManager()
    for _ in range(2):
        dialog = ConnectionDialog(manager)
        dialog.deleteLater()
    APP.sendPostedEvents(None, QEvent.Type.DeferredDelete)
    first = len(calls)
    dialog = ConnectionDialog(manager)
    dialog.deleteLater()
    APP.sendPostedEvents(None, QEvent.Type.DeferredDelete)
    assert len(calls) == first  # the third open searched nothing


def test_sad_a_program_installed_meanwhile_is_found(monkeypatch, tmp_path):
    from core import backend_registry as BR

    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    monkeypatch.setenv("PATH", str(bin_dir))
    probe = BR._check_command_available("axross-test-tool")
    BR._PATH_STATE["value"] = None
    assert probe() is False
    tool = bin_dir / "axross-test-tool"
    tool.write_text("#!/bin/sh\n")
    tool.chmod(0o755)
    os.utime(bin_dir, ns=(10**18, 10**18))  # the folder changed
    BR._PATH_STATE["value"] = None  # a second later
    assert probe() is True
    assert probe.lookups == 2
    assert probe() is True and probe.lookups == 2  # nothing changed: no search


def test_edge_nfs_needs_mount_and_umount_and_a_helper(monkeypatch):
    from core import backend_registry as BR

    present = {"mount"}
    monkeypatch.setattr(BR.shutil, "which", lambda c, *a, **k: f"/x/{c}" if c in present else None)
    probe = BR._CommandProbe(all_of=("mount", "umount"), any_of=("mount.nfs", "mount.nfs4", "mount"))
    assert probe() is False  # umount missing (the old `and` of two probes said True)
    present.add("umount")
    probe.reset()
    assert probe() is True


def test_edge_recheck_missing_resets_only_what_was_missing():
    from core import backend_registry as BR

    BR.ensure_initialized()
    probes = [i._availability for i in BR._registry.values()
              if type(i._availability) is BR._ImportProbe]
    for p in probes:
        p()
    BR.recheck_missing()
    for p in probes:
        assert p.resolved == (p._result is True)


# -- window flags before the first show ------------------------------------------------------


def _dialog() -> QDialog:
    d = QDialog()
    layout = QVBoxLayout(d)
    for _ in range(20):
        layout.addWidget(QLineEdit())
    return d


def test_happy_flags_of_a_window_not_shown_yet_are_only_stored():
    from ui import viewer_window as VW

    d = _dialog()
    calls = []
    d.setWindowFlag = lambda *a: calls.append(a)  # the reparenting path
    expected = d.windowFlags() | Qt.WindowType.WindowMaximizeButtonHint
    VW.allow_maximize(d)
    assert calls == [] and d.windowFlags() == expected
    VW.set_window_flag(d, Qt.WindowType.FramelessWindowHint, True)
    assert d.windowFlags() & Qt.WindowType.FramelessWindowHint
    del d.setWindowFlag
    d.show()
    APP.processEvents()
    assert d.windowFlags() & Qt.WindowType.FramelessWindowHint
    assert d.windowHandle().flags() & Qt.WindowType.FramelessWindowHint
    d.close()
    d.deleteLater()


def test_edge_a_window_on_screen_still_goes_through_set_window_flag():
    from ui import viewer_window as VW

    d = _dialog()
    d.show()
    APP.processEvents()
    calls = []
    real = d.setWindowFlag
    d.setWindowFlag = lambda *a: (calls.append(a), real(*a))
    VW.allow_maximize(d)
    assert len(calls) == 1 and d.windowFlags() & Qt.WindowType.WindowMaximizeButtonHint
    VW.allow_maximize(d)  # already set: nothing
    assert len(calls) == 1
    d.close()
    d.deleteLater()


def test_happy_add_close_corner_gives_the_same_flags_as_before():
    from ui import title_bar
    from ui.close_corner import add_close_corner

    d = _dialog()
    expected = d.windowFlags() | Qt.WindowType.WindowMaximizeButtonHint
    if title_bar.own_title_bars():
        expected |= Qt.WindowType.FramelessWindowHint
    add_close_corner(d)
    assert d.windowFlags() == expected
    d.deleteLater()


# -- the theme in use, picked again ------------------------------------------------------------


def test_happy_the_theme_in_use_is_not_applied_again(monkeypatch):
    from ui.main_window import MainWindow

    win = MainWindow()
    win._reconnect_timer.stop()
    try:
        win.set_theme("classic", store=False)
        sheets = []
        real = QApplication.setStyleSheet
        monkeypatch.setattr(QApplication, "setStyleSheet",
                            lambda self, css: (sheets.append(css), real(self, css)))
        win.set_theme("classic", store=False)
        assert sheets == []
        win.set_theme("modern", store=False)
        assert sheets and sheets[-1] == APP.styleSheet() != ""
    finally:
        win.close()
        win.deleteLater()
        APP.sendPostedEvents(None, QEvent.Type.DeferredDelete)
