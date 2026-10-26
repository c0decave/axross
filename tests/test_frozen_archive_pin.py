"""A one-file bundle keeps reading its own modules after its file is replaced.

PyInstaller reads every module that is imported late (a context menu, a
dialog) from the executable's embedded PYZ archive, and opens the file by
its *path* for each of them (PyInstaller/loader/pyimod01_archive.py,
ZlibArchiveReader.extract). Once another file sits at that path - the
self-update renames the new version over the running one, a release copies
a fresh build into dist/ - the running process reads the new file at the
old offsets: "zlib.error: Error -3 while decompressing data: incorrect
header check" from the first late import (seen 2026-10-26 on the pack menu
of a file pane; reproduced with the 0.14.50 bundle: replaced while running,
`from core import packer` failed; not replaced, it imported).

core.frozen_archive keeps a descriptor of the file the process started from
and lets the archive read through it.
"""

from __future__ import annotations

import os
import subprocess
import sys
import threading
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

A = pytest.importorskip("PyInstaller.loader.pyimod01_archive")
writers = pytest.importorskip("PyInstaller.archive.writers")

from core import frozen_archive as FA  # noqa: E402

needs_pread = pytest.mark.skipif(not hasattr(os, "pread"), reason="no os.pread (Windows)")


def _pyz(path: Path, modules: dict[str, str], tmp: Path) -> Path:
    entries, code = [], {}
    for name, source in modules.items():
        src = tmp / f"{name}.py"
        src.write_text(source)
        entries.append((name, str(src), "PYMODULE"))
        code[name] = compile(source, str(src), "exec")
    writers.ZlibArchiveWriter(str(path), entries, code)
    return path


@pytest.fixture
def archive(tmp_path, monkeypatch):
    """A real PYZ, a real reader, and the archive module as the bundle has it."""
    path = _pyz(tmp_path / "app.bin", {"alpha": "VALUE = 'alpha'\n", "beta": "VALUE = 'b' * 3\n"},
                tmp_path)
    reader = A.ZlibArchiveReader(str(path), 0)
    monkeypatch.delattr(A, "open", raising=False)  # module global, set by the pin
    yield path, reader
    FA._unpin_for_tests(A)


def _value(reader, name: str) -> str:
    namespace: dict = {}
    exec(reader.extract(name), namespace)  # noqa: S102 - our own test module
    return namespace["VALUE"]


def _replace(path: Path, tmp: Path, modules: dict[str, str]) -> None:
    new = _pyz(tmp / "new.bin", modules, tmp)
    os.replace(new, path)  # what the self-update does: a rename over the running file


def test_sad_without_the_pin_a_replaced_file_breaks_the_next_read(archive, tmp_path):
    path, reader = archive
    _replace(path, tmp_path, {"zzz": "VALUE = 'other'\n" * 40})
    with pytest.raises(Exception):  # zlib.error, or garbage that does not unmarshal
        _value(reader, "beta")


@needs_pread
def test_happy_pinned_reads_the_file_it_started_from(archive, tmp_path):
    path, reader = archive
    assert FA.pin_archive(A, reader) is True
    _replace(path, tmp_path, {"zzz": "VALUE = 'other'\n" * 40})
    assert _value(reader, "alpha") == "alpha"
    assert _value(reader, "beta") == "bbb"


@needs_pread
def test_edge_other_files_still_open_normally(archive, tmp_path):
    _path, reader = archive
    FA.pin_archive(A, reader)
    other = tmp_path / "other.txt"
    other.write_text("plain")
    with A.open(str(other), "r") as fh:
        assert fh.read() == "plain"


@needs_pread
def test_edge_pinning_twice_keeps_one_descriptor(archive):
    _path, reader = archive
    assert FA.pin_archive(A, reader) is True
    fds = len(os.listdir("/proc/self/fd")) if os.path.isdir("/proc/self/fd") else None
    assert FA.pin_archive(A, reader) is True
    if fds is not None:
        assert len(os.listdir("/proc/self/fd")) == fds


@needs_pread
def test_sad_a_file_replaced_before_the_pin_is_not_pinned(archive, tmp_path, caplog):
    path, reader = archive
    _replace(path, tmp_path, {"zzz": "VALUE = 'other'\n" * 40})
    assert FA.pin_archive(A, reader) is False
    assert not hasattr(A, "open")
    assert "replaced" in caplog.text


@needs_pread
def test_edge_parallel_late_imports_read_their_own_bytes(archive, tmp_path):
    path, reader = archive
    FA.pin_archive(A, reader)
    _replace(path, tmp_path, {"zzz": "VALUE = 'other'\n" * 40})
    errors, results = [], []

    def work(name, want):
        try:
            for _ in range(200):
                results.append(_value(reader, name) == want)
        except Exception as exc:  # noqa: BLE001 - collected for the assert
            errors.append(exc)

    threads = [threading.Thread(target=work, args=(n, w))
               for n, w in (("alpha", "alpha"), ("beta", "bbb")) * 3]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert errors == [] and all(results) and len(results) == 1200


def test_edge_not_frozen_pins_nothing():
    assert FA.pin_frozen_archive() is False


def test_happy_main_pins_before_anything_else():
    source = (Path(__file__).resolve().parent.parent / "main.py").read_text()
    body = source.split("def main() -> int:", 1)[1]
    first = body.index("pin_frozen_archive()")
    assert first < body.index("restore_loader_env(")


needs_bundle = pytest.mark.skipif(not os.environ.get("AXROSS_FROZEN_BINARY"),
                                  reason="needs a built bundle")


def _run_replaced(tmp_path: Path, body: str, replacement: bytes | None,
                  prologue: str = "") -> str:
    """Run a --script in a copy of AXROSS_FROZEN_BINARY: *prologue*, then it
    prints 'started' and waits; the copy is replaced by a rename with
    *replacement* (None: left alone), then *body* runs. Returns the output."""
    import shutil

    exe = tmp_path / "axross"
    shutil.copy2(os.environ["AXROSS_FROZEN_BINARY"], exe)
    go = tmp_path / "go"
    script = tmp_path / "late.py"
    script.write_text(
        prologue + "import os, time\n"
        "print('started', flush=True)\n"
        f"while not os.path.exists({str(go)!r}):\n    time.sleep(0.05)\n" + body)
    home = tmp_path / "home"
    env = {**os.environ, "HOME": str(home), "XDG_CONFIG_HOME": str(home / ".config"),
           "XDG_CACHE_HOME": str(home / ".cache"), "QT_QPA_PLATFORM": "offscreen",
           "AXROSS_NO_UPDATE_CHECK": "1", "AXROSS_E2E_DIR": str(tmp_path)}
    proc = subprocess.Popen([str(exe), "--script", str(script)], env=env,
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    seen = []
    for line in proc.stdout:  # the bundle unpacked and the script runs
        seen.append(line)
        if line.strip() == "started":
            break
    else:
        proc.wait(timeout=30)
        raise AssertionError("the script never started:\n" + "".join(seen))
    if replacement is not None:
        new = tmp_path / "axross.new"
        new.write_bytes(replacement)
        os.replace(new, exe)
    go.touch()
    out, _ = proc.communicate(timeout=180)
    return "".join(seen) + out + f"\nexit {proc.returncode}\n"


@needs_bundle
def test_e2e_frozen_bundle_imports_late_after_its_file_was_replaced(tmp_path):
    """AXROSS_FROZEN_BINARY=<bundle>: replaced by a rename, a late import works."""
    out = _run_replaced(tmp_path, "from core import packer\n"
                        "print('late import ok', packer.__name__, flush=True)\n",
                        os.urandom(1024 * 1024))
    assert "late import ok core.packer" in out, out


# Copies a folder like F5 in a file pane: the window's modules are loaded
# before the file is replaced, the transfer starts after. Seen 2026-10-26 on
# a 0.13 bundle: every file of a copied folder failed with "Error -3 while
# decompressing data", only the folders were created; reproduced with the
# 0.14.50 bundle (the first late import is in TransferManager.transfer_files).
_COPY_FOLDER = """\
import os, time
from pathlib import Path
base = Path(os.environ["AXROSS_E2E_DIR"])
src, dst = base / "src", base / "dst"
names = ["release.sh", "Containerfile", "docs/PLAN.md", "docs/deep/ADAPTERS.md"]
for i, name in enumerate(names):
    (src / name).parent.mkdir(parents=True, exist_ok=True)
    (src / name).write_bytes(os.urandom(64) * (i + 1) * 100)
dst.mkdir()
from core.local_fs import LocalFS
from core.transfer_manager import TransferManager
from core.transfer_worker import TransferDirection, TransferStatus
mgr = TransferManager()
jobs = mgr.transfer_files(LocalFS(), LocalFS(), [str(src)], str(dst), TransferDirection.UPLOAD)
final = {TransferStatus.DONE, TransferStatus.ERROR, TransferStatus.CANCELLED}
end = time.monotonic() + 60
while time.monotonic() < end:
    app.processEvents()
    jobs = list(mgr._jobs.values())
    if jobs and all(j.status in final for j in jobs):
        break
    time.sleep(0.01)
for j in jobs:
    print("job", j.filename, j.status.name, j.error_message or "", flush=True)
same = [n for n in names
        if (dst / "src" / n).is_file() and (dst / "src" / n).read_bytes() == (src / n).read_bytes()]
print("copied", len(same), "of", len(names), flush=True)
mgr.shutdown()  # as the window does on close: no worker thread outlives Qt
"""

# The window has these loaded before anyone can copy.
_WINDOW_LOADED = """\
from PyQt6.QtWidgets import QApplication
app = QApplication.instance() or QApplication([])
import ui.main_window
"""


def _copied(out: str) -> str:
    return next((line for line in out.splitlines() if line.startswith("copied ")), out)


@needs_bundle
def test_e2e_frozen_bundle_copies_a_folder_after_its_file_was_replaced(tmp_path):
    """Replaced by a rename while the window runs: every file of the folder
    arrives byte for byte, not just its folders."""
    out = _run_replaced(tmp_path, _COPY_FOLDER, os.urandom(1024 * 1024), _WINDOW_LOADED)
    assert _copied(out) == "copied 4 of 4", out
    assert "\nexit 0\n" in out, out
    assert "decompressing" not in out, out


@needs_bundle
def test_e2e_frozen_bundle_copies_a_folder_when_its_file_stays(tmp_path):
    """The control: nothing replaced, the same copy arrives."""
    out = _run_replaced(tmp_path, _COPY_FOLDER, None, _WINDOW_LOADED)
    assert _copied(out) == "copied 4 of 4", out
    assert "\nexit 0\n" in out, out


@needs_bundle
def test_e2e_frozen_bundle_copies_after_a_shifted_copy_of_itself_replaced_it(tmp_path):
    """A replacement that is a real bundle at other offsets (what a new
    version is): compressed data sits where the old table points, but not
    the right data. The copy still arrives."""
    shifted = os.urandom(4096) + Path(os.environ["AXROSS_FROZEN_BINARY"]).read_bytes()
    out = _run_replaced(tmp_path, _COPY_FOLDER, shifted, _WINDOW_LOADED)
    assert _copied(out) == "copied 4 of 4", out
    assert "\nexit 0\n" in out, out
