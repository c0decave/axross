"""The Forensic Tools extension (punch-list item 8).

Operator: *„testdisk und andere forensic tools als extensions einbinden um
z.b. auf qemu/qcow/vdi/ext4... images direkt forensic machen zu koennen"*.

qemu-img runs for real when installed (qcow2 -> raw round trip); fls and
icat are stubbed here with the output format of The Sleuth Kit 4.x - the
real tools are checked in a container (evidence file). TestDisk and
PhotoRec are interactive: the terminal pane really types the command.
"""

from __future__ import annotations

import hashlib
import importlib.util
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from core import extensions as EX  # noqa: E402
from core.local_fs import LocalFS  # noqa: E402
from tests.test_disk_image import LINUX, SECTOR, gpt_image, put_ext4  # noqa: E402


def load():
    path = EX.bundled_dir() / "forensic_tools.py"
    spec = importlib.util.spec_from_file_location("example_forensic_tools", path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


FT = load()
_APP = None


def qapp():
    """One QApplication for the whole file, kept referenced: one made and
    dropped inside a test is destroyed at once, and the next widget aborts
    the process ("Must construct a QApplication before a QWidget")."""
    global _APP
    from PyQt6.QtWidgets import QApplication

    _APP = QApplication.instance() or QApplication([])
    return _APP


QEMU_IMG = shutil.which("qemu-img")

# What `fls -r -p -o 2048 disk.img` prints for a small ext4 with one deleted file.
FLS_OUTPUT = """d/d 11:\tlost+found
r/r 12:\thello.txt
d/d 13:\tdocs
r/r 14:\tdocs/report final.pdf
r/r * 15:\tdocs/secret.txt
r/r * 16(realloc):\told.log
l/l 17:\tlink-to-hello
V/V 32769:\t$OrphanFiles
-/r * 18:\t$OrphanFiles/OrphanFile-18
"""


def stub(tmp_path, name, body):
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir(exist_ok=True)
    tool = bin_dir / name
    tool.write_text("#!/bin/sh\n" + body + "\n")
    tool.chmod(0o755)
    return bin_dir


# -- happy ------------------------------------------------------------------------------


def test_happy_hash_image_matches_hashlib(tmp_path):
    data = os.urandom(3 * 1024 * 1024 + 17)
    path = tmp_path / "e.dd"
    path.write_bytes(data)
    got = FT.hash_image(LocalFS(), str(path))
    assert got == {"MD5": hashlib.md5(data).hexdigest(), "SHA-1": hashlib.sha1(data).hexdigest(),
                   "SHA-256": hashlib.sha256(data).hexdigest()}


def test_happy_parse_fls():
    entries = FT.parse_fls(FLS_OUTPUT)
    by_path = {e.path: e for e in entries}
    assert by_path["docs"].is_dir and by_path["docs/report final.pdf"].inode == "14"
    assert by_path["docs/secret.txt"].deleted and not by_path["hello.txt"].deleted
    assert by_path["old.log"].deleted and by_path["old.log"].reallocated
    assert by_path["$OrphanFiles/OrphanFile-18"].deleted
    assert len(entries) == 9


@pytest.mark.skipif(QEMU_IMG is None, reason="qemu-img not installed")
def test_e2e_qcow2_to_raw_round_trip(tmp_path):
    image = gpt_image([(LINUX, 2048, 4095, "root")], size=4 * 1024 * 1024)
    put_ext4(image, 2048 * SECTOR, b"fromqcow")
    raw = tmp_path / "orig.raw"
    raw.write_bytes(bytes(image))
    qcow = tmp_path / "vm.qcow2"
    subprocess.run([QEMU_IMG, "convert", "-f", "raw", "-O", "qcow2", str(raw), str(qcow)],
                   check=True)
    info = FT.image_info(str(qcow))
    assert info["Format"] == "qcow2" and info["Virtual size"] == len(image)
    target = FT.convert_to_raw(str(qcow))
    assert target == str(tmp_path / "vm.raw")
    assert Path(target).read_bytes() == bytes(image)
    # The raw copy opens with Disk Image… (core.disk_image).
    from core import disk_image as DI

    assert DI.inspect_path(target).partitions[0].label == "fromqcow"


def test_happy_extract_with_icat(tmp_path, monkeypatch):
    bin_dir = stub(tmp_path, "icat", 'echo "content of inode $4 at offset $2"')
    monkeypatch.setenv("PATH", f"{bin_dir}:{os.environ['PATH']}")
    out = tmp_path / "out"
    out.mkdir()
    entries = FT.parse_fls(FLS_OUTPUT)
    written = FT.extract("/img/disk.img", entries, str(out), 2048)
    names = sorted(os.path.basename(w) for w in written)
    assert "docs_report_final.pdf" in names and "deleted_docs_secret.txt" in names
    assert "docs" not in names  # folders are not extracted
    assert (out / "hello.txt").read_text() == "content of inode 12 at offset 2048\n"


def test_happy_the_actions_are_registered_for_images():
    actions = []

    class Api:
        window = None

        def add_context_action(self, label, cb, applies_to="any", extensions=()):
            actions.append((label, applies_to, extensions))

    FT.activate(Api())
    labels = [a[0] for a in actions]
    assert labels == ["Hash Image (MD5, SHA-1, SHA-256)", "Image Info (qemu-img)",
                      "Convert to Raw Image (qemu-img)…", "Browse File System (Sleuth Kit)…",
                      "Recover Partitions (TestDisk)", "Carve Files (PhotoRec)"]
    assert all(a[1] == "single_file" and ".qcow2" in a[2] and ".vdi" in a[2] for a in actions)


def test_e2e_a_terminal_pane_runs_the_command(tmp_path, monkeypatch):
    """What TestDisk / PhotoRec use: a local shell pane types the command."""
    app = qapp()
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    from ui.main_window import MainWindow

    win = MainWindow()
    try:
        win._reconnect_timer.stop()
        marker = tmp_path / "ran it.txt"
        term = win.open_terminal_command(["sh", "-c", f"echo ok > '{marker}'"], cwd=str(tmp_path),
                                         label="test")
        assert term in win._terminal_panes and win.workspace_of(term) is win.current_workspace()
        end = time.time() + 15
        while not marker.exists() and time.time() < end:
            app.processEvents()
            time.sleep(0.05)
        assert marker.read_text() == "ok\n"
    finally:
        for t in list(win._terminal_panes):
            t.shutdown()
        win.close()
        win.deleteLater()


# -- sad --------------------------------------------------------------------------------


def test_sad_a_missing_tool_names_its_package(monkeypatch):
    monkeypatch.setattr(FT.shutil, "which", lambda name: None)
    with pytest.raises(FT.ToolError, match="package: sleuthkit"):
        FT.list_files("/img/disk.img", 0)
    with pytest.raises(FT.ToolError, match="qemu"):
        FT.image_info("/img/x.qcow2")


def test_sad_convert_never_overwrites_and_cleans_up_a_failure(tmp_path, monkeypatch):
    src = tmp_path / "a.qcow2"
    src.write_bytes(b"x")
    existing = tmp_path / "a.raw"
    existing.write_bytes(b"keep")
    with pytest.raises(FT.ToolError, match="not overwritten"):
        FT.convert_to_raw(str(src), str(existing))
    assert existing.read_bytes() == b"keep"
    bin_dir = stub(tmp_path, "qemu-img", 'echo partial > "$5"; echo "qemu-img: Could not open" >&2; exit 1')
    monkeypatch.setenv("PATH", f"{bin_dir}:{os.environ['PATH']}")
    target = tmp_path / "new.raw"
    with pytest.raises(FT.ToolError, match="Could not open"):
        FT.convert_to_raw(str(src), str(target))
    assert not target.exists()


def test_sad_a_failing_icat_leaves_no_file(tmp_path, monkeypatch):
    bin_dir = stub(tmp_path, "icat", 'echo "icat: Error reading image" >&2; exit 1')
    monkeypatch.setenv("PATH", f"{bin_dir}:{os.environ['PATH']}")
    with pytest.raises(FT.ToolError, match="Error reading image"):
        FT.extract("/img/d.img", FT.parse_fls("r/r 12:\thello.txt"), str(tmp_path))
    assert not (tmp_path / "hello.txt").exists()


@pytest.mark.parametrize("offset", [-1, "0", 1.5])
def test_sad_bad_offsets(offset, tmp_path, monkeypatch):
    with pytest.raises(ValueError):
        FT.list_files("/img/d.img", offset)


def test_sad_remote_shells_do_not_run_commands():
    qapp()
    from ui.terminal_pane import TerminalPaneWidget

    term = TerminalPaneWidget.__new__(TerminalPaneWidget)
    term._profile, term._transport = object(), None
    assert TerminalPaneWidget.run_command(term, ["testdisk", "/x"]) is False


# -- edge -------------------------------------------------------------------------------


def test_edge_raw_target_numbers_instead_of_overwriting(tmp_path):
    (tmp_path / "vm.raw").write_bytes(b"")
    (tmp_path / "vm-1.raw").write_bytes(b"")
    assert FT.raw_target(str(tmp_path / "vm.qcow2")) == str(tmp_path / "vm-2.raw")
    assert FT.raw_target(str(tmp_path / "noext")) == str(tmp_path / "noext.raw")


def test_edge_hostile_names_are_flattened_and_existing_files_kept(tmp_path, monkeypatch):
    bin_dir = stub(tmp_path, "icat", 'echo new')
    monkeypatch.setenv("PATH", f"{bin_dir}:{os.environ['PATH']}")
    (tmp_path / "etc_passwd").write_text("old")
    lines = "r/r 20:\t../../etc/passwd\nr/r 21:\t/etc/passwd\nr/r 22:\t\n"
    written = FT.extract("/i.img", FT.parse_fls(lines), str(tmp_path))
    assert (tmp_path / "etc_passwd").read_text() == "old"  # kept
    assert all(Path(w).parent == tmp_path for w in written)
    assert FT.safe_name("a/../b c") == "a_.._b_c"
    assert FT.safe_name("///") == "unnamed"


def test_edge_garbage_and_huge_fls_output():
    assert FT.parse_fls("garbage\n\nr/r x:\tbad\n") == []
    many = "r/r 1:\tf\n" * (FT.MAX_FLS_LINES + 10)
    assert len(FT.parse_fls(many)) == FT.MAX_FLS_LINES


def test_edge_hash_stops_when_cancelled(tmp_path):
    path = tmp_path / "big.dd"
    path.write_bytes(b"\0" * (FT.CHUNK * 3))
    calls = []
    FT.hash_image(LocalFS(), str(path), cancel=lambda: calls.append(1) or len(calls) > 1)
    assert len(calls) == 2


def test_e2e_browse_opens_the_file_list_and_extracts(tmp_path, monkeypatch):
    """Browse File System through activate(): the partition from
    core.disk_image, fls / icat stubbed with The Sleuth Kit's format."""
    from types import SimpleNamespace

    from PyQt6.QtWidgets import QFileDialog, QMainWindow, QToolButton

    qapp()
    bin_dir = stub(tmp_path, "fls", f'printf "%s" "$(cat {tmp_path}/fls.txt)"')
    stub(tmp_path, "icat", 'echo "inode $4"')
    (tmp_path / "fls.txt").write_text(FLS_OUTPUT)
    monkeypatch.setenv("PATH", f"{bin_dir}:{os.environ['PATH']}")
    image = gpt_image([(LINUX, 2048, 4095, "root")], size=4 * 1024 * 1024)
    put_ext4(image, 2048 * SECTOR, b"r")
    img = tmp_path / "disk.img"
    img.write_bytes(bytes(image))

    class Api:
        window = QMainWindow()
        actions = {}

        def add_context_action(self, label, cb, applies_to="any", extensions=()):
            self.actions[label] = cb

        def run_in_background(self, work, on_done=None, on_error=None):
            try:
                result = work()
            except Exception as exc:  # noqa: BLE001
                raise AssertionError(exc) from exc
            on_done(result)

        def notify(self, text):
            self.note = text

    api = Api()
    FT.activate(api)
    ctx = SimpleNamespace(backend=LocalFS(), folder=str(tmp_path), paths=[str(img)], items=[],
                          pane=None, is_local=True)
    api.actions["Browse File System (Sleuth Kit)…"](ctx)
    dialog = api.window._forensic_browse_dialog
    try:
        assert dialog.findChild(QToolButton, "axCloseCorner") is not None
        assert dialog.table.model().rowCount() == 9 and dialog.sector == 2048
        dialog.filter.setText("secret")
        assert [e.path for e in dialog.visible_entries()] == ["docs/secret.txt"]
        assert dialog.table.model().index(0, 0).data() == "docs/secret.txt"
        out = tmp_path / "out"
        out.mkdir()
        monkeypatch.setattr(QFileDialog, "getExistingDirectory", lambda *a, **k: str(out))
        dialog.table.selectRow(0)
        dialog.extract_selected()
        assert (out / "deleted_docs_secret.txt").read_text() == "inode 15\n"
    finally:
        dialog.close()


# -- round-2 verification: hostile images ----------------------------------------------


def _secret(tmp_path):
    secret = tmp_path / "private" / "id_key"
    secret.parent.mkdir()
    secret.write_bytes(b"TOP-SECRET-KEY-MATERIAL\n" + b"\0" * (64 * 1024 - 24))
    return secret


@pytest.mark.skipif(QEMU_IMG is None, reason="qemu-img not installed")
@pytest.mark.parametrize("name", ["evidence.img", "vm.qcow2"])
def test_sad_convert_refuses_an_image_whose_backing_file_is_a_local_file(tmp_path, name):
    """A qcow2 header (also inside a file named .img - qemu-img probes the
    format) can name any readable file as its backing file; converting it
    copied that file into the "raw image"."""
    secret = _secret(tmp_path)
    image = tmp_path / "case" / name
    image.parent.mkdir()
    subprocess.run([QEMU_IMG, "create", "-q", "-f", "qcow2", "-b", str(secret), "-F", "raw",
                    str(image), "64K"], check=True)
    with pytest.raises(FT.ToolError, match="backing file"):
        FT.convert_to_raw(str(image))
    assert not any(p.suffix == ".raw" for p in image.parent.iterdir())


@pytest.mark.skipif(QEMU_IMG is None, reason="qemu-img not installed")
def test_sad_convert_refuses_a_vmdk_whose_extent_lies_outside_its_folder(tmp_path):
    secret = _secret(tmp_path)
    image = tmp_path / "case" / "disk.vmdk"
    image.parent.mkdir()
    image.write_text(
        "# Disk DescriptorFile\nversion=1\nCID=fffffffe\nparentCID=ffffffff\n"
        'createType="monolithicFlat"\n\n'
        f'RW 128 FLAT "../private/{secret.name}" 0\n\n'
        'ddb.virtualHWVersion = "4"\n')
    with pytest.raises(FT.ToolError, match="outside"):
        FT.convert_to_raw(str(image))
    assert not (image.parent / "disk.raw").exists()


@pytest.mark.skipif(QEMU_IMG is None, reason="qemu-img not installed")
def test_edge_a_flat_vmdk_with_its_extent_beside_it_still_converts(tmp_path):
    folder = tmp_path / "case"
    folder.mkdir()
    data = os.urandom(64 * 1024)
    (folder / "disk-flat.vmdk").write_bytes(data)
    image = folder / "disk.vmdk"
    image.write_text(
        "# Disk DescriptorFile\nversion=1\nCID=fffffffe\nparentCID=ffffffff\n"
        'createType="monolithicFlat"\n\nRW 128 FLAT "disk-flat.vmdk" 0\n\n'
        'ddb.virtualHWVersion = "4"\n')
    target = FT.convert_to_raw(str(image))
    # (qemu-img 2.12 counts the one extent twice; the data comes first.)
    assert Path(target).read_bytes()[:len(data)] == data


def test_sad_convert_names_the_format_it_checked_and_cleans_up(tmp_path, monkeypatch):
    """The format qemu-img info reported is passed with -f, so convert does
    not probe again; a convert that fails after writing leaves no file."""
    log = tmp_path / "argv.log"
    bin_dir = stub(tmp_path, "qemu-img", (
        f'echo "$@" >> "{log}"\n'
        'if [ "$1" = info ]; then echo \'{"format": "qcow2", "virtual-size": 1}\'; exit 0; fi\n'
        'for last; do :; done; echo partial > "$last"; echo "qemu-img: write failed" >&2; exit 1'))
    monkeypatch.setenv("PATH", f"{bin_dir}:{os.environ['PATH']}")
    src = tmp_path / "a.qcow2"
    src.write_bytes(b"x")
    target = tmp_path / "a.raw"
    with pytest.raises(FT.ToolError, match="write failed"):
        FT.convert_to_raw(str(src), str(target))
    assert not target.exists()
    convert = [ln for ln in log.read_text().splitlines() if ln.startswith("convert")][0]
    assert convert.split()[:5] == ["convert", "-f", "qcow2", "-O", "raw"]


def test_edge_file_names_that_are_not_utf8_do_not_break_the_listing(tmp_path, monkeypatch):
    """ext file names are raw bytes and fls prints them as they are; one such
    name made the whole Browse fail with UnicodeDecodeError."""
    bin_dir = stub(tmp_path, "fls", "printf 'r/r 12:\\thello.txt\\nr/r 13:\\tcaf\\351.txt\\n'")
    monkeypatch.setenv("PATH", f"{bin_dir}:{os.environ['PATH']}")
    entries = FT.list_files("/img/d.img", 0)
    assert [e.inode for e in entries] == ["12", "13"]
    assert entries[1].path.startswith("caf")


def _browse(tmp_path, monkeypatch, fls_text):
    """The Browse dialog through activate() with *fls_text* as fls output."""
    from types import SimpleNamespace

    from PyQt6.QtWidgets import QMainWindow

    qapp()
    (tmp_path / "fls.txt").write_text(fls_text)
    bin_dir = stub(tmp_path, "fls", f'cat "{tmp_path}/fls.txt"')
    stub(tmp_path, "icat", 'echo "inode $4"')
    monkeypatch.setenv("PATH", f"{bin_dir}:{os.environ['PATH']}")
    image = gpt_image([(LINUX, 2048, 4095, "root")], size=4 * 1024 * 1024)
    put_ext4(image, 2048 * SECTOR, b"r")
    img = tmp_path / "disk.img"
    img.write_bytes(bytes(image))
    gui = []

    class Api:
        window = QMainWindow()
        actions = {}

        def add_context_action(self, label, cb, applies_to="any", extensions=()):
            self.actions[label] = cb

        def run_in_background(self, work, on_done=None, on_error=None):
            result = work()
            start = time.monotonic()
            on_done(result)
            gui.append(time.monotonic() - start)

        def notify(self, text):
            self.note = text

    api = Api()
    FT.activate(api)
    ctx = SimpleNamespace(backend=LocalFS(), folder=str(tmp_path), paths=[str(img)], items=[],
                          pane=None, is_local=True)
    api.actions["Browse File System (Sleuth Kit)…"](ctx)
    return api.window._forensic_browse_dialog, gui


def test_edge_a_listing_at_the_line_cap_opens_and_filters_without_freezing(tmp_path, monkeypatch):
    """200 000 entries (the cap; a Windows image has more files) built
    800 000 table items on the GUI thread (16 s) and each filter keystroke
    hid rows one by one (97 s) - measured before the fix."""
    many = "".join(f"r/r {i}:\tdir/file{i}.txt\n" for i in range(1, FT.MAX_FLS_LINES + 1))
    dialog, gui = _browse(tmp_path, monkeypatch, many)
    try:
        start = time.monotonic()
        dialog.filter.setText("file199999")
        filtered = time.monotonic() - start
        assert dialog.visible_entries() == [dialog.entries[199998]]
        assert sum(gui) + filtered < 20, (gui, filtered)
    finally:
        dialog.close()


def test_e2e_select_all_after_a_filter_extracts_only_what_is_shown(tmp_path, monkeypatch):
    from PyQt6.QtWidgets import QFileDialog

    dialog, _gui = _browse(tmp_path, monkeypatch, FLS_OUTPUT)
    try:
        dialog.filter.setText("docs/")
        dialog.table.selectAll()
        out = tmp_path / "out"
        out.mkdir()
        monkeypatch.setattr(QFileDialog, "getExistingDirectory", lambda *a, **k: str(out))
        dialog.extract_selected()
        assert sorted(p.name for p in out.iterdir()) == ["deleted_docs_secret.txt",
                                                         "docs_report_final.pdf"]
    finally:
        dialog.close()


# -- bughunt 2026-10-22 ----------------------------------------------------------------------


def test_sad_an_icat_that_times_out_leaves_no_half_file(tmp_path, monkeypatch):
    """icat hangs past the timeout: a ToolError, and the half-written file
    is gone - before, TimeoutExpired escaped and the partial file stayed,
    so the next Extract kept it as "existing"."""
    bin_dir = stub(tmp_path, "icat", 'echo partial; exec sleep 5')
    monkeypatch.setenv("PATH", f"{bin_dir}:{os.environ['PATH']}")
    monkeypatch.setattr(FT, "TIMEOUT", 1)
    out = tmp_path / "out"
    out.mkdir()
    with pytest.raises(FT.ToolError, match="hello.txt"):
        FT.extract("/img/d.img", FT.parse_fls("r/r 12:\thello.txt"), str(out))
    assert os.listdir(out) == []


def test_sad_an_icat_that_cannot_start_leaves_no_empty_file(tmp_path, monkeypatch):
    monkeypatch.setattr(FT, "need", lambda tool: str(tmp_path / "no-such-icat"))
    out = tmp_path / "out"
    out.mkdir()
    with pytest.raises(FT.ToolError):
        FT.extract("/img/d.img", FT.parse_fls("r/r 12:\thello.txt"), str(out))
    assert os.listdir(out) == []


def test_happy_entries_with_the_same_name_are_all_extracted(tmp_path, monkeypatch):
    """fls lists several deleted files of one path (one per inode) - every
    one selected is extracted, the later ones under a name with their
    inode. Before, the second was skipped as "existing" without a word."""
    bin_dir = stub(tmp_path, "icat", 'echo "inode $4"')
    monkeypatch.setenv("PATH", f"{bin_dir}:{os.environ['PATH']}")
    out = tmp_path / "out"
    out.mkdir()
    lines = ("r/r * 45:\tdocs/report.doc\nr/r * 67:\tdocs/report.doc\n"
             "r/r 70:\tdocs/report.doc\nr/r 71:\tdocs_report.doc\n")
    written = FT.extract("/img/d.img", FT.parse_fls(lines), str(out))
    assert len(written) == 4
    contents = sorted((out / os.path.basename(w)).read_text() for w in written)
    assert contents == ["inode 45\n", "inode 67\n", "inode 70\n", "inode 71\n"]
    assert (out / "deleted_docs_report.doc").read_text() == "inode 45\n"
    assert (out / "deleted_docs_report-67.doc").read_text() == "inode 67\n"


def test_edge_extracting_the_same_selection_twice_writes_nothing_new(tmp_path, monkeypatch):
    """The names are the same each time, so a second Extract into the same
    folder keeps every file of the first and adds no copies."""
    bin_dir = stub(tmp_path, "icat", 'echo "inode $4"')
    monkeypatch.setenv("PATH", f"{bin_dir}:{os.environ['PATH']}")
    out = tmp_path / "out"
    out.mkdir()
    entries = FT.parse_fls("r/r * 45:\ta.txt\nr/r * 67:\ta.txt\n")
    assert len(FT.extract("/img/d.img", entries, str(out))) == 2
    assert FT.extract("/img/d.img", entries, str(out)) == []
    assert sorted(os.listdir(out)) == ["deleted_a-67.txt", "deleted_a.txt"]


def test_edge_a_file_made_meanwhile_is_not_removed(tmp_path, monkeypatch):
    """The target appears between the check and the open: open refuses
    (exclusive) and the other file stays as it is."""
    bin_dir = stub(tmp_path, "icat", 'echo new')
    monkeypatch.setenv("PATH", f"{bin_dir}:{os.environ['PATH']}")
    out = tmp_path / "out"
    out.mkdir()
    real_exists = os.path.exists

    def late_file(path):
        found = real_exists(path)
        if str(path) == str(out / "hello.txt") and not found:
            Path(path).write_text("someone else's")
        return found

    monkeypatch.setattr(FT.os.path, "exists", late_file)
    with pytest.raises(FileExistsError):
        FT.extract("/img/d.img", FT.parse_fls("r/r 12:\thello.txt"), str(out))
    assert (out / "hello.txt").read_text() == "someone else's"


def _gpt_4k(first_lba: int, last_lba: int) -> bytearray:
    """A GPT disk with 4096-byte sectors (4Kn): header at byte 4096,
    entries from LBA 2, one Linux partition."""
    import struct
    import uuid

    from tests.test_disk_image import guid_bytes

    lba = 4096
    image = bytearray((last_lba + 8) * lba)
    image[446:462] = struct.pack("<B3xB3xII", 0, 0xEE, 1, len(image) // lba - 1)
    image[510:512] = b"\x55\xaa"
    entry = bytearray(128)
    entry[0:16] = guid_bytes(LINUX)
    entry[16:32] = uuid.uuid4().bytes_le
    entry[32:48] = struct.pack("<QQ", first_lba, last_lba)
    header = bytearray(92)
    header[0:8] = b"EFI PART"
    header[72:80] = struct.pack("<Q", 2)
    header[80:84] = struct.pack("<I", 128)
    header[84:88] = struct.pack("<I", 128)
    image[lba:lba + 92] = header
    image[2 * lba:2 * lba + 128] = entry
    return image


def test_sad_a_4k_sector_disk_is_browsed_at_the_partition_byte_offset(tmp_path, monkeypatch):
    """fls / icat take -o in 512-byte sectors unless -b names another size
    (The Sleuth Kit: raw.cpp ``img_info->sector_size = 512`` unless a_ssize;
    fls.cpp opens the file system at ``imgaddr * img->sector_size``). On a
    4Kn GPT disk the offset was counted in 4096-byte sectors: fls looked an
    eighth of the way in and found no file system."""
    from types import SimpleNamespace

    from PyQt6.QtWidgets import QMainWindow

    from core import disk_image as DI

    qapp()
    image = _gpt_4k(256, 1023)  # the partition starts at byte 1 MiB
    put_ext4(image, 256 * 4096, b"root4k")
    img = tmp_path / "disk4k.img"
    img.write_bytes(bytes(image))
    info = DI.inspect_path(str(img))
    assert info.sector_size == 4096 and info.partitions[0].start == 1024 * 1024
    # A Sleuth Kit stand-in that, like fls, reads at -o times 512 bytes.
    (tmp_path / "fls.txt").write_text(FLS_OUTPUT)
    bin_dir = stub(tmp_path, "fls", f'[ "$4" = 2048 ] || {{ echo "Cannot determine file system type '
                                    f'(offset $4)" >&2; exit 1; }}; cat "{tmp_path}/fls.txt"')
    stub(tmp_path, "icat", '[ "$2" = 2048 ] || exit 1; echo "inode $4"')
    monkeypatch.setenv("PATH", f"{bin_dir}:{os.environ['PATH']}")
    errors = []

    class Api:
        window = QMainWindow()
        actions = {}

        def add_context_action(self, label, cb, applies_to="any", extensions=()):
            self.actions[label] = cb

        def run_in_background(self, work, on_done=None, on_error=None):
            try:
                result = work()
            except Exception as exc:  # noqa: BLE001
                errors.append(str(exc))
                return
            on_done(result)

        def notify(self, text):
            self.note = text

    from PyQt6.QtWidgets import QMessageBox

    monkeypatch.setattr(QMessageBox, "warning", lambda *a, **k: errors.append(a[2]))
    api = Api()
    FT.activate(api)
    ctx = SimpleNamespace(backend=LocalFS(), folder=str(tmp_path), paths=[str(img)], items=[],
                          pane=None, is_local=True)
    api.actions["Browse File System (Sleuth Kit)…"](ctx)
    assert errors == []
    dialog = api.window._forensic_browse_dialog
    try:
        assert dialog.sector == 2048 and dialog.table.model().rowCount() == 9
        written = FT.extract(str(img), FT.parse_fls("r/r 12:\thello.txt"), str(tmp_path),
                             dialog.sector)
        assert Path(written[0]).read_text() == "inode 12\n"
    finally:
        dialog.close()


def test_edge_a_partition_off_the_512_byte_grid_is_refused_with_a_reason(tmp_path, monkeypatch):
    """A fixed VDI whose data offset is no multiple of 512: fls cannot be
    pointed at it, so it is said instead of reading the wrong bytes."""
    from types import SimpleNamespace

    from PyQt6.QtWidgets import QMainWindow, QMessageBox

    from core import disk_image as DI

    qapp()
    shown, ran = [], []
    monkeypatch.setattr(QMessageBox, "warning", lambda *a, **k: shown.append(a[2]))
    odd = DI.ImageInfo(size=10_000, kind="vdi", scheme="none", partitions=[
        DI.Partition(0, 1000, 9000, "none", filesystem="ext4")])

    class Api:
        window = QMainWindow()
        actions = {}

        def add_context_action(self, label, cb, applies_to="any", extensions=()):
            self.actions[label] = cb

        def run_in_background(self, work, on_done=None, on_error=None):
            ran.append(work)
            on_done(odd if len(ran) == 1 else work())

    monkeypatch.setattr(DI, "inspect_path", lambda path: odd)
    api = Api()
    FT.activate(api)
    ctx = SimpleNamespace(backend=LocalFS(), folder=str(tmp_path), paths=[str(tmp_path / "x.vdi")],
                          items=[], pane=None, is_local=True)
    api.actions["Browse File System (Sleuth Kit)…"](ctx)
    assert len(ran) == 1 and "512-byte" in shown[0]


def test_edge_the_same_entry_twice_is_extracted_once(tmp_path, monkeypatch):
    bin_dir = stub(tmp_path, "icat", 'echo "inode $4"')
    monkeypatch.setenv("PATH", f"{bin_dir}:{os.environ['PATH']}")
    out = tmp_path / "out"
    out.mkdir()
    (entry,) = FT.parse_fls("r/r 12:\thello.txt\n")
    assert len(FT.extract("/img/d.img", [entry, entry], str(out))) == 1
    assert os.listdir(out) == ["hello.txt"]
