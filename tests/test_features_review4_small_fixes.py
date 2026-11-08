"""The small findings of review 4 (features/extensions).

- Scheduled Jobs accepted a script that does not exist, and its run failed
  with "[Errno 2] No such file or directory: '/home/…/x.py'"; there was no
  Run Now.
- metadata_read said "size": 0 for every file it could not read.
- Seven tabs made from seven agent profiles all read "New task".
- Create SHA256SUMS never wrote over an existing manifest (no way to update
  it) and said "no files to checksum" for a selected folder.
- Mail Project > Import from Mailbox never closed its connection.
- The Media Player said "the sound card's stream keeps closing" on a
  machine without any audio device.
- A narrow dock title was cut mid-letter, without "…".
- Forensic Tools: "X is not installed" without the way to install it.
- mail_list_new described the old "only opened mail counts" rule.
"""

from __future__ import annotations

import importlib.util
import os
import sys
import time
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
pytest.importorskip("PyQt6.QtWidgets", reason="PyQt6 not installed")

from PyQt6.QtWidgets import QApplication  # noqa: E402

from core import extensions as EX  # noqa: E402
from core.local_fs import LocalFS  # noqa: E402
from core.scheduler import Job, JobStore  # noqa: E402

APP = QApplication.instance() or QApplication([])


def _load(name: str):
    path = EX.bundled_dir() / f"{name}.py"
    spec = importlib.util.spec_from_file_location(f"review4_{name}", path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module      # a @dataclass looks its module up
    spec.loader.exec_module(module)
    return module


# -- Scheduled Jobs ------------------------------------------------------------------------


def test_sad_a_job_for_a_script_that_does_not_exist_is_refused(tmp_path, monkeypatch):
    from ui import scheduler_dialog as SD

    monkeypatch.setattr(SD.SchedulerDialog, "_saved_scripts", staticmethod(lambda: ["mirror"]))
    store = JobStore(tmp_path / "jobs.json")
    dlg = SD.SchedulerDialog(store)
    dlg._name_edit.setText("nightly")
    dlg._target_edit.setText("does_not_exist")
    with mock.patch.object(SD.QMessageBox, "warning") as warn:
        dlg._on_add()
    assert store.load() == []
    assert "does_not_exist" in warn.call_args.args[2] and "mirror" in warn.call_args.args[2]
    dlg._target_edit.setText("mirror")
    dlg._on_add()
    assert [j.target for j in store.load()] == ["mirror"]
    dlg.deleteLater()


def test_edge_a_job_whose_script_was_deleted_says_so_in_a_sentence(monkeypatch):
    from core import scheduler

    monkeypatch.setattr("core.security_mode.require", lambda *a, **k: None)
    job = Job(job_id="j", name="n", kind="script", target="gone_script_review4", interval_s=3600)
    with pytest.raises(RuntimeError) as err:
        scheduler.run_script_job(job)
    text = str(err.value)
    assert "does not exist" in text and "gone_script_review4" in text and "Errno" not in text


def test_happy_run_now_starts_the_selected_job(tmp_path, monkeypatch):
    from ui import scheduler_dialog as SD

    monkeypatch.setattr(SD.SchedulerDialog, "_saved_scripts", staticmethod(lambda: ["mirror"]))
    started = []
    dlg = SD.SchedulerDialog(JobStore(tmp_path / "jobs.json"), run_now=lambda j: started.append(j.name) or True)
    dlg.add_job(name="nightly", kind="script", target="mirror", interval_s=3600)
    dlg._table.selectRow(0)
    dlg._on_run_now()
    assert started == ["nightly"] and "nightly" in dlg.status_text()
    assert not dlg._run_btn.isHidden()
    dlg.deleteLater()


# -- metadata_read --------------------------------------------------------------------------


def test_happy_metadata_read_reports_the_size_of_a_file_it_does_not_read(tmp_path):
    from core.metadata_tools import read_metadata

    (tmp_path / "hello.txt").write_text("hello\n")
    report = read_metadata(LocalFS(), str(tmp_path / "hello.txt"))
    assert report.error and report.size == 6


# -- agent tabs from profiles ---------------------------------------------------------------


def test_happy_a_tab_from_a_profile_is_labelled_with_the_profile():
    from ui.agent_dock import tab_label

    assert tab_label(SimpleNamespace(title="New task", agent_profile="Research")) == "Research"
    assert tab_label(SimpleNamespace(title="New task", agent_profile="")) == "New task"
    assert tab_label(SimpleNamespace(title="check the disk", agent_profile="Research")) == "check the disk"


# -- SHA256SUMS ---------------------------------------------------------------------------


class _Api:
    window = None

    def __init__(self):
        self.notes, self.entries = [], {}

    def notify(self, text, *a, **k):
        self.notes.append(text)

    def run_in_background(self, work, on_done=None, on_error=None):
        result = work()
        if on_done is not None:
            on_done(result)

    def add_context_action(self, label, callback, **kw):
        self.entries[label] = callback


def _create(CM):
    api = _Api()
    CM.activate(api)
    return api, api.entries["Create SHA256SUMS"]


def _item(path: Path):
    return next(i for i in LocalFS().list_dir(str(path.parent)) if i.name == path.name)


def test_happy_an_existing_manifest_can_be_updated(tmp_path, monkeypatch):
    CM = _load("checksum_manifest")
    (tmp_path / "a.txt").write_text("a")
    (tmp_path / "b.txt").write_text("b")
    other = "0" * 64
    (tmp_path / "SHA256SUMS").write_text(f"{other}  old.bin\n{'1' * 64}  a.txt\n")
    monkeypatch.setattr(CM, "ask_existing", lambda *a: "update")
    api, create = _create(CM)
    create(SimpleNamespace(items=[_item(tmp_path / "a.txt")], backend=LocalFS(),
                           folder=str(tmp_path), pane=None))
    pairs = dict((n, d) for d, n in CM.parse_manifest((tmp_path / "SHA256SUMS").read_text()))
    assert pairs["old.bin"] == other                       # kept
    assert pairs["a.txt"] == CM.sha256_of(LocalFS(), str(tmp_path / "a.txt"))   # renewed
    assert "b.txt" not in pairs
    assert "wrote SHA256SUMS for 1 file(s)" == api.notes[-1]


def test_sad_replace_writes_only_the_files_hashed_now(tmp_path, monkeypatch):
    CM = _load("checksum_manifest")
    (tmp_path / "a.txt").write_text("a")
    (tmp_path / "SHA256SUMS").write_text(f"{'0' * 64}  old.bin\n")
    monkeypatch.setattr(CM, "ask_existing", lambda *a: "replace")
    _api, create = _create(CM)
    create(SimpleNamespace(items=[], backend=LocalFS(), folder=str(tmp_path), pane=None))
    names = [n for _d, n in CM.parse_manifest((tmp_path / "SHA256SUMS").read_text())]
    assert names == ["a.txt"]


def test_edge_a_selected_folder_gets_a_manifest_of_its_files(tmp_path):
    CM = _load("checksum_manifest")
    sub = tmp_path / "photos"
    sub.mkdir()
    (sub / "x.jpg").write_bytes(b"x")
    (sub / "y.jpg").write_bytes(b"y")
    api, create = _create(CM)
    create(SimpleNamespace(items=[_item(sub)], backend=LocalFS(), folder=str(tmp_path), pane=None))
    names = [n for _d, n in CM.parse_manifest((sub / "SHA256SUMS").read_text())]
    assert names == ["x.jpg", "y.jpg"] and not (tmp_path / "SHA256SUMS").exists()


# -- Mail Project: the import's connection --------------------------------------------------


def test_happy_import_from_mailbox_closes_its_connection(tmp_path, monkeypatch):
    from core import profiles as PR
    from ui.mail_project import MailProjectDialog

    class Backend:
        closed = False

        def list_dir(self, path):
            self.listed = path
            return []

        def close(self):
            Backend.closed = True

    profile = SimpleNamespace(protocol="pop3")

    class PM:
        def list_names(self):
            return ["pop"]

        def get(self, name):
            return profile

    monkeypatch.setattr(PR, "ProfileManager", PM)
    folders = []
    monkeypatch.setattr("ui.mail_project.QInputDialog.getItem", staticmethod(lambda *a, **k: ("pop", True)))
    monkeypatch.setattr("ui.mail_project.QInputDialog.getText",
                        staticmethod(lambda *a, **k: folders.append(k.get("text")) or ("/", True)))
    dlg = MailProjectDialog(connect=lambda p: Backend())
    dlg.open_project(str(tmp_path / "proj"))
    dlg.import_mailbox()
    end = time.monotonic() + 10
    while not Backend.closed and time.monotonic() < end:
        APP.processEvents()
        time.sleep(0.01)
    assert Backend.closed
    assert folders == ["/"]          # POP3: its mail is at "/"
    dlg.close()
    dlg.deleteLater()


# -- Media Player, dock titles, Forensic Tools, mail tools ------------------------------------


def test_sad_no_audio_device_is_named(monkeypatch):
    MP = _load("media_player")
    from core import multimedia_probe

    monkeypatch.setattr(multimedia_probe, "cached",
                        lambda: SimpleNamespace(ok=True, outputs=0, inputs=0))
    assert MP.no_audio_device()
    monkeypatch.setattr(multimedia_probe, "cached",
                        lambda: SimpleNamespace(ok=True, outputs=2, inputs=1))
    assert not MP.no_audio_device()
    monkeypatch.setattr(multimedia_probe, "cached", lambda: None)
    assert not MP.no_audio_device()


def test_edge_a_narrow_dock_title_is_cut_with_an_ellipsis():
    from PyQt6.QtWidgets import QDockWidget

    from ui.dock_titlebar import DockTitleBar

    dock = QDockWidget()
    bar = DockTitleBar("A rather long panel title that does not fit", "extensions", dock)
    label = bar._title_label
    label.resize(60, 20)
    assert label.shown_text().endswith("…") and label.text().startswith("A rather long")
    label.resize(2000, 20)
    assert label.shown_text() == label.text()
    dock.deleteLater()


def test_happy_a_missing_forensic_program_offers_the_features_page(monkeypatch):
    FT = _load("forensic_tools")
    assert FT.feature_key("fls") == "tool:sleuthkit"
    assert FT.feature_key("photorec") == "tool:testdisk"
    monkeypatch.setattr(FT.shutil, "which", lambda name: None)
    with pytest.raises(FT.ToolMissing) as err:
        FT.need("qemu-img")
    assert err.value.tool == "qemu-img" and isinstance(err.value, FT.ToolError)

    offered = []
    monkeypatch.setattr("ui.features_dialog.offer_features",
                        lambda parent, key, text: offered.append((key, text)))
    api = _Api()
    FT.activate(api)
    carve = api.entries["Carve Files (PhotoRec)"]
    carve(SimpleNamespace(is_local=True, paths=["/tmp/disk.img"]))
    assert offered and offered[0][0] == "tool:testdisk" and "photorec" in offered[0][1]


def test_edge_mail_list_new_describes_how_mail_is_marked_handled():
    from core import mail_dock as MD

    tools = MD.MailTools(MD.MailDockConfig(name="x", mailbox_profile="imap"), mailbox=None,
                         ask_send=lambda *a: False, smtp=lambda: None, drafts_dir=Path("/nonexistent"),
                         bus=MD.DockBus()).function_tools()
    text = next(t.description for t in tools if t.name == "mail_list_new")
    assert "once this run ends with an answer" in text

