"""The Backup Repositories extension (punch-list item 19).

Operator: *„eine extension die in der lage ist duplicity archive zu lesen mit
dem passenden passwort oder key, sodass man wenigstens die basic infos
bekommt, das gleiche fuer restic und borg"*.

restic runs for real (a repository made here with two snapshots); the Borg
and duplicity layouts are built as those tools write them, and their CLIs
are checked in a container (tests/test_backup_repos_container.py style runs
are recorded in the evidence, not here).
"""

from __future__ import annotations

import importlib.util
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from core import extensions as EX  # noqa: E402
from core.local_fs import LocalFS  # noqa: E402


def load():
    path = EX.bundled_dir() / "backup_repos.py"
    spec = importlib.util.spec_from_file_location("example_backup_repos", path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


BR = load()
FS = LocalFS()
RESTIC = shutil.which("restic")

BORG_CONFIG = """[repository]
version = 1
segments_per_dir = 1000
max_segment_size = 524288000
append_only = 0
storage_quota = 0
additional_free_space = 0
id = 4c0ffee0c0ffee0c0ffee0c0ffee0c0ffee0c0ffee0c0ffee0c0ffee0c0ffee0
key = hqlhbGdvcml0aG2mc2hhMjU2pGRhdGHaAN6Y
"""


def borg_repo(root: Path, repokey=True) -> Path:
    root.mkdir()
    (root / "README").write_text("This is a Borg Backup repository.\nSee https://borgbackup.readthedocs.io/\n")
    text = BORG_CONFIG if repokey else BORG_CONFIG.replace(BORG_CONFIG.splitlines()[-1], "key = ")
    (root / "config").write_text(text)
    (root / "data" / "0").mkdir(parents=True)
    for n in (1, 2, 3):
        (root / "data" / "0" / str(n)).write_bytes(b"BORG_SEG" + b"\0" * 10)
    (root / "hints.3").write_bytes(b"x")
    (root / "index.3").write_bytes(b"x")
    return root


DUP_FILES = {
    "duplicity-full.20260101T100000Z.manifest.gpg": 900,
    "duplicity-full.20260101T100000Z.vol1.difftar.gpg": 26_214_400,
    "duplicity-full.20260101T100000Z.vol2.difftar.gpg": 1_048_576,
    "duplicity-full-signatures.20260101T100000Z.sigtar.gpg": 5000,
    "duplicity-inc.20260101T100000Z.to.20260102T100000Z.manifest.gpg": 700,
    "duplicity-inc.20260101T100000Z.to.20260102T100000Z.vol1.difftar.gpg": 2048,
    "duplicity-new-signatures.20260101T100000Z.to.20260102T100000Z.sigtar.gpg": 300,
    "duplicity-inc.20260102T100000Z.to.20260103T100000Z.vol1.difftar.gpg": 4096,
    "duplicity-full.20260201T080000Z.vol1.difftar.gpg": 10_000,
    "unrelated.txt": 3,
}


def dup_repo(root: Path, files=DUP_FILES) -> Path:
    root.mkdir()
    for name, size in files.items():
        with open(root / name, "wb") as fh:
            fh.truncate(size)
    return root


@pytest.fixture
def restic_repo(tmp_path):
    if RESTIC is None:
        pytest.skip("restic not installed")
    repo, src = tmp_path / "repo", tmp_path / "src"
    src.mkdir()
    (src / "a.txt").write_text("one")
    env = {**os.environ, "RESTIC_PASSWORD": "correct horse", "RESTIC_CACHE_DIR": str(tmp_path / "c")}
    subprocess.run([RESTIC, "init", "--repo", str(repo)], env=env, check=True, capture_output=True)
    for tag in ("first", "second"):
        (src / f"{tag}.txt").write_text(tag)
        subprocess.run([RESTIC, "--repo", str(repo), "backup", "--tag", tag, "--host", "lab",
                        str(src)], env=env, check=True, capture_output=True)
    truth = json.loads(subprocess.run([RESTIC, "--repo", str(repo), "snapshots", "--json"],
                                      env=env, check=True, capture_output=True).stdout)
    return repo, truth


# -- happy ------------------------------------------------------------------------------


def test_happy_restic_detected_and_counted_without_password(restic_repo):
    repo, truth = restic_repo
    assert BR.detect(FS, str(repo)) == "restic"
    facts = dict(BR.basic_info(FS, str(repo)).facts)
    assert facts["Snapshots"] == str(len(truth)) == "2" and facts["Keys"] == "1"


def test_happy_restic_unlocked_lists_the_snapshots(restic_repo, monkeypatch, tmp_path):
    repo, truth = restic_repo
    monkeypatch.setenv("RESTIC_CACHE_DIR", str(tmp_path / "c"))
    before = sorted(p.relative_to(repo) for p in repo.rglob("*"))
    snaps = BR.unlock("restic", str(repo), "correct horse")
    assert sorted(s.id for s in snaps) == sorted(t["short_id"] for t in truth)
    assert sorted(s.tags[0] for s in snaps) == ["first", "second"]
    assert all(s.host == "lab" for s in snaps)
    # --no-lock: the repository is unchanged (no lock file left or written).
    assert sorted(p.relative_to(repo) for p in repo.rglob("*")) == before


def test_happy_borg_layout(tmp_path):
    repo = borg_repo(tmp_path / "borg")
    assert BR.detect(FS, str(repo)) == "borg"
    info = BR.basic_info(FS, str(repo))
    facts = dict(info.facts)
    assert facts["Version"] == "1" and facts["Segments"] == "3"
    assert facts["Key"].startswith("in the repository") and not info.needs_keyfile
    assert facts["Repository id"].startswith("4c0ffee0")


def test_happy_duplicity_chains_from_the_names(tmp_path):
    repo = dup_repo(tmp_path / "dup")
    assert BR.detect(FS, str(repo)) == "duplicity"
    info = BR.basic_info(FS, str(repo))
    facts = dict(info.facts)
    assert facts["Backup chains"] == "2" and facts["Encryption"] == "GnuPG"
    rows = [(s.id, s.time, s.note) for s in info.snapshots]
    assert rows[0] == ("full 20260101T100000Z", "2026-01-01 10:00:00 UTC",
                       "2 volume(s), 26.0 MiB, 2 incremental")
    assert [r[0] for r in rows] == ["full 20260101T100000Z", "inc 20260102T100000Z",
                                    "inc 20260103T100000Z", "full 20260201T080000Z"]


def test_happy_the_context_action_is_offered_for_one_folder():
    # One repository per window, with its own password prompt: the action
    # is offered for the current folder or ONE selected folder - never for
    # several, where all but the first were silently ignored.
    actions = []

    class Api:
        window = None

        def add_context_action(self, label, cb, applies_to="any", extensions=()):
            actions.append((label, applies_to))

    BR.activate(Api())
    assert actions == [("Backup Repository Info…", "folder"),
                       ("Backup Repository Info…", "single_folder")]


# -- sad --------------------------------------------------------------------------------


def test_sad_a_plain_folder_is_no_repository(tmp_path):
    (tmp_path / "x.txt").write_text("x")
    assert BR.detect(FS, str(tmp_path)) is None
    with pytest.raises(BR.RepoError, match="no restic, Borg or duplicity"):
        BR.basic_info(FS, str(tmp_path))


def test_sad_a_wrong_restic_password(restic_repo, monkeypatch, tmp_path):
    repo, _truth = restic_repo
    monkeypatch.setenv("RESTIC_CACHE_DIR", str(tmp_path / "c"))
    with pytest.raises(BR.RepoError, match="(?i)wrong password|no key found"):
        BR.unlock("restic", str(repo), "nope")


def test_sad_the_password_is_never_on_the_command_line(monkeypatch):
    seen = {}

    def fake_run(argv, **kw):
        seen["argv"], seen["env"] = argv, kw["env"]

        class P:
            returncode, stderr = 0, ""
            stdout = '{"archives": []}' if argv[1] == "list" else "[]"
        return P()

    monkeypatch.setattr(BR.subprocess, "run", fake_run)
    monkeypatch.setenv("RESTIC_PASSWORD_FILE", "/elsewhere")
    monkeypatch.setenv("BORG_BASE_DIR", "/kept")
    BR.restic_snapshots("/r", "s3cret")
    assert "s3cret" not in " ".join(seen["argv"]) and seen["env"]["RESTIC_PASSWORD"] == "s3cret"
    assert "RESTIC_PASSWORD_FILE" not in seen["env"]  # an inherited setting cannot override
    BR.borg_archives("/r", "s3cret", keyfile="/k")
    assert "s3cret" not in " ".join(seen["argv"]) and seen["env"]["BORG_KEY_FILE"] == "/k"
    assert "--bypass-lock" in seen["argv"]
    # Settings that do not override the password stay (found in the container run).
    assert seen["env"]["BORG_BASE_DIR"] == "/kept"


def test_sad_a_missing_tool(monkeypatch):
    monkeypatch.setattr(BR, "tool_for", lambda kind: None)
    with pytest.raises(BR.RepoError, match="not installed"):
        BR.unlock("borg", "/r", "pw")


def test_sad_a_broken_borg_config(tmp_path):
    repo = borg_repo(tmp_path / "borg")
    (repo / "config").write_text("[repository]\nversion = 1\n[repository]\n")
    with pytest.raises(BR.RepoError, match="unreadable"):
        BR.basic_info(FS, str(repo), "borg")


# -- edge -------------------------------------------------------------------------------


def test_edge_borg_keyfile_mode_asks_for_the_key(tmp_path):
    info = BR.basic_info(FS, str(borg_repo(tmp_path / "borg", repokey=False)))
    assert info.needs_keyfile and dict(info.facts)["Key"].startswith("kept outside")


def test_edge_duplicity_unencrypted_and_an_orphan_incremental(tmp_path):
    files = {
        "duplicity-inc.20250101T000000Z.to.20250102T000000Z.vol1.difftar.gz": 10,
        "duplicity-full.20250201T000000Z.vol1.difftar.gz": 20,
    }
    info = BR.basic_info(FS, str(dup_repo(tmp_path / "d", files)))
    assert dict(info.facts)["Encryption"] == "none"
    # The incremental before any full belongs to no chain.
    assert [s.id for s in info.snapshots] == ["full 20250201T000000Z"]


def test_edge_duplicity_status_parses_the_collection_table(monkeypatch):
    out = """Last full backup date: Thu Jan  1 10:00:00 2026
Collection Status
-----------------
Connecting with backend: BackendWrapper
Archive dir: /tmp/x
Found 0 secondary backup chain(s).
Found primary backup chain with matching signature chain:
-------------------------
Chain start time: Thu Jan  1 10:00:00 2026
Chain end time: Fri Jan  2 10:00:00 2026
Number of contained backup sets: 2
Total number of contained volumes: 3
 Type of backup set:                            Time:      Num volumes:
                Full         Thu Jan  1 10:00:00 2026                 2
         Incremental         Fri Jan  2 10:00:00 2026                 1
-------------------------
No orphaned or incomplete backup sets found.
"""
    monkeypatch.setattr(BR, "_run", lambda argv, env: out)
    snaps = BR.duplicity_status("/r", "pw")
    assert [(s.id, s.time, s.note) for s in snaps] == [
        ("Full", "Thu Jan  1 10:00:00 2026", "2 volume(s)"),
        ("Incremental", "Fri Jan  2 10:00:00 2026", "1 volume(s)"),
    ]


class _FakeTools:
    """BR._run stand-in: records (argv, env, input) and answers per tool."""

    def __init__(self, gpg_error: str | None = None) -> None:
        self.calls: list[tuple[list, dict, object]] = []
        self.gpg_error = gpg_error

    def __call__(self, argv, env_extra, input_text=None):
        self.calls.append((list(argv), dict(env_extra), input_text))
        if argv[0].endswith("gpg"):
            if self.gpg_error:
                raise BR.RepoError(self.gpg_error)
            return "decrypted manifest"
        return (
            " Type of backup set:                            Time:      Num volumes:\n"
            "                Full         Thu Jan  1 10:00:00 2026                 2\n"
        )

    def tools(self) -> list[str]:
        return [Path(argv[0]).name for argv, _env, _in in self.calls]


def test_sad_a_wrong_duplicity_password_is_refused(tmp_path, monkeypatch):
    """Found by the live run (tests/test_backup_repos_live.py): duplicity
    collection-status reads only the file names, so a WRONG passphrase
    listed the chains as if it were right. The newest encrypted manifest is
    now decrypted first."""
    repo = dup_repo(tmp_path / "dup")
    fake = _FakeTools(gpg_error="gpg: decryption failed: Bad session key")
    monkeypatch.setattr(BR, "_run", fake)
    monkeypatch.setattr(BR, "tool_for", lambda kind: f"/usr/bin/{kind}")
    with pytest.raises(BR.RepoError, match="password does not open"):
        BR.unlock("duplicity", str(repo), "wrong")
    assert fake.tools() == ["gpg"]  # duplicity is not even asked


def test_happy_the_right_duplicity_password_decrypts_the_newest_manifest(tmp_path, monkeypatch):
    repo = dup_repo(tmp_path / "dup")
    fake = _FakeTools()
    monkeypatch.setattr(BR, "_run", fake)
    monkeypatch.setattr(BR, "tool_for", lambda kind: f"/usr/bin/{kind}")
    snaps = BR.unlock("duplicity", str(repo), "s3cret")
    assert [s.id for s in snaps] == ["Full"]
    assert fake.tools() == ["gpg", "duplicity"]
    gpg_argv, _env, given = fake.calls[0]
    newest = "duplicity-inc.20260101T100000Z.to.20260102T100000Z.manifest.gpg"
    assert gpg_argv[-1] == str(repo / newest)
    assert "s3cret" not in " ".join(gpg_argv) and given == "s3cret\n"  # stdin, not argv
    # A cached passphrase must not hide a wrong one.
    assert "--no-symkey-cache" in gpg_argv and "--batch" in gpg_argv


def test_edge_an_unencrypted_duplicity_repo_needs_no_gpg(tmp_path, monkeypatch):
    files = {
        "duplicity-full.20250201T000000Z.manifest": 5,
        "duplicity-full.20250201T000000Z.vol1.difftar.gz": 20,
    }
    repo = dup_repo(tmp_path / "plain", files)
    fake = _FakeTools()
    monkeypatch.setattr(BR, "_run", fake)
    monkeypatch.setattr(BR, "tool_for", lambda kind: f"/usr/bin/{kind}")
    BR.unlock("duplicity", str(repo), "")
    assert fake.tools() == ["duplicity"]


def test_sad_gpg_missing_for_an_encrypted_duplicity_repo(tmp_path, monkeypatch):
    repo = dup_repo(tmp_path / "dup")
    monkeypatch.setattr(BR, "_run", _FakeTools())
    monkeypatch.setattr(
        BR, "tool_for", lambda kind: None if kind == "gpg" else f"/usr/bin/{kind}"
    )
    with pytest.raises(BR.RepoError, match="gpg is not installed"):
        BR.unlock("duplicity", str(repo), "pw")


def test_edge_run_hands_the_password_on_stdin(monkeypatch):
    seen = {}

    def fake_run(argv, **kw):
        seen.update(kw)

        class P:
            returncode, stderr, stdout = 0, "", "ok"
        return P()

    monkeypatch.setattr(BR.subprocess, "run", fake_run)
    BR._run(["gpg"], {}, input_text="pw\n")
    assert seen["input"] == "pw\n" and "stdin" not in seen
    BR._run(["borg"], {})
    assert seen["stdin"] == BR.subprocess.DEVNULL


class SyncApi:
    """The extension API with run_in_background run at once."""

    def __init__(self):
        from PyQt6.QtWidgets import QApplication, QMainWindow

        self.app = QApplication.instance() or QApplication([])
        self.window = QMainWindow()
        self.actions, self.notes = {}, []

    def add_context_action(self, label, cb, applies_to="any", extensions=()):
        self.actions[(label, applies_to)] = cb

    def run_in_background(self, work, on_done=None, on_error=None):
        try:
            result = work()
        except Exception as exc:  # noqa: BLE001 - handed on like the host does
            if on_error:
                on_error(exc)
            return
        if on_done:
            on_done(result)

    def notify(self, text):
        self.notes.append(text)


def test_e2e_the_repository_dialog_opens_with_the_chains(tmp_path):
    from types import SimpleNamespace

    api = SyncApi()
    BR.activate(api)
    repo = dup_repo(tmp_path / "dup")
    ctx = SimpleNamespace(backend=FS, folder=str(repo), paths=[], items=[], pane=None, is_local=True)
    api.actions[("Backup Repository Info…", "folder")](ctx)
    dialog = api.window._backup_repo_dialog
    try:
        assert dialog.table.rowCount() == 4 and "Backup chains" in dialog.facts.text()
        assert dialog.unlock_button.isEnabled()
        from PyQt6.QtWidgets import QToolButton

        assert dialog.findChild(QToolButton, "axCloseCorner") is not None
    finally:
        dialog.close()


# -- round-2 verification ----------------------------------------------------------------


def test_sad_an_unencrypted_borg_repository_is_listed_without_a_prompt(tmp_path, monkeypatch):
    """Borg asks "Attempting to access a previously unknown unencrypted
    repository! Do you want to continue? [yN]" and stdin is closed: the
    listing failed with "Cache initialization aborted" (borg 1.2 in a
    container). The stub answers like borg does."""
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    borg = bin_dir / "borg"
    borg.write_text(
        "#!/bin/sh\n"
        'if [ "$BORG_UNKNOWN_UNENCRYPTED_REPO_ACCESS_IS_OK" != yes ]; then\n'
        '  echo "Warning: Attempting to access a previously unknown unencrypted repository!" >&2\n'
        '  echo "Cache initialization aborted" >&2; exit 2\nfi\n'
        "echo '{\"archives\": [{\"name\": \"plain\", \"time\": \"2026-10-22T03:00:00.000\", "
        "\"id\": \"0123456789abcdef0123\"}]}'\n")
    borg.chmod(0o755)
    monkeypatch.setenv("BORG_UNKNOWN_UNENCRYPTED_REPO_ACCESS_IS_OK", "no")
    snaps = BR.borg_archives(str(tmp_path), "", exe=str(borg))
    assert [s.id for s in snaps] == ["plain"]


def test_edge_markup_in_folder_names_and_borg_config_is_shown_literally(tmp_path):
    from types import SimpleNamespace

    api = SyncApi()
    BR.activate(api)
    repo = borg_repo(tmp_path / "<s>struck<br> &amp;")
    config = repo / "config"
    config.write_text(config.read_text().replace("version = 1", "version = <i>1</i>"))
    ctx = SimpleNamespace(backend=FS, folder=str(repo), paths=[], items=[], pane=None,
                          is_local=True)
    api.actions[("Backup Repository Info…", "folder")](ctx)
    dialog = api.window._backup_repo_dialog
    try:
        from PyQt6.QtWidgets import QLabel

        shown = [QTextDocumentText(lbl.text()) for lbl in dialog.findChildren(QLabel)]
        assert any(f"{repo}" in text for text in shown), shown
        assert any("Version: <i>1</i>" in text for text in shown), shown
    finally:
        dialog.close()


def QTextDocumentText(html: str) -> str:  # noqa: N802 - mirrors Qt's rendering
    """What a rich-text QLabel shows for *html*."""
    from PyQt6.QtGui import QTextDocument

    doc = QTextDocument()
    doc.setHtml(html)
    return doc.toPlainText().replace(" ", "\n")
