"""Backup repositories: what a restic, Borg or duplicity repository holds.

Right-click a folder (or nothing, for the current one): *Backup Repository
Info…*. Without a password - on any backend, read through the listing - it
shows what the layout tells:

* **restic**: snapshot, key, index and pack-folder counts (its config is
  encrypted);
* **Borg**: the plain ``config`` (version, id, segment settings, append-only,
  repokey or keyfile) and the segment count;
* **duplicity**: every backup chain from the file names alone - full and
  incremental backups with their times, volumes, size and encryption.

*Unlock…* asks for the password (and a Borg key file when the repository
uses one) and lists the snapshots / archives through the tool itself:
``restic snapshots --json --no-lock``, ``borg list --json --bypass-lock``,
``duplicity collection-status`` (which reads only file names, so the
password is first checked by decrypting the newest manifest with gpg).
Local repositories only; the password goes to the tool's environment
(RESTIC_PASSWORD, BORG_PASSPHRASE, PASSPHRASE) or gpg's stdin, never a
command line, and is not stored. Nothing is written to the repository.
"""

from __future__ import annotations

import configparser
import json
import os
import re
import shutil
import subprocess
import tempfile
from dataclasses import dataclass, field

from core.subprocess_env import clean_child_env

EXTENSION = {
    "name": "Backup Repositories",
    "version": "1.0",
    "description": "Right-click a folder: what a restic, Borg or duplicity repository holds - "
    "from its layout without a password, its snapshots with one.",
    "author": "axross",
}

TIMEOUT = 300
MAX_LISTED = 20000
_DUP = re.compile(
    r"^duplicity-(?P<kind>full|inc|full-signatures|new-signatures)\."
    r"(?P<a>\d{8}T\d{6}Z)(?:\.to\.(?P<b>\d{8}T\d{6}Z))?\."
    r"(?P<rest>.+)$"
)


class RepoError(RuntimeError):
    pass


@dataclass
class Snapshot:
    id: str
    time: str
    host: str = ""
    paths: list[str] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)
    note: str = ""


@dataclass
class RepoInfo:
    kind: str
    facts: list[tuple[str, str]] = field(default_factory=list)
    snapshots: list[Snapshot] = field(default_factory=list)
    needs_keyfile: bool = False


# -- detection (any backend) ------------------------------------------------------------


def _names(backend, folder: str) -> dict[str, object]:
    return {i.name: i for i in backend.list_dir(folder) if i.name not in (".", "..")}


def detect(backend, folder: str) -> str | None:
    """"restic", "borg", "duplicity" or None."""
    items = _names(backend, folder)
    dirs = {n for n, i in items.items() if i.is_dir}
    if "config" in items and {"data", "index", "keys", "snapshots"} <= dirs:
        return "restic"
    if "config" in items and "data" in dirs:
        text = _read_text(backend, backend.join(folder, "config"), 64 * 1024)
        if "[repository]" in text:
            return "borg"
    if "README" in items and "data" in dirs:
        if "Borg Backup repository" in _read_text(backend, backend.join(folder, "README"), 4096):
            return "borg"
    if any(_DUP.match(n) for n in items):
        return "duplicity"
    return None


def _read_text(backend, path: str, limit: int) -> str:
    try:
        with backend.open_read(path) as fh:
            return fh.read(limit).decode("utf-8", "replace")
    except OSError:
        return ""


def _count(backend, folder: str) -> int:
    try:
        return sum(1 for i in backend.list_dir(folder) if i.name not in (".", ".."))
    except OSError:
        return 0


def basic_info(backend, folder: str, kind: str | None = None) -> RepoInfo:
    """What the layout tells without a password."""
    kind = kind or detect(backend, folder)
    if kind == "restic":
        info = RepoInfo("restic")
        info.facts = [
            ("Snapshots", str(_count(backend, backend.join(folder, "snapshots")))),
            ("Keys", str(_count(backend, backend.join(folder, "keys")))),
            ("Index files", str(_count(backend, backend.join(folder, "index")))),
            ("Pack folders", str(_count(backend, backend.join(folder, "data")))),
            ("Encryption", "always (AES-256, password needed for anything more)"),
        ]
        return info
    if kind == "borg":
        return _borg_basic(backend, folder)
    if kind == "duplicity":
        return duplicity_chains([i for i in backend.list_dir(folder)][:MAX_LISTED])
    raise RepoError("This folder is no restic, Borg or duplicity repository.")


def _borg_basic(backend, folder: str) -> RepoInfo:
    info = RepoInfo("borg")
    parser = configparser.ConfigParser(interpolation=None)
    try:
        parser.read_string(_read_text(backend, backend.join(folder, "config"), 64 * 1024))
    except configparser.Error as exc:
        raise RepoError(f"the Borg config is unreadable: {exc}") from exc
    repo = parser["repository"] if parser.has_section("repository") else {}
    for key, label in (("version", "Version"), ("id", "Repository id"),
                       ("segments_per_dir", "Segments per folder"),
                       ("max_segment_size", "Max segment size"),
                       ("storage_quota", "Storage quota"),
                       ("additional_free_space", "Reserved free space")):
        if key in repo:
            info.facts.append((label, repo[key]))
    info.facts.append(("Append-only", "yes" if repo.get("append_only", "0") == "1" else "no"))
    has_key = bool(repo.get("key", "").strip())
    info.needs_keyfile = not has_key
    info.facts.append(("Key", "in the repository (repokey)" if has_key
                       else "kept outside (keyfile mode, or unencrypted)"))
    data = backend.join(folder, "data")
    segments = 0
    try:
        for sub in backend.list_dir(data)[:1000]:
            if sub.is_dir:
                segments += _count(backend, backend.join(data, sub.name))
    except OSError:
        pass
    info.facts.append(("Segments", str(segments)))
    return info


def duplicity_chains(items) -> RepoInfo:
    """Backup chains from duplicity's file names."""
    fulls: dict[str, dict] = {}
    incs: list[dict] = []
    total = 0
    encrypted = set()
    for item in items:
        match = _DUP.match(item.name)
        if not match:
            continue
        kind, a, b, rest = match.group("kind", "a", "b", "rest")
        size = int(getattr(item, "size", 0) or 0)
        total += size
        encrypted.add(rest.endswith(".gpg"))
        if kind == "full":
            entry = fulls.setdefault(a, {"time": a, "volumes": 0, "size": 0, "incs": []})
            entry["size"] += size
            if rest.startswith("vol") and ".difftar" in rest:
                entry["volumes"] += 1
        elif kind == "inc":
            incs.append({"from": a, "to": b, "size": size,
                         "volume": rest.startswith("vol") and ".difftar" in rest})
    for inc in sorted(incs, key=lambda i: i["to"] or ""):
        base = max((t for t in fulls if t <= inc["from"]), default=None)
        if base is not None:
            fulls[base]["incs"].append(inc)
    info = RepoInfo("duplicity")
    info.facts = [
        ("Backup chains", str(len(fulls))),
        ("Size", _human(total)),
        ("Encryption", "GnuPG" if encrypted == {True} else
         "none" if encrypted == {False} else "mixed" if encrypted else "unknown"),
    ]
    for time in sorted(fulls):
        chain = fulls[time]
        times = sorted({i["to"] for i in chain["incs"] if i["to"]})
        info.snapshots.append(Snapshot(
            id=f"full {time}", time=_iso(time),
            note=f"{chain['volumes']} volume(s), {_human(chain['size'])}, "
                 f"{len(times)} incremental"))
        for t in times:
            vols = [i for i in chain["incs"] if i["to"] == t and i["volume"]]
            size = sum(i["size"] for i in chain["incs"] if i["to"] == t)
            info.snapshots.append(Snapshot(id=f"inc {t}", time=_iso(t),
                                           note=f"{len(vols)} volume(s), {_human(size)}"))
    return info


def _iso(stamp: str) -> str:
    return f"{stamp[0:4]}-{stamp[4:6]}-{stamp[6:8]} {stamp[9:11]}:{stamp[11:13]}:{stamp[13:15]} UTC"


def _human(n: int) -> str:
    value = float(n)
    for unit in ("B", "KiB", "MiB", "GiB", "TiB"):
        if value < 1024 or unit == "TiB":
            return f"{int(value)} B" if unit == "B" else f"{value:.1f} {unit}"
        value /= 1024
    return f"{n} B"


# -- unlocking (local, through the tool) --------------------------------------------------


#: Inherited settings that would override the password or the repository
#: given here. Others (BORG_BASE_DIR, RESTIC_CACHE_DIR …) stay.
OVERRIDING_ENV = frozenset({
    "RESTIC_PASSWORD", "RESTIC_PASSWORD_FILE", "RESTIC_PASSWORD_COMMAND",
    "RESTIC_REPOSITORY", "RESTIC_REPOSITORY_FILE", "RESTIC_KEY_HINT",
    "BORG_PASSPHRASE", "BORG_PASSCOMMAND", "BORG_PASSPHRASE_FD", "BORG_REPO", "BORG_KEY_FILE",
    "PASSPHRASE", "SIGN_PASSPHRASE",
})


def _run(argv, env_extra, input_text: str | None = None) -> str:
    """*argv* with the password in *env_extra*, or on stdin (*input_text*);
    never on the command line. Without *input_text* stdin is closed."""
    env = {k: v for k, v in clean_child_env().items() if k not in OVERRIDING_ENV}
    env.update(env_extra)
    feed = {"input": input_text} if input_text is not None else {"stdin": subprocess.DEVNULL}
    try:
        proc = subprocess.run(argv, capture_output=True, text=True, timeout=TIMEOUT,
                              env=env, check=False, **feed)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise RepoError(str(exc)) from exc
    if proc.returncode != 0:
        lines = [ln for ln in proc.stderr.splitlines() if ln.strip()]
        raise RepoError(lines[-1] if lines else f"{argv[0]} failed (exit {proc.returncode})")
    return proc.stdout


def tool_for(kind: str) -> str | None:
    return shutil.which(
        {"restic": "restic", "borg": "borg", "duplicity": "duplicity", "gpg": "gpg"}[kind]
    )


def restic_snapshots(repo: str, password: str, exe: str = "restic") -> list[Snapshot]:
    out = _run([exe, "--repo", repo, "snapshots", "--json", "--no-lock"],
               {"RESTIC_PASSWORD": password})
    snaps = []
    for s in json.loads(out or "[]") or []:
        snaps.append(Snapshot(id=s.get("short_id") or s.get("id", "")[:8],
                              time=str(s.get("time", ""))[:19].replace("T", " "),
                              host=s.get("hostname", ""), paths=list(s.get("paths") or []),
                              tags=list(s.get("tags") or [])))
    return snaps


def borg_archives(repo: str, password: str, keyfile: str = "", exe: str = "borg") -> list[Snapshot]:
    # The two *_IS_OK answer borg's yes/no questions (stdin is closed, so a
    # question aborts): a moved repository, and an unencrypted one this user
    # never opened - only a listing follows, nothing is written to it.
    env = {"BORG_PASSPHRASE": password, "BORG_RELOCATED_REPO_ACCESS_IS_OK": "yes",
           "BORG_UNKNOWN_UNENCRYPTED_REPO_ACCESS_IS_OK": "yes",
           "BORG_DISPLAY_PASSPHRASE": "no"}
    if keyfile:
        env["BORG_KEY_FILE"] = keyfile
    out = _run([exe, "list", "--json", "--bypass-lock", repo], env)
    data = json.loads(out or "{}")
    if not isinstance(data, dict):
        raise RepoError("borg list printed no archive list")
    return [Snapshot(id=a.get("name", ""), time=str(a.get("time", ""))[:19].replace("T", " "),
                     note=a.get("id", "")[:16])
            for a in data.get("archives", [])]


def duplicity_status(repo: str, password: str, exe: str = "duplicity") -> list[Snapshot]:
    with tempfile.TemporaryDirectory(prefix="axross-dup-") as cache:
        out = _run([exe, "collection-status", "--archive-dir", cache,
                    "file://" + os.path.abspath(repo)], {"PASSPHRASE": password})
    snaps = []
    for line in out.splitlines():
        match = re.match(r"^\s*(Full|Incremental)\s+(.+?)\s+(\d+)\s*$", line)
        if match:
            snaps.append(Snapshot(id=match.group(1), time=match.group(2),
                                  note=f"{match.group(3)} volume(s)"))
    return snaps


def _newest_encrypted_manifest(repo: str) -> str | None:
    """The newest ``duplicity-*.manifest.gpg`` in *repo*, or None."""
    try:
        names = os.listdir(repo)
    except OSError as exc:
        raise RepoError(f"cannot list {repo}: {exc}") from exc
    newest = None
    for name in names:
        match = _DUP.match(name)
        if not match or match.group("kind") not in ("full", "inc"):
            continue
        if match.group("rest") == "manifest.gpg":
            stamp = match.group("b") or match.group("a")
            if newest is None or stamp > newest[0]:
                newest = (stamp, name)
    return newest[1] if newest else None


def duplicity_check_password(repo: str, password: str, gpg: str = "gpg") -> None:
    """RepoError unless *password* decrypts the newest encrypted manifest.

    ``duplicity collection-status`` reads only the file names: with a wrong
    passphrase it lists the chains and exits 0 (duplicity 3.0.4, found by
    tests/test_backup_repos_live.py). A manifest is small, so decrypting
    one is the cheap proof. The password goes on stdin; the agent's
    passphrase cache is bypassed, so a right password typed before cannot
    let a wrong one through. An unencrypted repository has nothing to check.
    """
    name = _newest_encrypted_manifest(repo)
    if name is None:
        return
    argv = [gpg, "--batch", "--quiet", "--no-tty", "--pinentry-mode", "loopback",
            "--no-symkey-cache", "--passphrase-fd", "0", "--decrypt",
            os.path.join(repo, name)]
    try:
        _run(argv, {}, input_text=password + "\n")
    except RepoError as exc:
        # gpg's own last line says why (a wrong passphrase: "Bad session
        # key"; a key-encrypted backup without its secret key: "No secret key").
        raise RepoError(
            f"The password does not open this repository: gpg could not decrypt {name} ({exc})."
        ) from exc


def unlock(kind: str, repo: str, password: str, keyfile: str = "") -> list[Snapshot]:
    exe = tool_for(kind)
    if exe is None:
        raise RepoError(f"{kind} is not installed - install it to list the snapshots.")
    if kind == "restic":
        return restic_snapshots(repo, password, exe)
    if kind == "borg":
        return borg_archives(repo, password, keyfile, exe)
    if _newest_encrypted_manifest(repo) is not None:
        gpg = tool_for("gpg")
        if gpg is None:
            raise RepoError("gpg is not installed - duplicity needs it for this repository.")
        duplicity_check_password(repo, password, gpg)
    return duplicity_status(repo, password, exe)


# -- interface ------------------------------------------------------------------------------


def activate(api):
    from html import escape

    from PyQt6.QtWidgets import (
        QDialog,
        QFileDialog,
        QHBoxLayout,
        QInputDialog,
        QLabel,
        QLineEdit,
        QMessageBox,
        QPushButton,
        QTableWidget,
        QTableWidgetItem,
        QVBoxLayout,
    )

    class RepoDialog(QDialog):
        def __init__(self, ctx, folder, info: RepoInfo):
            super().__init__(api.window)
            self.setWindowTitle(f"{info.kind} repository")
            self.resize(760, 460)
            from ui.close_corner import add_close_corner
            self.ctx, self.folder, self.info = ctx, folder, info
            layout = QVBoxLayout(self)
            # Rich text: the folder name and the Borg config values are the
            # repository's, so they are escaped and shown as they are.
            self.facts = QLabel("<br>".join(f"<b>{escape(k)}:</b> {escape(v)}"
                                            for k, v in info.facts))
            self.facts.setWordWrap(True)
            layout.addWidget(QLabel(f"<b>{escape(folder)}</b>"))
            layout.addWidget(self.facts)
            self.table = QTableWidget(0, 5)
            self.table.setHorizontalHeaderLabels(["ID", "Time", "Host", "Paths / tags", "Note"])
            self.table.horizontalHeader().setStretchLastSection(True)
            layout.addWidget(self.table, 1)
            self.status = QLabel("")
            layout.addWidget(self.status)
            row = QHBoxLayout()
            self.unlock_button = QPushButton("Unlock…")
            self.unlock_button.setEnabled(ctx.is_local)
            self.unlock_button.setToolTip("List the snapshots with the repository's password"
                                          if ctx.is_local else "Local repositories only")
            self.unlock_button.clicked.connect(self.ask_unlock)
            close = QPushButton("Close")
            close.clicked.connect(self.close)
            row.addStretch(1)
            row.addWidget(self.unlock_button)
            row.addWidget(close)
            layout.addLayout(row)
            add_close_corner(self)
            self.fill(info.snapshots)

        def fill(self, snaps):
            self.table.setRowCount(len(snaps))
            for r, s in enumerate(snaps):
                extra = ", ".join(s.paths + [f"#{t}" for t in s.tags])
                for c, text in enumerate((s.id, s.time, s.host, extra, s.note)):
                    self.table.setItem(r, c, QTableWidgetItem(text))
            self.table.resizeColumnsToContents()

        def ask_unlock(self):
            password, ok = QInputDialog.getText(self, "Unlock", "Repository password:",
                                                QLineEdit.EchoMode.Password)
            if not ok:
                return
            keyfile = ""
            if self.info.kind == "borg" and self.info.needs_keyfile:
                keyfile, _f = QFileDialog.getOpenFileName(self, "Borg key file (Cancel: none)")
            self.status.setText("Reading the snapshots…")
            kind, folder = self.info.kind, self.folder
            api.run_in_background(lambda: unlock(kind, folder, password, keyfile),
                                  on_done=self.unlocked, on_error=self.failed)

        def unlocked(self, snaps):
            self.status.setText(f"{len(snaps)} snapshot(s)")
            self.fill(snaps)

        def failed(self, exc):
            self.status.setText(str(exc))
            QMessageBox.warning(self, "Unlock", str(exc))

    def show(ctx):
        folder = ctx.paths[0] if ctx.paths else ctx.folder

        def done(info):
            dialog = RepoDialog(ctx, folder, info)
            dialog.show()
            api.window._backup_repo_dialog = dialog  # kept alive while open

        api.run_in_background(lambda: basic_info(ctx.backend, folder), on_done=done,
                              on_error=lambda exc: api.notify(str(exc)))

    api.add_context_action("Backup Repository Info…", show, applies_to="folder")
    # One repository per window, each with its own password prompt: offered
    # for ONE selected folder, so no selected folder is silently skipped.
    api.add_context_action("Backup Repository Info…", show, applies_to="single_folder")
