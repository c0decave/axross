"""Round 8 security review: protected places (core.protected_places,
core.mcp_server, core.agent_sandbox).

* H1: one archive_extract call checked every member with one write checker
  whose lexists/shape memo still said "no HEAD here" after the member HEAD
  was made, and the repository shape needed ``objects``/``refs`` to be
  folders while Git only asks access(X_OK): members objects (an executable
  file), HEAD, config (``core.fsmonitor``), refs/ made a folder whose
  ``git status`` ran code. Now every member is looked up afresh, any entry
  named objects/refs counts, and an archive member named HEAD is refused.
* M1: ``.hg/hgrc-not-shared``, Sapling's ``.sl/config``, darcs's
  ``_darcs/prefs/defaults`` and Breezy's ``.bzr/branch/branch.conf`` were
  writable, and a folder renamed to ``.hg`` brought its hgrc along.
* M3: with a root holding /proc (``--mcp-root /``) ``/proc/<pid>/environ``
  (axross's API keys) was handed out.
* L1: chmod through a hard link changed the protected file's mode.
* L6: secrets in a project folder (a PEM key, ``.git-credentials``,
  ``.env``, ``terraform.tfstate``, a KeePass database) were handed out.
* L7: only ``.git/commondir`` was set aside after a sandboxed task;
  ``.git/config.worktree`` and the submodules' ``commondir`` stayed.
"""

from __future__ import annotations

import io
import os
import shutil
import subprocess
import sys
import tarfile
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core import agent_sandbox as SB  # noqa: E402
from core import protected_places as P  # noqa: E402
from tests import mcp_group_testkit as T  # noqa: E402

_HOST_PATH_ENV = "AXROSS_AGENT_HOST_PATH"
posix_only = pytest.mark.skipif(os.name != "posix", reason="POSIX paths")


@pytest.fixture
def home(tmp_path, monkeypatch) -> Path:
    real = tmp_path / "home"
    (real / ".config").mkdir(parents=True)
    (real / "proj").mkdir()
    monkeypatch.setenv("HOME", str(real))
    for name in (P.HOST_HOME_ENV, _HOST_PATH_ENV, "ZDOTDIR", "APPDATA", "LOCALAPPDATA",
                 "XDG_RUNTIME_DIR",
                 *(v for _p, v, _h in P.XDG_PLACES), *(h for _p, _v, h in P.XDG_PLACES)):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("PATH", "/usr/bin:/bin")
    monkeypatch.setattr(P, "ZDOTDIR_SYSTEM_FILES", (), raising=False)
    return real


def _call(tools, name, **args):
    try:
        return "ok", T.call(tools, name, args)
    except T.RpcError as exc:
        return "error", exc.message


def _tar(path: Path, members) -> None:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tf:
        for name, data, mode in members:
            ti = tarfile.TarInfo(name)
            ti.mode = mode
            if data is None:
                ti.type = tarfile.DIRTYPE
                tf.addfile(ti)
            else:
                ti.size = len(data)
                tf.addfile(ti, io.BytesIO(data))
    path.write_bytes(buf.getvalue())


# -- H1: an archive builds a Git folder ---------------------------------------------------

def _fsmonitor_config(marker: Path) -> bytes:
    return (f"[core]\n\trepositoryformatversion = 0\n\tbare = false\n\tworktree = ..\n"
            f"\tfsmonitor = touch {marker}; false\n").encode()


@posix_only
@pytest.mark.skipif(shutil.which("git") is None, reason="needs git")
def test_sad_archive_objects_file_head_config_refs_runs_no_code(home, tmp_path):
    proj = home / "proj"
    marker = tmp_path / "PWNED"
    _tar(proj / "docs.tar", [("objects", b"", 0o755),
                             ("HEAD", b"ref: refs/heads/main\n", 0o644),
                             ("config", _fsmonitor_config(marker), 0o644),
                             ("refs", None, 0o755)])
    tools = T.build(proj, ["archive"], allow_write=True)
    status, _msg = _call(tools, "archive_extract", path="docs.tar")
    assert status == "error"
    out = proj / "docs"
    if out.is_dir():  # whatever is left, git must not take it for a repository with code
        env = dict(os.environ, GIT_CONFIG_NOSYSTEM="1", GIT_CEILING_DIRECTORIES=str(proj))
        subprocess.run(["git", "status", "--short"], cwd=out, env=env,
                       capture_output=True, timeout=60)
    assert not marker.exists()
    assert not (out / "config").exists()


@pytest.mark.parametrize("members", [
    [("HEAD", b"ref: refs/heads/main\n", 0o644)],
    [("sub/deeper/HEAD", b"ref: x\n", 0o644)],
    [("commondir", b"../x\n", 0o644), ("HEAD", b"ref: x\n", 0o644)],
])
def test_sad_archive_member_named_head_refused(home, members):
    proj = home / "proj"
    _tar(proj / "a.tar", members)
    tools = T.build(proj, ["archive"], allow_write=True)
    status, msg = _call(tools, "archive_extract", path="a.tar")
    assert status == "error" and "HEAD" in msg


def test_happy_archive_without_git_names_extracts(home):
    proj = home / "proj"
    _tar(proj / "b.tar", [("src", None, 0o755), ("src/main.py", b"print(1)\n", 0o644),
                          ("objects", b"", 0o644), ("refs", None, 0o755),
                          ("docs/config", b"x = 1\n", 0o644), ("head.txt", b"x", 0o644)])
    tools = T.build(proj, ["archive"], allow_write=True)
    status, out = _call(tools, "archive_extract", path="b.tar")
    assert status == "ok", out
    assert (proj / "b" / "docs" / "config").read_text() == "x = 1\n"


def test_sad_checker_sees_what_the_last_member_made(home):
    """One checker for many paths: what was made after a check counts."""
    folder = home / "proj" / "x"
    folder.mkdir()
    check = P.write_checker(granted=[str(home / "proj")])
    assert check(str(folder / "HEAD"), entry=True) is None
    (folder / "HEAD").write_text("ref: refs/heads/main\n")
    assert check(str(folder / "config"), entry=True) is not None
    assert check(str(folder / "hooks"), entry=True) is not None


@pytest.mark.parametrize("kind", ["file", "symlink"])
def test_edge_objects_as_a_file_makes_the_shape(home, kind):
    """Git asks access(X_OK) of objects/refs, not that they be folders."""
    folder = home / "proj" / "y"
    folder.mkdir()
    if kind == "file":
        (folder / "objects").write_bytes(b"")
        os.chmod(folder / "objects", 0o755)
    else:
        (home / "proj" / "elsewhere").mkdir()
        os.symlink("../elsewhere", folder / "objects")
    (folder / "refs").mkdir()
    granted = [str(home / "proj")]
    assert P.refusal(str(folder / "HEAD"), granted=granted) is not None
    (folder / "HEAD").write_text("ref: refs/heads/main\n")
    assert P.refusal(str(folder / "config"), granted=granted) is not None


def test_happy_head_alone_in_a_write_call_stays_writable(home):
    """write_file (not an archive) of a lone HEAD: allowed as before."""
    granted = [str(home / "proj")]
    assert P.refusal(str(home / "proj" / "z" / "HEAD"), granted=granted) is None


# -- M1: Mercurial, Sapling, darcs, Breezy ------------------------------------------------

@pytest.mark.parametrize("rel", [
    "repo/.hg/hgrc-not-shared", "repo/.sl/config", "repo/.sl/hgrc", "repo/.sl/sharedpath",
    "repo/_darcs/prefs/defaults", "repo/.bzr/branch/branch.conf", "repo/.bzr/branch/location",
    "repo/.hg", "repo/.sl", "repo/_darcs", "repo/_darcs/prefs", "repo/.bzr/branch",
])
def test_sad_other_vcs_code_files_refused(home, rel):
    assert P.refusal(str(home / "proj" / rel), granted=[str(home / "proj")]) is not None


@pytest.mark.parametrize("rel", ["repo/.hg/store/data/x.i", "repo/.hg/dirstate",
                                 "repo/_darcs/patches/p1", "repo/.bzr/repository/pack-names",
                                 "repo/.sl/store/x"])
def test_happy_other_vcs_working_files_stay_writable(home, rel):
    assert P.refusal(str(home / "proj" / rel), granted=[str(home / "proj")]) is None


@pytest.mark.parametrize("vcs,inner", [(".hg", "hgrc"), (".hg", "hgrc-not-shared"),
                                       (".sl", "config"), (".bzr", "branch/branch.conf")])
def test_edge_folder_renamed_to_a_vcs_folder_refused(home, vcs, inner):
    proj = home / "proj"
    src = proj / "x" / inner
    src.parent.mkdir(parents=True)
    src.write_text("[hooks]\npre-status = touch PWNED\n")
    tools = T.build(proj, [], allow_write=True)
    status, _msg = _call(tools, "rename", src="x", dst=vcs)
    assert status == "error"
    assert not (proj / vcs).exists()


def test_sad_write_hgrc_not_shared_through_mcp(home):
    proj = home / "proj"
    (proj / ".hg").mkdir()
    (proj / ".hg" / "requires").write_text("store\n")
    tools = T.build(proj, [], allow_write=True)
    status, _msg = _call(tools, "write_file", path=".hg/hgrc-not-shared",
                         content="[hooks]\npre-status = touch PWNED\n")
    assert status == "error"
    assert not (proj / ".hg" / "hgrc-not-shared").exists()


# -- M3: /proc ---------------------------------------------------------------------------

@posix_only
@pytest.mark.skipif(not os.path.isdir("/proc/self"), reason="needs /proc")
@pytest.mark.parametrize("rel", ["self/environ", "{pid}/environ", "{pid}/task/{pid}/environ",
                                 "{pid}/cmdline", "{pid}/mem", "{pid}/maps", "thread-self/environ",
                                 "{pid}/fd/0"])
def test_sad_proc_secrets_refused(home, rel):
    path = "/proc/" + rel.format(pid=os.getpid())
    assert P.read_refusal(path) is not None
    assert P.refusal(path) is not None


@posix_only
def test_sad_run_secrets_refused(home):
    assert P.read_refusal("/run/secrets/db_password") is not None
    assert P.read_refusal("/var/run/secrets/kubernetes.io/serviceaccount/token") is not None


@posix_only
@pytest.mark.skipif(not os.path.isdir("/proc/self"), reason="needs /proc")
def test_happy_proc_system_files_stay_readable(home):
    assert P.read_refusal("/proc/cpuinfo") is None
    assert P.read_refusal(f"/proc/{os.getpid()}/status") is None


@posix_only
@pytest.mark.skipif(not os.path.isdir("/proc/self"), reason="needs /proc")
def test_sad_mcp_root_slash_does_not_hand_out_environ(home, monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "sk-R8MARKER-x")
    tools = T.build("/", [], allow_write=False)
    pid = os.getpid()
    for path in (f"/proc/{pid}/environ", f"/proc/{pid}/task/{pid}/environ"):
        status, out = _call(tools, "read_file", path=path, max_bytes=65536)
        assert status == "error", out
    status, out = _call(tools, "grep", pattern="R8MARKER", path=f"/proc/{pid}", max_depth=1)
    assert status == "error" or not out["matches"]


# -- L1: chmod through a hard link ---------------------------------------------------------

@posix_only
def test_sad_chmod_through_hard_link_refused(home):
    bashrc = home / ".bashrc"
    bashrc.write_text("echo hi\n")
    os.chmod(bashrc, 0o644)
    proj = home / "proj"
    os.link(bashrc, proj / "bashrc.bak")
    tools = T.build(proj, [], allow_write=True)
    for mode in ("0", "0o755"):
        status, _msg = _call(tools, "chmod", path="bashrc.bak", mode=mode)
        assert status == "error"
    assert (bashrc.stat().st_mode & 0o777) == 0o644


@posix_only
def test_happy_chmod_single_name_file(home):
    proj = home / "proj"
    (proj / "run.sh").write_text("echo\n")
    tools = T.build(proj, [], allow_write=True)
    status, _msg = _call(tools, "chmod", path="run.sh", mode="0o755")
    assert status == "ok"
    assert (proj / "run.sh").stat().st_mode & 0o777 == 0o755


# -- L6: project-level secrets -------------------------------------------------------------

_PEM = "-----BEGIN " + "RSA PRIVATE KEY-----\nR8MARKER\n-----END " + "RSA PRIVATE KEY-----\n"


@pytest.mark.parametrize("rel,content", [
    ("deploy/id_rsa", _PEM),
    ("deploy/server.key.txt", _PEM),
    ("deploy/bundle.pem", "Bag Attributes\n  localKeyID: 01\n" + _PEM.replace("RSA ", "")),
    ("deploy/k", "-----BEGIN " + "OPENSSH PRIVATE KEY-----\nR8MARKER\n"),
    ("deploy/enc", "-----BEGIN " + "ENCRYPTED PRIVATE KEY-----\nR8MARKER\n"),
    ("deploy/pgp.asc", "-----BEGIN " + "PGP PRIVATE KEY BLOCK-----\nR8MARKER\n"),
    ("deploy/putty", "PuTTY-User-Key-File-3: ssh-ed25519\nR8MARKER\n"),
    ("vault.bin", b"\x03\xd9\xa2\x9a\x67\xfb\x4b\xb5R8MARKER"),
    (".git-credentials", "https://u" + ":R8MARKER@" + "github.com\n"),
    (".env", "API_KEY=R8MARKER\n"),
    (".env.production", "API_KEY=R8MARKER\n"),
    ("infra/terraform.tfstate", '{"secret": "R8MARKER"}'),
    ("infra/terraform.tfstate.backup", '{"secret": "R8MARKER"}'),
    ("sub/.netrc", "machine x password R8MARKER\n"),
    ("db/.pgpass", "h:5432:*:u:R8MARKER\n"),
    ("Documents/kp.kdbx", "R8MARKER"),
    ("certs/client.p12", "R8MARKER"),
])
def test_sad_project_secrets_not_handed_out(home, rel, content):
    path = home / "proj" / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    if isinstance(content, bytes):
        path.write_bytes(content)
    else:
        path.write_text(content)
    assert P.read_refusal(str(path)) is not None
    tools = T.build(home / "proj", [], allow_write=False)
    status, out = _call(tools, "read_file", path=rel)
    assert status == "error", out
    status, out = _call(tools, "grep", pattern="R8MARKER", path=".")
    assert status == "error" or not out["matches"], out


@pytest.mark.parametrize("rel,content", [
    (".env.example", "API_KEY=changeme\n"),
    (".env.sample", "API_KEY=\n"),
    ("deploy/id_rsa.pub", "ssh-rsa AAAA x@y\n"),
    ("certs/ca.pem", "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n"),
    ("docs/keys.md", "Generate a key with ssh-keygen; it starts with BEGIN OPENSSH.\n"),
    ("src/environment.py", "ENV = 1\n"),
])
def test_happy_ordinary_project_files_stay_readable(home, rel, content):
    path = home / "proj" / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content)
    assert P.read_refusal(str(path)) is None
    tools = T.build(home / "proj", [], allow_write=False)
    status, out = _call(tools, "read_file", path=rel)
    assert status == "ok", out


@posix_only
def test_edge_secret_content_check_ignores_fifos(home):
    fifo = home / "proj" / "pipe"
    os.mkfifo(fifo)
    assert P._secret_content(str(fifo)) is False  # never blocks on a FIFO


# -- L7: Git pointer files set aside after a sandboxed task --------------------------------

def test_sad_sandbox_watches_config_worktree_and_submodule_pointers(home):
    proj = home / "proj"
    for d in (".git/hooks", ".git/info", ".git/refs", ".git/modules/sub/hooks",
              ".git/modules/sub/info", ".git/worktrees/wt", "sub"):
        (proj / d).mkdir(parents=True, exist_ok=True)
    (proj / ".git" / "config").write_text("[extensions]\n\tworktreeConfig = true\n")
    (proj / ".git" / "HEAD").write_text("ref: refs/heads/main\n")
    (proj / ".git" / "modules" / "sub" / "config").write_text("[core]\n")
    (proj / ".git" / "worktrees" / "wt" / "commondir").write_text("../..\n")
    (proj / "sub" / ".git").write_text("gitdir: ../.git/modules/sub\n")
    plan = SB._mount_plan(SB.SandboxProfile(name="t"), str(proj), True)
    watch = SB._git_pointer_watch(plan)
    expected = [proj / ".git" / "commondir", proj / ".git" / "config.worktree",
                proj / ".git" / "modules" / "sub" / "commondir",
                proj / ".git" / "modules" / "sub" / "config.worktree",
                proj / ".git" / "worktrees" / "wt" / "config.worktree"]
    for path in expected:
        assert str(path) in watch
    # what was there at the start is the user's, never set aside
    assert str(proj / ".git" / "worktrees" / "wt" / "commondir") not in watch
    # made by the task -> set aside
    (proj / ".git" / "config.worktree").write_text("[core]\n\tfsmonitor = x\n")
    (proj / ".git" / "modules" / "sub" / "commondir").write_text("/tmp/evil\n")
    moved = SB._set_aside_git_pointers(watch)
    assert len(moved) == 2
    assert not (proj / ".git" / "config.worktree").exists()
    assert not (proj / ".git" / "modules" / "sub" / "commondir").exists()
