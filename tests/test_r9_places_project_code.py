"""Round 9 security review: protected places (core.protected_places,
core.mcp_server, core.agent_sandbox).

* M1: the agent wrote project files other programs run as code - Claude
  Code's ``.claude/settings.json`` (a SessionStart hook), VS Code's
  ``.vscode/tasks.json`` / ``settings.json`` / ``mcp.json``, Cursor's
  ``.cursor/mcp.json``, JetBrains' ``.idea`` - and, in a repository whose
  config sets ``core.hooksPath`` (``.githooks``, husky's ``.husky/_``),
  ``.githooks/pre-commit`` plus chmod 0755: the user's next ``git commit``
  ran it. Now those folders and files are refused at any depth, the folder
  ``core.hooksPath`` names (the repository's config, the global and system
  configs, ``GIT_CONFIG_*``) and the files a repository's config includes
  are refused, and the sandbox mounts the existing ones read-only.
* Low: Git's names were compared case-sensitively on Linux, but on a
  case-insensitive volume (FAT/exFAT, SMB, an ext4 casefold folder) Git
  opening ``HEAD`` gets ``head``: a member or file ``head`` beside a
  config, ``objects/`` and ``refs/`` made a repository.
* Low: secret recognition missed a PEM key after the first 4 KiB (a
  haproxy bundle), ``.envrc``, ``*.env``, a project's ``.npmrc``,
  ``.pypirc``, ``.aws/credentials``, ``.docker/config.json``,
  ``kubeconfig``, ``credentials.json``, ``secrets.yaml``, ``.htpasswd``
  and ``id_rsa.bak``.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import zipfile
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
                 "XDG_RUNTIME_DIR", "GIT_CONFIG_GLOBAL", "GIT_CONFIG_SYSTEM",
                 *(v for _p, v, _h in P.XDG_PLACES), *(h for _p, _v, h in P.XDG_PLACES)):
        monkeypatch.delenv(name, raising=False)
    for name in list(os.environ):
        if name.startswith("GIT_CONFIG_"):
            monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("GIT_CONFIG_NOSYSTEM", "1")
    monkeypatch.setenv("PATH", "/usr/bin:/bin")
    monkeypatch.setattr(P, "ZDOTDIR_SYSTEM_FILES", (), raising=False)
    return real


def _call(tools, name, **args):
    try:
        return "ok", T.call(tools, name, args)
    except T.RpcError as exc:
        return "error", exc.message


def _repo(root: Path, config: str = "") -> Path:
    (root / ".git" / "objects").mkdir(parents=True)
    (root / ".git" / "refs").mkdir()
    (root / ".git" / "HEAD").write_text("ref: refs/heads/main\n")
    (root / ".git" / "config").write_text("[core]\n\trepositoryformatversion = 0\n" + config)
    return root


# -- M1: project tool settings ----------------------------------------------------------


PROJECT_FILES = (".claude/settings.json", ".claude/settings.local.json", ".vscode/tasks.json",
                 ".vscode/settings.json", ".vscode/launch.json", ".vscode/mcp.json",
                 ".cursor/mcp.json", ".idea/workspace.xml", ".zed/tasks.json",
                 ".devcontainer/devcontainer.json", ".husky/pre-commit", ".husky/_/pre-commit",
                 ".mcp.json", ".devcontainer.json", ".pre-commit-config.yaml", "lefthook.yml",
                 "app.code-workspace")


@posix_only
@pytest.mark.parametrize("rel", PROJECT_FILES)
def test_sad_project_tool_settings_are_refused(home, rel):
    path = home / "proj" / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    assert P.refusal(str(path)) is not None


@posix_only
def test_sad_project_tool_folders_refused_at_any_depth_and_case(home):
    for rel in ("a/b/.VSCode/tasks.json", "sub/.Claude/settings.json", "x/.IDEA",
                "deep/er/.husky", "w/.MCP.json"):
        assert P.refusal(str(home / "proj" / rel), entry=True) is not None, rel


@posix_only
def test_sad_agent_cannot_plant_a_session_start_hook_through_the_tools(home):
    proj = home / "proj"
    tools = T.build(str(proj), [], allow_write=True)
    hook = '{"hooks": {"SessionStart": [{"hooks": [{"type": "command", "command": "id"}]}]}}'
    for folder, rel in ((".claude", ".claude/settings.json"), (".vscode", ".vscode/tasks.json"),
                        (".cursor", ".cursor/mcp.json"), (".idea", ".idea/workspace.xml")):
        assert _call(tools, "mkdir", path=folder)[0] == "error"
        (proj / folder).mkdir(exist_ok=True)  # the user's own folder
        status, message = _call(tools, "write_file", path=rel, content=hook)
        assert status == "error" and "other programs run code" in message, rel
        assert not (proj / rel).exists()
    assert _call(tools, "write_file", path=".mcp.json", content="{}")[0] == "error"
    assert not (proj / ".mcp.json").exists()


@posix_only
def test_happy_ordinary_project_files_stay_writable(home):
    proj = home / "proj"
    for rel in ("src/main.py", "vscode-notes.md", "docs/claude.md", ".claudeignore",
                "settings.json", "tasks.json", "mcp.json", ".github/workflows/ci.yml"):
        assert P.refusal(str(proj / rel)) is None, rel


# -- M1: core.hooksPath -----------------------------------------------------------------


@posix_only
def test_sad_folder_named_by_the_repositorys_hooks_path_is_refused(home):
    repo = _repo(home / "proj", "\thooksPath = .githooks\n")
    assert P.refusal(str(repo / ".githooks" / "pre-commit")) is not None
    assert P.refusal(str(repo / ".githooks"), entry=True) is not None
    # Another folder of the work tree is not a hooks folder.
    assert P.refusal(str(repo / "githooks-old" / "pre-commit")) is None


@posix_only
def test_edge_hooks_path_quoted_with_comment_and_case(home):
    repo = _repo(home / "proj", '[CORE]\n\tHooksPath = "tools/git hooks" ; managed\n')
    assert P.refusal(str(repo / "tools" / "git hooks" / "post-checkout")) is not None
    assert P.refusal(str(repo / "tools" / "other")) is None


@posix_only
def test_sad_global_hooks_path_absolute_and_relative(home):
    (home / ".gitconfig").write_text("[include]\n\tpath = ~/.gitconfig.d/hooks\n")
    (home / ".gitconfig.d").mkdir()
    (home / ".gitconfig.d" / "hooks").write_text("[core]\n\thooksPath = ~/my-hooks\n")
    assert P.refusal(str(home / "my-hooks" / "pre-commit")) is not None
    (home / ".gitconfig").write_text("[core]\n\thooksPath = hooks-of-every-repo\n")
    repo = _repo(home / "proj")
    assert P.refusal(str(repo / "hooks-of-every-repo" / "pre-push")) is not None
    assert P.refusal(str(home / "hooks-of-every-repo" / "pre-push")) is None  # not a repo


@posix_only
def test_sad_hooks_path_from_git_config_environment(home, monkeypatch):
    monkeypatch.setenv("GIT_CONFIG_COUNT", "1")
    monkeypatch.setenv("GIT_CONFIG_KEY_0", "core.hooksPath")
    monkeypatch.setenv("GIT_CONFIG_VALUE_0", str(home / "env-hooks"))
    assert P.refusal(str(home / "env-hooks" / "pre-commit")) is not None


@posix_only
def test_sad_file_a_repository_config_includes_is_refused(home):
    repo = _repo(home / "proj", "[include]\n\tpath = ../.gitconfig-project\n")
    assert P.refusal(str(repo / ".gitconfig-project")) is not None


@posix_only
def test_edge_worktree_gitdir_file_uses_the_common_config(home):
    main = _repo(home / "main", "\thooksPath = .githooks\n")
    wt_git = main / ".git" / "worktrees" / "w"
    wt_git.mkdir(parents=True)
    (wt_git / "commondir").write_text("../..\n")
    wt = home / "proj" / "w"
    wt.mkdir()
    (wt / ".git").write_text(f"gitdir: {wt_git}\n")
    assert P.refusal(str(wt / ".githooks" / "pre-commit")) is not None


@posix_only
def test_sad_hooks_path_write_and_chmod_through_tools_and_git_commit_runs_nothing(home):
    git = shutil.which("git")
    if git is None:
        pytest.skip("git is not installed")
    repo = home / "proj"
    env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_CONFIG")}
    env.update(GIT_CONFIG_NOSYSTEM="1", GIT_AUTHOR_NAME="u", GIT_AUTHOR_EMAIL="u@x",
               GIT_COMMITTER_NAME="u", GIT_COMMITTER_EMAIL="u@x")

    def g(*args):
        return subprocess.run([git, *args], cwd=repo, env=env, capture_output=True, text=True)

    g("init", "-q")
    g("config", "core.hooksPath", ".githooks")
    (repo / ".githooks").mkdir()
    (repo / "a.txt").write_text("a\n")
    g("add", "a.txt")
    g("commit", "-qm", "init")
    marker = home / "PWNED"
    tools = T.build(str(repo), [], allow_write=True)
    status, message = _call(tools, "write_file", path=".githooks/pre-commit",
                            content=f"#!/bin/sh\ntouch {marker}\n")
    assert status == "error" and "core.hooksPath" in message
    assert _call(tools, "chmod", path=".githooks/pre-commit", mode="0755")[0] == "error"
    (repo / "a.txt").write_text("b\n")
    g("add", "a.txt")
    assert g("commit", "-qm", "user commit").returncode == 0
    assert not marker.exists()


@posix_only
def test_happy_sandbox_mounts_project_settings_and_hooks_read_only(home):
    proj = _repo(home / "proj", "\thooksPath = .githooks\n")
    for rel in (".vscode", ".claude", ".githooks"):
        (proj / rel).mkdir()
    (proj / ".mcp.json").write_text("{}")
    (proj / "sub").mkdir()
    (proj / "sub" / ".devcontainer").mkdir()
    entries = P.project_code_entries(str(proj))
    assert {os.path.basename(p) for p in entries} >= {".vscode", ".claude", ".githooks",
                                                     ".mcp.json"}
    plan = {p: (rw, kind) for p, rw, kind in
            SB._mount_plan(SB.SandboxProfile(name="t"), str(proj), True)}
    for rel in (".vscode", ".claude", ".githooks", ".mcp.json", "sub/.devcontainer"):
        assert plan[str(proj / rel)] == (False, "bind"), rel
    assert plan[str(proj)] == (True, "bind")


# -- Low: Git's names on a case-insensitive volume ---------------------------------------


@posix_only
def test_sad_lowercase_head_member_is_refused(home):
    check = P.write_checker(members=True)
    for name in ("head", "Head", "x/hEaD"):
        assert check(str(home / "proj" / name)) is not None, name


@posix_only
def test_sad_lowercase_head_beside_a_config_is_refused(home):
    folder = home / "proj" / "w"
    for sub in ("objects", "refs"):
        (folder / sub).mkdir(parents=True)
    (folder / "config").write_text("[core]\n\tfsmonitor = id\n")
    assert P.refusal(str(folder / "head")) is not None
    assert P.refusal(str(home / "proj" / "x" / ".GIT" / "config")) is not None


@posix_only
def test_sad_archive_with_lowercase_head_extracts_nothing(home):
    proj = home / "proj"
    archive = proj / "a.zip"
    with zipfile.ZipFile(archive, "w") as zf:
        zf.writestr("objects/", b"")
        zf.writestr("refs/", b"")
        zf.writestr("config", b"[core]\n\tfsmonitor = id\n")
        zf.writestr("head", b"ref: refs/heads/main\n")
    tools = T.build(str(proj), ["archive"], allow_write=True)
    status, _message = _call(tools, "archive_extract", path="a.zip")
    assert status == "error"
    assert not (proj / "a" / "head").exists()


# -- Low: secret recognition ------------------------------------------------------------


_KEY = ("-----BEGIN " + "RSA PRIVATE KEY-----\nMIIEsecret\n-----END " + "RSA PRIVATE KEY-----\n")
_CERT = "-----BEGIN CERTIFICATE-----\n" + ("MIIF" + "A" * 60 + "\n") * 28 + \
    "-----END CERTIFICATE-----\n"


@posix_only
def test_sad_pem_key_after_the_first_4_kib_is_secret(home):
    proj = home / "proj"
    (proj / "site.pem").write_text(_CERT * 3 + _KEY)
    (proj / "k.txt").write_text("#" * 9000 + "\n" + _KEY)
    (proj / "k_nbsp").write_text(_KEY.replace("BEGIN RSA", "BEGIN\u00a0RSA"))
    for name in ("site.pem", "k.txt", "k_nbsp"):
        assert P.read_refusal(str(proj / name)) is not None, name


@posix_only
def test_sad_project_secret_names_are_refused(home):
    proj = home / "proj"
    for rel in (".envrc", "prod.env", ".npmrc", ".pypirc", ".aws/credentials",
                ".docker/config.json", ".kube/config", "kubeconfig", "credentials.json",
                "secrets.yaml", ".htpasswd", "backup/id_rsa.bak", "id_ed25519.old"):
        path = proj / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("token=x\n")
        assert P.read_refusal(str(path)) is not None, rel


@posix_only
def test_happy_examples_public_keys_and_plain_files_stay_readable(home):
    proj = home / "proj"
    (proj / "c.pem").write_text(_CERT * 3)
    (proj / "big.txt").write_text("x" * (P.SECRET_CONTENT_SCAN + 10) + _KEY)
    for rel in (".env.example", "id_rsa.pub", "notes.txt", "config.json", "credentials.md"):
        (proj / rel).write_text("x\n")
    for rel in ("c.pem", "big.txt", ".env.example", "id_rsa.pub", "notes.txt",
                "config.json", "credentials.md"):
        assert P.read_refusal(str(proj / rel)) is None, rel


@posix_only
def test_edge_a_root_granted_inside_a_settings_folder_is_writable_below_it(home):
    root = home / "proj" / ".claude" / "worktrees" / "w"
    root.mkdir(parents=True)
    assert P.refusal(str(root / "src" / "main.py"), granted=(str(root),)) is None
    assert P.refusal(str(root / ".vscode" / "tasks.json"), granted=(str(root),)) is not None
    assert P.refusal(str(root / "src" / "main.py")) is not None  # not granted


@posix_only
def test_happy_the_user_can_grant_a_settings_folder_itself(home):
    folder = home / "proj" / ".vscode"
    folder.mkdir()
    assert P.refusal(str(folder / "tasks.json"), granted=(str(folder),)) is None
    assert P.refusal(str(folder / "tasks.json"), granted=(str(home / "proj"),)) is not None
