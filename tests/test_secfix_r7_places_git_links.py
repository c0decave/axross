"""Round 7 security review: protected places through symlinks, Git folders
by shape, hard links, the read side's default-deny, the XDG parser.

* H1: core.mcp_server checked the protected places, default-deny and the
  secrets on the resolved path only. A stow link (``~/.config/kitty ->
  ~/dotfiles/kitty``, ``~/.wezterm.lua -> dotfiles/wezterm.lua``) was written
  through its target, a key behind ``~/.ssh/id_ed25519 -> ~/keys/...`` was
  handed out. Now the typed path, each symlink hop and the resolved path are
  checked, and the target of a link in those places counts as the place.
* H2: the Git rule went by the name ``.git``: ``.git/commondir``,
  ``worktrees/*/commondir``, a bare ``x.git/hooks/*`` and a folder made to
  look like a repository (HEAD + objects + refs) were writable.
* M4: a file with other hard links was written in place - a hard link in
  the root rewrote ``~/.bashrc`` or ``.git/config``.
* M5: credential stores the lists missed; reads below the home's hidden
  entries and ~/snap are default-deny unless granted.
* M6: the sandbox's secret walk ran out on ~/.cache and left the rest readable.
* L4: XDG_CONFIG_HOME set in files and forms the parser missed.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core import agent_sandbox as SB  # noqa: E402
from core import mcp_server as M  # noqa: E402
from core import protected_places as P  # noqa: E402
from core.local_fs import LocalFS  # noqa: E402

_HOST_PATH_ENV = "AXROSS_AGENT_HOST_PATH"


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


def _tools(root, extra=()):
    kw = {"extra_roots": tuple(extra)} if extra else {}
    return M._build_tools(LocalFS(), allow_write=True, root=str(root), **kw)


def _call(tools, name, args) -> str:
    resp = M._handle_request(
        {"jsonrpc": "2.0", "id": 1, "method": "tools/call",
         "params": {"name": name, "arguments": args}},
        tools, cancels=M._CancelRegistry(), tasks=M._TaskRegistry())
    if "error" in resp:
        return "error: " + resp["error"]["message"]
    if resp["result"].get("isError"):
        return "error: " + resp["result"]["content"][0]["text"]
    return "ok"


def _stow(home: Path) -> None:
    (home / "dotfiles" / "kitty").mkdir(parents=True)
    (home / "dotfiles" / "kitty" / "kitty.conf").write_text("font_size 11\n")
    os.symlink("../dotfiles/kitty", home / ".config" / "kitty")
    (home / "dotfiles" / "wezterm.lua").write_text("return {}\n")
    os.symlink("dotfiles/wezterm.lua", home / ".wezterm.lua")


# -- H1: symlinks --------------------------------------------------------------------------

def test_sad_stow_link_target_not_written_through_mcp(home):
    _stow(home)
    tools = _tools(home)
    for path in (home / ".config" / "kitty" / "kitty.conf",
                 home / "dotfiles" / "kitty" / "kitty.conf",
                 home / ".wezterm.lua", home / "dotfiles" / "wezterm.lua"):
        assert _call(tools, "write_file", {"path": str(path), "content": "x"}).startswith(
            "error"), path
    assert (home / "dotfiles" / "kitty" / "kitty.conf").read_text() == "font_size 11\n"
    assert (home / "dotfiles" / "wezterm.lua").read_text() == "return {}\n"


def test_happy_other_files_beside_the_link_target_stay_writable(home):
    _stow(home)
    tools = _tools(home)
    assert _call(tools, "write_file", {"path": str(home / "dotfiles" / "README"),
                                       "content": "x"}) == "ok"
    assert _call(tools, "write_file", {"path": str(home / "proj" / "a.txt"),
                                       "content": "x"}) == "ok"


def test_happy_granting_the_link_target_lifts_it(home):
    _stow(home)
    tools = _tools(home / "dotfiles" / "kitty")
    assert _call(tools, "write_file", {"path": "kitty.conf", "content": "font_size 12\n"}) == "ok"


def test_edge_dangling_link_hop_counts(home):
    (home / "dotfiles").mkdir()
    os.symlink("dotfiles/pdbrc", home / ".pdbrc")
    reason = P.refusal(str(home / "dotfiles" / "pdbrc"), granted=[str(home)])
    assert reason is not None
    chain = P._link_chain(str(home / ".pdbrc"))
    assert chain[0] == str(home / ".pdbrc") and chain[-1] == str(home / "dotfiles" / "pdbrc")


def test_sad_secret_behind_link_in_ssh_not_handed_out(home):
    (home / "keys").mkdir()
    (home / "keys" / "id_ed25519").write_text("PRIVATE\n")
    (home / ".ssh").mkdir()
    os.symlink("../keys/id_ed25519", home / ".ssh" / "id_ed25519")
    tools = _tools(home)
    for path in (home / ".ssh" / "id_ed25519", home / "keys" / "id_ed25519"):
        assert _call(tools, "read_file", {"path": str(path)}).startswith("error"), path


def test_sad_typed_path_counts_where_the_link_scan_does_not_reach(home):
    """A link deeper than the scan of the hidden folders: the name typed
    (in ~/.local/share, ~/.aws) decides, not only where the link leads."""
    (home / "stuff").mkdir()
    deep = home / ".local" / "share" / "a" / "b"
    deep.mkdir(parents=True)
    os.symlink(home / "stuff", deep / "link")
    (home / "plain").mkdir()
    (home / "plain" / "creds").write_text("aws_secret_access_key = x\n")
    secret_dir = home / ".aws" / "sub" / "deep" / "x"
    secret_dir.mkdir(parents=True)
    os.symlink(home / "plain" / "creds", secret_dir / "link")
    tools = _tools(home)
    assert _call(tools, "write_file", {"path": str(deep / "link" / "evil.js"),
                                       "content": "x"}).startswith("error")
    assert not (home / "stuff" / "evil.js").exists()
    assert _call(tools, "read_file", {"path": str(secret_dir / "link")}).startswith("error")
    assert _call(tools, "read_file", {"path": str(home / "plain" / "creds")}) == "ok"


# -- H2: Git folders ------------------------------------------------------------------------

@pytest.mark.parametrize("rel", [
    "repo/.git/commondir", "repo/.git/worktrees/wt/commondir", "repo/.git/worktrees/wt/gitdir",
    "bare.git/config", "bare.git/hooks/post-receive", "vendor/repo.git/hooks/pre-receive",
    "repo/.hg/hgrc", "repo/.hg/sharedpath", "repo/.jj/repo", "repo/.jj/repo/config.toml",
])
def test_sad_git_pointer_and_bare_names_refused(home, rel):
    assert P.refusal(str(home / "proj" / rel), granted=[str(home / "proj")]) is not None


@pytest.mark.parametrize("rel", ["repo/.git/index", "repo/.git/HEAD", "repo/.git/packed-refs",
                                 "repo/.git/refs/heads/main", "repo/.hg/store/data/x.i",
                                 "repo/src/main.py"])
def test_happy_git_working_files_stay_writable(home, rel):
    assert P.refusal(str(home / "proj" / rel), granted=[str(home / "proj")]) is None


def test_sad_folder_shaped_like_a_repository(home):
    src = home / "proj" / "repo" / "src"
    (src / "objects").mkdir(parents=True)
    (src / "refs").mkdir()
    tools = _tools(home / "proj")
    # The last of HEAD / objects / refs would make it a repository.
    assert _call(tools, "write_file", {"path": "repo/src/HEAD", "content": "ref: x\n"}
                 ).startswith("error")
    assert not (src / "HEAD").exists()
    (src / "HEAD").write_text("ref: refs/heads/main\n")  # the user's own bare repository
    assert _call(tools, "write_file", {"path": "repo/src/config", "content": "[core]\n"}
                 ).startswith("error")
    assert _call(tools, "write_file", {"path": "repo/src/hooks/pre-commit", "content": "x"}
                 ).startswith("error")
    # its objects, refs and HEAD are written as Git writes them
    assert _call(tools, "write_file", {"path": "repo/src/refs/main", "content": "x"}) == "ok"


def test_edge_mkdir_completing_the_shape_refused(home):
    folder = home / "proj" / "x"
    (folder / "objects").mkdir(parents=True)
    (folder / "HEAD").write_text("ref: refs/heads/main\n")
    tools = _tools(home / "proj")
    assert _call(tools, "mkdir", {"path": "x/refs"}).startswith("error")
    assert not (folder / "refs").exists()


@pytest.mark.parametrize("first,second", [("HEAD", "config"), ("config", "HEAD"),
                                          ("hooks/post-checkout", "HEAD")])
def test_sad_head_and_config_never_meet_whatever_the_order(home, first, second):
    """Folders made on the way (a bulk copy's, an archive's) are not checked;
    HEAD and the config are files and whichever comes second is refused."""
    (home / "proj" / "y").mkdir()
    if first.startswith("hooks/"):
        (home / "proj" / "y" / "hooks").mkdir()
    tools = _tools(home / "proj")
    assert _call(tools, "write_file", {"path": f"y/{first}", "content": "x\n"}) == "ok"
    assert _call(tools, "write_file", {"path": f"y/{second}", "content": "x\n"}).startswith(
        "error")


def test_sad_bulk_copy_cannot_assemble_a_repository(home):
    src = home / "proj" / "src"
    (src / "objects" / "ab").mkdir(parents=True)
    (src / "objects" / "ab" / "cd").write_text("o")
    (src / "HEAD").write_text("ref: refs/heads/main\n")
    dst = home / "proj" / "dst"
    (dst / "refs" / "heads").mkdir(parents=True)
    (dst / "config").write_text("[core]\n\tfsmonitor = x\n")
    tools = _tools(home / "proj")
    _call(tools, "bulk_copy", {"src": "src", "dst": "dst", "overwrite": True})
    assert not (dst / "HEAD").exists()


def test_sad_commondir_redirect_never_runs_fsmonitor(home, tmp_path):
    repo = home / "proj" / "r"
    subprocess.run(["git", "init", "-q", str(repo)], check=True)
    tools = _tools(home / "proj")
    assert _call(tools, "write_file", {"path": "r/.git/commondir", "content": "../x\n"}
                 ).startswith("error")
    assert not (repo / ".git" / "commondir").exists()


# -- M4: hard links -------------------------------------------------------------------------

def test_sad_write_through_hard_link_refused(home):
    bashrc = home / ".bashrc"
    bashrc.write_text("# profile\n")
    os.link(bashrc, home / "proj" / "bashrc.bak")
    tools = _tools(home / "proj")
    result = _call(tools, "write_file", {"path": "bashrc.bak", "content": "# replaced\n"})
    assert result.startswith("error") and "hard link" in result
    assert bashrc.read_text() == "# profile\n"


def test_edge_open_write_hard_link_not_truncated(home):
    from core.confined_fs import ConfinedLocalFS

    target = home / "proj" / "a"
    target.write_text("keep\n")
    os.link(target, home / "proj" / "b")
    fs = ConfinedLocalFS([str(home / "proj")])
    with pytest.raises(PermissionError):
        fs.open_write(str(home / "proj" / "b"))
    assert target.read_text() == "keep\n"
    with fs.open_write(str(home / "proj" / "new")) as fh:
        fh.write(b"x")
    assert (home / "proj" / "new").read_bytes() == b"x"


def test_sad_hard_link_to_secret_not_read(home):
    (home / ".aws").mkdir()
    secret = home / ".aws" / "credentials"
    secret.write_text("aws_secret_access_key = x\n")
    os.link(secret, home / "proj" / "notes.txt")
    tools = _tools(home / "proj")
    assert _call(tools, "read_file", {"path": "notes.txt"}).startswith("error")
    (home / "proj" / "plain.txt").write_text("x")
    os.link(home / "proj" / "plain.txt", home / "proj" / "plain2.txt")
    assert _call(tools, "read_file", {"path": "plain2.txt"}) == "ok"


# -- M5: the read side ----------------------------------------------------------------------

@pytest.mark.parametrize("rel", [
    "snap/firefox/common/.mozilla/firefox/p/logins.json",
    "snap/chromium/common/chromium/Default/Cookies",
    ".local/share/TelegramDesktop/tdata/key_datas", ".config/discord/Local Storage/x.log",
    ".config/glab-cli/config.yml", ".config/doctl/config.yaml", ".config/hcloud/cli.toml",
    ".terraformrc", ".config/filezilla/sitemanager.xml", ".purple/accounts.xml",
    ".fly/config.yml", ".config/ngrok/ngrok.yml", ".config/Element/x", ".wireguard/wg0.conf",
])
def test_sad_more_credential_stores_are_secret(home, rel):
    path = home / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("secret\n")
    assert P.read_refusal(str(path)) is not None
    # also with a grant of the folder (a secret stays secret)
    assert P.read_refusal(str(path), granted=[str(path.parent)]) is not None


def test_sad_hidden_entries_default_deny_for_reads(home):
    conf = home / ".config" / "someapp" / "settings.ini"
    conf.parent.mkdir(parents=True)
    conf.write_text("x")
    (home / ".pdbrc").write_text("x")
    tools = _tools(home)
    assert _call(tools, "read_file", {"path": str(conf)}).startswith("error")
    assert _call(tools, "read_file", {"path": str(home / ".pdbrc")}).startswith("error")
    # names stay listable
    assert _call(tools, "list_dir", {"path": str(home / ".config")}) == "ok"


def test_happy_granted_hidden_folder_and_plain_files_readable(home):
    conf = home / ".config" / "someapp" / "settings.ini"
    conf.parent.mkdir(parents=True)
    conf.write_text("x")
    (home / "proj" / "a.txt").write_text("x")
    assert _call(_tools(conf.parent), "read_file", {"path": "settings.ini"}) == "ok"
    assert _call(_tools(home), "read_file", {"path": str(home / "proj" / "a.txt")}) == "ok"
    tools = _tools(home / "proj", extra=[(str(conf.parent), False)])
    assert _call(tools, "read_file", {"path": str(conf)}) == "ok"


def test_edge_grant_of_local_does_not_open_local_share(home):
    target = home / ".local" / "share" / "gnome-shell" / "extensions" / "e" / "extension.js"
    assert P.refusal(str(target), granted=[str(home / ".local")]) is not None
    assert P.refusal(str(home / ".local" / "x"), granted=[str(home / ".local")]) is None


def test_sad_snap_writes_default_deny(home):
    path = home / "snap" / "firefox" / "common" / ".mozilla" / "firefox" / "p" / "user.js"
    assert P.refusal(str(path), granted=[str(home)]) is not None


# -- M6: the sandbox's secret walk ----------------------------------------------------------

def test_sad_walk_budget_covers_the_big_entry_and_finds_the_rest(home, monkeypatch):
    monkeypatch.setattr(P, "MAX_SECRET_WALK_ENTRY", 50)
    cache = home / ".cache" / "go-build"
    cache.mkdir(parents=True)
    for i in range(80):
        (cache / f"{i:03d}-d").write_text("")
    for rel in (".zsh_history", ".config/someapp/api_token.json", ".config/foo/server.key",
                ".local/share/app/credentials.db"):
        path = home / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("s")
    hides = [p for p, _folder in P.secret_hides(within=[str(home)])]
    for rel in (".zsh_history", ".config/someapp/api_token.json", ".config/foo/server.key",
                ".local/share/app/credentials.db", ".cache/go-build/000-d"):
        real = os.path.realpath(home / rel)
        assert any(real == h or real.startswith(h + os.sep) for h in hides), rel
    # only the entry that ran out is covered whole, not all of ~/.cache or ~/.config
    assert str(cache) in hides
    assert str(home / ".config") not in hides


def test_happy_package_stores_are_skipped(home):
    store = home / ".cargo" / "registry" / "src" / "x"
    store.mkdir(parents=True)
    (store / "token.rs.txt").write_text("")
    hides = [p for p, _folder in P._pattern_secrets(str(home), None)]
    assert not any("registry" in h for h in hides)


# -- the sandbox's mount plan ---------------------------------------------------------------

def _mode(plan, path) -> str:
    cover = [(p, rw, k) for p, rw, k in plan if k != "absent"
             and (str(path) == p or str(path).startswith(p.rstrip("/") + "/"))]
    if not cover:
        return "not mounted"
    p, rw, kind = max(cover, key=lambda c: len(c[0]))
    return kind if kind in ("hide", "dir") and not rw else ("rw" if rw else "ro")


def test_sad_sandbox_link_targets_and_child_repo_read_only(home):
    _stow(home)
    (home / "keys").mkdir()
    (home / "keys" / "id_ed25519").write_text("PRIVATE\n")
    (home / ".ssh").mkdir()
    os.symlink("../keys/id_ed25519", home / ".ssh" / "id_ed25519")
    subprocess.run(["git", "init", "-q", str(home / "proj")], check=True)
    (home / "proj" / ".git" / "commondir").write_text("x\n")  # an existing pointer: read-only
    plan = SB._mount_plan(SB.SandboxProfile(name="t"), str(home), True)
    assert _mode(plan, home / "dotfiles" / "kitty" / "kitty.conf") == "ro"
    assert _mode(plan, home / "keys" / "id_ed25519") == "hide"
    assert _mode(plan, home / "proj" / ".git" / "config") == "ro"
    assert _mode(plan, home / "proj" / ".git" / "hooks" / "pre-commit") == "ro"
    assert _mode(plan, home / "proj" / ".git" / "commondir") == "ro"
    assert _mode(plan, home / "proj" / ".git" / "objects" / "ab") == "rw"
    assert _mode(plan, home / "dotfiles" / "README") == "rw"


def test_edge_sandbox_sets_aside_a_new_commondir(home):
    repo = home / "proj"
    subprocess.run(["git", "init", "-q", str(repo)], check=True)
    plan = SB._mount_plan(SB.SandboxProfile(name="t"), str(repo), True)
    watch = SB._git_pointer_watch(plan)
    assert str(repo / ".git" / "commondir") in watch
    (repo / ".git" / "commondir").write_text("../evil\n")  # made by the agent
    moved = SB._set_aside_git_pointers(watch)
    assert len(moved) == 1 and not (repo / ".git" / "commondir").exists()
    assert Path(moved[0]).read_text() == "../evil\n"
    assert SB._set_aside_git_pointers(watch) == []


# -- L4: the XDG parser ---------------------------------------------------------------------

@pytest.mark.parametrize("rel,line", [
    (".xprofile", 'export XDG_CONFIG_HOME="$HOME/cfg"'),
    (".xsessionrc", 'export XDG_CONFIG_HOME="$HOME/cfg"'),
    (".bash_login", 'export XDG_CONFIG_HOME="$HOME/cfg"'),
    (".config/plasma-workspace/env/xdg.sh", 'export XDG_CONFIG_HOME="$HOME/cfg"'),
    (".config/fish/config.fish", "set -gx XDG_CONFIG_HOME ~/cfg"),
    (".profile", 'export XDG_CONFIG_HOME="${XDG_CONFIG_HOME:-$HOME/cfg}"'),
    (".profile", 'export LANG=C XDG_CONFIG_HOME="$HOME/cfg"'),
    (".profile", 'XDG_CONFIG_HOME="$HOME/cfg"; export XDG_CONFIG_HOME'),
    (".profile", "export XDG_CONFIG_HOME=$HOME/cfg  # moved"),
    (".bashrc", '[ -z "$XDG_CONFIG_HOME" ] && export XDG_CONFIG_HOME="$HOME/cfg"'),
    (".zshenv", 'export XDG_CONFIG_HOME="/home/$USER/cfg"'),
])
def test_sad_xdg_variants_found(home, rel, line):
    path = home / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(line + "\n")
    (home / "cfg" / "autostart").mkdir(parents=True)
    assert P.refusal(str(home / "cfg" / "autostart" / "evil.desktop"), entry=True,
                     granted=[str(home)]) is not None


def test_happy_xdg_comment_and_other_variable_ignored(home):
    (home / ".profile").write_text('# export XDG_CONFIG_HOME="$HOME/old"\n'
                                   'export XDG_CONFIG_HOME="$OTHER/x"\n')
    assert P._recorded_xdg(str(home)) == {}
