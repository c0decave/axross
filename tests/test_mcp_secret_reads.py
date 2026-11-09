"""MCP tools do not hand out axross's tokens and keys or the SSH / GnuPG
private keys, unless the operator opts in (review 1 of 0.15.176).

Before: the MCP root defaults to the home folder (main.py) and the read
tools had no deny list. A read-only, prompt-injected client read
``~/.config/axross/gdrive_token.json`` (a Google Drive refresh token) or
``~/.ssh/id_ed25519`` with read_file, grep, checksum, resources/read or a
group's reader, and copied them to a readable name - "read my files"
became write access to the cloud account or the SSH hosts.
"""

from __future__ import annotations

import base64
import json
import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core import mcp_server as M  # noqa: E402
from core import protected_places as P  # noqa: E402
from core.local_fs import LocalFS  # noqa: E402
from tests import mcp_group_testkit as T  # noqa: E402

SECRETS = {
    ".config/axross/gdrive_token.json": '{"refresh_token": "1//SECRET-GDRIVE"}',
    ".config/axross/dropbox_token.work-0123456789ab.json": '{"refresh_token": "SECRET-DBX"}',
    ".config/axross/onedrive_token.json": "SECRET-ONEDRIVE",
    ".ssh/id_ed25519": "SECRET-SSH\n",
    ".ssh/work_server": "SECRET-SSH-WORK\n",
    ".gnupg/private-keys-v1.d/0123ABCD.key": "SECRET-GPG",
    ".android/adbkey": "SECRET-ADB\n",
    ".local/state/axross/chat/matrix-abc/store.db": "SECRET-CHAT",
}
PUBLIC = {
    ".ssh/id_ed25519.pub": "ssh-ed25519 AAAA public",
    ".ssh/known_hosts": "host ssh-ed25519 AAAA",
    ".config/axross/bookmarks.json": "[]",
    "notes.txt": "my notes",
}


@pytest.fixture
def home(tmp_path, monkeypatch) -> Path:
    home = tmp_path / "home"
    for rel, text in {**SECRETS, **PUBLIC}.items():
        path = home / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.delenv(P.HOST_HOME_ENV, raising=False)
    monkeypatch.delenv("XDG_RUNTIME_DIR", raising=False)
    monkeypatch.delenv("XDG_DATA_HOME", raising=False)
    return home


def _tools(home, **kw) -> dict:
    return T.build(home, kw.pop("groups", ()), **kw)


@pytest.mark.parametrize("rel", sorted(SECRETS))
def test_sad_read_file_refuses_a_secret_under_the_default_root(home, rel):
    tools = _tools(home)
    with pytest.raises(T.RpcError) as err:
        T.call(tools, "read_file", {"path": str(home / rel), "encoding": "text"})
    assert "secret" in err.value.message
    assert "SECRET" not in json.dumps(err.value.data or {}) + err.value.message


@pytest.mark.parametrize("rel", sorted(PUBLIC))
def test_happy_other_files_are_read_as_before(home, rel):
    out = T.call(_tools(home), "read_file", {"path": str(home / rel), "encoding": "text"})
    assert out["text"] == PUBLIC[rel]


def test_happy_names_of_secret_places_are_still_listed(home):
    tools = _tools(home)
    names = {e["name"] for e in T.call(tools, "list_dir", {"path": str(home / ".ssh")})}
    assert {"id_ed25519", "id_ed25519.pub", "work_server"} <= names
    walked = T.call(tools, "walk", {"path": str(home), "max_depth": 6})
    assert str(home / ".config/axross/gdrive_token.json") in {e["path"] for e in
                                                             walked["entries"]}
    assert T.call(tools, "stat", {"path": str(home / ".ssh/id_ed25519")})["size"] > 0


def test_sad_grep_and_checksums_do_not_read_secrets(home):
    tools = _tools(home)
    found = T.call(tools, "grep", {"pattern": "SECRET", "path": str(home), "max_depth": 6})
    assert found["matches"] == []
    refused = {u["path"] for u in found["unreadable"]}
    assert str(home / ".ssh/id_ed25519") in refused
    with pytest.raises(T.RpcError):
        T.call(tools, "checksum", {"path": str(home / ".ssh/id_ed25519")})
    tree = T.call(tools, "recursive_checksum", {"path": str(home / ".ssh")})
    by_path = {e["path"]: e for e in tree["entries"]}
    assert "checksum" not in by_path[str(home / ".ssh/id_ed25519")]
    assert "checksum" in by_path[str(home / ".ssh/id_ed25519.pub")]
    assert not tree["complete"]


def test_sad_resources_read_refuses_a_secret(home):
    resp = M._handle_request(
        {"jsonrpc": "2.0", "id": 1, "method": "resources/read",
         "params": {"uri": f"axross://{home}/.config/axross/gdrive_token.json"}},
        [], cancels=M._CancelRegistry(), resources=M._build_resources(LocalFS(), root=str(home)))
    assert "error" in resp and "SECRET" not in json.dumps(resp)


def test_sad_a_symlink_in_the_root_does_not_lead_to_a_secret(home):
    (home / "innocent.txt").symlink_to(home / ".ssh" / "id_ed25519")
    (home / "keys").symlink_to(home / ".ssh")
    tools = _tools(home)
    for path in (home / "innocent.txt", home / "keys" / "id_ed25519"):
        with pytest.raises(T.RpcError) as err:
            T.call(tools, "read_file", {"path": str(path)})
        assert "secret" in err.value.message


def test_sad_secrets_are_not_copied_moved_or_linked_to_a_readable_name(home):
    """~/.android/adbkey is no write-protected place: a copy, a move or a
    hard link would give it a name the read tools hand out."""
    tools = _tools(home, allow_write=True)
    key = str(home / ".android" / "adbkey")
    attempts = [
        ("copy", {"src": key, "dst": str(home / "a")}),
        ("bulk_copy", {"src": str(home / ".android"), "dst": str(home / "b")}),
        ("rename", {"src": key, "dst": str(home / "c")}),
        ("hardlink", {"target": key, "link_path": str(home / "d")}),
    ]
    for name, args in attempts:
        with pytest.raises(T.RpcError) as err:
            T.call(tools, name, args)
        assert "secret" in err.value.message, name
    assert sorted(p.name for p in home.iterdir()) == [".android", ".config", ".gnupg",
                                                       ".local", ".ssh", "notes.txt"]


def test_sad_group_readers_do_not_read_secrets(home):
    tools = _tools(home, groups={"filetype"})
    with pytest.raises(T.RpcError) as err:
        T.call(tools, "file_type", {"path": str(home / ".ssh/id_ed25519")})
    assert "secret" in err.value.message
    assert T.call(tools, "file_type", {"path": str(home / "notes.txt")})


def test_happy_the_operator_can_opt_in(home):
    tools = _tools(home, allow_secret_reads=True)
    out = T.call(tools, "read_file", {"path": str(home / ".ssh/id_ed25519")})
    assert b"SECRET-SSH" in base64.b64decode(out["content_b64"])
    resources = M._build_resources(LocalFS(), root=str(home), allow_secret_reads=True)
    entry = resources.read(f"axross://{home}/.android/adbkey")
    assert b"SECRET-ADB" in base64.b64decode(entry["blob"])


def test_edge_in_the_sandbox_the_host_homes_secrets_stay_refused(home, tmp_path, monkeypatch):
    sandbox_home = tmp_path / "sandbox-tmp"
    sandbox_home.mkdir()
    monkeypatch.setenv("HOME", str(sandbox_home))  # the worker's HOME is /tmp
    monkeypatch.setenv(P.HOST_HOME_ENV, str(home))
    assert P.read_refusal(str(home / ".ssh/id_ed25519"))
    assert P.read_refusal(str(home / "notes.txt")) is None


def test_edge_case_insensitive_systems_and_xdg_places(home, tmp_path, monkeypatch):
    monkeypatch.setattr(P, "_case_insensitive", lambda: True)
    assert P.read_refusal(str(home / ".SSH" / "ID_ED25519"))
    assert P.read_refusal(str(home / ".SSH" / "id_ed25519.PUB")) is None
    monkeypatch.setattr(P, "_case_insensitive", lambda: False)
    runtime = tmp_path / "run"
    monkeypatch.setenv("XDG_RUNTIME_DIR", str(runtime))
    assert P.read_refusal(str(runtime / "axross" / "mcp-http-7331.token"))
    data = tmp_path / "data"
    monkeypatch.setenv("XDG_DATA_HOME", str(data))
    assert P.read_refusal(str(data / "axross" / "bluetooth-direct-keys.json"))


def test_edge_a_folder_holding_secrets_is_refused_only_as_a_whole(home):
    assert P.read_refusal(str(home / ".ssh")) is None  # listed, not read
    assert P.read_refusal(str(home / ".ssh"), entry=True)  # copied or moved whole
    assert P.read_refusal(str(home), entry=True)
    assert P.read_refusal(str(home / "Documents"), entry=True) is None


def test_edge_the_write_list_is_unchanged(home):
    """The read side is a list of its own: ~/.android is not write-protected
    (only by default-deny since round 6, which a grant of it lifts)."""
    assert P.refusal(str(home / ".android" / "adbkey"), granted=[str(home / ".android")]) is None
    assert P.refusal(str(home / ".ssh" / "id_ed25519"))


def _main(*argv):
    from tests.test_mcp_write_root import _main_in_process

    return _main_in_process(*argv)


def test_happy_the_cli_flag_reaches_the_stdio_server():
    code, err, serve, _http = _main("--mcp-server", "--mcp-allow-secret-reads")
    assert code == 0, err
    assert serve.call_args.args[0].allow_secret_reads is True
    code, err, serve, _http = _main("--mcp-server")
    assert code == 0, err
    assert serve.call_args.args[0].allow_secret_reads is False


def test_sad_the_cli_flag_is_refused_over_http():
    code, err, serve, serve_http = _main("--mcp-server", "--mcp-http", "127.0.0.1:7331",
                                         "--mcp-allow-secret-reads")
    assert code == 2 and "stdio-only" in err
    serve.assert_not_called()
    serve_http.assert_not_called()


def test_edge_the_tool_manifest_is_the_same_with_the_flag(home, capsys):
    """The flag changes what tools read, not which tools there are."""
    plain = {t.name for t in M._build_tools(LocalFS(), allow_write=False, root=str(home))}
    opted = {t.name for t in M._build_tools(LocalFS(), allow_write=False, root=str(home),
                                            allow_secret_reads=True)}
    assert plain == opted
    assert os.environ["HOME"] == str(home)
