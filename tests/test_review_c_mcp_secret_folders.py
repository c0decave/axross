"""Review C, round 1: secrets known by the name of their folder.

``.aws/credentials``, ``.docker/config.json`` and ``.kube/config`` are
secret wherever they are, and on a remote every file of ``.ssh`` and
``.gnupg`` is - by the folder's name. ``rename proj/.kube proj/plain``
took the name away: ``read_file proj/plain/config`` handed the cluster's
token out; on a remote, ``rename ~/.gnupg ~/gnupg`` handed out the GnuPG
private keys (no PEM line in them for the content scan). Now such a folder
is not moved whole. Their backup copies (``credentials.bak``,
``config~``) are secret like the files.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core import mcp_groups as G  # noqa: E402
from core import mcp_server as M  # noqa: E402
from core import protected_places as P  # noqa: E402
from core.local_fs import LocalFS  # noqa: E402
from core.profiles import ConnectionProfile  # noqa: E402
from core.ram_fs import RamFsSession  # noqa: E402


def _call(tools, name, **arguments):
    return M._handle_request({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                              "params": {"name": name, "arguments": arguments}},
                             tools, cancels=M._CancelRegistry())


def _ok(resp) -> bool:
    result = resp.get("result")
    return result is not None and not result.get("isError")


def _text(resp) -> str:
    return json.dumps(resp, ensure_ascii=False)


@pytest.fixture
def home(tmp_path, monkeypatch):
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.delenv(P.HOST_HOME_ENV, raising=False)
    return home


def _local(home):
    return M._build_tools(LocalFS(), allow_write=True, root=str(home), allow_exec=False)


@pytest.mark.parametrize("folder,name", [(".kube", "config"), (".aws", "credentials"),
                                         (".docker", "config.json"), (".KUBE", "config")])
def test_sad_the_folder_of_a_secret_pair_is_not_renamed(home, folder, name):
    proj = home / "proj"
    (proj / folder).mkdir(parents=True)
    (proj / folder / name).write_text("SUPERSECRET\n")
    tools = _local(home)
    resp = _call(tools, "rename", src=str(proj / folder), dst=str(proj / "plain"))
    assert not _ok(resp)
    assert (proj / folder / name).exists() and not (proj / "plain").exists()


@pytest.mark.parametrize("name", ["credentials.bak", "credentials~", "credentials.old"])
def test_sad_a_backup_copy_of_a_secret_pair_is_secret(home, name):
    aws = home / "proj" / ".aws"
    aws.mkdir(parents=True)
    (aws / name).write_text("aws_secret_access_key=BBB\n")
    resp = _call(_local(home), "read_file", path=str(aws / name), encoding="text")
    assert not _ok(resp) and "BBB" not in _text(resp)


def test_happy_other_folders_are_renamed_and_read(home):
    proj = home / "proj"
    (proj / "kube-notes").mkdir(parents=True)
    (proj / "kube-notes" / "config").write_text("just notes\n")
    tools = _local(home)
    assert _ok(_call(tools, "rename", src=str(proj / "kube-notes"), dst=str(proj / "notes")))
    resp = _call(tools, "read_file", path=str(proj / "notes" / "config"), encoding="text")
    assert _ok(resp) and "just notes" in _text(resp)


@pytest.fixture
def remote(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    ram = RamFsSession("r")
    for folder in ("/home", "/home/u", "/home/u/.gnupg", "/home/u/.gnupg/private-keys-v1.d",
                   "/home/u/.ssh", "/home/u/site", "/home/u/site/.kube"):
        ram.mkdir(folder)
    for path, data in (("/home/u/.gnupg/private-keys-v1.d/ABCD.key",
                        b"Key: (private-key (rsa (n #00AA#)(d #SECRETD#)))\n"),
                       ("/home/u/.ssh/work", b"SECRETKEY\n"),
                       ("/home/u/site/.kube/config", b"token: SECRETTOKEN\n"),
                       ("/home/u/site/.kube/config.bak", b"token: SECRETTOKEN\n")):
        with ram.open_write(path) as handle:
            handle.write(data)
    registry = G.RemoteRegistry()
    registry.attach("pane:box", ram, ConnectionProfile(name="box", protocol="sftp", host="h",
                                                       port=22))
    tools = M._build_tools(LocalFS(), allow_write=True, root=str(tmp_path),
                           tool_groups=frozenset(G.GROUPS), allow_exec=False,
                           remote_registry=registry)
    return tools, ram


@pytest.mark.parametrize("src", ["/home/u/.gnupg", "/home/u/.ssh", "/home/u/site/.kube",
                                 "/home/u/.GnuPG"])
def test_sad_a_remotes_secret_folder_is_not_renamed(remote, src):
    tools, ram = remote
    if src.endswith("GnuPG"):
        ram.rename("/home/u/.gnupg", src)
    resp = _call(tools, "rename", src=src, dst="/home/u/plain", backend="pane:box")
    assert not _ok(resp)
    assert not ram.exists("/home/u/plain")


def test_sad_a_backup_copy_of_a_remote_secret_pair_is_secret(remote):
    tools, _ram = remote
    resp = _call(tools, "read_file", path="/home/u/site/.kube/config.bak", backend="pane:box",
                 encoding="text")
    assert not _ok(resp) and "SECRETTOKEN" not in _text(resp)


def test_happy_a_remotes_plain_folder_is_renamed(remote):
    tools, ram = remote
    assert _ok(_call(tools, "rename", src="/home/u/site", dst="/home/u/www", backend="pane:box"))
    assert ram.exists("/home/u/www")
