"""The MCP group tools that read files through a folder or a name list leave
the secret files out (review 2 of 0.15.176).

Before: round 1 put a secret-read deny list (core.protected_places) in front
of read_file, grep, the checksums and every group tool's *path*, but
``pack`` checked only its folder. ``pack(folder=~, names=[".ssh"])`` packed
``~/.ssh/id_ed25519`` - and ``.android/adbkey`` named directly - into a zip
under the root, and read_file on the zip handed out the keys.
``duplicates_scan`` likewise read (hashed) every secret under its folder.
"""

from __future__ import annotations

import base64
import io
import zipfile
from pathlib import Path

import pytest

from core import cas
from core import protected_places as P
from tests import mcp_group_testkit as T

SECRETS = {
    ".ssh/id_ed25519": "SECRET-SSH\n",
    ".android/adbkey": "SECRET-ADB\n",
    ".config/axross/gdrive_token.json": "SECRET-GDRIVE",
    ".gnupg/private-keys-v1.d/0123.key": "SECRET-GPG",
}
PUBLIC = {
    ".ssh/id_ed25519.pub": "ssh-ed25519 AAAA public",
    ".ssh/known_hosts": "host ssh-ed25519 AAAA",
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


def _zip_members(tools, path: str) -> dict[str, bytes]:
    data = base64.b64decode(T.call(tools, "read_file", {"path": path})["content_b64"])
    with zipfile.ZipFile(io.BytesIO(data)) as z:
        return {n: z.read(n) for n in z.namelist()}


def test_sad_pack_leaves_the_ssh_keys_in_a_named_folder_out(home):
    tools = T.build(home, {"packer"}, allow_write=True)
    out = T.call(tools, "pack", {"folder": str(home), "names": [".ssh", "notes.txt"],
                                 "archive_name": "x"})
    members = _zip_members(tools, out["path"])
    assert ".ssh/id_ed25519" not in members
    assert not any(b"SECRET" in v for v in members.values())
    assert ".ssh/id_ed25519" in out["skipped"]
    # The public files around the keys are packed as before.
    assert members[".ssh/id_ed25519.pub"] == b"ssh-ed25519 AAAA public"
    assert members["notes.txt"] == b"my notes"


def test_sad_pack_refuses_a_secret_named_directly(home):
    tools = T.build(home, {"packer"}, allow_write=True)
    out = T.call(tools, "pack", {"folder": str(home / ".android"), "names": ["adbkey"],
                                 "archive_name": "y"})
    assert out["skipped"] == ["adbkey"] and out["files"] == 0
    assert _zip_members(tools, out["path"]) == {}


def test_edge_pack_leaves_a_wholly_secret_folder_out_recursively(home):
    tools = T.build(home, {"packer"}, allow_write=True)
    out = T.call(tools, "pack", {"folder": str(home), "names": [".gnupg", ".config"],
                                 "archive_name": "z"})
    members = _zip_members(tools, out["path"])
    assert ".gnupg/private-keys-v1.d" in out["skipped"]
    assert ".config/axross/gdrive_token.json" in out["skipped"]
    assert not any(b"SECRET" in v for v in members.values())


def test_sad_duplicates_scan_does_not_read_secrets(home, monkeypatch):
    read: list[str] = []
    real = cas._index_one

    def spy(backend, backend_id, path, *a, **kw):
        read.append(path)
        return real(backend, backend_id, path, *a, **kw)

    monkeypatch.setattr(cas, "_index_one", spy)
    (home / "copy.pub").write_text("ssh-ed25519 AAAA public", encoding="utf-8")
    tools = T.build(home, {"duplicates"})
    scan = T.call(tools, "duplicates_scan", {"path": str(home)})
    assert scan["status"] == "complete"
    hashed = {Path(p).relative_to(home).as_posix() for p in read}
    assert hashed.isdisjoint(SECRETS), hashed & set(SECRETS)
    assert {".ssh/id_ed25519.pub", "copy.pub", "notes.txt"} <= hashed
    groups = T.call(tools, "duplicates_groups", {"path": str(home)})["groups"]
    assert len(groups) == 1 and len(groups[0]["copies"]) == 2
