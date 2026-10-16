"""MCP capability group ``crypto``: encrypt / decrypt in the axross .axenc
format (core.encrypted_overlay), both mutating. The passphrase never shows
up in an answer, an error or the audit trail; nothing is overwritten."""

from __future__ import annotations

import os

import pytest

from core import encrypted_overlay as E
from core import mcp_server as M
from tests import mcp_group_testkit as T

PASS = "correct horse battery staple"
WRONG = "wrong-passphrase-marker"


@pytest.fixture
def root(tmp_path):
    r = tmp_path / "root"
    r.mkdir()
    (r / "a.txt").write_bytes(b"plain secret bytes\n")
    (tmp_path / "outside.txt").write_text("x")
    return r


def _cr(root, write=True):
    return T.build(root, {"crypto"}, allow_write=write)


def test_happy_tools_only_with_write(root):
    assert not {"encrypt", "decrypt"} & set(_cr(root, write=False))
    assert {"encrypt", "decrypt"} <= set(_cr(root))


def test_happy_encrypt_then_decrypt_round_trip(root, caplog):
    T.capture_audit(caplog)
    tools = _cr(root)
    enc = T.call(tools, "encrypt", {"path": str(root / "a.txt"), "passphrase": PASS})
    assert enc["path"] == str(root / "a.txt.axenc")
    blob = (root / "a.txt.axenc").read_bytes()
    assert blob.startswith(E.MAGIC) and b"plain secret" not in blob
    assert (root / "a.txt").exists()  # the plaintext stays, as in the GUI
    dec = T.call(tools, "decrypt", {"path": enc["path"], "passphrase": PASS})
    assert dec["path"] == str(root / "a (2).txt")  # a.txt exists: never overwritten
    assert (root / "a (2).txt").read_bytes() == b"plain secret bytes\n"
    assert oct(os.stat(dec["path"]).st_mode & 0o777) == "0o600"
    lines = T.audit_lines(caplog)
    assert [ln.split()[0:2] for ln in lines] == [
        ["tool=encrypt", "outcome=attempt"],
        ["tool=encrypt", "outcome=ok"],
        ["tool=decrypt", "outcome=attempt"],
        ["tool=decrypt", "outcome=ok"],
    ]
    assert not any(PASS in ln for ln in lines)


def test_edge_encrypt_twice_gets_a_fresh_name(root):
    tools = _cr(root)
    T.call(tools, "encrypt", {"path": str(root / "a.txt"), "passphrase": PASS})
    second = T.call(tools, "encrypt", {"path": str(root / "a.txt"), "passphrase": PASS})
    assert second["path"] == str(root / "a.txt (2).axenc")


def test_edge_decrypt_of_a_name_without_suffix(root):
    tools = _cr(root)
    blob = E.encrypt_bytes(b"x", PASS)
    (root / "blob.bin").write_bytes(blob)
    out = T.call(tools, "decrypt", {"path": str(root / "blob.bin"), "passphrase": PASS})
    assert out["path"] == str(root / "blob.bin.decrypted")


def test_sad_wrong_passphrase_writes_nothing_and_leaks_nothing(root, caplog):
    T.capture_audit(caplog)
    tools = _cr(root)
    T.call(tools, "encrypt", {"path": str(root / "a.txt"), "passphrase": PASS})
    before = set(os.listdir(root))
    with pytest.raises(T.RpcError) as err:
        T.call(tools, "decrypt", {"path": str(root / "a.txt.axenc"), "passphrase": WRONG})
    assert WRONG not in err.value.message and PASS not in err.value.message
    assert set(os.listdir(root)) == before
    lines = T.audit_lines(caplog)
    assert any("tool=decrypt outcome=refused" in ln for ln in lines)
    assert not any(WRONG in ln or PASS in ln for ln in lines)


def test_sad_outside_root_and_bad_arguments(root):
    tools = _cr(root)
    with pytest.raises(T.RpcError) as err:
        T.call(tools, "encrypt", {"path": str(root.parent / "outside.txt"), "passphrase": PASS})
    assert "escapes" in err.value.message
    assert not (root.parent / "outside.txt.axenc").exists()
    for args in ({"path": str(root / "a.txt")}, {"path": str(root / "a.txt"), "passphrase": ""}):
        with pytest.raises(T.RpcError) as err:
            T.call(tools, "encrypt", args)
        assert err.value.code == M.ERR_INVALID_PARAMS


def test_sad_symlink_out_of_root(root):
    os.symlink(root.parent / "outside.txt", root / "link.txt")
    with pytest.raises(T.RpcError) as err:
        T.call(_cr(root), "encrypt", {"path": str(root / "link.txt"), "passphrase": PASS})
    assert "escapes" in err.value.message


def test_sad_encrypt_a_folder(root):
    (root / "d").mkdir()
    with pytest.raises(T.RpcError):
        T.call(_cr(root), "encrypt", {"path": str(root / "d"), "passphrase": PASS})
    assert not (root / "d.axenc").exists()


def test_edge_encrypt_refuses_a_file_above_the_cap(root, monkeypatch):
    monkeypatch.setattr(E, "MAX_ENCRYPTED_SIZE", 4)
    with pytest.raises(T.RpcError) as err:
        T.call(_cr(root), "encrypt", {"path": str(root / "a.txt"), "passphrase": PASS})
    assert "larger" in err.value.message
    assert not (root / "a.txt.axenc").exists()
