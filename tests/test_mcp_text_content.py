"""read_file and write_file carry text as text, not only as Base64.

Both tools moved content as Base64 only. A small local model cannot
encode or decode Base64 reliably: driven by the agent against a local
Qwen2.5-1.5B (llama.cpp), it answered "what does notes.txt say" with a
stat call and refused to write a file. ``read_file(encoding="text")``
returns ``text`` (UTF-8, undecodable bytes replaced and flagged) and
``write_file`` takes ``content`` (UTF-8 text) instead of
``content_b64``. Base64 stays the default and stays exact for any bytes.
"""

from __future__ import annotations

import base64

import pytest

from tests import mcp_group_testkit as T


def _tools(root, write=True):
    return T.build(root, set(), allow_write=write)


# --- happy ------------------------------------------------------------------


def test_happy_read_text(tmp_path):
    text = "Grüße, axross ✓\n"
    (tmp_path / "n.txt").write_text(text, encoding="utf-8")
    r = T.call(_tools(tmp_path), "read_file", {"path": str(tmp_path / "n.txt"), "encoding": "text"})
    assert r == {"text": text, "size": len(text.encode()), "truncated": False, "replaced": False}


def test_happy_write_text(tmp_path):
    target, text = tmp_path / "w.txt", "zwei\nZeilen ✓\n"
    r = T.call(_tools(tmp_path), "write_file", {"path": str(target), "content": text})
    assert target.read_text(encoding="utf-8") == text and r == {"size": len(text.encode())}


def test_happy_base64_stays_the_default(tmp_path):
    (tmp_path / "b.bin").write_bytes(b"\x00\xff")
    r = T.call(_tools(tmp_path), "read_file", {"path": str(tmp_path / "b.bin")})
    assert r == {"content_b64": base64.b64encode(b"\x00\xff").decode(), "size": 2, "truncated": False}


# --- sad --------------------------------------------------------------------


def test_sad_write_needs_exactly_one_content(tmp_path):
    tools = _tools(tmp_path)
    for args in ({"path": str(tmp_path / "x")},
                 {"path": str(tmp_path / "x"), "content": "a", "content_b64": "YQ=="}):
        with pytest.raises(T.RpcError) as info:
            T.call(tools, "write_file", args)
        assert info.value.code == -32602 and "exactly one" in str(info.value)
    assert not (tmp_path / "x").exists()


def test_sad_an_unknown_encoding_is_refused(tmp_path):
    (tmp_path / "n.txt").write_text("x")
    with pytest.raises(T.RpcError) as info:
        T.call(_tools(tmp_path), "read_file", {"path": str(tmp_path / "n.txt"), "encoding": "latin-1"})
    assert info.value.code == -32602


# --- edge -------------------------------------------------------------------


def test_edge_undecodable_bytes_are_replaced_and_flagged(tmp_path):
    (tmp_path / "m.bin").write_bytes(b"ok \xff\xfe end")
    r = T.call(_tools(tmp_path), "read_file", {"path": str(tmp_path / "m.bin"), "encoding": "text"})
    assert r["replaced"] is True and r["text"].startswith("ok ") and r["text"].endswith(" end")


def test_edge_a_cut_inside_a_character_is_not_a_replacement(tmp_path):
    (tmp_path / "u.txt").write_text("aä", encoding="utf-8")  # 'ä' is two bytes
    r = T.call(_tools(tmp_path), "read_file", {"path": str(tmp_path / "u.txt"), "encoding": "text",
                                               "max_bytes": 2})
    assert r == {"text": "a", "size": 2, "truncated": True, "replaced": False}


def test_edge_empty_text_writes_an_empty_file(tmp_path):
    T.call(_tools(tmp_path), "write_file", {"path": str(tmp_path / "e.txt"), "content": ""})
    assert (tmp_path / "e.txt").read_bytes() == b""
