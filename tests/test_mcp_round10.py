"""Round 10 of the MCP tool review (0.15.184): the gaps blind graders named,
closed through the same guards as the other tools, and the catalogue Glama
serves under ``--mcp-tools all``.

Measured before: nothing listed or restored axross's trash although
trash_duplicates fills it ("restore in the axross app"); write_file only
replaced whole files; an older version could be read but not made current
again; no tool listed the LLM profiles run_llm_agent takes ("an unknown
name's error does"); walk_tree, search_content and list_duplicate_scans
stopped at their caps with no way on. ``all`` served the 20 Android tools
as well - 72 tools under Glama's command line; create_symlink and
create_hardlink, run_backend_command and run_backend_script were two
tools each of one safety class."""

from __future__ import annotations

import io
import os
import stat

import pytest

from core import mcp_groups as G
from core import mcp_names as N
from core import mcp_server as M
from core.backend import SessionLifecycle
from core.local_fs import LocalFS
from models.exec_result import ExecResult
from tests import mcp_group_testkit as T


def _files(root, write=True, groups=(), **kw):
    return T.build(root, set(groups), allow_write=write, **kw)


# -- what "all" means -------------------------------------------------------------------


def test_happy_all_is_every_group_but_the_device_ones():
    assert G.parse_groups(["all"]) == frozenset(G.GROUPS) - {"adb"} == frozenset(G.ALL_GROUPS)
    assert G.parse_groups(["all,adb"]) == frozenset(G.GROUPS)
    assert G.parse_groups(["all", "adb"]) == frozenset(G.GROUPS)
    assert G.groups_from(["all"], env_value="adb") == frozenset(G.GROUPS)
    assert G.parse_groups(["adb"]) == frozenset({"adb"})
    assert G.OPT_IN_GROUPS == {"adb"}


def test_happy_glamas_command_line_serves_54_tools_and_all_adb_74(tmp_path):
    def served(groups):
        return M._build_tools(LocalFS(), allow_write=True, root=str(tmp_path),
                              allow_scripts=True, tool_groups=G.parse_groups(groups),
                              allow_exec=True)

    general = {N.public(t.name) for t in served(["all"])}
    every = {N.public(t.name) for t in served(["all,adb"])}
    assert len(general) == 54 and len(every) == 74
    assert every - general == {N.public(t["name"]) for t in M._adb_device.tool_definitions()}


# -- write_file: create, append, at_offset ----------------------------------------------


def test_happy_append_adds_at_the_end_and_keeps_the_mode(tmp_path, caplog):
    T.capture_audit(caplog)
    (tmp_path / "log.txt").write_text("one\n")
    os.chmod(tmp_path / "log.txt", 0o640)
    tools = _files(tmp_path)
    out = T.call(tools, "write_file", {"path": "log.txt", "content": "two\n",
                                       "write_mode": "append"})
    assert out == {"size": 4, "file_size": 8}
    assert (tmp_path / "log.txt").read_text() == "one\ntwo\n"
    assert stat.S_IMODE(os.stat(tmp_path / "log.txt").st_mode) == 0o640
    assert any("tool=write_file outcome=ok" in ln and "write_mode='append'" in ln
               for ln in T.audit_lines(caplog))


def test_happy_at_offset_overwrites_in_place_and_may_grow_the_file(tmp_path):
    (tmp_path / "b.bin").write_bytes(b"0123456789")
    tools = _files(tmp_path)
    T.call(tools, "write_file", {"path": "b.bin", "content": "AB", "write_mode": "at_offset",
                                 "offset": 3})
    assert (tmp_path / "b.bin").read_bytes() == b"012AB56789"
    out = T.call(tools, "write_file", {"path": "b.bin", "content_b64": "WFla",
                                       "write_mode": "at_offset", "offset": 9})
    assert (tmp_path / "b.bin").read_bytes() == b"012AB5678XYZ" and out["file_size"] == 12
    T.call(tools, "write_file", {"path": "b.bin", "content": "!", "write_mode": "at_offset",
                                 "offset": 12})  # at the very end: an append
    assert (tmp_path / "b.bin").read_bytes().endswith(b"XYZ!")


def test_sad_at_offset_past_the_end_or_without_an_offset_fails(tmp_path):
    (tmp_path / "b.bin").write_bytes(b"abc")
    tools = _files(tmp_path)
    for args, words in (({"write_mode": "at_offset", "offset": 4}, "past the end"),
                        ({"write_mode": "at_offset"}, "needs offset"),
                        ({"offset": 1}, "only for write_mode at_offset"),
                        ({"write_mode": "append", "offset": 1}, "only for write_mode")):
        with pytest.raises(T.RpcError) as err:
            T.call(tools, "write_file", {"path": "b.bin", "content": "x", **args})
        assert words in err.value.message, (args, err.value.message)
    assert (tmp_path / "b.bin").read_bytes() == b"abc"


def test_sad_append_needs_an_existing_file_and_a_small_one(tmp_path, monkeypatch):
    tools = _files(tmp_path)
    with pytest.raises(T.RpcError) as err:
        T.call(tools, "write_file", {"path": "none.txt", "content": "x",
                                     "write_mode": "append"})
    assert "No such file" in err.value.message and not (tmp_path / "none.txt").exists()
    monkeypatch.setattr(M, "MAX_EDIT_FILE_BYTES", 8)
    (tmp_path / "big.txt").write_text("123456789")
    with pytest.raises(T.RpcError) as err:
        T.call(tools, "write_file", {"path": "big.txt", "content": "x",
                                     "write_mode": "append"})
    assert "at most" in err.value.message
    assert (tmp_path / "big.txt").read_text() == "123456789"


def test_happy_create_makes_a_private_file_and_never_replaces(tmp_path):
    tools = _files(tmp_path)
    T.call(tools, "write_file", {"path": "new.txt", "content": "first", "write_mode": "create"})
    assert stat.S_IMODE(os.stat(tmp_path / "new.txt").st_mode) == 0o600
    with pytest.raises(T.RpcError) as err:
        T.call(tools, "write_file", {"path": "new.txt", "content": "second",
                                     "write_mode": "create"})
    assert "File exists" in err.value.message
    assert (tmp_path / "new.txt").read_text() == "first"
    assert [p.name for p in tmp_path.iterdir()] == ["new.txt"]  # no temp file left


def test_sad_every_mode_keeps_the_write_guards(tmp_path):
    outside = tmp_path / "outside.txt"
    outside.write_text("keep")
    root = tmp_path / "root"
    (root / ".axross-trash").mkdir(parents=True)  # a protected place in any root
    (root / ".axross-trash" / "entry").write_text("trashed")
    tools = _files(root)
    for mode in M.WRITE_MODES:
        extra = {"offset": 0} if mode == "at_offset" else {}
        for path in (str(outside), ".axross-trash/entry"):
            with pytest.raises(T.RpcError):
                T.call(tools, "write_file", {"path": path, "content": "x",
                                             "write_mode": mode, **extra})
    assert outside.read_text() == "keep"
    assert (root / ".axross-trash" / "entry").read_text() == "trashed"


# -- restore_file_version -----------------------------------------------------------------


class _Versioned(LocalFS):
    """The local disk with a version history kept in memory."""

    def __init__(self):
        super().__init__()
        self.old: dict[tuple[str, str], bytes] = {}

    def list_versions(self, path):
        from models.file_version import FileVersion

        return [FileVersion(version_id=v, size=len(b), is_current=False)
                for (p, v), b in self.old.items() if p == path]

    def open_version_read(self, path, version_id):
        try:
            return io.BytesIO(self.old[(path, version_id)])
        except KeyError:
            raise OSError(f"no version {version_id}") from None


def test_happy_restore_file_version_makes_the_old_content_current(tmp_path, caplog):
    T.capture_audit(caplog)
    (tmp_path / "doc.txt").write_text("new")
    backend = _Versioned()
    backend.old[(str(tmp_path / "doc.txt"), "v1")] = b"old content"
    tools = {t.name: t for t in M._build_tools(backend, allow_write=True, root=str(tmp_path))}
    out = T.call(tools, "restore_file_version", {"path": "doc.txt", "version_id": "v1"})
    assert out == {"path": str(tmp_path / "doc.txt"), "version_id": "v1", "size": 11}
    assert (tmp_path / "doc.txt").read_text() == "old content"
    assert any("tool=restore_file_version outcome=ok" in ln for ln in T.audit_lines(caplog))
    with pytest.raises(T.RpcError) as err:
        T.call(tools, "restore_file_version", {"path": "doc.txt", "version_id": "v9"})
    assert "no version" in err.value.message and (tmp_path / "doc.txt").read_text() == "old content"


def test_sad_restore_file_version_needs_write_versions_and_the_root(tmp_path):
    assert "restore_version" not in _files(tmp_path, write=False)
    (tmp_path / "f.txt").write_text("x")
    with pytest.raises(T.RpcError):  # the local disk keeps no versions
        T.call(_files(tmp_path), "restore_file_version", {"path": "f.txt", "version_id": "1"})
    backend = _Versioned()
    outside = tmp_path.parent / f"{tmp_path.name}-outside.txt"
    backend.old[(str(outside), "v1")] = b"planted"
    tools = {t.name: t for t in M._build_tools(backend, allow_write=True, root=str(tmp_path))}
    with pytest.raises(T.RpcError):
        T.call(tools, "restore_file_version", {"path": str(outside), "version_id": "v1"})
    assert not outside.exists()


# -- paging: walk_tree, search_content, list_duplicate_scans ------------------------------


def _tree(root, n=7):
    (root / "d").mkdir()
    for i in range(n):
        (root / f"f{i}.txt").write_text("needle\nneedle\n")
        (root / "d" / f"g{i}.txt").write_text("needle\n")


def test_happy_walk_tree_pages_with_next_offset_through_the_whole_tree(tmp_path):
    _tree(tmp_path)
    tools = _files(tmp_path, write=False)
    whole = T.call(tools, "walk", {"path": ".", "max_entries": 1000})
    assert whole["next_offset"] is None and not whole["truncated"]
    seen, offset = [], 0
    while offset is not None:
        page = T.call(tools, "walk", {"path": ".", "max_entries": 4, "offset": offset})
        assert page["offset"] == offset and len(page["entries"]) <= 4
        seen += page["entries"]
        offset = page["next_offset"]
        assert page["truncated"] == (offset is not None)
    assert seen == whole["entries"] and len(seen) == 15  # 7 + d + 7, in one order


def test_happy_search_content_pages_with_next_offset(tmp_path):
    _tree(tmp_path)
    tools = _files(tmp_path, write=False)
    whole = T.call(tools, "grep", {"pattern": "needle", "max_matches": 500})
    assert len(whole["matches"]) == 21 and whole["next_offset"] is None
    seen, offset = [], 0
    while offset is not None:
        page = T.call(tools, "grep", {"pattern": "needle", "max_matches": 5, "offset": offset})
        seen += page["matches"]
        offset = page["next_offset"]
    assert seen == whole["matches"]


def test_happy_list_duplicate_scans_pages(tmp_path):
    (tmp_path / "a").mkdir()
    (tmp_path / "b").mkdir()
    tools = _files(tmp_path, groups={"duplicates"}, write=False)
    for folder in ("a", "b", "."):
        T.call(tools, "duplicates_scan", {"path": folder})
    first = T.call(tools, "duplicates_scans", {"max_scans": 2})
    assert len(first["scans"]) == 2 and first["truncated"] and first["next_offset"] == 2
    rest = T.call(tools, "duplicates_scans", {"max_scans": 2, "offset": 2})
    assert not rest["truncated"] and rest["next_offset"] is None
    ids = [s["scan_id"] for s in first["scans"] + rest["scans"]]
    assert ids == [s["scan_id"] for s in T.call(tools, "duplicates_scans", {})["scans"]]


# -- the trash: list_trash and restore_from_trash -----------------------------------------


@pytest.fixture
def trashed(tmp_path):
    root = tmp_path / "root"
    (root / "sub").mkdir(parents=True)
    (root / "a.txt").write_text("same\n")
    (root / "sub" / "b.txt").write_text("same\n")
    os.utime(root / "a.txt", (1_000_000_000, 1_000_000_000))
    tools = _files(root, groups={"duplicates"})
    T.call(tools, "duplicates_scan", {})
    T.call(tools, "duplicates_dedupe", {"dry_run": False})
    assert not (root / "sub" / "b.txt").exists()
    return root, tools


def test_happy_list_trash_shows_what_a_dedupe_moved(trashed):
    root, tools = trashed
    listed = T.call(tools, "trash_list", {})
    assert listed["trash_root"] == str(root / ".axross-trash")
    assert [e["original_path"] for e in listed["entries"]] == [str(root / "sub" / "b.txt")]
    entry = listed["entries"][0]
    assert entry["size"] == 5 and entry["is_dir"] is False and entry["trashed_at"]
    assert listed["count"] == 1 and listed["next_offset"] is None
    assert "trash_list" in _files(root, groups={"duplicates"}, write=False)  # read-only


def test_happy_restore_from_trash_puts_the_file_back_once(trashed, caplog):
    T.capture_audit(caplog)
    root, tools = trashed
    trash_id = T.call(tools, "trash_list", {})["entries"][0]["trash_id"]
    (root / "sub").rmdir()  # its folder went too: it is made again
    out = T.call(tools, "trash_restore", {"trash_id": trash_id})
    assert out == {"trash_id": trash_id, "path": str(root / "sub" / "b.txt"), "is_dir": False}
    assert (root / "sub" / "b.txt").read_text() == "same\n"
    assert T.call(tools, "trash_list", {})["entries"] == []
    with pytest.raises(T.RpcError) as err:
        T.call(tools, "trash_restore", {"trash_id": trash_id})
    assert "trash entry not found" in err.value.message
    lines = T.audit_lines(caplog)
    assert any("tool=restore_from_trash outcome=ok" in ln for ln in lines)


def test_sad_restore_from_trash_never_replaces_and_stays_in_the_root(trashed, tmp_path):
    root, tools = trashed
    trash_id = T.call(tools, "trash_list", {})["entries"][0]["trash_id"]
    (root / "sub" / "b.txt").write_text("newer")
    with pytest.raises(T.RpcError) as err:
        T.call(tools, "trash_restore", {"trash_id": trash_id})
    assert "already exists" in err.value.message
    assert (root / "sub" / "b.txt").read_text() == "newer"
    for dst in (str(tmp_path / "outside.txt"), ".axross-trash/x.txt", "../x.txt"):
        with pytest.raises(T.RpcError):
            T.call(tools, "trash_restore", {"trash_id": trash_id, "dst": dst})
    assert not (tmp_path / "outside.txt").exists()
    out = T.call(tools, "trash_restore", {"trash_id": trash_id, "dst": "back/b.txt"})
    assert out["path"] == str(root / "back" / "b.txt")
    assert (root / "back" / "b.txt").read_text() == "same\n"
    assert "trash_restore" not in _files(root, groups={"duplicates"}, write=False)


def test_sad_an_entry_from_outside_the_root_is_neither_listed_nor_restored(tmp_path):
    from core import trash as TR

    root = tmp_path / "root"
    root.mkdir()
    secret = tmp_path / "elsewhere.txt"
    secret.write_text("not the root's")
    trash_id = os.path.basename(TR.trash(LocalFS(), str(secret), root=str(root / ".axross-trash")))
    tools = _files(root, groups={"duplicates"})
    assert T.call(tools, "trash_list", {})["entries"] == []
    for args in ({"trash_id": trash_id}, {"trash_id": trash_id, "dst": "here.txt"}):
        with pytest.raises(T.RpcError) as err:
            T.call(tools, "trash_restore", args)
        assert "not found" in err.value.message
    assert not (root / "here.txt").exists() and not secret.exists()


def test_sad_a_tampered_trash_record_is_not_restored(trashed):
    import json

    root, tools = trashed
    trash_id = T.call(tools, "trash_list", {})["entries"][0]["trash_id"]
    meta = root / ".axross-trash" / f"{trash_id}.meta.json"
    record = json.loads(meta.read_text())
    if "mac" not in record:
        pytest.skip("no trash key here: the record is not authenticated")
    record["original_path"] = str(root / "elsewhere.txt")
    meta.write_text(json.dumps(record))
    with pytest.raises(T.RpcError) as err:
        T.call(tools, "trash_restore", {"trash_id": trash_id})
    assert "not what axross wrote" in err.value.message
    assert not (root / "elsewhere.txt").exists()


# -- list_llm_profiles ------------------------------------------------------------------------


def test_happy_list_llm_profiles_gives_names_and_models_never_keys(tmp_path, monkeypatch):
    from core import llm_profiles as LP

    profiles = [LP.LLMProfile(name="local", model="llama3", endpoint="http://10.0.0.5:11434"),
                LP.LLMProfile(name="cloud", provider="openai", model="gpt-x",
                              endpoint="https://api.example/v1")]
    monkeypatch.setattr(LP.LLMSettings, "load", classmethod(
        lambda cls, path=None: cls(profiles=profiles, active="cloud")))

    def no_keyring(*_a, **_k):
        raise AssertionError("the keyring was opened")

    monkeypatch.setattr(LP, "get_api_key", no_keyring)
    tools = _files(tmp_path, groups={"agent"}, write=False)
    out = T.call(tools, "llm_profiles", {})
    assert out == {"profiles": [{"name": "local", "model": "llama3", "active": False},
                                {"name": "cloud", "model": "gpt-x", "active": True}],
                   "active": "cloud"}
    text = str(out)
    assert "10.0.0.5" not in text and "api.example" not in text


def test_happy_run_llm_agent_takes_llm_profile_and_its_former_profile(tmp_path, monkeypatch):
    from core import llm_profiles as LP

    monkeypatch.setattr(LP.LLMSettings, "load", classmethod(
        lambda cls, path=None: cls(profiles=[LP.LLMProfile(name="known")], active="")))
    tools = _files(tmp_path, groups={"agent"}, write=False)
    for key in ("llm_profile", "profile"):
        with pytest.raises(T.RpcError) as err:
            T.call(tools, "agent_run", {"task": "x", key: "nope"})
        assert "no LLM profile named 'nope'" in err.value.message and "'known'" in err.value.message


# -- the merged tools ----------------------------------------------------------------------


def test_happy_create_link_makes_both_kinds_and_the_former_names_still_work(tmp_path):
    (tmp_path / "f.txt").write_text("x")
    tools = _files(tmp_path)
    assert {"symlink"} <= set(tools) and "hardlink" not in tools
    # The result is the one create_symlink and create_hardlink always gave.
    assert T.call(tools, "create_link", {"target": "f.txt", "link_path": "s"}) == {"ok": True}
    assert os.path.islink(tmp_path / "s")
    assert T.call(tools, "create_link", {"target": "f.txt", "link_path": "h",
                                         "kind": "hard"}) == {"ok": True}
    assert T.call(tools, "hardlink", {"target": "f.txt", "link_path": "h4"}) == {"ok": True}
    assert os.stat(tmp_path / "h").st_ino == os.stat(tmp_path / "f.txt").st_ino
    T.call(tools, "create_hardlink", {"target": "f.txt", "link_path": "h2"})
    T.call(tools, "hardlink", {"target": "f.txt", "link_path": "h3"})
    T.call(tools, "create_symlink", {"target": "f.txt", "link_path": "s2"})
    assert not os.path.islink(tmp_path / "h2") and not os.path.islink(tmp_path / "h3")
    assert os.path.islink(tmp_path / "s2")
    assert N.resolve("create_hardlink", {"target": "a"}) == ("symlink",
                                                              {"target": "a", "kind": "hard"})


class _Shell(SessionLifecycle):
    """A POSIX host that records what it is asked to run."""

    def __init__(self):
        self.calls = []

    def exec(self, cmd, *, timeout=30.0, stdin=None, stdout_cap=1 << 20, stderr_cap=1 << 16,
             env=None):
        self.calls.append({"cmd": cmd, "stdin": stdin})
        return ExecResult(0, b"ok\n", b"")


def test_happy_run_backend_command_runs_a_script_too_and_the_former_name_works(tmp_path):
    box = _Shell()
    tools = T.build(tmp_path, ("exec",), backends={"box": box}, allow_exec=True)
    assert "remote_exec" in tools and len([t for t in tools.values() if t.group == "exec"]) == 1
    T.call(tools, "run_backend_command", {"backend": "box", "script": "echo hi\n",
                                          "interpreter": "bash"})
    T.call(tools, "run_backend_script", {"backend": "box", "script": "echo hi\n"})
    assert [c["cmd"] for c in box.calls] == ["bash -s --", "sh -s --"]
    assert box.calls[0]["stdin"] == b"echo hi\n"
    for args in ({"command": "id", "script": "id"}, {}, {"command": "id", "interpreter": "sh"},
                 {"script": "cat", "stdin": "x"}):
        with pytest.raises(T.RpcError):
            T.call(tools, "run_backend_command", {"backend": "box", **args})
    assert len(box.calls) == 2


# -- the blind grade of round 10 (independent9) --------------------------------------------


def test_sad_without_an_image_decoder_no_tool_points_at_render_preview(tmp_path, monkeypatch):
    from core import previews

    monkeypatch.setattr(previews, "preview_available", lambda: False)
    tools = M._build_tools(LocalFS(), allow_write=False, root=str(tmp_path))
    assert "preview" not in {t.name for t in tools}
    assert not [t.name for t in tools if "render_preview" in t.description]


def test_happy_write_file_is_not_marked_idempotent_since_append_adds_again(tmp_path):
    tool = next(t for t in M._build_tools(LocalFS(), allow_write=True, root=str(tmp_path))
                if t.name == "write_file")
    assert tool.annotations["idempotentHint"] is False


def test_happy_search_index_and_duplicate_groups_say_their_next_offset(tmp_path):
    (tmp_path / "a.txt").write_text("same")
    (tmp_path / "b.txt").write_text("same")
    tools = _files(tmp_path, groups={"duplicates"}, write=False)
    T.call(tools, "duplicates_scan", {})
    page = T.call(tools, "duplicates_groups", {"max_groups": 1})
    assert page["next_offset"] is None and not page["truncated"]
    assert T.call(tools, "search", {})["next_offset"] is None
