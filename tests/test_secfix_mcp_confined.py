"""MCP file tools: no write or read lands outside the root or in a protected
place through a symlink swapped in between the check and the use (final
security review of 0.15.177, finding 1).

Before: write_file checked the path as a string (_enforce_root, the
protected places) and atomic_write then opened the same string again. A
second call of the same client - the HTTP transport and tasks/start run
calls in threads - renamed a folder of the path away and put the server's
own ``symlink`` to ``~/.config/autostart`` (or to the home folder) in its
place: ``proj/w1/evil.desktop`` landed in the autostart folder,
``w1/.bash_profile`` became ``~/.bash_profile`` (the reviewer's race won
after 11-67 attempts). Now:

* the local backend opens every path beneath its root's descriptor without
  following a symlink (core.confined_fs: openat2 RESOLVE_BENEATH |
  RESOLVE_NO_SYMLINKS, else a component walk with O_NOFOLLOW) and writes
  the temp file and its rename relative to the folder's descriptor;
* the symlink tool refuses a target outside the write roots or at a folder
  that holds a protected place;
* the mutating tools run one at a time.

The swap is made deterministic here: it happens inside the call, right
after the checks (a hook on the root check every mutating tool runs last).
"""

from __future__ import annotations

import os
import stat
import threading
import time
from pathlib import Path

import pytest

from core import confined_fs as C
from core import mcp_server as M
from core import protected_places as P
from core.local_fs import LocalFS
from tests import mcp_group_testkit as T

pytestmark = pytest.mark.skipif(not C.FD_CONFINED, reason="needs dir_fd (POSIX)")


@pytest.fixture
def home(tmp_path, monkeypatch) -> Path:
    home = tmp_path / "home"
    (home / ".config" / "autostart").mkdir(parents=True)
    (home / ".ssh").mkdir()
    (home / ".ssh" / "id_ed25519").write_text("not a real key - SECRET\n")
    (home / ".profile").write_text("# debian default\n")
    (home / "proj" / "w1").mkdir(parents=True)
    (home / "outside").mkdir()
    (home / "outside" / "victim.txt").write_text("keep me")
    monkeypatch.setenv("HOME", str(home))
    for var in ("XDG_CONFIG_HOME", "XDG_DATA_HOME", "XDG_STATE_HOME", "XDG_CACHE_HOME",
                P.HOST_HOME_ENV):
        monkeypatch.delenv(var, raising=False)
    return home


@pytest.fixture(params=["openat2", "walk"])
def resolver(request, monkeypatch):
    """Both ways of resolving beneath the root."""
    if request.param == "openat2":
        if not C.uses_openat2():
            pytest.skip("no openat2 on this kernel")
    else:
        monkeypatch.setattr(C, "_openat2_fn", [None])
    return request.param


def _swap(folder: Path, link_to: Path) -> None:
    os.rename(folder, str(folder) + ".r")
    os.symlink(link_to, folder)


def _swap_after_check(monkeypatch, folder: Path, link_to: Path, operation: str | None = None):
    """Once the call's checks are done (the root check of *operation*, the
    last check a mutating tool makes), rename *folder* away and put a
    symlink to *link_to* in its place (what the second thread did)."""
    real = M._refuse_configured_root
    done = []

    def hook(path, root, op):
        real(path, root, op)
        if not done and operation in (None, op):
            done.append(True)
            _swap(folder, link_to)

    monkeypatch.setattr(M, "_refuse_configured_root", hook)
    return done


def _swap_before_copy(monkeypatch, folder: Path, link_to: Path):
    """bulk_copy checks every file and then copies it: swap in between."""
    from core import server_ops

    real = server_ops.server_side_copy
    done = []

    def hook(*args, **kwargs):
        if not done:
            done.append(True)
            _swap(folder, link_to)
        return real(*args, **kwargs)

    monkeypatch.setattr(server_ops, "server_side_copy", hook)
    return done


def _tools(root: Path, **kw):
    return T.build(root, (), allow_write=True, **kw)


# -- sad: the swap is refused ----------------------------------------------------------


def test_sad_write_file_through_a_swapped_folder_does_not_reach_the_autostart_folder(
        home, resolver, monkeypatch):
    tools = _tools(home / "proj")
    swapped = _swap_after_check(monkeypatch, home / "proj" / "w1", home / ".config" / "autostart")
    with pytest.raises(T.RpcError) as err:
        T.call(tools, "write_file", {"path": str(home / "proj" / "w1" / "evil.desktop"),
                                     "content": "[Desktop Entry]\nExec=sh -c id\n"})
    assert swapped and "symbolic link" in err.value.message
    assert os.listdir(home / ".config" / "autostart") == []


def test_sad_write_file_through_a_swapped_folder_does_not_create_bash_profile(
        home, resolver, monkeypatch):
    tools = _tools(home)
    _swap_after_check(monkeypatch, home / "proj", home)
    with pytest.raises(T.RpcError):
        T.call(tools, "write_file", {"path": str(home / "proj" / ".bash_profile"),
                                     "content": "id > /tmp/pwned\n. ~/.profile\n"})
    assert not os.path.lexists(home / ".bash_profile")


@pytest.mark.parametrize("tool, args, after_check", [
    ("mkdir", lambda w: {"path": f"{w}/made"}, None),
    ("remove", lambda w: {"path": f"{w}/victim.txt"}, None),
    ("chmod", lambda w: {"path": f"{w}/victim.txt", "mode": "777"}, None),
    ("rename", lambda w: {"src": f"{w}/../w1.keep", "dst": f"{w}/moved.txt"},
     "rename destination"),
    ("copy", lambda w: {"src": f"{w}/../w1.keep", "dst": f"{w}/copied.txt"}, None),
    ("symlink", lambda w: {"target": "../w1.keep", "link_path": f"{w}/ln"}, None),
    ("bulk_copy", lambda w: {"src": f"{w}/../w1.keep", "dst": f"{w}/bulk.txt"}, "copy"),
])
def test_sad_every_mutating_tool_refuses_a_folder_swapped_for_a_link(
        home, resolver, monkeypatch, tool, args, after_check):
    (home / "proj" / "w1" / "victim.txt").write_text("inside")
    (home / "proj" / "w1.keep").write_text("payload")
    outside = home / "outside"
    before = {p.name: (p.read_text(), stat.S_IMODE(p.stat().st_mode)) for p in outside.iterdir()}
    tools = _tools(home / "proj")
    if after_check == "copy":
        swapped = _swap_before_copy(monkeypatch, home / "proj" / "w1", outside)
    else:
        swapped = _swap_after_check(monkeypatch, home / "proj" / "w1", outside, after_check)
    try:
        T.call(tools, tool, args(str(home / "proj" / "w1")))
    except T.RpcError:
        pass
    assert swapped, "the swap did not happen"
    after = {p.name: (p.read_text(), stat.S_IMODE(p.stat().st_mode)) for p in outside.iterdir()}
    assert after == before, f"{tool} reached through the swapped-in link"


def test_sad_read_file_through_a_swapped_folder_does_not_return_the_ssh_key(
        home, resolver, monkeypatch):
    (home / "proj" / "w1" / "id_ed25519").write_text("decoy\n")
    tools = _tools(home / "proj")
    real = P.secret_checker

    def checker():
        check = real()

        def swapped(path, *, entry=False):
            reason = check(path, entry=entry)
            if not os.path.islink(home / "proj" / "w1"):
                os.rename(home / "proj" / "w1", home / "proj" / "w1.r")
                os.symlink(home / ".ssh", home / "proj" / "w1")
            return reason

        return swapped

    monkeypatch.setattr(P, "secret_checker", checker)
    with pytest.raises(T.RpcError):
        out = T.call(tools, "read_file", {"path": str(home / "proj" / "w1" / "id_ed25519"),
                                          "encoding": "text"})
        assert "SECRET" not in out["text"]


def test_sad_a_symlink_to_a_place_outside_the_write_roots_is_refused(home):
    tools = _tools(home / "proj")
    for target in (str(home / ".config" / "autostart"), "../../outside", "/"):
        with pytest.raises(T.RpcError) as err:
            T.call(tools, "symlink", {"target": target, "link_path": str(home / "proj" / "l")})
        assert "symlink target" in err.value.message
    assert not os.path.lexists(home / "proj" / "l")


def test_sad_a_symlink_to_the_home_folder_or_a_protected_place_is_refused(home):
    tools = _tools(home)
    for target in (str(home), str(home / ".config"), "../.ssh", str(home / ".bash_profile")):
        with pytest.raises(T.RpcError):
            T.call(tools, "symlink", {"target": target, "link_path": str(home / "proj" / "l")})
    assert not os.path.lexists(home / "proj" / "l")


# -- edge: one mutation at a time -------------------------------------------------------


def test_edge_mutating_tools_run_one_at_a_time(home, monkeypatch):
    tools = _tools(home / "proj")
    entered, release = threading.Event(), threading.Event()
    real = M._refuse_configured_root

    def slow(path, root, operation):
        real(path, root, operation)
        if operation == "mkdir":
            entered.set()
            release.wait(10)

    monkeypatch.setattr(M, "_refuse_configured_root", slow)
    first = threading.Thread(target=T.call, args=(tools, "mkdir", {"path": "a"}))
    first.start()
    assert entered.wait(10)
    second_done = threading.Event()

    def second():
        T.call(tools, "rename", {"src": "w1", "dst": "w2"})
        second_done.set()

    threading.Thread(target=second).start()
    time.sleep(0.5)
    try:
        assert not second_done.is_set(), "rename ran while mkdir was still running"
    finally:
        release.set()
        first.join(10)
    assert second_done.wait(10)
    assert (home / "proj" / "a").is_dir() and (home / "proj" / "w2").is_dir()


def test_edge_reads_are_not_held_up_by_a_running_write(home, monkeypatch):
    (home / "proj" / "r.txt").write_text("hello")
    tools = _tools(home / "proj")
    entered, release = threading.Event(), threading.Event()
    real = M._refuse_configured_root

    def slow(path, root, operation):
        real(path, root, operation)
        entered.set()
        release.wait(10)

    monkeypatch.setattr(M, "_refuse_configured_root", slow)
    writer = threading.Thread(target=T.call, args=(tools, "mkdir", {"path": "b"}))
    writer.start()
    try:
        assert entered.wait(10)
        assert T.call(tools, "read_file", {"path": "r.txt", "encoding": "text"})["text"] == "hello"
    finally:
        release.set()
        writer.join(10)


# -- happy: what worked before still works ------------------------------------------------


def test_happy_write_tools_work_beneath_the_root_and_through_inner_links(home, resolver):
    root = home / "proj"
    os.symlink("w1", root / "inner")  # a link inside the root, resolved by the check
    tools = _tools(root)
    T.call(tools, "write_file", {"path": "inner/a.txt", "content": "one"})
    assert (root / "w1" / "a.txt").read_text() == "one"
    T.call(tools, "write_file", {"path": "w1/a.txt", "content": "two"})
    assert (root / "w1" / "a.txt").read_text() == "two"
    T.call(tools, "mkdir", {"path": "x/y/z"})
    T.call(tools, "copy", {"src": "w1/a.txt", "dst": "x/y/z/b.txt"})
    T.call(tools, "rename", {"src": "x/y/z/b.txt", "dst": "x/c.txt"})
    T.call(tools, "chmod", {"path": "x/c.txt", "mode": "600"})
    assert stat.S_IMODE((root / "x" / "c.txt").stat().st_mode) == 0o600
    T.call(tools, "symlink", {"target": "c.txt", "link_path": "x/l"})
    assert os.readlink(root / "x" / "l") == "c.txt"
    assert T.call(tools, "read_file", {"path": "x/l", "encoding": "text"})["text"] == "two"
    names = {e["name"] for e in T.call(tools, "list_dir", {"path": "x"})}
    assert names == {"c.txt", "l", "y"}
    T.call(tools, "remove", {"path": "x", "recursive": True})
    assert not (root / "x").exists()
    T.call(tools, "symlink", {"target": "not-yet", "link_path": "dangling"})
    assert os.path.islink(root / "dangling")


def test_happy_write_file_keeps_the_mode_and_hard_links_of_the_file(home, resolver):
    root = home / "proj"
    script = root / "run.sh"
    script.write_text("#!/bin/sh\n")
    os.chmod(script, 0o750)
    (root / "a").write_text("A")
    os.link(root / "a", root / "b")
    tools = _tools(root)
    T.call(tools, "write_file", {"path": "run.sh", "content": "#!/bin/sh\necho\n"})
    assert stat.S_IMODE(script.stat().st_mode) == 0o750
    T.call(tools, "write_file", {"path": "a", "content": "B"})
    assert (root / "b").read_text() == "B" and os.path.samefile(root / "a", root / "b")
    assert not [n for n in os.listdir(root) if n.endswith(".tmp")]


def test_happy_the_local_backend_is_confined_and_still_reports_local(home):
    local = LocalFS()
    tools = T.build(home / "proj", (), allow_write=True, backend=local,
                    backends={"local": local})
    out = T.call(tools, "list_backends", {})
    rows = out if isinstance(out, list) else out["backends"]
    assert [(r["id"], r["class"], r["is_default"]) for r in rows] == [("local", "LocalFS", True)]
    # The mutating handlers run under the one lock.
    assert getattr(tools["write_file"].handler, "__wrapped__", None) is not None
    assert getattr(tools["read_file"].handler, "__wrapped__", None) is None


# -- the confined file system itself -------------------------------------------------------


def test_sad_confined_fs_refuses_a_link_anywhere_on_the_way(tmp_path, resolver):
    root = tmp_path / "r"
    (root / "d").mkdir(parents=True)
    (tmp_path / "out").mkdir()
    (tmp_path / "out" / "f").write_text("outside")
    os.symlink(tmp_path / "out", root / "l")
    os.symlink(tmp_path / "out" / "f", root / "fl")
    fs = C.ConfinedLocalFS([str(root)])
    for op in (
        lambda: fs.open_write(str(root / "l" / "f")),
        lambda: fs.list_dir(str(root / "l")),
        lambda: fs.mkdir(str(root / "l" / "new")),
        lambda: fs.remove(str(root / "l" / "f")),
        lambda: fs.confined_atomic_write(str(root / "l" / "f"), b"x"),
        lambda: fs.confined_atomic_write(str(root / "fl"), b"x"),
        lambda: fs.chmod(str(root / "fl"), 0o777),
    ):
        with pytest.raises(PermissionError):
            op()
    assert (tmp_path / "out" / "f").read_text() == "outside"
    with pytest.raises(PermissionError):
        fs.open_read(str(tmp_path / "out" / "f"))  # outside every root
    # A final link that resolves inside the root is read through; one that
    # resolves outside is not.
    with pytest.raises(PermissionError):
        fs.open_read(str(root / "fl"))


def test_edge_confined_fs_works_without_read_permission_on_a_folder(tmp_path, resolver):
    if os.geteuid() == 0:
        pytest.skip("root reads every folder")
    root = tmp_path / "r"
    (root / "x").mkdir(parents=True)
    (root / "x" / "f").write_text("data")
    os.chmod(root / "x", 0o311)  # search, no read
    try:
        fs = C.ConfinedLocalFS([str(root)])
        with fs.open_read(str(root / "x" / "f")) as fh:
            assert fh.read() == b"data"
    finally:
        os.chmod(root / "x", 0o755)


def test_happy_confined_fs_is_used_only_for_the_plain_local_backend():
    class Sub(LocalFS):
        pass

    assert C.confinable(LocalFS()) and not C.confinable(Sub())
