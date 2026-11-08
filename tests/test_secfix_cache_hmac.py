"""The extension code cache cannot be planted (pre-release security review 4).

Before: an agent or MCP client allowed to write in the home folder wrote
``~/.cache/axross/extension-code/<key>.code`` - the key is the SHA-256 of
public inputs (the bundled extension's source and path) and the entry's
integrity check a plain SHA-256 of its payload - and axross ran that byte
code at the next start, outside every sandbox. ``~/.cache/axross`` was no
protected place either. Now every entry carries an HMAC under a random
0600 secret in ``~/.config/axross`` (a protected place and a secret), and
the cache folder (``$XDG_CACHE_HOME/axross`` too) is protected: no tool
writes there and the agent sandbox mounts it read-only.

Also: a one-file binary unpacks to a new ``/tmp/_MEIxxxx`` at every start;
its bundled extensions are keyed by their path in the bundle, so the cache
hits there (it never did, and every start wrote new entries).
"""

from __future__ import annotations

import hashlib
import marshal
import os
import stat
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core import agent_sandbox as SB  # noqa: E402
from core import extension_code_cache as ECC  # noqa: E402
from core import protected_places as P  # noqa: E402

needs_posix = pytest.mark.skipif(not ECC._disk_allowed(), reason="the disk cache is POSIX only")


@pytest.fixture(autouse=True)
def own_home(tmp_path, monkeypatch) -> Path:
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path / "cache"))
    for name in (P.HOST_HOME_ENV, "XDG_CONFIG_HOME", "XDG_DATA_HOME", "XDG_STATE_HOME",
                 *(host for _p, _v, host in P.XDG_PLACES)):
        monkeypatch.delenv(name, raising=False)
    ECC.clear_memory()
    yield home
    ECC.clear_memory()


def _value(code) -> int:
    ns: dict = {}
    exec(code, ns)  # noqa: S102 - the test's own source
    return ns["VALUE"]


def _plant(src: bytes, path: str, evil_value: int) -> Path:
    """What the reviewer's archive/cache_plant.py did: an entry for *src*
    holding other byte code, with a correct SHA-256 of that payload."""
    key = ECC.source_key(src, path)
    folder = ECC.cache_dir()
    folder.mkdir(parents=True, mode=0o700, exist_ok=True)
    payload = marshal.dumps(compile(f"VALUE = {evil_value}\n", path, "exec"))
    entry = folder / (key + ".code")
    fd = os.open(entry, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as fh:
        fh.write(ECC._MAGIC + key.encode() + b"\n" + hashlib.sha256(payload).digest() + payload)
    return entry


@needs_posix
def test_sad_a_planted_entry_with_a_correct_checksum_is_never_run(tmp_path):
    src, path = b"VALUE = 1\n", str(tmp_path / "ext.py")
    _plant(src, path, 666)
    before = dict(ECC.stats)
    assert _value(ECC.compile_source(src, path)) == 1
    assert ECC.stats["disk"] == before["disk"]
    assert ECC.stats["compiled"] == before["compiled"] + 1


@needs_posix
def test_sad_a_planted_entry_replacing_a_real_one_is_never_run(tmp_path):
    src, path = b"VALUE = 1\n", str(tmp_path / "ext.py")
    ECC.compile_source(src, path)  # a real entry, with the right MAC
    ECC.clear_memory()
    _plant(src, path, 666)
    assert _value(ECC.compile_source(src, path)) == 1


@pytest.mark.parametrize("rel", [
    "extension-code/0123.code", "update/axross-new.AppImage", "mcp-discover/servers.json",
])
def test_sad_the_cache_folder_is_a_protected_place(own_home, tmp_path, rel):
    for base in (own_home / ".cache" / "axross", tmp_path / "cache" / "axross"):
        assert P.refusal(str(base / rel)), base / rel
    assert P.refusal(str(own_home / ".cache" / "pip" / "x")) is None  # other caches are not


def test_sad_the_cache_secret_is_a_secret_and_protected(own_home):
    key = own_home / ".config" / "axross" / ECC.SECRET_NAME
    assert ECC.secret_path() == key
    assert P.read_refusal(str(key))
    assert P.refusal(str(key))


def test_sad_the_sandbox_mounts_the_cache_read_only(own_home, tmp_path):
    (own_home / ".cache" / "axross").mkdir(parents=True)
    plan = {p: (rw, kind) for p, rw, kind in
            SB._mount_plan(SB.SandboxProfile(name="t"), str(own_home), True)}
    assert plan[str(own_home / ".cache" / "axross")] == (False, "bind")
    # $XDG_CACHE_HOME inside the writable home: missing, an empty read-only folder.
    inside = own_home / "xdg-cache"
    os.environ["XDG_CACHE_HOME"] = str(inside)
    plan = {p: (rw, kind) for p, rw, kind in
            SB._mount_plan(SB.SandboxProfile(name="t"), str(own_home), True)}
    assert plan[str(inside / "axross")] == (False, "dir")
    argv = SB.sandbox_command(SB.SandboxProfile(name="t", engine="bubblewrap"), str(own_home),
                              writable=True)
    i = argv.index("AXROSS_AGENT_HOST_XDG_CACHE_HOME")
    assert argv[i - 1] == "--setenv" and argv[i + 1] == str(inside)


@needs_posix
def test_happy_the_secret_is_made_private_once_and_the_cache_hits(own_home, tmp_path):
    src, path = b"VALUE = 1\n", str(tmp_path / "ext.py")
    ECC.compile_source(src, path)
    key = ECC.secret_path()
    st = key.lstat()
    assert stat.S_ISREG(st.st_mode) and stat.S_IMODE(st.st_mode) == 0o600
    assert st.st_size == 32
    secret = key.read_bytes()
    ECC.clear_memory()
    before = ECC.stats["disk"]
    assert _value(ECC.compile_source(src, path)) == 1
    assert ECC.stats["disk"] == before + 1
    assert key.read_bytes() == secret  # read again, not made anew
    assert not [n for n in os.listdir(key.parent) if n.endswith(".tmp")]


@needs_posix
@pytest.mark.parametrize("spoil", ["mode", "link", "size"])
def test_edge_a_secret_that_is_not_safe_turns_the_disk_cache_off(own_home, tmp_path, spoil):
    src, path = b"VALUE = 1\n", str(tmp_path / "ext.py")
    ECC.compile_source(src, path)
    ECC.clear_memory()
    key = ECC.secret_path()
    if spoil == "mode":
        os.chmod(key, 0o644)
    elif spoil == "link":
        elsewhere = tmp_path / "elsewhere.key"
        elsewhere.write_bytes(key.read_bytes())
        os.chmod(elsewhere, 0o600)
        key.unlink()
        key.symlink_to(elsewhere)
    else:
        key.write_bytes(key.read_bytes() + b"x")
    before = dict(ECC.stats)
    assert _value(ECC.compile_source(src, path)) == 1
    assert ECC.stats["disk"] == before["disk"]  # memory only
    assert ECC.stats["compiled"] == before["compiled"] + 1


@needs_posix
def test_edge_a_secret_another_process_made_first_is_used(own_home):
    folder = ECC.secret_path().parent
    folder.mkdir(parents=True, mode=0o700)
    theirs = b"k" * 32
    fd = os.open(ECC.secret_path(), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as fh:
        fh.write(theirs)
    assert ECC._make_secret(folder) is None  # the link loses: no clobber
    assert ECC._secret() == theirs
    assert ECC.secret_path().read_bytes() == theirs
    assert not [n for n in os.listdir(folder) if n.endswith(".tmp")]


@needs_posix
def test_happy_a_one_file_binary_unpacked_elsewhere_hits_the_cache(tmp_path, monkeypatch):
    """Two starts of a PyInstaller one-file binary: the same bundled source
    under two random /tmp/_MEIxxxx folders is one entry, and the code read
    back names the file it runs from now."""
    src = b"def f():\n    return 1\nVALUE = f()\n"
    first, second = tmp_path / "_MEIaaaa", tmp_path / "_MEIbbbb"
    monkeypatch.setattr(sys, "frozen", True, raising=False)
    monkeypatch.setattr(sys, "_MEIPASS", str(first), raising=False)
    path1 = str(first / "resources" / "extensions" / "ext.py")
    assert _value(ECC.compile_source(src, path1)) == 1
    ECC.clear_memory()
    monkeypatch.setattr(sys, "_MEIPASS", str(second), raising=False)
    path2 = str(second / "resources" / "extensions" / "ext.py")
    before = dict(ECC.stats)
    code = ECC.compile_source(src, path2)
    assert ECC.stats["disk"] == before["disk"] + 1
    assert ECC.stats["compiled"] == before["compiled"]
    assert len(list(ECC.cache_dir().glob("*.code"))) == 1
    inner = next(c for c in code.co_consts if hasattr(c, "co_filename"))
    assert code.co_filename == path2 and inner.co_filename == path2
    assert _value(code) == 1
    # A file outside the bundle keeps its own path in the key.
    assert ECC.source_key(src, str(tmp_path / "user" / "ext.py")) != ECC.source_key(src, path2)
