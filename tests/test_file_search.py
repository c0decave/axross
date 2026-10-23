"""The Find Files engine (core.file_search on top of core.search_federation).

Local trees go through fd / rg when they are installed and through a
pure-Python walker otherwise - with the same results; remote backends
through their list_dir / open_read. Archives (zip, tar.*, single
compressed files, nested) are searched as an option, bounded by member,
size and ratio caps. Every run is cancellable.
"""

from __future__ import annotations

import gzip
import io
import os
import shutil
import sys
import tarfile
import threading
import time
import zipfile
from datetime import datetime
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core import file_search as FS  # noqa: E402
from core import metadata_index as MX  # noqa: E402
from core import search_federation as SF  # noqa: E402
from core.local_fs import LocalFS  # noqa: E402
from core.ram_fs import RamFsSession  # noqa: E402
from models.file_item import FileItem  # noqa: E402

HAVE_FD = FS.find_tool("fd") is not None
HAVE_RG = FS.find_tool("rg") is not None


def _zip_bytes(members: dict[str, bytes], compression=zipfile.ZIP_DEFLATED) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression) as zf:
        for name, data in members.items():
            zf.writestr(name, data)
    return buf.getvalue()


def _tar_gz_bytes(members: dict[str, bytes]) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        for name, data in members.items():
            info = tarfile.TarInfo(name)
            info.size = len(data)
            info.mtime = 1_700_000_000
            tf.addfile(info, io.BytesIO(data))
    return buf.getvalue()


@pytest.fixture
def tree(tmp_path):
    root = tmp_path / "root"
    (root / "sub" / "deep").mkdir(parents=True)
    (root / ".hidden").mkdir()
    (root / "node_modules").mkdir()
    (root / "a.txt").write_text("hello world\nfoo\n")
    (root / "b.log").write_text("nothing to see\n")
    (root / ".hidden" / "secret.txt").write_text("hello hidden\n")
    (root / "sub" / "deep" / "notes.md").write_text("first line\nHello there\n")
    (root / "sub" / "deep" / "photo.jpg").write_bytes(b"\xff\xd8\xff\xe0" + b"\0" * 64)
    (root / "node_modules" / "x.txt").write_text("hello\n")
    (root / "blob").write_bytes(b"\x89PNG\r\n\x1a\n" + b"\0" * 64)
    (root / "win.vdi").write_bytes(b"\0" * 128)
    (root / "arch.zip").write_bytes(
        _zip_bytes({"docs/readme.txt": b"hello from zip\n", "pic.png": b"\x89PNG" + b"\0" * 8})
    )
    inner = _zip_bytes({"deep.txt": b"say hello nested\n"})
    (root / "nested.tar.gz").write_bytes(_tar_gz_bytes({"inner.zip": inner, "plain.txt": b"x\n"}))
    (root / "single.txt.gz").write_bytes(gzip.compress(b"hello gzip\n"))
    os.symlink(root, root / "loop")  # a symlink loop must not be followed
    return root


def _run(scopes, query, **kwargs):
    hits = []
    summary = FS.run_search(scopes, query, on_hit=lambda scope, hit: hits.append(hit), **kwargs)
    return hits, summary


def _local(root, **query):
    q = SF.SearchQuery(**query)
    return _run([FS.SearchScope(LocalFS(), str(root))], q)


def _rel(hits, root) -> set[str]:
    out = set()
    for h in hits:
        path = h.path
        out.add(os.path.relpath(path, root) if path.startswith(str(root)) else path)
    return out


# --- happy -----------------------------------------------------------------


def test_happy_name_glob_finds_hidden_files_and_skips_ignored_folders(tree) -> None:
    hits, summary = _local(tree, name="*.txt")
    assert _rel(hits, tree) == {"a.txt", ".hidden/secret.txt"}
    assert summary.found == 2 and not summary.cancelled and not summary.truncated


def test_happy_hidden_files_can_be_left_out(tree) -> None:
    hits, _ = _local(tree, name="*.txt", include_hidden=False)
    assert _rel(hits, tree) == {"a.txt"}


def test_happy_categories_use_names_and_content_of_local_files(tree) -> None:
    hits, _ = _local(tree, categories=("images",))
    assert _rel(hits, tree) == {"sub/deep/photo.jpg", "blob"}
    assert {h.category for h in hits} == {"images"}


def test_happy_disk_image_category(tree) -> None:
    hits, _ = _local(tree, categories=("disk_images",))
    assert _rel(hits, tree) == {"win.vdi"}


def test_happy_contains_literal_ignores_case_by_default(tree) -> None:
    hits, _ = _local(tree, contains="hello")
    assert _rel(hits, tree) == {"a.txt", ".hidden/secret.txt", "sub/deep/notes.md"}
    by_name = {os.path.basename(h.path): h for h in hits}
    assert "hello world" in by_name["a.txt"].snippet
    assert "Hello there" in by_name["notes.md"].snippet


def test_happy_contains_case_sensitive(tree) -> None:
    hits, _ = _local(tree, contains="Hello", case_sensitive=True)
    assert _rel(hits, tree) == {"sub/deep/notes.md"}


def test_happy_contains_regex(tree) -> None:
    hits, _ = _local(tree, contains=r"hel+o\s+wor", contains_is_regex=True)
    assert _rel(hits, tree) == {"a.txt"}


def test_happy_regex_anchors_work_per_line(tree) -> None:
    hits, _ = _local(tree, contains=r"^hello there$", contains_is_regex=True)
    assert _rel(hits, tree) == {"sub/deep/notes.md"}


def test_happy_inside_archives_including_nested_zip_in_tar(tree) -> None:
    hits, summary = _local(tree, name="*.txt", contains="hello", search_archives=True)
    rel = _rel(hits, tree)
    assert "arch.zip!/docs/readme.txt" in rel
    assert "nested.tar.gz!/inner.zip!/deep.txt" in rel
    assert "single.txt.gz!/single.txt" in rel
    nested = next(h for h in hits if h.path.endswith("deep.txt"))
    assert nested.archive_path == str(tree / "nested.tar.gz")
    assert nested.member == "inner.zip!/deep.txt"
    assert "hello nested" in nested.snippet
    assert summary.archives >= 3


def test_happy_archive_members_match_categories_by_name(tree) -> None:
    hits, _ = _local(tree, categories=("images",), search_archives=True)
    assert "arch.zip!/pic.png" in _rel(hits, tree)


def test_happy_archives_are_not_opened_without_the_option(tree) -> None:
    hits, summary = _local(tree, name="*.txt")
    assert not any("!/" in h.path for h in hits)
    assert summary.archives == 0


def test_happy_size_and_mtime_filters(tree) -> None:
    old = tree / "b.log"
    os.utime(old, (1_000_000_000, 1_000_000_000))
    hits, _ = _local(tree, name="*.log", modified_before=1_500_000_000.0)
    assert _rel(hits, tree) == {"b.log"}
    hits, _ = _local(tree, name="*.txt", min_size=14)
    assert _rel(hits, tree) == {"a.txt"}


def test_happy_hits_arrive_while_the_search_runs(tree) -> None:
    seen_during = []

    def on_hit(scope, hit):
        seen_during.append((scope.label, hit.path))

    FS.run_search(
        [FS.SearchScope(LocalFS(), str(tree), label="mine")],
        SF.SearchQuery(name="*.txt"),
        on_hit=on_hit,
    )
    assert {label for label, _ in seen_during} == {"mine"}
    assert len(seen_during) == 2


def test_happy_remote_backend_through_list_dir_and_open_read(tmp_path) -> None:
    ram = RamFsSession()
    ram.mkdir("/data")
    ram.mkdir("/data/keys")
    for path, data in {
        "/data/report.pdf": b"%PDF-1.4",
        "/data/keys/server.pem": b"-----BEGIN CERTIFICATE-----\n",
        "/data/notes.txt": b"meeting at noon\n",
        "/data/pack.zip": _zip_bytes({"inside/wallet.dat": b"\0" * 16}),
    }.items():
        with ram.open_write(path) as fh:
            fh.write(data)
    scope = FS.SearchScope(ram, "/data")
    hits, _ = _run([scope], SF.SearchQuery(categories=("documents",)))
    assert {h.path for h in hits} == {"/data/report.pdf", "/data/notes.txt"}
    hits, _ = _run([scope], SF.SearchQuery(contains="NOON"))
    assert [h.path for h in hits] == ["/data/notes.txt"]
    hits, _ = _run([scope], SF.SearchQuery(categories=("crypto_wallets",), search_archives=True))
    assert [h.path for h in hits] == ["/data/pack.zip!/inside/wallet.dat"]
    assert hits[0].archive_path == "/data/pack.zip"
    hits, summary = _run([scope], SF.SearchQuery(categories=("keys_certs",)))
    assert [h.path for h in hits] == ["/data/keys/server.pem"]
    assert summary.engines[scope.label] == "walk"


def test_happy_the_metadata_index_is_a_source(tmp_path, tree) -> None:
    db = tmp_path / "index.sqlite"
    MX.index_dir(LocalFS(), str(tree), backend_id="LocalFS:Local", db_path=db)
    hits = []
    summary = FS.run_search(
        [],
        SF.SearchQuery(name="*.jpg"),
        on_hit=lambda scope, hit: hits.append((scope, hit)),
        use_index=True,
        index_db=db,
    )
    assert [h.path for _s, h in hits] == [str(tree / "sub" / "deep" / "photo.jpg")]
    scope = hits[0][0]
    assert scope.kind == "index" and scope.label == "LocalFS:Local"
    assert summary.engines["Index"] == "index"


def test_happy_federated_search_honours_categories() -> None:
    ram = RamFsSession()
    for name in ("a.png", "b.txt", "c.mkv"):
        with ram.open_write(f"/{name}") as fh:
            fh.write(b"x")
    rep = SF.federated_search([ram], SF.SearchQuery(categories=("videos",), roots=["/"]))
    assert [h.path for h in rep.hits] == ["/c.mkv"]


# --- tools: fd / rg present vs absent --------------------------------------


QUERIES = [
    dict(name="*.txt"),
    dict(name="*.TXT", include_hidden=False),
    dict(contains="hello"),
    dict(contains="Hello", case_sensitive=True),
    dict(contains=r"wor\w+", contains_is_regex=True),
    dict(categories=("images",)),
    dict(name="*.txt", contains="hello", search_archives=True),
    dict(max_depth=0),
    dict(max_depth=1, name="*"),
]


@pytest.mark.parametrize("query", QUERIES, ids=[str(q) for q in QUERIES])
def test_happy_tools_and_python_fallback_give_the_same_results(tree, monkeypatch, query) -> None:
    with_tools, s_tools = _local(tree, **query)
    monkeypatch.setattr(FS, "find_tool", lambda name: None)
    without, s_python = _local(tree, **query)
    assert _rel(with_tools, tree) == _rel(without, tree)
    assert s_python.engines[str(tree)] == "python"


@pytest.mark.skipif(not (HAVE_FD and HAVE_RG), reason="fd and rg are not installed")
def test_happy_the_real_fd_and_rg_are_used_when_installed(tree) -> None:
    _hits, summary = _local(tree, name="*.txt", contains="hello")
    assert summary.engines[str(tree)] == "fd+rg"
    _hits, summary = _local(tree, name="*.txt")
    assert summary.engines[str(tree)] == "fd"


def test_happy_find_tool_prefers_a_bundled_binary(tmp_path, monkeypatch) -> None:
    bundle = tmp_path / "bundle"
    (bundle / "bin").mkdir(parents=True)
    exe = bundle / "bin" / ("rg.exe" if os.name == "nt" else "rg")
    exe.write_text("#!/bin/sh\n")
    exe.chmod(0o755)
    monkeypatch.setattr(sys, "frozen", True, raising=False)
    monkeypatch.setattr(sys, "_MEIPASS", str(bundle), raising=False)
    monkeypatch.setattr(FS.shutil, "which", lambda name: None)
    assert FS.find_tool("rg") == str(exe)
    assert FS.find_tool("fd") is None


def test_edge_fd_is_also_found_under_its_debian_name(monkeypatch) -> None:
    monkeypatch.setattr(sys, "frozen", False, raising=False)
    monkeypatch.setattr(
        FS.shutil, "which", lambda name: "/usr/bin/fdfind" if name == "fdfind" else None
    )
    assert FS.find_tool("fd") == "/usr/bin/fdfind"


@pytest.mark.skipif(not HAVE_RG, reason="rg is not installed")
def test_edge_a_regex_rg_rejects_falls_back_to_python(tree) -> None:
    # Look-around is Python-only; rg refuses the pattern, the search still works.
    hits, summary = _local(tree, contains=r"hello(?= world)", contains_is_regex=True)
    assert _rel(hits, tree) == {"a.txt"}
    assert "python" in summary.engines[str(tree)]


# --- sad -------------------------------------------------------------------


def test_sad_an_invalid_query_is_refused_before_any_walk(tree) -> None:
    with pytest.raises(ValueError, match="invalid"):
        _local(tree, regex="[")
    with pytest.raises(ValueError, match="unknown file category"):
        _local(tree, categories=("passwords",))
    with pytest.raises(ValueError):
        _local(tree, contains=r"(a+)+$", contains_is_regex=True)


def test_sad_a_missing_root_is_reported_not_raised(tmp_path) -> None:
    hits, summary = _local(tmp_path / "gone", name="*")
    assert hits == []
    assert summary.errors and "gone" in summary.errors[0]


@pytest.mark.skipif(os.geteuid() == 0 if hasattr(os, "geteuid") else True, reason="root reads all")
def test_sad_an_unreadable_folder_is_skipped_and_reported(tree, monkeypatch) -> None:
    locked = tree / "sub" / "locked"
    locked.mkdir()
    (locked / "in.txt").write_text("hello\n")
    locked.chmod(0)
    try:
        for tools in (True, False):
            if not tools:
                monkeypatch.setattr(FS, "find_tool", lambda name: None)
            hits, summary = _local(tree, name="*.txt")
            assert _rel(hits, tree) == {"a.txt", ".hidden/secret.txt"}
            if not tools:
                assert any("locked" in e for e in summary.errors)
    finally:
        locked.chmod(0o755)


def test_sad_a_zip_bomb_member_is_not_decompressed(tree) -> None:
    (tree / "bomb.zip").write_bytes(_zip_bytes({"zeros.txt": b"0" * (4 * 1024 * 1024)}))
    hits, summary = _local(tree, name="zeros.txt", contains="0", search_archives=True)
    assert hits == []
    assert summary.skipped.get("bomb", 0) == 1
    # The name alone is still found: listing does not decompress.
    hits, _ = _local(tree, name="zeros.txt", search_archives=True)
    assert _rel(hits, tree) == {"bomb.zip!/zeros.txt"}


def test_sad_a_damaged_archive_is_reported_and_the_search_goes_on(tree) -> None:
    (tree / "broken.zip").write_bytes(b"PK\x03\x04 this is not a zip")
    hits, summary = _local(tree, name="a.txt", search_archives=True)
    assert _rel(hits, tree) == {"a.txt"}
    assert any("broken.zip" in e for e in summary.errors)


def test_sad_a_remote_list_dir_failure_is_reported() -> None:
    class Dead:
        name = "dead"

        def list_dir(self, path):
            raise OSError("connection reset")

        def join(self, *parts):
            return "/".join(parts)

    hits, summary = _run([FS.SearchScope(Dead(), "/")], SF.SearchQuery())
    assert hits == [] and "connection reset" in summary.errors[0]


# --- edge ------------------------------------------------------------------


def test_edge_member_count_cap_stops_inside_one_archive(tree) -> None:
    (tree / "many.zip").write_bytes(_zip_bytes({f"f{i}.txt": b"x" for i in range(50)}))
    hits = []
    summary = FS.run_search(
        [FS.SearchScope(LocalFS(), str(tree))],
        SF.SearchQuery(name="f*.txt", search_archives=True),
        on_hit=lambda s, h: hits.append(h),
        limits=FS.SearchLimits(max_archive_members=10),
    )
    assert len(hits) == 10
    assert summary.skipped.get("archive_members") == 1


def test_edge_nested_depth_cap(tree) -> None:
    level3 = _zip_bytes({"core.txt": b"hello core"})
    level2 = _zip_bytes({"l3.zip": level3})
    level1 = _zip_bytes({"l2.zip": level2})
    (tree / "l1.zip").write_bytes(level1)
    deep = []
    FS.run_search(
        [FS.SearchScope(LocalFS(), str(tree))],
        SF.SearchQuery(name="core.txt", search_archives=True),
        on_hit=lambda s, h: deep.append(h),
        limits=FS.SearchLimits(max_archive_depth=2),
    )
    assert deep == []
    FS.run_search(
        [FS.SearchScope(LocalFS(), str(tree))],
        SF.SearchQuery(name="core.txt", search_archives=True),
        on_hit=lambda s, h: deep.append(h),
        limits=FS.SearchLimits(max_archive_depth=3),
    )
    assert [h.member for h in deep] == ["l2.zip!/l3.zip!/core.txt"]


def test_edge_symlink_loop_is_not_followed(tree) -> None:
    hits, summary = _local(tree, name="*")
    assert not any("/loop/" in h.path for h in hits)
    assert "loop" in _rel(hits, tree)  # the link itself is an entry


def test_edge_max_hits_truncates(tree) -> None:
    for i in range(30):
        (tree / f"many{i}.dat").write_text("x")
    hits = []
    summary = FS.run_search(
        [FS.SearchScope(LocalFS(), str(tree))],
        SF.SearchQuery(name="many*.dat"),
        on_hit=lambda s, h: hits.append(h),
        limits=FS.SearchLimits(max_hits=7),
    )
    assert len(hits) == 7 and summary.truncated


def test_edge_content_beyond_the_per_file_cap_is_not_searched(tree, monkeypatch) -> None:
    big = tree / "big.txt"
    big.write_bytes(b"early needle\n" + b"y" * 5000 + b"\nlate marker\n")
    limits = FS.SearchLimits(max_content_bytes=1024)
    for tools in (True, False):
        if not tools:
            monkeypatch.setattr(FS, "find_tool", lambda name: None)
        early, late = [], []
        FS.run_search([FS.SearchScope(LocalFS(), str(tree))], SF.SearchQuery(contains="needle"),
                      on_hit=lambda s, h: early.append(h), limits=limits)
        FS.run_search([FS.SearchScope(LocalFS(), str(tree))], SF.SearchQuery(contains="marker"),
                      on_hit=lambda s, h: late.append(h), limits=limits)
        assert [os.path.basename(h.path) for h in early] == ["big.txt"]
        assert late == []


def test_edge_a_match_split_across_read_chunks_is_found(tree, monkeypatch) -> None:
    monkeypatch.setattr(FS, "find_tool", lambda name: None)
    monkeypatch.setattr(FS, "_CHUNK", 16)
    (tree / "split.txt").write_bytes(b"aaaaaaaaaaaaaaneedle-across\n")
    hits, _ = _local(tree, contains="needle-across")
    assert _rel(hits, tree) == {"split.txt"}


def test_edge_a_fifo_is_never_opened(tree, monkeypatch) -> None:
    if not hasattr(os, "mkfifo"):
        pytest.skip("no FIFOs here")
    os.mkfifo(tree / "pipe.txt")
    for tools in (True, False):
        if not tools:
            monkeypatch.setattr(FS, "find_tool", lambda name: None)
        started = time.monotonic()
        hits, _ = _local(tree, name="*.txt", contains="hello")
        assert time.monotonic() - started < 10
        assert "pipe.txt" not in _rel(hits, tree)


def test_edge_empty_query_lists_every_file(tree) -> None:
    hits, _ = _local(tree)
    rel = _rel(hits, tree)
    assert {"a.txt", "b.log", "blob", "arch.zip", "loop"} <= rel
    assert "node_modules/x.txt" not in rel


def _wide_tree(root: Path, dirs: int, files: int) -> None:
    for d in range(dirs):
        sub = root / f"d{d:04d}"
        sub.mkdir(parents=True)
        for f in range(files):
            (sub / f"f{f}.txt").write_text("hello\n")


@pytest.mark.parametrize("tools", [True, False])
def test_edge_cancel_stops_a_local_run_within_half_a_second(tmp_path, monkeypatch, tools) -> None:
    if not tools:
        monkeypatch.setattr(FS, "find_tool", lambda name: None)
    _wide_tree(tmp_path / "w", 400, 25)
    stop = threading.Event()
    stopped_at = []

    def on_hit(scope, hit):
        if not stop.is_set():
            stop.set()
            stopped_at.append(time.monotonic())

    summary = FS.run_search(
        [FS.SearchScope(LocalFS(), str(tmp_path / "w"))],
        SF.SearchQuery(contains="hello"),
        on_hit=on_hit,
        cancel=stop.is_set,
    )
    assert summary.cancelled
    assert time.monotonic() - stopped_at[0] < 0.5
    assert summary.found < 10_000


def test_edge_cancel_stops_a_slow_remote_walk(tmp_path) -> None:
    class Slow:
        name = "slow"

        def list_dir(self, path):
            time.sleep(0.02)
            return [FileItem(name=f"d{i}", is_dir=True) for i in range(5)] + [
                FileItem(name="f.txt", size=1, modified=datetime.fromtimestamp(0))
            ]

        def join(self, *parts):
            return "/".join(p.rstrip("/") for p in parts)

    stop = threading.Event()
    timer = threading.Timer(0.2, stop.set)
    timer.start()
    started = time.monotonic()
    summary = FS.run_search([FS.SearchScope(Slow(), "")], SF.SearchQuery(max_depth=-1),
                            on_hit=lambda s, h: None, cancel=stop.is_set)
    assert summary.cancelled
    assert time.monotonic() - started < 0.7


def test_edge_hidden_check_applies_to_folders_on_remote_backends() -> None:
    ram = RamFsSession()
    ram.mkdir("/.config")
    with ram.open_write("/.config/app.ini") as fh:
        fh.write(b"x")
    with ram.open_write("/plain.ini") as fh:
        fh.write(b"x")
    hits, _ = _run([FS.SearchScope(ram, "/")], SF.SearchQuery(name="*.ini", include_hidden=False))
    assert [h.path for h in hits] == ["/plain.ini"]


def test_edge_index_is_skipped_for_content_queries(tmp_path) -> None:
    db = tmp_path / "i.sqlite"
    MX.upsert(db, "LocalFS:Local", "/x/a.txt", name="a.txt", size=1, is_dir=False)
    hits, summary = _run([], SF.SearchQuery(contains="x"), use_index=True, index_db=db)
    assert hits == []
    assert summary.skipped.get("index_content") == 1


def test_edge_scope_label_defaults_to_the_root() -> None:
    assert FS.SearchScope(LocalFS(), "/tmp").label == "/tmp"
    ram = RamFsSession()
    assert FS.SearchScope(ram, "/x").label == f"{ram.name}:/x"


@pytest.mark.skipif(shutil.which("rg") is None, reason="rg is not installed")
def test_edge_odd_file_names_survive_the_tool_output(tree) -> None:
    odd = tree / "new\nline hello.txt"
    odd.write_text("hello\n")
    hits, _ = _local(tree, name="*hello.txt", contains="hello")
    assert _rel(hits, tree) == {"new\nline hello.txt"}


def test_edge_an_archive_searched_inside_is_not_also_a_content_hit(tree) -> None:
    # A stored (uncompressed) zip holds the member's text verbatim; with
    # "inside archives" the member is the hit, not the container too.
    (tree / "stored.zip").write_bytes(
        _zip_bytes({"memo.txt": b"unique phrase\n"}, compression=zipfile.ZIP_STORED)
    )
    hits, _ = _local(tree, contains="unique phrase", search_archives=True)
    assert _rel(hits, tree) == {"stored.zip!/memo.txt"}
    hits, _ = _local(tree, contains="unique phrase")
    assert _rel(hits, tree) == {"stored.zip"}


def test_edge_tar_member_names_are_shown_without_dot_slash(tree) -> None:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tf:
        for name in ("./docs/a.txt", "/abs/b.txt"):
            info = tarfile.TarInfo(name)
            info.size = 2
            tf.addfile(info, io.BytesIO(b"x\n"))
    (tree / "dots.tar").write_bytes(buf.getvalue())
    hits, _ = _local(tree, name="*.txt", search_archives=True)
    # Raw paths: os.path.relpath (_rel) would normalise "!/./" away.
    raw = {h.path for h in hits if "dots.tar" in h.path}
    assert raw == {f"{tree}/dots.tar!/docs/a.txt", f"{tree}/dots.tar!/abs/b.txt"}
    assert {h.member for h in hits if "dots.tar" in h.path} == {"docs/a.txt", "abs/b.txt"}


def test_sad_a_remote_handle_without_context_manager_support_is_read() -> None:
    class Handle:
        def __init__(self, data: bytes) -> None:
            self._io = io.BytesIO(data)

        def read(self, n=-1):
            return self._io.read(n)

        def close(self) -> None:
            self._io.close()

    class Bare:
        name = "bare"
        archive = _zip_bytes({"in/key.pem": b"-----BEGIN CERTIFICATE-----\n"})

        def list_dir(self, path):
            return [FileItem(name="pack.zip", size=len(self.archive),
                             modified=datetime.fromtimestamp(0))]

        def join(self, *parts):
            return "/".join(p.rstrip("/") for p in parts)

        def open_read(self, path):
            return Handle(self.archive)

    hits, summary = _run([FS.SearchScope(Bare(), "")],
                         SF.SearchQuery(categories=("keys_certs",), search_archives=True))
    assert [h.path for h in hits] == ["/pack.zip!/in/key.pem"]
    assert summary.errors == []


# --- round-2 verification ----------------------------------------------------


class _BackendError(Exception):
    """A protocol library's own exception: not an OSError (smbprotocol,
    botocore, paramiko ... raise their own types from read())."""


@pytest.mark.parametrize("where", ["open", "read"])
def test_sad_a_remote_archive_that_fails_with_a_backend_error_is_reported(where) -> None:
    """One remote archive that cannot be read must not end the whole run:
    the content path already treats any backend exception as "skip this
    file"; the archive copy has to as well."""
    good = _zip_bytes({"in/note.txt": b"x"})

    class Failing:
        def read(self, n=-1):
            raise _BackendError("STATUS_FILE_LOCK_CONFLICT")

        def close(self) -> None:
            pass

    class Remote:
        name = "remote"

        def list_dir(self, path):
            return [FileItem(name=n, size=len(good), modified=datetime.fromtimestamp(0))
                    for n in ("bad.zip", "good.zip", "plain.txt")]

        def join(self, *parts):
            return "/".join(p.rstrip("/") for p in parts)

        def open_read(self, path):
            if path.endswith("bad.zip"):
                if where == "open":
                    raise _BackendError("STATUS_SHARING_VIOLATION")
                return Failing()
            return io.BytesIO(good)

    hits, summary = _run([FS.SearchScope(Remote(), "")],
                         SF.SearchQuery(search_archives=True))
    paths = sorted(h.path for h in hits)
    assert "/good.zip!/in/note.txt" in paths and "/plain.txt" in paths
    assert any("bad.zip" in e for e in summary.errors)


def test_edge_a_tar_of_endless_folder_entries_stops_at_the_member_cap(tree) -> None:
    """Folder, link and device headers are members too: a tar of millions of
    folder entries (they compress to almost nothing) must stop at the member
    cap instead of being read - and kept in tarfile's member list - whole."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        for i in range(500):
            info = tarfile.TarInfo(f"d{i}")
            info.type = tarfile.DIRTYPE
            tf.addfile(info)
        info = tarfile.TarInfo("late.txt")
        info.size = 2
        tf.addfile(info, io.BytesIO(b"x\n"))
    (tree / "dirs.tar.gz").write_bytes(buf.getvalue())
    hits = []
    summary = FS.run_search(
        [FS.SearchScope(LocalFS(), str(tree))],
        SF.SearchQuery(name="late.txt", search_archives=True),
        on_hit=lambda s, h: hits.append(h),
        limits=FS.SearchLimits(max_archive_members=100),
    )
    assert hits == []
    assert summary.skipped.get("archive_members") == 1
