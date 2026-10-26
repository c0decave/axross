"""federated_search over real backends of the families its docs named:
a real ImapSession against the scripted IMAP server, a real SqliteFsSession,
LocalFS and RamFS - every hit is a path the pane can open.

Found while measuring core/search_federation.py (54 % of its branches,
docs/TEST_COVERAGE_MATRIX.md of 2026-10-26): README, docs/MULTI_SYSTEM*.md
and the federated_search docstring promised "IMAP SEARCH for IMAP, native
find_by_query for DB-FS". No backend has the ``search_messages`` or
``find_by_query`` those adapters looked for, so every search ran the
client-side walk - and had a backend ever grown ``search_messages``, the
IMAP adapter would have answered with bare message numbers as paths. The
adapters are gone, the docs say what runs.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from mail_fuzz_servers import FakeImapServer  # noqa: E402

from core import imap_client as IC  # noqa: E402
from core import search_federation as SF  # noqa: E402
from core.local_fs import LocalFS  # noqa: E402
from core.ram_fs import RamFsSession  # noqa: E402
from core.sqlite_fs_client import SqliteFsSession  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture(autouse=True)
def _short_imap_timeout(monkeypatch):
    monkeypatch.setattr(IC, "IMAP_TIMEOUT", 2.0)


@pytest.fixture
def sqlite_fs(tmp_path):
    fs = SqliteFsSession(str(tmp_path / "fs.sqlite"))
    fs.mkdir("/etc")
    with fs.open_write("/etc/app.conf") as fh:
        fh.write(b"listen 80\nX-Forwarded-For on\n")
    with fs.open_write("/etc/other.conf") as fh:
        fh.write(b"nothing here\n")
    yield fs
    fs.disconnect()


@pytest.fixture
def local_tree(tmp_path):
    root = tmp_path / "local"
    (root / "etc").mkdir(parents=True)
    (root / "etc" / "site.conf").write_text("X-Forwarded-For off\n")
    (root / "etc" / "notes.txt").write_text("X-Forwarded-For\n")
    return root


def _paths(result, label_part: str) -> list[str]:
    return sorted(h.path for h in result.hits if label_part in h.backend_label)


# ------------------------------------------------------------------ happy
def test_happy_e2e_one_query_over_sqlite_fs_and_local_returns_openable_paths(
    sqlite_fs, local_tree
):
    local = LocalFS()
    q = SF.SearchQuery(name="*.conf", contains="X-Forwarded-For", roots=["/etc"])
    result = SF.federated_search([sqlite_fs], q)
    assert result.errors == {}
    assert [h.path for h in result.hits] == ["/etc/app.conf"]
    # roots apply to every backend: the local folder exists on LocalFS only,
    # so the SQLite backend reports it instead of answering "no matches"
    q_local = SF.SearchQuery(
        name="*.conf", contains="X-Forwarded-For", roots=[str(local_tree / "etc")]
    )
    result = SF.federated_search([local, sqlite_fs], q_local)
    assert [h.path for h in result.hits] == [str(local_tree / "etc" / "site.conf")]
    assert list(result.errors) == [SF._label(sqlite_fs)]
    for hit in result.hits:
        assert hit.warning == ""


def test_happy_e2e_imap_hits_are_message_files_not_numbers():
    with FakeImapServer() as srv:
        imap = IC.ImapSession(srv.host, srv.port, "u", "p", use_ssl=False)
        q = SF.SearchQuery(name="*.eml", roots=["/INBOX"], max_depth=1)
        result = SF.federated_search([imap], q, per_backend_timeout_s=20)
        assert result.errors == {}
        paths = [h.path for h in result.hits]
        assert paths, "the INBOX of the scripted server holds a message"
        for p in paths:
            assert p.startswith("/INBOX/") and p.endswith(".eml"), p
            assert imap.stat(p).name == p.rsplit("/", 1)[1]


# -------------------------------------------------------------------- sad
def test_sad_a_backend_that_fails_is_reported_and_the_others_still_answer(sqlite_fs):
    broken = RamFsSession("fed-broken")
    try:
        broken.list_dir = lambda path: (_ for _ in ()).throw(OSError("gone"))
        q = SF.SearchQuery(name="*.conf", roots=["/etc"])
        result = SF.federated_search([broken, sqlite_fs], q)
        assert sorted(h.path for h in result.hits) == ["/etc/app.conf", "/etc/other.conf"]
        assert list(result.errors) == [SF._label(broken)]
        assert "gone" in result.errors[SF._label(broken)]
    finally:
        broken.disconnect()


def test_sad_a_local_root_that_does_not_exist_is_an_error_not_zero_hits(tmp_path):
    result = SF.federated_search(
        [LocalFS()], SF.SearchQuery(name="*", roots=[str(tmp_path / "missing")])
    )
    assert result.hits == []
    assert len(result.errors) == 1
    assert "missing" in next(iter(result.errors.values()))


# ------------------------------------------------------------------- edge
def test_edge_an_empty_root_is_zero_hits_and_no_error(tmp_path, sqlite_fs):
    sqlite_fs.mkdir("/empty")
    (tmp_path / "empty").mkdir()
    for backend, root in ((LocalFS(), str(tmp_path / "empty")), (sqlite_fs, "/empty")):
        result = SF.federated_search([backend], SF.SearchQuery(name="*", roots=[root]))
        assert result.hits == [] and result.errors == {}, backend


def test_edge_a_root_that_lists_but_has_no_match_is_no_error(sqlite_fs):
    result = SF.federated_search([sqlite_fs], SF.SearchQuery(name="*.none", roots=["/etc"]))
    assert result.hits == [] and result.errors == {}


@pytest.mark.parametrize("method", ["search_messages", "find_by_query"])
def test_edge_no_built_in_adapter_waits_for_a_method_no_backend_has(method):
    defined = [
        p.relative_to(ROOT).as_posix()
        for p in (ROOT / "core").glob("*.py")
        if re.search(rf"^\s+def {method}\(", p.read_text(encoding="utf-8"), re.M)
    ]
    assert defined == []
    assert method not in (ROOT / "core" / "search_federation.py").read_text(encoding="utf-8")


DOCS = [
    "README.md",
    "README_de.md",
    "README_es.md",
    "docs/MULTI_SYSTEM.md",
    "docs/MULTI_SYSTEM_de.md",
    "docs/MULTI_SYSTEM_es.md",
    "docs/SCRIPTING_REFERENCE.md",
    "core/scripting.py",
]


@pytest.mark.parametrize("doc", DOCS)
def test_edge_the_docs_promise_no_native_search_that_does_not_run(doc):
    text = (ROOT / doc).read_text(encoding="utf-8")
    assert "find_by_query" not in text
    assert "IMAP SEARCH for IMAP" not in text and "IMAP SEARCH für IMAP" not in text
    assert "IMAP SEARCH para" not in text


def test_edge_a_registered_adapter_still_takes_over_its_protocol(sqlite_fs):
    calls = []

    def adapter(backend, query, max_hits):
        calls.append(backend)
        return [SF.SearchHit(backend_label="x", path="/from-adapter")]

    SF.register_adapter("sqlite", adapter)
    try:
        result = SF.federated_search([sqlite_fs], SF.SearchQuery(name="*"))
    finally:
        SF._ADAPTERS.pop("sqlite", None)
    assert calls == [sqlite_fs]
    assert [h.path for h in result.hits] == ["/from-adapter"]
