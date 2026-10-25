"""Discover: curated awesome-lists of MCP servers, for browsing.

A source of Add from Catalog… (core.mcp_catalog, ``discover``) that reads
the README of curated lists over raw.githubusercontent.com:

=====================================  ========  ==========================
list                                   licence   offline
=====================================  ========  ==========================
``R00T-Kim/awesome-offensive-mcp``     CC0-1.0   snapshot in resources/mcp
``wong2/awesome-mcp-servers``          MIT       live only
=====================================  ========  ==========================

A README is **untrusted text**: it is read bounded, never rendered, and
only its category headings, entry names, descriptions and GitHub
repository links are taken. Every text is cleaned to plain text (markdown
links become their text, HTML tags go, control and bidi characters go);
the only URL kept is the entry's GitHub repository, rebuilt from parts
that passed strict patterns. An entry without such a link is left out.

Nothing is ever built from a bare repository. An entry is **installable**
only where a source axross already trusts names the same repository: the
official MCP Registry (a server whose ``repository.url`` is the entry's)
or Docker Hub's curated ``mcp`` namespace (an image whose README names the
repository). The install then goes through that source's usual path
(core.mcp_install). Every other entry is **link only**: Open Repository,
no install.

The parsed lists and the cross-references are cached for :data:`TTL`
(``$XDG_CACHE_HOME/axross/mcp-discover``); :meth:`DiscoverSource.refresh`
reads everything again. A cross-reference run is bounded by a request
budget; what it did not reach is checked when it is selected.
"""

from __future__ import annotations

import dataclasses
import json
import logging
import os
import re
import threading
import time
import unicodedata
import urllib.parse
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from core import mcp_catalog as M

log = logging.getLogger(__name__)

#: A README larger than this is refused.
MAX_README_BYTES = 1 << 20
#: Entries read of one list.
MAX_LIST_ENTRIES = 1500
MAX_LINES = 50000
#: Characters of a line that are looked at.
MAX_LINE = 4000
#: Seconds a parsed list and a cross-reference are kept.
TTL = 24 * 3600
#: Seconds a list that could not be read is not asked again.
FAILED_TTL = 300
#: Requests one cross-reference run may make.
CROSSREF_BUDGET = 300
#: A cache file larger than this is ignored.
MAX_CACHE_BYTES = 8 << 20
#: A cached registry answer of one server larger than this is not kept.
MAX_CACHED_ITEM = 64 << 10
SNAPSHOT_SCHEMA = "axross-mcp-discover-snapshot"
#: How the notes of _list_entries start (what is shown instead of the live list).
_NOTE_MARKS = ("the copy read on ", "the offline snapshot ")

RAW = "https://raw.githubusercontent.com"


@dataclass(frozen=True)
class DiscoverList:
    id: str
    #: ``owner/repo`` of the list.
    title: str
    #: The README, raw.
    url: str
    repository: str
    license: str
    #: A snapshot in resources/mcp ("" = none; only for a list whose
    #: licence allows shipping it).
    snapshot: str = ""


LISTS = (
    DiscoverList("r00t-kim", "R00T-Kim/awesome-offensive-mcp",
                 f"{RAW}/R00T-Kim/awesome-offensive-mcp/main/README.md",
                 "https://github.com/R00T-Kim/awesome-offensive-mcp", "CC0-1.0",
                 "discover-awesome-offensive-mcp.json"),
    DiscoverList("wong2", "wong2/awesome-mcp-servers",
                 f"{RAW}/wong2/awesome-mcp-servers/main/README.md",
                 "https://github.com/wong2/awesome-mcp-servers", "MIT"),
)

LINK_ONLY = ("link only: neither the MCP Registry nor Docker Hub's mcp namespace names this "
             "repository - open it and judge it yourself; axross never builds from a bare "
             "repository")
UNCHECKED = ("not checked yet: axross looks for this repository in the MCP Registry and Docker "
             "Hub's mcp namespace")
VIA_TITLES = {"mcpregistry": "MCP Registry", "dockerhub": "Docker Hub (mcp/*)"}

# -- GitHub links ----------------------------------------------------------------------------

_OWNER = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9]|-(?=[A-Za-z0-9])){0,38}$")
_REPO = re.compile(r"^[A-Za-z0-9._-]{1,100}$")
_SEGMENT = re.compile(r"^[A-Za-z0-9._-]{1,100}$")
#: First path parts of github.com that are no user or organisation.
_RESERVED = frozenset({
    "about", "apps", "collections", "customer-stories", "enterprise", "events", "explore",
    "features", "login", "marketplace", "new", "notifications", "orgs", "organizations",
    "pricing", "readme", "search", "security", "settings", "site", "sponsors", "topics",
    "trending", "users",
})


def github_location(url) -> tuple[str, str]:
    """``(repository, folder)`` of an https GitHub link:
    ``https://github.com/<owner>/<repo>`` rebuilt from checked parts, and
    ``tree|blob/<ref>/<path>`` when the link points into it ("" else).
    ``("", "")`` for anything else (another host or scheme, credentials, a
    port, odd characters, no repository)."""
    if not isinstance(url, str) or not url or len(url) > 500:
        return "", ""
    if any(ch.isspace() or unicodedata.category(ch) in ("Cc", "Cf") for ch in url):
        return "", ""
    try:
        parts = urllib.parse.urlsplit(url)
    except ValueError:
        return "", ""
    if parts.scheme != "https" or parts.netloc.lower() not in ("github.com", "www.github.com"):
        return "", ""
    segments = [s for s in parts.path.split("/") if s]
    if len(segments) < 2:
        return "", ""
    owner, repo = segments[0], segments[1]
    if repo.lower().endswith(".git"):
        repo = repo[:-4]
    if (not _OWNER.match(owner) or owner.lower() in _RESERVED or not _REPO.match(repo)
            or repo in (".", "..")):
        return "", ""
    folder = ""
    rest = segments[2:]
    if (3 <= len(rest) <= 12 and rest[0] in ("tree", "blob")
            and all(_SEGMENT.match(s) and s not in (".", "..") for s in rest[1:])):
        folder = "/".join(rest)
    return f"https://github.com/{owner}/{repo}", folder


def github_repo(url) -> str:
    """The canonical ``https://github.com/<owner>/<repo>`` of *url*, or ""."""
    return github_location(url)[0]


# -- markdown as plain text ------------------------------------------------------------------

_HEADING = re.compile(r"^(#{1,6})\s+(.*?)\s*#*\s*$")
_ITEM = re.compile(r"^\s{0,8}[-*+]\s+(.*)$")
_LINK = re.compile(r"\[((?:[^\[\]]|\[[^\[\]]*\]){1,300})\]"
                   r"\(\s*((?:[^()\s]|\([^()\s]{0,200}\)){1,500})\s*\)")
# A link target with one level of parentheses inside (javascript:alert(1)).
_TARGET = r"\((?:[^()]|\([^()]{0,200}\)){0,500}\)"
_IMAGE_MD = re.compile(r"!\[([^\[\]]{0,300})\]" + _TARGET)
_LINK_MD = re.compile(r"\[([^\[\]]{0,300})\]" + _TARGET)
_SCRIPT = re.compile(r"<(script|style)\b[^>]{0,500}>.*?</\1\s*>", re.IGNORECASE | re.DOTALL)
_TAG = re.compile(r"</?[A-Za-z!][^<>]{0,500}>")
_FENCE = re.compile(r"^\s{0,3}(```|~~~)")
#: Headings whose entries are no MCP servers (clients, frameworks, ...).
_SKIP = re.compile(r"\b(?:clients?|frameworks?|sponsors?|contribut\w*|licen[cs]es?|categories"
                   r"|disclaimer|what is|table of contents|tutorials?|resources|related"
                   r"|star history)\b", re.IGNORECASE)


def _plain(text: str, limit: int, *, emoji: bool = True) -> str:
    """Markdown and HTML of *text* as plain text: images and links as their
    text, tags and their scripts dropped, emphasis marks gone, cleaned and
    cut (core.mcp_catalog.clean_text). *emoji* False drops symbols too."""
    text = _SCRIPT.sub("", text)
    text = _IMAGE_MD.sub(r"\1", text)
    text = _LINK_MD.sub(r"\1", text)
    text = _TAG.sub("", text)
    text = text.replace("**", "").replace("__", "").replace("`", "").replace("*", "")
    if not emoji:
        text = "".join(ch for ch in text
                       if unicodedata.category(ch) not in ("So", "Sk", "Mn"))
    return M.clean_text(text, limit)


def _category(heading: str) -> str:
    text = _plain(heading, 200, emoji=False)
    return re.sub(r"^[^\w(]+", "", text).strip()[:60]


def parse_readme(text, *, listed_in: str) -> tuple[list[M.CatalogEntry], list[str]]:
    """The entries of an awesome-list README: list items that start with a
    link to a GitHub repository, under their heading (the category).
    Returns the entries and one warning per item left out."""
    if isinstance(text, bytes):
        text = text.decode("utf-8", errors="replace")
    if not isinstance(text, str):
        return [], ["the list is not text"]
    text = text[:MAX_README_BYTES].replace("\r\n", "\n").replace("\r", "\n")
    entries: list[M.CatalogEntry] = []
    warnings: list[str] = []
    seen: set[str] = set()
    headings: dict[int, str] = {}
    fenced = False
    for line in text.split("\n")[:MAX_LINES]:
        line = line[:MAX_LINE]
        if _FENCE.match(line):
            fenced = not fenced
            continue
        if fenced:
            continue
        heading = _HEADING.match(line)
        if heading:
            level = len(heading.group(1))
            headings = {k: v for k, v in headings.items() if k < level}
            headings[level] = heading.group(2)
            continue
        item = _ITEM.match(line)
        if not item:
            continue
        if any(_SKIP.search(_plain(h, 200)) for k, h in headings.items() if k >= 2):
            continue
        body = item.group(1).lstrip("*_ ")
        link = _LINK.match(body)
        if not link:
            continue
        name = _plain(link.group(1), M.MAX_SHORT)
        repo, folder = github_location(link.group(2))
        label = M.clean_text(name, 40) or "?"
        if not repo:
            warnings.append(f"{label}: not a GitHub repository - left out")
            continue
        if len(entries) >= MAX_LIST_ENTRIES:
            warnings.append(f"at most {MAX_LIST_ENTRIES} entries of a list are read")
            break
        owner_repo = repo[len("https://github.com/"):]
        path = folder.split("/", 2)[2] if folder else ""
        entry_id = f"discover:{owner_repo}" + (f"/{path}" if path else "")
        if entry_id.lower() in seen:
            warnings.append(f"{label}: its repository is listed twice - the first is kept")
            continue
        seen.add(entry_id.lower())
        rest = body[link.end():].lstrip("*_ ")
        rest = re.sub(r"^(?:[-–—:|]\s*)", "", rest)
        category = next((_category(headings[k]) for k in sorted(headings, reverse=True)
                         if k >= 2 and _category(headings[k])), "") or "Other"
        leaf = folder.rsplit("/", 1)[-1] if folder else owner_repo.split("/", 1)[1]
        entries.append(M.CatalogEntry(
            id=entry_id, name=M.server_name(leaf), title=name or leaf,
            description=_plain(rest, M.MAX_DESCRIPTION), category=category,
            source="discover", repository=repo + (f"/{folder}" if folder else ""),
            kind="link", why_not=UNCHECKED, listed_in=M.clean_text(listed_in, 100),
            xref="unchecked",
        ))
    return entries, warnings


def merge_lists(lists) -> list[M.CatalogEntry]:
    """The entries of several lists, each repository once: the first
    list's entry, with every list that names it."""
    out: dict[str, M.CatalogEntry] = {}
    for entries in lists:
        for entry in entries:
            key = entry.id.lower()
            first = out.get(key)
            if first is None:
                out[key] = entry
            elif entry.listed_in and entry.listed_in not in first.listed_in.split(", "):
                out[key] = dataclasses.replace(first,
                                               listed_in=f"{first.listed_in}, {entry.listed_in}")
    return list(out.values())


def name_core(text: str) -> str:
    """What is left of a name without "mcp" and "server": the part that two
    spellings of one server share (``mcp-shodan`` and ``shodan-mcp-server``
    both give ``shodan``)."""
    words = [w for w in re.split(r"[^a-z0-9]+", str(text or "").lower())
             if w and w not in ("mcp", "server")]
    core = "".join(words)
    if core.endswith("mcp") and len(core) > 5:  # GhidraMCP
        core = core[:-3]
    if core.startswith("mcp") and len(core) > 5:  # mcpshodan
        core = core[3:]
    return core


# -- the cache -------------------------------------------------------------------------------


def cache_dir() -> Path:
    """``$XDG_CACHE_HOME/axross/mcp-discover`` (an absolute XDG_CACHE_HOME
    only), else ``~/.cache/axross/mcp-discover``."""
    base = os.environ.get("XDG_CACHE_HOME", "").strip()
    root = Path(base) if base and os.path.isabs(base) else Path.home() / ".cache"
    return root / "axross" / "mcp-discover"


_default_cache_dir = cache_dir


def _read_json(path: Path):
    try:
        with open(path, "rb") as handle:
            raw = handle.read(MAX_CACHE_BYTES + 1)
    except OSError:
        return None
    if len(raw) > MAX_CACHE_BYTES:
        return None
    try:
        return json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError, RecursionError):
        return None


def _write_json(path: Path, data) -> None:
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_name(f"{path.name}.{os.getpid()}.{threading.get_ident()}.tmp")
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(data, handle)
        os.replace(tmp, path)
    except OSError as exc:
        log.info("mcp discover: cache %s not written: %s", path, exc)


def snapshot_path(lst: DiscoverList) -> Path:
    return M.builtin_path().parent / lst.snapshot


def load_snapshot(lst: DiscoverList) -> tuple[str, str]:
    """``(readme, what it is)`` of the list's shipped snapshot; CatalogError
    when there is none or it is unusable."""
    if not lst.snapshot:
        raise M.CatalogError("no snapshot")
    data = _read_json(snapshot_path(lst))
    if (not isinstance(data, dict) or data.get("schema") != SNAPSHOT_SCHEMA
            or not isinstance(data.get("readme"), str)):
        raise M.CatalogError("the snapshot is not usable")
    commit = M.clean_text(data.get("commit"), 40)
    retrieved = M.clean_text(data.get("retrieved"), 10)
    return data["readme"], f"the offline snapshot of commit {commit[:7]} ({retrieved})"


# -- the source ------------------------------------------------------------------------------


class _CountingOpener:
    """The opener of a source that counts its requests (the budget)."""

    def __init__(self, inner, owner: DiscoverSource) -> None:
        self._inner = inner
        self._owner = owner

    def open(self, request, timeout=None):
        with self._owner._lock:
            self._owner._requests += 1
            if self._inner is None:
                self._inner = M.default_opener()
        return self._inner.open(request, timeout=timeout)


class DiscoverSource(M.Source):
    """The curated lists of :data:`LISTS`, cross-referenced on request."""

    id = "discover"
    title = "Discover"

    def __init__(self, *, opener=None, cache_dir: Path | None = None, lists=LISTS,
                 ttl: float = TTL, now: Callable[[], float] = time.time,
                 registry_base: str = M.MCP_REGISTRY, hub_base: str = M.DOCKER_HUB,
                 allow_http: bool = False) -> None:
        self._lock = threading.RLock()
        self._requests = 0
        super().__init__(opener=_CountingOpener(opener, self))
        self.lists = tuple(lists)
        self.ttl = float(ttl)
        self._now = now
        self._allow_http = allow_http
        self._cache = Path(cache_dir) if cache_dir is not None else _default_cache_dir()
        self._registry_base = registry_base.rstrip("/")
        self._hub = M.DockerHubSource(base=hub_base, opener=self._opener, allow_http=allow_http)
        #: list id -> (time, entries, warnings, ok)
        self._lists: dict[str, tuple[float, list, list, bool]] = {}
        self._xref: dict | None = None
        self._registry_answers: dict[str, tuple[list, bool]] = {}

    # -- lists ---------------------------------------------------------------------------

    def _list_file(self, lst: DiscoverList) -> Path:
        return self._cache / f"list-{lst.id}.json"

    def _parse(self, lst: DiscoverList, text: str) -> tuple[list, list]:
        return parse_readme(text, listed_in=lst.title)

    def _list_entries(self, lst: DiscoverList, cancel) -> tuple[list, list]:
        now = self._now()
        with self._lock:
            held = self._lists.get(lst.id)
        if held is not None and now - held[0] < (self.ttl if held[3] else FAILED_TTL):
            return held[1], held[2]
        cached = _read_json(self._list_file(lst))
        cached_ok = (isinstance(cached, dict) and isinstance(cached.get("readme"), str)
                     and isinstance(cached.get("fetched"), (int, float)))
        if cached_ok and now - cached["fetched"] < self.ttl:
            entries, warnings = self._parse(lst, cached["readme"])
            self._hold(lst, cached["fetched"], entries, warnings, True)
            return entries, warnings
        try:
            raw = M.http_get(lst.url, opener=self._opener, cancel=cancel,
                             max_bytes=MAX_README_BYTES, allow_http=self._allow_http,
                             accept="text/plain")
        except M.CatalogError as exc:
            if str(exc) == "cancelled":
                raise
            why = str(exc)
            if cached_ok:
                when = time.strftime("%Y-%m-%d", time.localtime(cached["fetched"]))
                entries, warnings = self._parse(lst, cached["readme"])
                note = f"the copy read on {when} is shown (the live list: {why})"
            else:
                try:
                    readme, what = load_snapshot(lst)
                except M.CatalogError:
                    raise M.CatalogError(why) from None
                entries, warnings = self._parse(lst, readme)
                note = f"{what} is shown (the live list: {why})"
            warnings = [note, *warnings]
            self._hold(lst, now, entries, warnings, False)
            return entries, warnings
        text = raw.decode("utf-8", errors="replace")
        entries, warnings = self._parse(lst, text)
        _write_json(self._list_file(lst), {"fetched": now, "url": lst.url, "readme": text})
        self._hold(lst, now, entries, warnings, True)
        return entries, warnings

    def _hold(self, lst, when, entries, warnings, ok) -> None:
        with self._lock:
            self._lists[lst.id] = (when, entries, warnings, ok)

    def search(self, query: str = "", *, cancel=None) -> M.SearchResult:
        """The lists' entries matching *query*; ``notes`` say what was read
        instead of a live list (a cached copy, the snapshot) or which list
        could not be read, ``warnings`` the items left out."""
        result = M.SearchResult(self.id, self.title)
        try:
            result.entries, result.warnings, result.notes = self._collect(query, cancel)
        except M.CatalogError as exc:
            result.error = str(exc)
        return result

    def _search(self, query, cancel):
        entries, warnings, notes = self._collect(query, cancel)
        return entries, notes + warnings

    def _collect(self, query, cancel):
        parsed: list[list[M.CatalogEntry]] = []
        warnings: list[str] = []
        notes: list[str] = []
        for lst in self.lists:
            try:
                entries, said = self._list_entries(lst, cancel)
            except M.CatalogError as exc:
                if str(exc) == "cancelled":
                    raise
                notes.append(f"{lst.title} could not be read: {exc}")
                continue
            parsed.append(entries)
            for line in said:
                (notes if line.startswith(_NOTE_MARKS) else warnings).append(
                    f"{lst.title}: {line}")
        if not parsed:
            raise M.CatalogError("no list could be read - " + "; ".join(notes))
        entries = [self.apply_verdict(e) for e in merge_lists(parsed)]
        return [e for e in entries if e.matches(query)], warnings, notes

    def refresh(self) -> None:
        """Forget the lists and the cross-references: the next search and
        check read them again."""
        with self._lock:
            self._lists.clear()
            self._xref = {}
            self._registry_answers.clear()
            for lst in self.lists:
                try:
                    self._list_file(lst).unlink()
                except OSError:
                    pass
            try:
                (self._cache / "crossref.json").unlink()
            except OSError:
                pass

    # -- cross-reference -----------------------------------------------------------------

    def _verdicts(self) -> dict:
        with self._lock:
            if self._xref is None:
                data = _read_json(self._cache / "crossref.json")
                self._xref = {k: v for k, v in data.items()
                              if isinstance(k, str) and isinstance(v, dict)
                              and isinstance(v.get("t"), (int, float))
                              and v.get("xref") in ("link", "mcpregistry", "dockerhub")
                              } if isinstance(data, dict) else {}
            return self._xref

    def _save_verdicts(self) -> None:
        with self._lock:
            now = self._now()
            fresh = {k: v for k, v in self._verdicts().items() if now - v["t"] < self.ttl}
            _write_json(self._cache / "crossref.json", fresh)

    def _remember(self, entry: M.CatalogEntry, record: dict) -> None:
        record = dict(record, t=self._now())
        with self._lock:
            self._verdicts()[entry.id.lower()] = record

    def apply_verdict(self, entry: M.CatalogEntry) -> M.CatalogEntry:
        """*entry* with the cross-reference the cache holds (if fresh)."""
        record = self._verdicts().get(entry.id.lower())
        if record is None or self._now() - record["t"] >= self.ttl:
            return entry
        note = M.clean_text(record.get("note"), 500)
        if record["xref"] == "link":
            return dataclasses.replace(entry, xref="link", why_not=LINK_ONLY, notes=note)
        if record["xref"] == "mcpregistry":
            found = M.entry_from_registry(record.get("item"))
        else:
            name = record.get("hub")
            found = self._hub._entry({"name": name}) if isinstance(name, str) else None
        if found is None or not found.installable:
            return entry
        return self._installable(entry, found, record["xref"])

    def _installable(self, entry: M.CatalogEntry, found: M.CatalogEntry,
                     via: str) -> M.CatalogEntry:
        return dataclasses.replace(
            found, id=entry.id, title=entry.title, category=entry.category,
            description=entry.description or found.description, source=self.id,
            repository=entry.repository, listed_in=entry.listed_in, via=VIA_TITLES[via],
            xref=via,
        )

    def _registry_items(self, term: str, cancel) -> tuple[list, bool]:
        """The registry's servers for *term* (one page) and whether there
        were more."""
        key = term.lower()
        with self._lock:
            held = self._registry_answers.get(key)
        if held is not None:
            return held
        params = {"limit": "100", "version": "latest", "search": term[:100]}
        url = f"{self._registry_base}/v0.1/servers?{urllib.parse.urlencode(params)}"
        data = M.http_get_json(url, opener=self._opener, cancel=cancel,
                               allow_http=self._allow_http)
        if not isinstance(data, dict) or not isinstance(data.get("servers"), list):
            raise M.CatalogError("the MCP Registry's answer has no servers")
        meta = data.get("metadata") if isinstance(data.get("metadata"), dict) else {}
        answer = ([i for i in data["servers"][:200] if isinstance(i, dict)],
                  bool(meta.get("nextCursor")))
        with self._lock:
            self._registry_answers[key] = answer
        return answer

    @staticmethod
    def _match_registry(items, repo: str, path: str):
        """``(entry, item, note)`` of the registry server of *repo* (and
        its folder *path*), preferring one axross can install."""
        best = None
        for item in items:
            server = item.get("server") if isinstance(item.get("server"), dict) else {}
            where = server.get("repository") if isinstance(server.get("repository"), dict) else {}
            if github_repo(where.get("url")).lower() != repo.lower():
                continue
            sub = where.get("subfolder")
            sub = sub.strip("/") if isinstance(sub, str) else ""
            if sub.lower() != path.lower():
                continue
            entry = M.entry_from_registry(item)
            if entry is None:
                continue
            if entry.installable:
                return entry, item, ""
            if best is None:
                best = (None, None, f"The MCP Registry lists it ({entry.id.split(':', 1)[1]}), "
                                    f"but it cannot be installed: {entry.why_not}.")
        return best

    def _match_hub(self, leaf: str, repo: str, path: str, cancel):
        term = name_core(leaf)
        if len(term) < 2:
            return None
        found, _ = self._hub._search(term, cancel)
        ranked = []
        for entry in found:
            core = name_core(entry.identifier.rsplit("/", 1)[-1])
            if core == term:
                ranked.append((0, entry))
            elif not path and len(core) >= 3 and (term in core or core in term):
                ranked.append((1, entry))
        for _rank, entry in sorted(ranked, key=lambda r: r[0])[:3]:
            if cancel is not None and cancel.is_set():
                raise M.CatalogError("cancelled")
            detailed = self._hub.details(entry)
            if github_repo(detailed.repository).lower() == repo.lower():
                return entry
        return None

    def check(self, entry: M.CatalogEntry, cancel=None, *, save: bool = True) -> M.CatalogEntry:
        """*entry* cross-referenced: installable via the MCP Registry or
        Docker Hub, link only, or still unchecked (with why) when a source
        could not be asked. *save*: the verdict is written to the cache."""
        checked = self._check(entry, cancel)
        if save and checked.xref != "unchecked":
            self._save_verdicts()
        return checked

    def _check(self, entry: M.CatalogEntry, cancel) -> M.CatalogEntry:
        applied = self.apply_verdict(entry)
        if applied.xref in ("link", "mcpregistry", "dockerhub") and applied is not entry:
            return applied
        repo, folder = github_location(entry.repository)
        if not repo:
            return dataclasses.replace(entry, xref="link", why_not=LINK_ONLY)
        owner, name = repo.rsplit("/", 2)[-2:]
        path = folder.split("/", 2)[2] if folder else ""
        leaf = folder.rsplit("/", 1)[-1] if folder else name
        errors: list[str] = []
        note = ""
        try:
            items, more = self._registry_items(owner, cancel)
            match = self._match_registry(items, repo, path)
            if match is None and more:
                items, _more = self._registry_items(name_core(leaf) or leaf, cancel)
                match = self._match_registry(items, repo, path)
            if match is not None and match[0] is not None:
                found, item, _ = match
                record = {"xref": "mcpregistry"}
                if len(json.dumps(item)) <= MAX_CACHED_ITEM:
                    record["item"] = item
                    self._remember(entry, record)
                return self._installable(entry, found, "mcpregistry")
            if match is not None:
                note = match[2]
        except M.CatalogError as exc:
            if str(exc) == "cancelled":
                raise
            errors.append(f"MCP Registry: {exc}")
        try:
            hub = self._match_hub(leaf, repo, path, cancel)
            if hub is not None:
                self._remember(entry, {"xref": "dockerhub",
                                       "hub": hub.identifier.rsplit("/", 1)[-1]})
                return self._installable(entry, hub, "dockerhub")
        except M.CatalogError as exc:
            if str(exc) == "cancelled":
                raise
            errors.append(f"Docker Hub: {exc}")
        if errors:
            return dataclasses.replace(
                entry, xref="unchecked", why_not=UNCHECKED,
                notes=M.clean_text("The check failed - " + "; ".join(errors), 500))
        self._remember(entry, {"xref": "link", "note": note})
        return dataclasses.replace(entry, xref="link", why_not=LINK_ONLY, notes=note)

    def crossref_all(self, entries, *, on_entry: Callable[[M.CatalogEntry], None],
                     cancel: threading.Event | None = None, budget: int = CROSSREF_BUDGET,
                     workers: int = 4) -> int:
        """Check the unchecked of *entries* (at most *workers* at once) until
        *budget* requests are spent or *cancel* is set; *on_entry* hears
        every checked entry (from a worker thread). Returns how many were
        checked."""
        start = self._requests
        todo = [e for e in entries if e.xref == "unchecked"]
        done = [0]

        def one(entry: M.CatalogEntry) -> None:
            if cancel is not None and cancel.is_set():
                return
            if self._requests - start >= budget:
                return
            try:
                checked = self.check(entry, cancel, save=False)
            except M.CatalogError:
                return  # cancelled
            except Exception:  # noqa: BLE001 - one entry must not end the run
                log.exception("mcp discover: checking %s failed", entry.id)
                return
            with self._lock:
                done[0] += 1
            on_entry(checked)

        if todo:
            with ThreadPoolExecutor(max_workers=max(1, min(workers, len(todo))),
                                    thread_name_prefix="mcp-discover") as pool:
                list(pool.map(one, todo))
            self._save_verdicts()
        return done[0]

    def resolve(self, entry: M.CatalogEntry) -> M.CatalogEntry:
        """A Docker Hub entry's digest (as Docker Hub's own source does)."""
        if entry.xref == "dockerhub":
            return self._hub.resolve(entry)
        return entry
