"""Lists of public chat servers for the account editor of the chat panel:
IRC networks, Matrix homeservers, XMPP providers.

The account editor offers them in an editable drop-down - the user can
always type a server of their own. Where the list comes from:

* a snapshot bundled with axross (``resources/chat_servers/<protocol>.json``:
  name, host, port, TLS, a short note and the source of every entry, the
  date of the snapshot), so the drop-down works offline and on first use;
* "Refresh list": the public directories themselves (:data:`DIRECTORIES`),
  fetched off the GUI thread through axross's default proxy, each answer
  size-capped and time-limited, parsed defensively and cached under
  ``~/.cache/axross/chat-servers/<protocol>.json``. A refresh that fails
  keeps what was there; a cache that is unreadable or tampered with falls
  back to the snapshot.

Everything a directory sends is untrusted: only entries with a plain host
name, a valid port and short single-line text are kept; names and notes go
through :func:`core.chat.clean_name` / :func:`core.chat.clean_text` and are
shown as plain text, never as markup.
"""

from __future__ import annotations

import json
import logging
import os
import re
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Callable

from core.chat import clean_name, clean_text

log = logging.getLogger(__name__)

PROTOCOLS = ("irc", "matrix", "xmpp")
#: The largest answer read from a directory (bytes).
MAX_DOWNLOAD = 4 * 1024 * 1024
#: Seconds one directory may take for its whole answer.
FETCH_TIMEOUT = 20.0
#: Entries kept of one list (a directory could send any number).
MAX_ENTRIES = 1000
FORMAT = 1

#: Where "Refresh list" reads, per protocol: (url, parser name), tried in
#: order until one gives entries. The parsers are below.
DIRECTORIES: dict[str, tuple[tuple[str, str], ...]] = {
    # The IRC networks irssi ships in its default configuration - a short,
    # maintained list of the well-known networks with their TLS ports.
    "irc": (("https://raw.githubusercontent.com/irssi/irssi/master/irssi.conf", "irssi"),),
    # joinmatrix.org's list of public homeservers.
    "matrix": (("https://servers.joinmatrix.org/servers.json", "joinmatrix"),),
    # The XMPP Providers project (providers.xmpp.net): category A and B
    # providers; Kaidan's copy of the same file as a second place.
    "xmpp": (("https://data.xmpp.net/providers/v2/providers-B.json", "xmpp-providers"),
             ("https://raw.githubusercontent.com/KDE/kaidan/master/data/providers.json", "xmpp-providers")),
}

_HOST = re.compile(r"(?=.{1,253}\Z)([A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+"
                   r"[A-Za-z](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?")
_DATE = re.compile(r"\d{4}-\d{2}-\d{2}")


class ServerListError(Exception):
    """A list could not be fetched or read; the text is meant for the user."""


@dataclass(frozen=True)
class ServerEntry:
    """One public server. *host* is what the client connects to (an IRC
    server, a Matrix homeserver's client address, an XMPP domain); *domain*
    is the name in user ids when it differs (Matrix "example.org" served by
    "matrix.example.org")."""
    name: str
    host: str
    port: int = 0
    tls: bool = True
    note: str = ""
    source: str = ""
    domain: str = ""

    def label(self) -> str:
        """The line the drop-down shows."""
        where = self.host + (f":{self.port}" if self.port and self.port not in (443,) else "")
        security = "TLS" if self.tls else "no TLS"
        text = f"{self.name} - {where} ({security})" if self.name != self.host else f"{where} ({security})"
        return text + (f" - {self.note}" if self.note else "")


@dataclass
class ServerList:
    protocol: str
    entries: list[ServerEntry] = field(default_factory=list)
    #: YYYY-MM-DD of the data
    date: str = ""
    #: where it was read: "bundled" | "cache" | "fetched"
    origin: str = "bundled"
    sources: tuple[str, ...] = ()


# --- validation ------------------------------------------------------------------------

def valid_host(host: object) -> bool:
    return isinstance(host, str) and bool(_HOST.fullmatch(host))


def _https_url(value: object) -> str:
    if not isinstance(value, str) or len(value) > 300:
        return ""
    try:
        parts = urllib.parse.urlsplit(value.strip())
    except ValueError:
        return ""
    if parts.scheme != "https" or not valid_host(parts.hostname or "") or parts.username or parts.password:
        return ""
    return clean_name(value.strip(), 300)


def make_entry(raw: dict) -> ServerEntry | None:
    """A validated entry of *raw* (an untrusted dict), or None."""
    if not isinstance(raw, dict):
        return None
    host = raw.get("host")
    if not isinstance(host, str):
        return None
    host = host.strip().lower().rstrip(".")
    if not valid_host(host):
        return None
    port = raw.get("port", 0)
    if isinstance(port, bool) or not isinstance(port, int) or not 0 <= port <= 65535:
        return None
    tls = raw.get("tls", True)
    if not isinstance(tls, bool):
        return None
    name = clean_name(raw.get("name") if isinstance(raw.get("name"), str) else "", 80) or host
    note = raw.get("note", "")
    note = clean_text(note, 160, multiline=False).strip() if isinstance(note, str) else ""
    domain = raw.get("domain", "")
    domain = domain.strip().lower() if isinstance(domain, str) else ""
    if domain and not valid_host(domain):
        domain = ""
    return ServerEntry(name=name, host=host, port=port, tls=tls, note=note,
                       source=_https_url(raw.get("source", "")), domain=domain)


def entries_of(items, limit: int = MAX_ENTRIES) -> list[ServerEntry]:
    """The valid entries of *items*, without repeats (by host and port),
    at most *limit*."""
    out: list[ServerEntry] = []
    seen: set[tuple[str, int]] = set()
    for raw in items if isinstance(items, list) else []:
        entry = make_entry(raw)
        if entry is None or (entry.host, entry.port) in seen:
            continue
        seen.add((entry.host, entry.port))
        out.append(entry)
        if len(out) >= limit:
            break
    return out


def parse_list(data: object, protocol: str, origin: str) -> ServerList:
    """A list file (the snapshot or the cache) of *protocol*."""
    if not isinstance(data, dict) or data.get("format") != FORMAT or data.get("protocol") != protocol:
        raise ServerListError("not a server list of this protocol")
    date = data.get("snapshot_date", "")
    sources = data.get("sources", [])
    return ServerList(
        protocol=protocol,
        entries=entries_of(data.get("servers")),
        date=date if isinstance(date, str) and _DATE.fullmatch(date) else "",
        origin=origin,
        sources=tuple(u for u in (_https_url(s) for s in (sources if isinstance(sources, list) else [])[:10]) if u),
    )


def list_data(server_list: ServerList) -> dict:
    """The JSON of a list file."""
    servers = []
    for e in server_list.entries:
        item = asdict(e)
        if not item["domain"]:
            item.pop("domain")
        servers.append(item)
    return {"format": FORMAT, "protocol": server_list.protocol, "snapshot_date": server_list.date,
            "sources": list(server_list.sources), "servers": servers}


# --- the directories' formats ----------------------------------------------------------

_IRSSI_SERVER = re.compile(r"\{([^{}]{0,2000})\}")
_IRSSI_PAIR = re.compile(r"(\w{1,40})\s*=\s*\"([^\"\n]{0,300})\"\s*;")
_IRSSI_NET = re.compile(r"(\w{1,60})\s*=\s*\{([^{}]{0,2000})\}")


def parse_irssi(text: str, source: str = "") -> list[ServerEntry]:
    """The IRC networks of an irssi configuration (``servers = (...)`` with
    ``chatnets = {...}``): one entry per network, its TLS server preferred;
    networks whose chatnet is not IRC (SILC) are left out."""
    if not isinstance(text, str):
        return []
    text = text[:MAX_DOWNLOAD]
    servers_at = text.find("servers")
    chatnets_at = text.find("chatnets")
    if servers_at < 0:
        return []
    servers_part = text[servers_at:chatnets_at if chatnets_at > servers_at else len(text)]
    types: dict[str, str] = {}
    if chatnets_at >= 0:
        for name, body in _IRSSI_NET.findall(text[chatnets_at:]):
            pairs = dict(_IRSSI_PAIR.findall(body))
            types[name.lower()] = pairs.get("type", "")
    best: dict[str, dict] = {}
    for body in _IRSSI_SERVER.findall(servers_part)[:500]:
        pairs = dict(_IRSSI_PAIR.findall(body))
        net = pairs.get("chatnet", "")
        if not net or types.get(net.lower(), "IRC").upper() != "IRC":
            continue
        try:
            port = int(pairs.get("port", "6667"))
        except ValueError:
            continue
        tls = pairs.get("use_tls", pairs.get("use_ssl", "no")).lower() == "yes"
        verify = pairs.get("tls_verify", pairs.get("ssl_verify", "no")).lower() == "yes"
        note = "" if tls and verify else (
            "irssi's list does not check its certificate" if tls else "no TLS port listed - plain text")
        raw = {"name": net, "host": pairs.get("address", ""), "port": port, "tls": tls,
               "note": note, "source": source}
        known = best.get(net.lower())
        if known is None or (tls and not known["tls"]):
            best[net.lower()] = raw
    return entries_of(list(best.values()))


def parse_joinmatrix(data: object, source: str = "") -> list[ServerEntry]:
    """joinmatrix.org's ``servers.json``: ``{"public_servers": [...]}`` with
    the server name (``name``), its client address (``client_domain``),
    how to register and where the staff sits."""
    items = data.get("public_servers") if isinstance(data, dict) else None
    out = []
    for item in (items if isinstance(items, list) else [])[:MAX_ENTRIES * 2]:
        if not isinstance(item, dict) or not isinstance(item.get("name"), str):
            continue
        name = item["name"].strip().lower()
        client = item.get("client_domain") or name
        if not isinstance(client, str):
            continue
        host, _, port = client.strip().partition(":")
        notes = []
        for key in ("reg_method", "staff_jur"):
            value = item.get(key)
            if isinstance(value, str) and value.strip():
                notes.append(value.strip()[:60])
        out.append({"name": name, "host": host, "port": int(port) if port.isdigit() else 443, "tls": True,
                    "note": "; ".join(notes), "source": source, "domain": name})
    return entries_of(out)


def parse_xmpp_providers(data: object, source: str = "") -> list[ServerEntry]:
    """A provider list of the XMPP Providers project: ``[{"jid": domain,
    "category": "A".., "serverLocations": [...], "inBandRegistration": ...}]``."""
    out = []
    for item in (data if isinstance(data, list) else [])[:MAX_ENTRIES * 2]:
        if not isinstance(item, dict) or not isinstance(item.get("jid"), str):
            continue
        domain = item["jid"].strip().lower()
        notes = []
        category = item.get("category")
        if isinstance(category, str) and re.fullmatch(r"[A-D]", category):
            notes.append(f"category {category}")
        locations = item.get("serverLocations")
        if isinstance(locations, list):
            codes = [c.upper() for c in locations[:5] if isinstance(c, str) and re.fullmatch(r"[a-z]{2}", c)]
            if codes:
                notes.append(", ".join(codes))
        if item.get("inBandRegistration") is True:
            notes.append("sign-up in the app")
        elif isinstance(item.get("registrationWebPage"), dict) and item["registrationWebPage"]:
            notes.append("sign-up on the website")
        if item.get("freeOfCharge") is False:
            notes.append("paid")
        out.append({"name": domain, "host": domain, "port": 0, "tls": True, "note": "; ".join(notes),
                    "source": source})
    return entries_of(out)


PARSERS: dict[str, Callable[[bytes, str], list[ServerEntry]]] = {
    "irssi": lambda body, src: parse_irssi(body.decode("utf-8", errors="replace"), src),
    "joinmatrix": lambda body, src: parse_joinmatrix(_json(body), src),
    "xmpp-providers": lambda body, src: parse_xmpp_providers(_json(body), src),
}


def _json(body: bytes):
    try:
        return json.loads(body)
    except (ValueError, RecursionError):
        raise ServerListError("the answer is not JSON") from None


# --- files -------------------------------------------------------------------------------

def bundled_path(protocol: str) -> Path:
    return Path(__file__).resolve().parent.parent / "resources" / "chat_servers" / f"{protocol}.json"


def cache_dir() -> Path:
    base = os.environ.get("XDG_CACHE_HOME") or os.path.join(os.path.expanduser("~"), ".cache")
    return Path(base) / "axross" / "chat-servers"


def _read_file(path: Path, protocol: str, origin: str) -> ServerList:
    try:
        if path.stat().st_size > MAX_DOWNLOAD:
            raise ServerListError(f"{path.name} is too large")
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError, RecursionError) as exc:
        raise ServerListError(f"cannot read {path.name}: {exc}") from None
    return parse_list(data, protocol, origin)


def bundled(protocol: str) -> ServerList:
    """The snapshot shipped with axross (empty when it is missing)."""
    try:
        return _read_file(bundled_path(protocol), protocol, "bundled")
    except ServerListError as exc:
        log.warning("Chat server list %s: %s", protocol, exc)
        return ServerList(protocol)


def load(protocol: str, cache: Path | None = None) -> ServerList:
    """The list the drop-down offers: the cached refresh when it is readable
    and has entries, else the bundled snapshot."""
    if protocol not in PROTOCOLS:
        return ServerList(protocol)
    path = (cache or cache_dir()) / f"{protocol}.json"
    if path.exists():
        try:
            cached = _read_file(path, protocol, "cache")
            if cached.entries:
                return cached
        except ServerListError as exc:
            log.info("Chat server cache %s ignored: %s", protocol, exc)
    return bundled(protocol)


def save_cache(server_list: ServerList, cache: Path | None = None) -> Path:
    folder = cache or cache_dir()
    os.makedirs(folder, mode=0o700, exist_ok=True)
    path = folder / f"{server_list.protocol}.json"
    tmp = path.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(list_data(server_list), indent=1, ensure_ascii=False) + "\n", encoding="utf-8")
    os.replace(tmp, path)
    return path


# --- fetching ------------------------------------------------------------------------------

def _user_agent() -> str:
    from axross._version import __version__

    return f"axross/{__version__} (chat server list)"


def default_opener(host: str):
    """urllib's opener for *host*: axross's default proxy (Settings > Network
    & Proxy) when one applies, else the environment's; no redirects. A
    default proxy that cannot be used fails closed."""
    from core import proxy_settings as PS
    from core.agent_net import opener_without_redirects

    try:
        resolution = PS.resolve("default", None, host, 443, "https")
    except (PS.ProxyResolutionError, OSError, ValueError) as exc:
        raise ServerListError(f"the default proxy cannot be used: {exc}") from None
    if resolution.config is None:
        handler = urllib.request.ProxyHandler() if resolution.source == "default-none" \
            else urllib.request.ProxyHandler({})
        return opener_without_redirects(handler)
    from core.proxy import build_requests_proxies, effective_http_proxy

    try:
        cfg = effective_http_proxy(resolution.config)
        proxies = build_requests_proxies(cfg.proxy_type, cfg.host, cfg.port, cfg.username, cfg.password)
    except (OSError, ValueError) as exc:
        raise ServerListError(f"the default proxy cannot be used: {exc}") from None
    return opener_without_redirects(urllib.request.ProxyHandler({"https": proxies["https"],
                                                                 "http": proxies["http"]}))


def http_get(url: str, *, opener=None, timeout: float = FETCH_TIMEOUT, max_bytes: int = MAX_DOWNLOAD) -> bytes:
    """The body at *url* (https only): the whole answer within *timeout*,
    at most *max_bytes*."""
    parts = urllib.parse.urlsplit(url)
    host = parts.hostname or "?"
    if parts.scheme != "https":
        raise ServerListError(f"only https:// directories are read, not {url[:100]!r}")
    opener = opener if opener is not None else default_opener(host)
    request = urllib.request.Request(url, headers={"User-Agent": _user_agent(),
                                                   "Accept": "application/json, text/plain"})
    deadline = time.monotonic() + timeout
    body = bytearray()
    try:
        with opener.open(request, timeout=timeout) as response:
            reader = getattr(response, "read1", None) or response.read
            while True:
                if time.monotonic() > deadline:
                    raise ServerListError(f"{host} sent no complete answer within {timeout:g} s")
                chunk = reader(65536)
                if not chunk:
                    break
                body += chunk
                if len(body) > max_bytes:
                    raise ServerListError(f"{host}'s answer is larger than {max_bytes // 1024} KiB")
    except urllib.error.HTTPError as exc:
        raise ServerListError(f"{host} answered HTTP {exc.code}") from None
    except (urllib.error.URLError, OSError) as exc:
        raise ServerListError(f"cannot reach {host}: {getattr(exc, 'reason', exc)}") from None
    return bytes(body)


def refresh(protocol: str, *, get: Callable[[str], bytes] | None = None, cache: Path | None = None,
            today: str | None = None) -> ServerList:
    """Fetch *protocol*'s directories (:data:`DIRECTORIES`), the first that
    gives entries wins; the list is cached and returned. Raises
    ServerListError with every directory's problem when none worked - the
    cache is then left as it was. *get(url)* is for tests (no network)."""
    if protocol not in DIRECTORIES:
        raise ServerListError(f"no directory is known for {protocol}")
    get = get or http_get
    problems = []
    for url, parser in DIRECTORIES[protocol]:
        host = urllib.parse.urlsplit(url).hostname or url
        try:
            entries = PARSERS[parser](get(url), url)
        except ServerListError as exc:
            problems.append(f"{host}: {exc}")
            continue
        except Exception as exc:  # noqa: BLE001 - a hostile answer must not crash the refresh
            log.warning("Chat server list %s from %s: %s", protocol, host, exc, exc_info=True)
            problems.append(f"{host}: unreadable answer")
            continue
        if not entries:
            problems.append(f"{host}: no usable server in the answer")
            continue
        server_list = ServerList(protocol, entries, today or time.strftime("%Y-%m-%d"), "fetched", (url,))
        try:
            save_cache(server_list, cache)
        except OSError as exc:
            log.warning("Chat server list %s not cached: %s", protocol, exc)
        log.info("Chat server list %s: %d entries from %s", protocol, len(entries), host)
        return server_list
    raise ServerListError("; ".join(problems) or "nothing fetched")
