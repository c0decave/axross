"""Where MCP servers are found: catalogs and registries the user searches.

Agent Settings > MCP Servers > Add from Catalog… searches the *sources*
switched on in Agent Settings > MCP Sources (core.agent_settings
``mcp_sources``):

==============  ==========================================================
``builtin``     the shipped catalog, ``resources/mcp/catalog.json``:
                images of Docker's curated ``mcp/*`` namespace, pinned
                by digest - works offline
``dockerhub``   Docker Hub's curated ``mcp`` namespace, searched live
                (``hub.docker.com/v2/repositories/mcp/?name=``)
``mcpregistry`` the official MCP Registry
                (``registry.modelcontextprotocol.io/v0.1/servers``)
``c0decave``    the c0decave MCP Hub (:data:`HUB_URL`), a catalog of the
                shipped schema that may only name images under
                ``ghcr.io/c0decave/`` pinned by digest
``discover``    curated awesome-lists for browsing (core.mcp_discover):
                installable only where the MCP Registry or Docker Hub
                names the same repository, else "link only"
``file:PATH``   a catalog file of the user's (same schema as the shipped
``url:URL``     one), local or over https
==============  ==========================================================

What a source answers is **untrusted data**: every answer is size-bounded
and read within a deadline, JSON only (nothing is executed), every text is
cleaned of control and bidi characters and cut, URLs are http(s) only,
package names, versions and image references must match strict patterns
(none may start with ``-``, so none can become an option of podman, npm or
pip), and a registry's *runtime arguments* are never used. Nothing here
starts a program: core.mcp_install pulls, builds and runs, in podman.

A catalog file::

    {"schema": "axross-mcp-catalog", "version": 1, "title": "...",
     "entries": [{"id": "time", "name": "time", "title": "Time",
                  "description": "...", "category": "Knowledge & Reasoning",
                  "tags": ["time"], "repository": "https://...", "license": "MIT",
                  "kind": "oci", "image": "docker.io/mcp/time", "tag": "latest",
                  "digest": "sha256:<64 hex>",           # required for oci
                  "args": ["--flag"],                   # after the image
                  "env": [{"name": "API_KEY", "description": "...",
                           "secret": true, "required": true, "default": ""}],
                  "mounts": [{"target": "/data", "description": "...",
                              "required": false, "repeat": false}],
                  "network": "none",                    # none, allowlist or full
                  "hosts": ["api.example.com:443"]},    # for allowlist
                 {"kind": "npm", "package": "@scope/name", "version": "1.2.3", ...},
                 {"kind": "pypi", "package": "name", "version": "1.2.3", ...},
                 {"kind": "remote", "url": "https://mcp.example/mcp", "bearer": true, ...}]}

``network`` and ``hosts`` say what the server needs; the user still
chooses at install, and the default is no network.
"""

from __future__ import annotations

import dataclasses
import json
import logging
import re
import threading
import time
import unicodedata
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

log = logging.getLogger(__name__)

SCHEMA = "axross-mcp-catalog"
VERSION = 1
#: A catalog file larger than this is refused.
MAX_CATALOG_BYTES = 1 << 20
#: A registry answer larger than this is refused.
MAX_ANSWER_BYTES = 4 << 20
#: A Docker Hub README is cut to this before it is searched for details.
MAX_README_BYTES = 256 << 10
MAX_ENTRIES = 500
MAX_DESCRIPTION = 2000
MAX_SHORT = 200
MAX_ARGS = 32
MAX_ENV = 32
MAX_MOUNTS = 8
MAX_TAGS = 16
MAX_HOSTS = 16
MAX_EXTRA_SOURCES = 16
#: Seconds for a whole answer of a source (not per read).
REQUEST_TIMEOUT = 20.0
#: What axross can install and run.
KINDS = ("oci", "npm", "pypi", "remote")
NETWORKS = ("none", "allowlist", "full")

DOCKER_HUB = "https://hub.docker.com"
DOCKER_HUB_NAMESPACE = "mcp"
MCP_REGISTRY = "https://registry.modelcontextprotocol.io"
#: The c0decave MCP Hub: a catalog of this module's schema.
HUB_URL = "https://raw.githubusercontent.com/c0decave/axross-mcp-hub/main/catalog.json"
#: The only images the hub may name (normalized, with the trailing "/").
HUB_IMAGE_PREFIX = "ghcr.io/c0decave/"
NPM_REGISTRY = "https://registry.npmjs.org"
PYPI = "https://pypi.org"

_SERVER_NAME = re.compile(r"^[A-Za-z0-9_-]{1,32}$")
_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/@:+-]{0,199}$")
# An image without tag or digest: [registry[:port]/]path, lower case.
_IMAGE = re.compile(
    r"^[a-z0-9]+(?:[.-][a-z0-9]+)*(?::[0-9]{1,5})?"
    r"(?:/[a-z0-9]+(?:(?:[._]|__|-+)[a-z0-9]+)*)+$"
)
# Without a registry (docker.io implied): name or user/name.
_IMAGE_SHORT = re.compile(
    r"^[a-z0-9]+(?:(?:[._]|__|-+)[a-z0-9]+)*(?:/[a-z0-9]+(?:(?:[._]|__|-+)[a-z0-9]+)*)*$"
)
_TAG = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}$")
_DIGEST = re.compile(r"^sha256:[a-f0-9]{64}$")
_NPM = re.compile(r"^(?:@[a-z0-9][a-z0-9._~-]*/)?[a-z0-9][a-z0-9._~-]*$")
_PYPI = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?$")
_SEMVER = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$")
_PEP440 = re.compile(
    r"^[0-9]+(?:\.[0-9]+)*(?:(?:a|b|rc)[0-9]+)?(?:\.post[0-9]+)?(?:\.dev[0-9]+)?$"
)
_ENV_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,63}$")
_TARGET = re.compile(r"^/(?:[A-Za-z0-9._-]+|\{name\})(?:/(?:[A-Za-z0-9._-]+|\{name\}))*$")
_HUB_REPO = re.compile(r"^[a-z0-9][a-z0-9._-]{0,127}$")
_DATE = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}")
_IMAGE_MEDIA_TYPES = frozenset({
    "application/vnd.oci.image.index.v1+json",
    "application/vnd.oci.image.manifest.v1+json",
    "application/vnd.docker.distribution.manifest.list.v2+json",
    "application/vnd.docker.distribution.manifest.v2+json",
})


class CatalogError(ValueError):
    """A catalog or a source's answer cannot be used; the text says why."""


class _EntryError(ValueError):
    pass


# -- text --------------------------------------------------------------------------------


def clean_text(value, limit: int = MAX_SHORT, *, lines: bool = False) -> str:
    """*value* as text to show: control, format (bidi, zero-width) and
    other invisible characters removed, whitespace runs folded (line breaks
    kept with *lines*), cut to *limit* characters."""
    if not isinstance(value, str):
        return ""
    out = []
    for ch in value[: limit * 4]:
        if ch == "\n" and lines:
            out.append("\n")
        elif ch in "\t\r\n" or ch.isspace():
            out.append(" ")
        elif unicodedata.category(ch) in ("Cc", "Cf", "Cs", "Co", "Cn"):
            continue
        else:
            out.append(ch)
    text = "".join(out)
    if lines:
        text = "\n".join(re.sub(r" {2,}", " ", line).strip() for line in text.split("\n"))
        text = re.sub(r"\n{3,}", "\n\n", text).strip()
    else:
        text = re.sub(r" {2,}", " ", text).strip()
    return text[:limit]


def exact_text(value, limit: int = MAX_SHORT) -> str:
    """*value* (stripped) when it is one line of text that :func:`clean_text`
    leaves as it is and at most *limit* long, else "" - for names read from
    a file that must not be changed silently (a category, a profile name)."""
    if not isinstance(value, str) or len(value.strip()) > limit:
        return ""
    text = clean_text(value, limit)
    return text if text == value.strip() else ""


def clean_url(value, *, limit: int = 500) -> str:
    """An http(s) URL to show, or "" for anything else."""
    if not isinstance(value, str) or len(value) > limit:
        return ""
    if any(ch.isspace() or unicodedata.category(ch) in ("Cc", "Cf") for ch in value):
        return ""
    try:
        parts = urllib.parse.urlsplit(value)
    except ValueError:
        return ""
    if parts.scheme not in ("http", "https") or not parts.hostname:
        return ""
    return value


def server_name(text: str) -> str:
    """A valid MCP server name (core.mcp_client) made of *text*: the part
    after the last "/", other characters as "-", at most 32."""
    tail = str(text or "").rsplit("/", 1)[-1]
    name = re.sub(r"[^A-Za-z0-9_-]+", "-", tail).strip("-_")[:32].strip("-_")
    return name or "server"


def normalize_image(ref: str) -> str:
    """``name`` -> ``docker.io/library/name``, ``user/name`` ->
    ``docker.io/user/name``; a reference with a registry stays."""
    first = ref.split("/", 1)[0]
    if "/" in ref and ("." in first or ":" in first or first == "localhost"):
        return ref
    return f"docker.io/{ref}" if "/" in ref else f"docker.io/library/{ref}"


def split_image(ref: str) -> tuple[str, str, str]:
    """``(image, tag, digest)`` of a reference ``image[:tag][@sha256:...]``,
    the image normalized; ValueError if it is not a valid reference."""
    if not isinstance(ref, str) or not ref or ref.startswith("-") or len(ref) > 400:
        raise ValueError("not an image reference")
    name, _, digest = ref.partition("@")
    tag = ""
    slash = name.rfind("/")
    colon = name.rfind(":")
    if colon > slash:
        name, tag = name[:colon], name[colon + 1 :]
    if digest and not _DIGEST.match(digest):
        raise ValueError("not a sha256 digest")
    if tag and not _TAG.match(tag):
        raise ValueError("not a valid tag")
    if not (_IMAGE.match(name) or _IMAGE_SHORT.match(name)):
        raise ValueError("not a valid image name")
    name = normalize_image(name)
    if not _IMAGE.match(name) or len(name) > 255:
        raise ValueError("not a valid image name")
    return name, tag, digest


# -- entries -----------------------------------------------------------------------------


@dataclass(frozen=True)
class EnvSpec:
    name: str
    description: str = ""
    secret: bool = False
    required: bool = False
    default: str = ""


@dataclass(frozen=True)
class MountSpec:
    #: Where the folder appears in the container; ``{name}`` is replaced by
    #: the chosen folder's name.
    target: str
    description: str = ""
    required: bool = False
    #: Several folders may be chosen (each at its own ``{name}``).
    repeat: bool = False


@dataclass(frozen=True)
class CatalogEntry:
    id: str
    name: str
    title: str = ""
    description: str = ""
    category: str = ""
    tags: tuple[str, ...] = ()
    source: str = ""
    repository: str = ""
    #: The entry's page at its source (Docker Hub, the server's website).
    page: str = ""
    license: str = ""
    updated: str = ""
    kind: str = "oci"
    #: oci: the image (normalized, no tag); npm / pypi: the package name.
    identifier: str = ""
    tag: str = ""
    digest: str = ""
    version: str = ""
    args: tuple[str, ...] = ()
    env: tuple[EnvSpec, ...] = ()
    mounts: tuple[MountSpec, ...] = ()
    #: What the server needs: none, allowlist (hosts) or full.
    network: str = "none"
    hosts: tuple[str, ...] = ()
    #: remote: the Streamable HTTP endpoint and whether it wants a token.
    url: str = ""
    bearer: bool = False
    #: Why the entry cannot be installed ("" = it can).
    why_not: str = ""
    #: What the user should know (arguments that need a value, ...).
    notes: str = ""
    #: Who maintains the server when it is not axross's own (a third party):
    #: the catalog dialog says so, and that problems go upstream.
    maintainer: str = ""
    #: Discover (core.mcp_discover): the source that makes the entry
    #: installable ("" = none), the lists that name it, and the state of the
    #: cross-reference: "unchecked", "link", "mcpregistry" or "dockerhub".
    via: str = ""
    listed_in: str = ""
    xref: str = ""

    @property
    def installable(self) -> bool:
        return not self.why_not

    @property
    def image_ref(self) -> str:
        """oci: ``image@digest`` when pinned, else ``image:tag``."""
        if self.digest:
            return f"{self.identifier}@{self.digest}"
        return f"{self.identifier}:{self.tag or 'latest'}"

    @property
    def package_ref(self) -> str:
        """What the entry runs, as text: an image, ``npm name@version``, an URL."""
        if self.kind == "oci":
            return self.image_ref
        if self.kind in ("npm", "pypi"):
            return f"{self.kind} {self.identifier}=={self.version}" if self.kind == "pypi" \
                else f"npm {self.identifier}@{self.version}"
        return self.url or self.identifier

    def matches(self, query: str = "", *, category: str | None = None,
                tag: str | None = None) -> bool:
        """Every word of *query* in the entry's texts, and the category and
        tag when given (case-insensitive)."""
        if category and self.category.lower() != category.lower():
            return False
        if tag and tag.lower() not in (t.lower() for t in self.tags):
            return False
        hay = " ".join((self.name, self.title, self.description, self.category, self.identifier,
                        " ".join(self.tags))).lower()
        return all(word in hay for word in str(query or "").lower().split())


def _str(raw: dict, key: str, limit: int = MAX_SHORT, *, lines: bool = False) -> str:
    return clean_text(raw.get(key), limit, lines=lines)


def _bool(raw: dict, key: str) -> bool:
    return raw.get(key) is True


def _value(text, what: str) -> str:
    """An argument or environment value: one line, no NUL, bounded."""
    if not isinstance(text, str) or len(text) > 1000 or any(c in text for c in "\n\r\x00"):
        raise _EntryError(what)
    return text


def _env_specs(raw) -> tuple[EnvSpec, ...]:
    if raw is None:
        return ()
    if not isinstance(raw, list) or len(raw) > MAX_ENV:
        raise _EntryError("environment: a list of at most %d variables" % MAX_ENV)
    out: list[EnvSpec] = []
    for item in raw:
        if not isinstance(item, dict) or not _ENV_NAME.match(str(item.get("name") or "")):
            raise _EntryError("environment: a variable needs a name of letters, digits and _")
        default = item.get("default", "")
        try:
            default = _value(default if default is not None else "", "")
        except _EntryError:
            raise _EntryError(f"environment: {item['name']} has a multi-line default") from None
        if item["name"] in (s.name for s in out):
            continue
        out.append(EnvSpec(item["name"], _str(item, "description", 500), _bool(item, "secret"),
                           _bool(item, "required"), default))
    return tuple(out)


def _mount_specs(raw) -> tuple[MountSpec, ...]:
    if raw is None:
        return ()
    if not isinstance(raw, list) or len(raw) > MAX_MOUNTS:
        raise _EntryError("mounts: a list of at most %d folders" % MAX_MOUNTS)
    out: list[MountSpec] = []
    for item in raw:
        target = item.get("target") if isinstance(item, dict) else None
        if (
            not isinstance(target, str) or len(target) > 200 or not _TARGET.match(target)
            or any(part in (".", "..") for part in target.split("/"))
        ):
            raise _EntryError("mount: a target needs an absolute path of letters, digits, . _ -")
        if target in (m.target for m in out):
            continue
        out.append(MountSpec(target, _str(item, "description", 500), _bool(item, "required"),
                             _bool(item, "repeat")))
    return tuple(out)


def _args(raw) -> tuple[str, ...]:
    if raw is None:
        return ()
    if not isinstance(raw, list) or len(raw) > MAX_ARGS:
        raise _EntryError("arguments: a list of at most %d texts" % MAX_ARGS)
    out = []
    for item in raw:
        try:
            out.append(_value(item, ""))
        except _EntryError:
            raise _EntryError("arguments: each one a single-line text") from None
    return tuple(out)


def _hosts(raw) -> tuple[str, ...]:
    from core.agent_net import parse_host

    if raw is None:
        return ()
    if not isinstance(raw, list) or len(raw) > MAX_HOSTS:
        raise _EntryError("hosts: a list of at most %d host:port entries" % MAX_HOSTS)
    out = []
    for item in raw:
        try:
            host, port = parse_host(item if isinstance(item, str) else "")
        except ValueError as exc:
            raise _EntryError(f"host: {exc}") from None
        entry = f"[{host}]:{port}" if ":" in host else f"{host}:{port}"
        if entry not in out:
            out.append(entry)
    return tuple(out)


def _tags(raw) -> tuple[str, ...]:
    if not isinstance(raw, list):
        return ()
    out = []
    for item in raw[:MAX_TAGS]:
        tag = clean_text(item, 40)
        if tag and tag not in out:
            out.append(tag)
    return tuple(out)


def _version(kind: str, value) -> str:
    pattern = _SEMVER if kind == "npm" else _PEP440
    if not isinstance(value, str) or len(value) > 64 or not pattern.match(value):
        raise _EntryError(f"version: an exact {kind} version (no range)")
    return value


def parse_entry(raw, *, source: str, require_digest: bool = True) -> CatalogEntry:
    """One entry of a catalog file; _EntryError (the reason) if it is unusable."""
    if not isinstance(raw, dict):
        raise _EntryError("not an object")
    name = raw.get("name")
    if not isinstance(name, str) or not _SERVER_NAME.match(name):
        raise _EntryError("name: 1-32 letters, digits, '-' or '_'")
    entry_id = raw.get("id", name)
    if not isinstance(entry_id, str) or not _ID.match(entry_id):
        raise _EntryError("id: letters, digits and . _ / @ : + -")
    kind = raw.get("kind")
    if kind not in KINDS:
        raise _EntryError(f"kind: one of {', '.join(KINDS)}")
    network = raw.get("network", "none")
    if network not in NETWORKS:
        raise _EntryError(f"network: one of {', '.join(NETWORKS)}")
    hosts = _hosts(raw.get("hosts"))
    values = dict(
        id=entry_id, name=name, title=_str(raw, "title") or name,
        description=_str(raw, "description", MAX_DESCRIPTION, lines=True),
        category=_str(raw, "category", 60) or "Other", tags=_tags(raw.get("tags")),
        source=source, repository=clean_url(raw.get("repository")),
        page=clean_url(raw.get("page")), license=_str(raw, "license"),
        updated=_str(raw, "updated", 10) if _DATE.match(str(raw.get("updated") or "")) else "",
        kind=kind, args=_args(raw.get("args")), env=_env_specs(raw.get("env")),
        mounts=_mount_specs(raw.get("mounts")), network=network, hosts=hosts,
        notes=_str(raw, "notes", MAX_DESCRIPTION, lines=True),
        maintainer=_str(raw, "maintainer"),
    )
    if kind == "oci":
        image = raw.get("image")
        try:
            identifier, tag, digest = split_image(image if isinstance(image, str) else "")
        except ValueError as exc:
            raise _EntryError(f"image: {exc}") from None
        tag = raw.get("tag", tag or "latest")
        digest = raw.get("digest", digest)
        if not isinstance(tag, str) or not _TAG.match(tag):
            raise _EntryError("tag: letters, digits, . _ -")
        if digest or require_digest:
            if not isinstance(digest, str) or not _DIGEST.match(digest):
                raise _EntryError("digest: sha256:<64 hex digits> (an image is pinned)")
        values.update(identifier=identifier, tag=tag, digest=digest or "")
    elif kind in ("npm", "pypi"):
        package = raw.get("package")
        pattern, limit = (_NPM, 214) if kind == "npm" else (_PYPI, 100)
        if not isinstance(package, str) or len(package) > limit or not pattern.match(package):
            raise _EntryError(f"package: a {kind} package name")
        values.update(identifier=package, version=_version(kind, raw.get("version")))
    else:
        url = clean_url(raw.get("url"))
        if not url.startswith("https://"):
            raise _EntryError("url: an https:// endpoint")
        values.update(url=url, bearer=_bool(raw, "bearer"), network="full")
    return CatalogEntry(**values)


def parse_catalog(data, *, source: str,
                  require_digest: bool = True) -> tuple[list[CatalogEntry], list[str]]:
    """The entries of a catalog and one warning per entry skipped.
    CatalogError when the catalog as a whole is unusable."""
    if not isinstance(data, dict):
        raise CatalogError("a catalog is an object")
    if data.get("schema") != SCHEMA:
        raise CatalogError(f"not an axross MCP catalog (schema must be {SCHEMA!r})")
    if data.get("version") != VERSION:
        raise CatalogError(f"catalog version {data.get('version')!r}; this axross reads {VERSION}")
    raw_entries = data.get("entries")
    if not isinstance(raw_entries, list):
        raise CatalogError("entries: a list")
    if len(raw_entries) > MAX_ENTRIES:
        raise CatalogError(f"entries: at most {MAX_ENTRIES}, the catalog has {len(raw_entries)}")
    entries: list[CatalogEntry] = []
    warnings: list[str] = []
    seen: set[str] = set()
    for index, raw in enumerate(raw_entries, 1):
        label = clean_text(raw.get("id") or raw.get("name"), 40) if isinstance(raw, dict) else ""
        try:
            entry = parse_entry(raw, source=source, require_digest=require_digest)
        except _EntryError as exc:
            warnings.append(f"entry {index} ({label or '?'}): {exc}")
            continue
        if entry.id in seen:
            warnings.append(f"entry {index} ({label}): its id is there twice - the first is kept")
            continue
        seen.add(entry.id)
        entries.append(entry)
    return entries, warnings


def load_json(raw: bytes, what: str = "the catalog"):
    try:
        return json.loads(raw.decode("utf-8"))
    except RecursionError:
        raise CatalogError(f"{what} is not usable JSON (nested too deep)") from None
    except (UnicodeDecodeError, ValueError):
        raise CatalogError(f"{what} is not valid JSON") from None


def load_catalog_file(path, *, source: str) -> tuple[list[CatalogEntry], list[str]]:
    """A catalog file, read with its size bounded first."""
    path = Path(path)
    try:
        with open(path, "rb") as handle:
            raw = handle.read(MAX_CATALOG_BYTES + 1)
    except OSError as exc:
        raise CatalogError(f"cannot read {path}: {exc.strerror or exc}") from None
    if len(raw) > MAX_CATALOG_BYTES:
        raise CatalogError(f"{path.name} is larger than {MAX_CATALOG_BYTES // 1024} KiB")
    return parse_catalog(load_json(raw, path.name), source=source)


def builtin_path() -> Path:
    return Path(__file__).resolve().parent.parent / "resources" / "mcp" / "catalog.json"


def load_builtin() -> tuple[list[CatalogEntry], list[str]]:
    return load_catalog_file(builtin_path(), source="builtin")


# -- http --------------------------------------------------------------------------------


def _user_agent() -> str:
    from axross._version import __version__

    return f"axross/{__version__} (MCP catalog)"


def default_opener(abort=None):
    """urllib's opener that never follows a redirect; *abort* (an
    core.agent_net.AbortableConnections) can cut its connections."""
    from core.agent_net import opener_without_redirects

    return opener_without_redirects(*(abort.handlers() if abort is not None else ()))


def http_get(url: str, *, opener=None, timeout: float = REQUEST_TIMEOUT,
             max_bytes: int = MAX_ANSWER_BYTES, allow_http: bool = False,
             cancel: threading.Event | None = None, accept: str = "application/json") -> bytes:
    """The body at *url*: https only (http with *allow_http*, for tests),
    no redirects, the whole answer within *timeout*, at most *max_bytes*."""
    parts = urllib.parse.urlsplit(url)
    if parts.scheme != "https" and not (allow_http and parts.scheme == "http"):
        raise CatalogError(f"only https:// sources are read, not {parts.scheme or url!r}")
    host = parts.hostname or "?"
    request = urllib.request.Request(url, headers={"Accept": accept,
                                                   "User-Agent": _user_agent()})
    opener = opener if opener is not None else default_opener()
    deadline = time.monotonic() + timeout
    body = b""
    try:
        with opener.open(request, timeout=timeout) as response:
            reader = getattr(response, "read1", None) or response.read
            while True:
                if cancel is not None and cancel.is_set():
                    raise CatalogError("cancelled")
                if time.monotonic() > deadline:
                    raise CatalogError(f"{host} sent no complete answer within {timeout:g} s")
                chunk = reader(65536)
                if not chunk:
                    break
                body += chunk
                if len(body) > max_bytes:
                    raise CatalogError(f"{host}'s answer is larger than {max_bytes // 1024} KiB")
    except urllib.error.HTTPError as exc:
        raise CatalogError(f"{host} answered HTTP {exc.code}") from None
    except (urllib.error.URLError, OSError) as exc:
        if time.monotonic() > deadline:
            raise CatalogError(f"{host} sent no complete answer within {timeout:g} s") from None
        if cancel is not None and cancel.is_set():
            raise CatalogError("cancelled") from None
        raise CatalogError(f"cannot reach {host}: {getattr(exc, 'reason', exc)}") from None
    return body


def http_get_json(url: str, **kwargs):
    host = urllib.parse.urlsplit(url).hostname or "the source"
    return load_json(http_get(url, **kwargs), f"{host}'s answer")


# -- sources -----------------------------------------------------------------------------


@dataclass
class SearchResult:
    source: str
    title: str
    entries: list[CatalogEntry] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    #: Why the source gave nothing ("" = it answered).
    error: str = ""
    #: What the user should know of the answer (an offline copy is shown, ...).
    notes: list[str] = field(default_factory=list)


class Source:
    """A place to search. *opener* is urllib's (tests pass a fake)."""

    id = ""
    title = ""

    def __init__(self, *, opener=None) -> None:
        self._opener = opener

    def _get_json(self, url: str, cancel=None, **kwargs):
        return http_get_json(url, opener=self._opener, cancel=cancel, **kwargs)

    def search(self, query: str = "", *, cancel: threading.Event | None = None) -> SearchResult:
        result = SearchResult(self.id, self.title)
        try:
            result.entries, result.warnings = self._search(query, cancel)
        except CatalogError as exc:
            result.error = str(exc)
        return result

    def _search(self, query, cancel) -> tuple[list[CatalogEntry], list[str]]:
        raise NotImplementedError

    def details(self, entry: CatalogEntry) -> CatalogEntry:
        """The entry with what a second request tells (README facts)."""
        return entry

    def resolve(self, entry: CatalogEntry) -> CatalogEntry:
        """The entry pinned for an install (an image's digest), as far as
        this source can; CatalogError when it cannot."""
        return entry


class BuiltinSource(Source):
    id = "builtin"
    title = "Built-in catalog"

    def _search(self, query, cancel):
        entries, warnings = load_builtin()
        return [e for e in entries if e.matches(query)], warnings


class FileSource(Source):
    def __init__(self, path: str, **kwargs) -> None:
        super().__init__(**kwargs)
        self.path = path
        self.id = f"file:{path}"
        self.title = Path(path).name

    def _search(self, query, cancel):
        entries, warnings = load_catalog_file(self.path, source=self.id)
        return [e for e in entries if e.matches(query)], warnings


class UrlSource(Source):
    def __init__(self, url: str, **kwargs) -> None:
        super().__init__(**kwargs)
        self.url = url
        self.id = f"url:{url}"
        self.title = urllib.parse.urlsplit(url).hostname or url

    def _search(self, query, cancel):
        raw = http_get(self.url, opener=self._opener, cancel=cancel,
                       max_bytes=MAX_CATALOG_BYTES)
        entries, warnings = parse_catalog(load_json(raw, self.title), source=self.id)
        return [e for e in entries if e.matches(query)], warnings


class HubSource(Source):
    """The c0decave MCP Hub: a catalog of the shipped schema at
    :data:`HUB_URL`, read like a user's catalog URL, of which only oci
    entries pinned by digest under :data:`HUB_IMAGE_PREFIX` are kept."""

    id = "c0decave"
    title = "c0decave MCP Hub"

    def __init__(self, url: str = HUB_URL, *, opener=None, allow_http: bool = False) -> None:
        super().__init__(opener=opener)
        self.url = url
        self._allow_http = allow_http

    def _search(self, query, cancel):
        try:
            raw = http_get(self.url, opener=self._opener, cancel=cancel,
                           max_bytes=MAX_CATALOG_BYTES, allow_http=self._allow_http)
        except CatalogError as exc:
            if str(exc) == "cancelled":
                raise
            raise CatalogError(f"not reachable or not published yet ({exc})") from None
        data = load_json(raw, self.title)
        if (isinstance(data, dict) and isinstance(data.get("entries"), list)
                and len(data["entries"]) <= MAX_ENTRIES):
            # What is not a pinned image of ours is refused before the
            # entry is read at all (an npm or remote entry is not "fixed" by
            # require_digest, so it is named here).
            kept, refused = [], []
            for index, raw_entry in enumerate(data["entries"], 1):
                image = raw_entry.get("image") if isinstance(raw_entry, dict) else None
                try:
                    identifier = split_image(image)[0] if isinstance(image, str) else ""
                except ValueError:
                    identifier = ""
                if (isinstance(raw_entry, dict) and raw_entry.get("kind") == "oci"
                        and identifier.startswith(HUB_IMAGE_PREFIX)):
                    kept.append(raw_entry)
                else:
                    label = clean_text(raw_entry.get("id") or raw_entry.get("name"), 40) \
                        if isinstance(raw_entry, dict) else ""
                    refused.append(f"entry {index} ({label or '?'}): only images under "
                                   f"{HUB_IMAGE_PREFIX} pinned by digest are taken from "
                                   f"this source")
            data = dict(data, entries=kept)
        else:
            refused = []
        entries, warnings = parse_catalog(data, source=self.id, require_digest=True)
        return [e for e in entries if e.matches(query)], refused + warnings


class DockerHubSource(Source):
    """Docker Hub's curated namespace (``mcp``). Anonymous listing answers
    one page of up to 100 repositories per query."""

    id = "dockerhub"
    title = "Docker Hub (mcp/*)"

    def __init__(self, *, base: str = DOCKER_HUB, namespace: str = DOCKER_HUB_NAMESPACE,
                 opener=None, allow_http: bool = False) -> None:
        super().__init__(opener=opener)
        self.base = base.rstrip("/")
        self.namespace = namespace
        self._allow_http = allow_http

    def _search(self, query, cancel):
        params = {"page_size": "100", "ordering": "pull_count"}
        if query.strip():
            params["name"] = query.strip()[:100]
        url = f"{self.base}/v2/repositories/{self.namespace}/?{urllib.parse.urlencode(params)}"
        data = self._get_json(url, cancel, allow_http=self._allow_http)
        results = data.get("results") if isinstance(data, dict) else None
        if not isinstance(results, list):
            raise CatalogError("Docker Hub's answer has no results")
        entries: list[CatalogEntry] = []
        for raw in results[:200]:
            entry = self._entry(raw)
            if entry is not None:
                entries.append(entry)
        return entries, []

    def _entry(self, raw) -> CatalogEntry | None:
        if not isinstance(raw, dict) or not _HUB_REPO.match(str(raw.get("name") or "")):
            return None
        if raw.get("is_private") is True:
            return None
        media = raw.get("media_types")
        if isinstance(media, list) and media and not _IMAGE_MEDIA_TYPES.intersection(media):
            return None  # signatures, catalogs: not a server image
        name = raw["name"]
        categories = raw.get("categories")
        category = ""
        if isinstance(categories, list) and categories and isinstance(categories[0], dict):
            category = clean_text(categories[0].get("name"), 60)
        updated = str(raw.get("last_updated") or "")
        return CatalogEntry(
            id=f"dockerhub:{self.namespace}/{name}", name=server_name(name), title=name,
            description=clean_text(raw.get("description"), MAX_DESCRIPTION, lines=True),
            category=category or "Docker Hub", source=self.id,
            page=f"https://hub.docker.com/r/{self.namespace}/{name}",
            updated=updated[:10] if _DATE.match(updated) else "", kind="oci",
            identifier=f"docker.io/{self.namespace}/{name}", tag="latest",
            notes="Docker Hub does not say whether this server needs network or folders: "
                  "choose them at install.",
        )

    def _repo(self, entry: CatalogEntry) -> str:
        return entry.identifier.rsplit("/", 1)[-1]

    def details(self, entry: CatalogEntry) -> CatalogEntry:
        url = f"{self.base}/v2/repositories/{self.namespace}/{self._repo(entry)}/"
        try:
            data = self._get_json(url, allow_http=self._allow_http)
        except CatalogError as exc:
            log.info("mcp catalog: no Docker Hub details for %s: %s", entry.id, exc)
            return entry
        readme = data.get("full_description") if isinstance(data, dict) else None
        if not isinstance(readme, str):
            return entry
        readme = readme[:MAX_README_BYTES]
        repo = re.search(r"\*\*Repository\*\*\s*\|\s*([^\s|]+)", readme)
        lic = re.search(r"\*\*Licen[cs]e\*\*\s*\|\s*([^\n|]+)", readme)
        return dataclasses.replace(
            entry,
            repository=clean_url(repo.group(1)) if repo else entry.repository,
            license=clean_text(lic.group(1), MAX_SHORT) if lic else entry.license,
        )

    def resolve(self, entry: CatalogEntry) -> CatalogEntry:
        """The digest the tag points at now (Docker Hub's tag API)."""
        if entry.digest:
            return entry
        url = (f"{self.base}/v2/repositories/{self.namespace}/{self._repo(entry)}/tags/"
               f"{urllib.parse.quote(entry.tag or 'latest')}")
        data = self._get_json(url, allow_http=self._allow_http)
        digest = data.get("digest") if isinstance(data, dict) else None
        if not isinstance(digest, str) or not _DIGEST.match(digest):
            raise CatalogError(f"Docker Hub names no digest for {entry.image_ref}")
        return dataclasses.replace(entry, digest=digest)


_OFFICIAL = "io.modelcontextprotocol.registry/official"


class McpRegistrySource(Source):
    """The official MCP Registry, ``/v0.1/servers`` with ``search``,
    ``version=latest`` and cursor pages (at most *max_pages*)."""

    id = "mcpregistry"
    title = "MCP Registry"

    def __init__(self, *, base: str = MCP_REGISTRY, opener=None, max_pages: int = 3,
                 allow_http: bool = False) -> None:
        super().__init__(opener=opener)
        self.base = base.rstrip("/")
        self.max_pages = max(1, int(max_pages))
        self._allow_http = allow_http

    def _search(self, query, cancel):
        entries: list[CatalogEntry] = []
        seen: set[str] = set()
        cursor = ""
        for _page in range(self.max_pages):
            params = {"limit": "100", "version": "latest"}
            if query.strip():
                params["search"] = query.strip()[:100]
            if cursor:
                params["cursor"] = cursor
            url = f"{self.base}/v0.1/servers?{urllib.parse.urlencode(params)}"
            data = self._get_json(url, cancel, allow_http=self._allow_http)
            if not isinstance(data, dict) or not isinstance(data.get("servers"), list):
                raise CatalogError("the MCP Registry's answer has no servers")
            for item in data["servers"][:200]:
                entry = entry_from_registry(item)
                if entry is not None and entry.id not in seen:
                    seen.add(entry.id)
                    entries.append(entry)
            meta = data.get("metadata") if isinstance(data.get("metadata"), dict) else {}
            cursor = meta.get("nextCursor") if isinstance(meta.get("nextCursor"), str) else ""
            if not cursor or len(cursor) > 500:
                break
            if cancel is not None and cancel.is_set():
                raise CatalogError("cancelled")
        return entries, []


def _package_entry(package: dict, values: dict) -> dict:
    """The kind-specific values of a registry package; why_not when it
    cannot be run."""
    kind = clean_text(package.get("registryType"), 20).lower() or "unknown"
    values["kind"] = kind
    transport = package.get("transport") if isinstance(package.get("transport"), dict) else {}
    ttype = transport.get("type", "stdio")
    if kind not in ("oci", "npm", "pypi"):
        values["why_not"] = f"package type {kind} is not supported (oci, npm and pypi are)"
        return values
    if ttype != "stdio":
        values["why_not"] = f"a {clean_text(ttype, 30)} package is not supported (stdio is)"
        return values
    identifier = package.get("identifier")
    base = package.get("registryBaseUrl")
    try:
        if kind == "oci":
            image, tag, digest = split_image(identifier if isinstance(identifier, str) else "")
            version = package.get("version")
            if not tag and isinstance(version, str) and _TAG.match(version):
                tag = version
            values.update(identifier=image, tag=tag or "latest", digest=digest)
        else:
            pattern, limit, home = ((_NPM, 214, NPM_REGISTRY) if kind == "npm"
                                    else (_PYPI, 100, PYPI))
            if base not in (None, "", home, home + "/"):
                values["why_not"] = (f"only the public {kind} registry ({home}) is used, "
                                     f"not {clean_text(base, 80)}")
                return values
            if (not isinstance(identifier, str) or len(identifier) > limit
                    or not pattern.match(identifier)):
                raise _EntryError(f"{kind} package name")
            values.update(identifier=identifier, version=_version(kind, package.get("version")))
    except (ValueError, _EntryError) as exc:
        values["why_not"] = f"the package is not usable: {exc}"
        return values
    notes: list[str] = []
    if package.get("runtimeArguments"):
        notes.append("The entry's runtime arguments are not used (axross runs it its own way).")
    args: list[str] = []
    raw_args = package.get("packageArguments")
    for arg in raw_args[:MAX_ARGS] if isinstance(raw_args, list) else ():
        if not isinstance(arg, dict):
            continue
        value = arg.get("value", arg.get("default"))
        name = arg.get("name") if arg.get("type") == "named" else None
        label = clean_text(name or arg.get("valueHint") or arg.get("description") or "?", 60)
        if name is not None and (not isinstance(name, str)
                                 or not re.match(r"^--?[A-Za-z0-9][A-Za-z0-9_-]*$", name)):
            notes.append(f"An argument with an odd name ({label}) is left out.")
            continue
        usable = (isinstance(value, str) and bool(value) and "{" not in value
                  and len(value) <= 1000 and not any(c in value for c in "\n\r\x00"))
        if usable:
            args.extend([name, value] if name else [value])
        elif value is not None or arg.get("isRequired") is True:
            notes.append(f"The argument {label} needs a value: add it at install.")
    env: list[EnvSpec] = []
    raw_env = package.get("environmentVariables")
    for var in raw_env[:MAX_ENV] if isinstance(raw_env, list) else ():
        if not isinstance(var, dict):
            continue
        name = var.get("name")
        if not isinstance(name, str) or not _ENV_NAME.match(name):
            notes.append(f"An environment variable with an odd name "
                         f"({clean_text(name, 40)}) is left out.")
            continue
        default = var.get("default", var.get("value", ""))
        if not isinstance(default, str) or "{" in default or any(c in default for c in "\n\r\x00"):
            default = ""
        if name not in (e.name for e in env):
            env.append(EnvSpec(name, clean_text(var.get("description"), 500),
                               var.get("isSecret") is True, var.get("isRequired") is True,
                               default[:1000]))
    values.update(args=tuple(args), env=tuple(env), notes=" ".join(notes))
    return values


def _remote_entry(remote: dict, values: dict) -> dict:
    values.update(kind="remote", network="full")
    if remote.get("type") != "streamable-http":
        values["why_not"] = f"a {clean_text(remote.get('type'), 30)} remote is not supported"
        return values
    url = clean_url(remote.get("url"))
    if not url.startswith("https://") or "{" in url:
        values["why_not"] = "the remote needs an https:// URL without variables"
        return values
    values["url"] = url
    for header in remote.get("headers") or ():
        if not isinstance(header, dict):
            continue
        name = str(header.get("name") or "")
        value = str(header.get("value") or "")
        if name.lower() == "authorization" and value.lower().startswith("bearer "):
            values["bearer"] = True
        elif header.get("isRequired") is True or "{" in value:
            values["why_not"] = f"the remote needs the header {clean_text(name, 60)}"
            return values
    return values


def entry_from_registry(item) -> CatalogEntry | None:
    """A registry server (``{"server": {...}, "_meta": {...}}``) as an
    entry: its first package axross can run (oci, npm, pypi over stdio),
    else its Streamable HTTP remote, else an entry that says why not.
    None for what is no server or deleted."""
    if not isinstance(item, dict) or not isinstance(item.get("server"), dict):
        return None
    server = item["server"]
    meta = item.get("_meta") if isinstance(item.get("_meta"), dict) else {}
    official = meta.get(_OFFICIAL) if isinstance(meta.get(_OFFICIAL), dict) else {}
    status = official.get("status")
    if status == "deleted":
        return None
    full_name = clean_text(server.get("name"), 200)
    if not full_name:
        return None
    updated = str(official.get("updatedAt") or "")
    repo = server.get("repository") if isinstance(server.get("repository"), dict) else {}
    values: dict = dict(
        id=f"mcpregistry:{full_name}", name=server_name(full_name),
        title=clean_text(server.get("title"), MAX_SHORT) or full_name,
        description=clean_text(server.get("description"), MAX_DESCRIPTION, lines=True),
        category="MCP Registry", source="mcpregistry", repository=clean_url(repo.get("url")),
        page=clean_url(server.get("websiteUrl")),
        updated=updated[:10] if _DATE.match(updated) else "",
    )
    packages = [p for p in server.get("packages") or () if isinstance(p, dict)]
    remotes = [r for r in server.get("remotes") or () if isinstance(r, dict)]
    order = {"oci": 0, "npm": 1, "pypi": 2}
    runnable = sorted(
        (p for p in packages if str(p.get("registryType")) in order),
        key=lambda p: order[str(p.get("registryType"))],
    )
    candidates = [_package_entry(p, dict(values)) for p in runnable]
    chosen = next((c for c in candidates if not c.get("why_not")), None)
    if chosen is None and remotes:
        remote = _remote_entry(remotes[0], dict(values))
        if not remote.get("why_not") or not candidates:
            chosen = remote
    if chosen is None:
        chosen = candidates[0] if candidates else (
            _package_entry(packages[0], dict(values)) if packages
            else dict(values, kind="unknown", why_not="no package or remote axross can run")
        )
    if status == "deprecated":
        message = clean_text(official.get("statusMessage"), 300)
        chosen["notes"] = (f"Deprecated by its publisher{': ' + message if message else ''}. "
                           + chosen.get("notes", "")).strip()
    return CatalogEntry(**chosen)


# -- the sources a user switched on -------------------------------------------------------


@dataclass(frozen=True)
class CatalogSources:
    builtin: bool = True
    dockerhub: bool = True
    mcpregistry: bool = True
    #: The c0decave MCP Hub (HubSource).
    c0decave: bool = True
    #: The curated lists of core.mcp_discover.
    discover: bool = True
    #: The user's catalogs: absolute file paths or https:// URLs.
    extra: tuple[str, ...] = ()

    @staticmethod
    def problems_of(location: str) -> list[str]:
        if not isinstance(location, str) or not location.strip() or len(location) > 1000:
            return ["an absolute file path or an https:// URL"]
        if location.startswith("https://"):
            return [] if clean_url(location) else ["a valid https:// URL"]
        if "://" in location:
            return ["https:// only - other schemes are not read"]
        if not Path(location).is_absolute():
            return ["an absolute file path"]
        if any(c in location for c in "\n\r\x00"):
            return ["a path on one line"]
        return []

    @classmethod
    def from_dict(cls, data) -> CatalogSources:
        if not isinstance(data, dict):
            return cls()
        flags = {k: data[k] for k in ("builtin", "dockerhub", "mcpregistry", "c0decave",
                                      "discover")
                 if isinstance(data.get(k), bool)}
        extra: list[str] = []
        for item in data.get("extra") or () if isinstance(data.get("extra"), list) else ():
            if not cls.problems_of(item) and item not in extra:
                extra.append(item)
        return cls(**flags, extra=tuple(extra[:MAX_EXTRA_SOURCES]))

    def to_dict(self) -> dict:
        return {"builtin": self.builtin, "dockerhub": self.dockerhub,
                "mcpregistry": self.mcpregistry, "c0decave": self.c0decave,
                "discover": self.discover, "extra": list(self.extra)}

    def sources(self, *, opener=None) -> list[Source]:
        out: list[Source] = []
        if self.builtin:
            out.append(BuiltinSource(opener=opener))
        if self.c0decave:
            out.append(HubSource(opener=opener))
        if self.dockerhub:
            out.append(DockerHubSource(opener=opener))
        if self.mcpregistry:
            out.append(McpRegistrySource(opener=opener))
        if self.discover:
            from core.mcp_discover import DiscoverSource

            out.append(DiscoverSource(opener=opener))
        for location in self.extra:
            if location.startswith("https://"):
                out.append(UrlSource(location, opener=opener))
            else:
                out.append(FileSource(location, opener=opener))
        return out


def search_all(sources: list[Source], query: str = "", *,
               cancel: threading.Event | None = None,
               on_result: Callable[[SearchResult], None] | None = None) -> list[SearchResult]:
    """Every source searched (in parallel, at most four at once); the
    results in the order of *sources*. *on_result* hears each as it comes."""
    if not sources:
        return []

    def one(source: Source) -> SearchResult:
        try:
            result = source.search(query, cancel=cancel)
        except Exception as exc:  # noqa: BLE001 - one broken source must not cost the others
            log.exception("mcp catalog: source %s failed", source.id)
            result = SearchResult(source.id, source.title, error=f"failed: {exc}")
        if on_result is not None:
            on_result(result)
        return result

    with ThreadPoolExecutor(max_workers=min(4, len(sources)),
                            thread_name_prefix="mcp-catalog") as pool:
        return list(pool.map(one, sources))
