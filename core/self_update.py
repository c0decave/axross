"""Self-update of the one-file binaries (axross-full, axross-slim).

Once per start (Settings > Updates, on by default) axross asks GitHub for
the latest release of ``c0decave/axross``, in the background, with one
request. When it is newer, the window says so; *Download* fetches the
binary of this build's kind, checks it and puts it in place. It takes
effect at the next start - nothing that was downloaded is ever run before
its signature and checksum matched, and only on *Restart Now*.

Which file (:func:`detect_install`):

=================  ==========================================================
Python install     pip or a source checkout: never replaced, the answer is
                   ``pip install -U axross``
axross-full        Linux x86-64 one-file binary (asset ``axross-full``)
axross-slim        Linux x86-64 (``axross-slim``), macOS arm64
                   (``axross-slim-macos-arm64``), Windows x64
                   (``axross-slim-windows-x64.exe``)
=================  ==========================================================

The bundle records its flavour in :data:`FLAVOR_PATH` (build/axross.spec);
a binary without it is recognised by its file name.

The chain, measured against github.com on 2026-10-25: the API
(``api.github.com``) names the assets; a download URL
(``github.com/c0decave/axross/releases/download/vX/<name>``) answers 302 to
``release-assets.githubusercontent.com`` (``objects.githubusercontent.com``
before). Redirects are followed here, one by one, and only to those hosts,
only over https (:data:`ALLOWED_HOSTS`); urllib's own redirect handling is
off (core.agent_net.opener_without_redirects). The default proxy of
Settings > Network & Proxy is used (:func:`proxy_handler`); without one,
urllib's environment proxies.

Checks before anything is replaced:

* the asset URL is the release's own download URL, every size is bounded
  (:data:`MAX_API_BYTES`, :data:`MAX_SUMS_BYTES`, :data:`SIG_BYTES`,
  :data:`MAX_ASSET_BYTES`) and a download must have exactly the size the
  release states;
* the release's ``SHA256SUMS`` must carry a valid signature
  (:func:`verify_signature`): the asset ``SHA256SUMS.sig`` is the raw
  64-byte Ed25519 signature of the exact bytes of ``SHA256SUMS``, made with
  the release key whose public half is pinned in :data:`TRUSTED_KEYS`. No
  signature, one of another size, or one that does not verify: refused,
  before any entry of ``SHA256SUMS`` is read and before the binary is
  fetched. The checksums and GitHub's digests come from the release itself;
  the signature is what someone who can change the release cannot make;
* the SHA-256 must equal the entry of the signed ``SHA256SUMS`` (no
  entry, no file: refused) and, where the API gives one, its ``digest``
  of the same asset;
* a refused or cut download leaves nothing behind.

Releases are signed with ``scripts/sign_release.py`` (docs/PACKAGING.md).
Binaries released before signing (0.14.50 and older) do not check it;
they ignore the extra asset (they pick assets by their exact name).

Replacing (:func:`install`): the new file is written next to the running
binary (same file system), fsynced, gets the old file's mode; the old one
stays as ``<name>.previous`` (a hard link); then one atomic rename. A
folder that is not writable gets nothing: the file goes to
``~/.cache/axross/update/`` and the window offers *Save to…*. Windows
cannot replace a running program: the file lands next to it as
``<name>-X.Y.Z.exe`` and the window says how to finish.

Settings (settings.json, validated on read - the file is hand-editable):
``update_check_at_start`` (default true), ``update_auto_download``
(default false), ``update_skipped_version``, ``update_last_check``.
``AXROSS_NO_UPDATE_CHECK=1`` and the paranoid security mode switch the
start check off; *Check Now* and Help > Check for Updates… still work.
"""

from __future__ import annotations

import hashlib
import http.client
import json
import logging
import math
import os
import platform as _platform
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from base64 import b64decode
from binascii import Error as Base64Error
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Callable

from core import open_limits as OL
from core.mcp_catalog import clean_text

log = logging.getLogger(__name__)

REPOSITORY = "c0decave/axross"
LATEST_URL = f"https://api.github.com/repos/{REPOSITORY}/releases/latest"
RELEASES_PREFIX = f"https://github.com/{REPOSITORY}/releases/"
DOWNLOAD_PREFIX = f"{RELEASES_PREFIX}download/"
#: The only hosts a request or a redirect may reach (https only).
ALLOWED_HOSTS = frozenset({
    "api.github.com",
    "github.com",
    "release-assets.githubusercontent.com",
    "objects.githubusercontent.com",
})
SUMS_NAME = "SHA256SUMS"
#: The detached signature of SHA256SUMS: raw Ed25519 signature bytes.
SIG_NAME = SUMS_NAME + ".sig"
#: An Ed25519 signature is exactly this long; it is also the size bound.
SIG_BYTES = 64
#: The public release keys (raw 32 bytes, base64) a SHA256SUMS may be
#: signed with; any one of them verifying is enough. More than one only
#: while a key is rotated: a new key is added here a release before the
#: releases are signed with it. Tests replace it with their own key.
TRUSTED_KEYS: tuple[str, ...] = (
    "rJX0yymA5/Mbw24qIpuLNaLqC/FbvugEREz1p0pSz68=",  # signed 0.14.53 - 0.15.176
    "INHsCyIzJ305W1+SvRkrEMuaO7puYtlgnhP72N6+mcw=",  # from 0.15.176 on; signs once the binaries in use carry it
)
#: Written into the bundle by build/axross.spec: "full" or "slim". In the
#: first-party folder "axross" (core.third_party.FIRST_PARTY): a file at
#: the bundle root would be an unclaimed part of the bundle to the release
#: gate (tests/test_third_party_bundle.py).
FLAVOR_FILE = "axross-bundle-flavor.txt"
FLAVOR_PATH = ("axross", FLAVOR_FILE)
FLAVORS = ("full", "slim", "base")
#: The target system's glibc floor of a Linux binary ("glibc-2.34" or
#: "glibc-2.36"), written by build/axross.spec beside the flavour. A
#: bundle without it is a glibc-2.34 one (every binary before 0.15.166).
VARIANT_FILE = "axross-bundle-variant.txt"
VARIANT_PATH = ("axross", VARIANT_FILE)
VARIANTS = ("glibc-2.34", "glibc-2.36")

MAX_API_BYTES = 1 << 20
#: The assets of a release: GitHub's answer to ``releases/latest`` carries
#: every one, sorted by name ignoring case (measured 2026-11-08 on releases
#: of 22 and 991 assets). Should an answer ever end at exactly ASSETS_PAGE
#: entries - a full page, as the asset list hands them out - the rest is
#: read from the asset list's pages (ASSETS_PAGE each), up to MAX_ASSETS
#: assets in all; an asset listed twice is kept once.
MAX_ASSETS = 500
ASSETS_PAGE = 100
MAX_SUMS_BYTES = 64 << 10
MAX_ASSET_BYTES = 1 << 30
MAX_REDIRECTS = 5
MAX_NOTES_CHARS = 20000
MAX_STATUS_CHARS = 300
#: Seconds for the whole API answer.
API_TIMEOUT = 15.0
#: Seconds one read of a download may take (no bound on the whole: a big
#: file on a slow line takes what it takes; Cancel stops it).
READ_TIMEOUT = 60.0
_CHUNK = 1 << 16

NO_CHECK_ENV = "AXROSS_NO_UPDATE_CHECK"
SETTING_CHECK = "update_check_at_start"
SETTING_AUTO = "update_auto_download"
SETTING_SKIPPED = "update_skipped_version"
SETTING_LAST = "update_last_check"

PIP_HINT = "pip install -U axross"

_VERSION = re.compile(r"v?([0-9]{1,6})\.([0-9]{1,6})\.([0-9]{1,6})", re.ASCII)
_CANONICAL = re.compile(r"[0-9]{1,6}\.[0-9]{1,6}\.[0-9]{1,6}", re.ASCII)
_ASSET_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,199}", re.ASCII)
_HEX64 = re.compile(r"[0-9a-f]{64}", re.ASCII)
_TRUTHY = {"1", "true", "yes", "on"}
_UNSET = object()


class UpdateError(Exception):
    """The check or the update failed; the text says why, for people."""


class RateLimited(UpdateError):
    """GitHub's API refused: too many requests from this address."""


class ChecksumError(UpdateError):
    """What came does not match the release's checksums - refused."""


class SignatureError(ChecksumError):
    """The release's SHA256SUMS carries no valid signature of the release
    key - refused."""


class NotWritable(UpdateError):
    """The folder of the running binary cannot take the new file."""


class Cancelled(UpdateError):
    pass


# -- versions --------------------------------------------------------------------------


def parse_version(text) -> tuple[int, int, int] | None:
    """``(x, y, z)`` of ``"x.y.z"`` or ``"vx.y.z"``; None for anything else
    (a pre-release suffix included)."""
    if not isinstance(text, str):
        return None
    match = _VERSION.fullmatch(text)
    if match is None:
        return None
    return int(match[1]), int(match[2]), int(match[3])


def is_newer(candidate, current) -> bool:
    new, old = parse_version(candidate), parse_version(current)
    return new is not None and old is not None and new > old


# -- which binary is this ----------------------------------------------------------------


@dataclass(frozen=True)
class Install:
    """How this axross was installed and which release asset replaces it."""

    frozen: bool
    flavor: str = ""  # "full", "slim", "base", "" (unknown or not frozen)
    asset: str = ""  # the release asset of this build, "" when there is none
    executable: Path | None = None  # the real file of the running binary
    platform: str = ""
    machine: str = ""

    @property
    def can_download(self) -> bool:
        return self.frozen and bool(self.asset) and self.executable is not None

    @property
    def can_self_replace(self) -> bool:
        """The new file can take the running one's place (not on Windows)."""
        return self.can_download and self.platform != "win32"

    @property
    def title(self) -> str:
        return f"axross-{self.flavor}" if self.flavor else "axross"

    def why_not(self) -> str:
        """Why the update cannot replace this axross ("" when it can)."""
        if not self.frozen:
            return ("This axross runs from a Python installation (pip or a source checkout); "
                    f"update it with: {PIP_HINT}")
        if not self.flavor:
            return ("This binary does not say whether it is axross-full or axross-slim; "
                    "download the new version from the release page.")
        if not self.asset:
            return (f"There is no {self.title} build for {self.platform} {self.machine} in "
                    "the releases; download the new version from the release page.")
        if self.platform == "win32":
            return ("Windows cannot replace a running program: the new version is downloaded "
                    "next to it, and you finish the update after closing axross.")
        return ""


def asset_name(platform: str, machine: str, flavor: str, variant: str = "glibc-2.34") -> str:
    """The release asset of a binary of *flavor* (and, on Linux, glibc
    *variant*) on *platform*/*machine*: ``axross-full`` / ``-slim`` /
    ``-base`` for glibc 2.34, ``axross-full-glibc2.36`` ... for 2.36."""
    machine = (machine or "").lower()
    if platform.startswith("linux") and machine in ("x86_64", "amd64") and flavor in FLAVORS:
        suffix = "" if variant in ("", "glibc-2.34") else "-" + variant.replace("-", "")
        return f"axross-{flavor}{suffix}" if variant in VARIANTS or not variant else ""
    if platform == "darwin" and machine == "arm64" and flavor == "slim":
        return "axross-slim-macos-arm64"
    if platform == "win32" and machine in ("amd64", "x86_64") and flavor == "slim":
        return "axross-slim-windows-x64.exe"
    return ""


def _flavor_of(bundle_dir, executable: Path) -> str:
    if bundle_dir:
        try:
            with open(os.path.join(bundle_dir, *FLAVOR_PATH), encoding="ascii") as fh:
                marker = fh.read(64).strip()
        except (OSError, ValueError):
            marker = ""
        if marker in FLAVORS:
            return marker
    name = executable.name.lower()
    for flavor in FLAVORS:
        if name.startswith(f"axross-{flavor}"):
            return flavor
    return ""


def _variant_of(bundle_dir) -> str:
    """The bundle's glibc variant; glibc-2.34 for a bundle without the file."""
    if bundle_dir:
        try:
            with open(os.path.join(bundle_dir, *VARIANT_PATH), encoding="ascii") as fh:
                marker = fh.read(32).strip()
        except (OSError, ValueError):
            marker = ""
        if marker in VARIANTS:
            return marker
    return "glibc-2.34"


def detect_install(*, frozen=None, executable=None, bundle_dir=_UNSET, platform=None,
                   machine=None) -> Install:
    """This process's :class:`Install` (every argument is for tests)."""
    frozen = bool(getattr(sys, "frozen", False)) if frozen is None else bool(frozen)
    platform = platform or sys.platform
    machine = (machine or _platform.machine() or "").lower()
    if not frozen:
        return Install(False, platform=platform, machine=machine)
    exe = Path(os.path.realpath(executable or sys.executable))
    if bundle_dir is _UNSET:
        bundle_dir = getattr(sys, "_MEIPASS", None)
    flavor = _flavor_of(bundle_dir, exe)
    variant = _variant_of(bundle_dir)
    return Install(True, flavor, asset_name(platform, machine, flavor, variant), exe, platform, machine)


# -- releases ----------------------------------------------------------------------------


@dataclass(frozen=True)
class Asset:
    name: str
    url: str
    size: int
    digest: str = ""  # the API's sha256 (hex), "" when it gives none


@dataclass(frozen=True)
class Release:
    version: str
    tag: str
    page_url: str
    notes: str
    assets: tuple[Asset, ...]

    def asset(self, name: str) -> Asset | None:
        return next((a for a in self.assets if a.name == name), None)


@dataclass(frozen=True)
class CheckResult:
    current: str
    release: Release | None
    newer: bool
    message: str


def _asset(raw, tag: str) -> Asset | None:
    """An asset entry of the API, or None when it is not one of this
    release's own downloads."""
    if not isinstance(raw, dict):
        return None
    name, size, url = raw.get("name"), raw.get("size"), raw.get("browser_download_url")
    if not isinstance(name, str) or not _ASSET_NAME.fullmatch(name):
        return None
    if type(size) is not int or size <= 0:
        return None
    if url != f"{DOWNLOAD_PREFIX}{tag}/{name}":
        return None
    digest = raw.get("digest")
    hexdigest = ""
    if isinstance(digest, str) and digest.startswith("sha256:"):
        candidate = digest[len("sha256:"):].lower()
        if _HEX64.fullmatch(candidate):
            hexdigest = candidate
    return Asset(name, url, size, hexdigest)


def parse_release(data) -> Release:
    """A :class:`Release` from the API's JSON; UpdateError when it is none."""
    if not isinstance(data, dict):
        raise UpdateError("GitHub's answer is not a release")
    tag = data.get("tag_name")
    version = parse_version(tag)
    if version is None:
        raise UpdateError(
            f"GitHub names {clean_text(tag, 40)!r} as the latest release of {REPOSITORY}, "
            "which is not an axross version (vX.Y.Z), so no update can be offered; "
            f"download a new version from {RELEASES_PREFIX}")
    page = data.get("html_url")
    if page != f"{RELEASES_PREFIX}tag/{tag}":
        raise UpdateError("the latest release names no page of c0decave/axross")
    raw_assets = data.get("assets")
    if not isinstance(raw_assets, list):
        raise UpdateError("the latest release has no list of files")
    assets: dict[str, Asset] = {}
    for raw in raw_assets[:MAX_ASSETS]:
        asset = _asset(raw, tag)
        if asset is not None:
            assets.setdefault(asset.name, asset)  # listed twice: the first one
    return Release(
        version="%d.%d.%d" % version,
        tag=tag,
        page_url=page,
        notes=clean_text(data.get("body"), MAX_NOTES_CHARS, lines=True),
        assets=tuple(assets.values()),
    )


# -- http --------------------------------------------------------------------------------


def _user_agent() -> str:
    from axross._version import __version__

    return f"axross/{__version__} (update check)"


def proxy_handler() -> urllib.request.ProxyHandler:
    """urllib's proxy handler for the GitHub hosts: the default proxy of
    Settings > Network & Proxy (SOCKS, HTTPS and NTLM through the loopback
    shim), else the environment's proxies. A default proxy that cannot be
    read or used fails closed - never a silent direct connection."""
    from core import proxy_settings as PS

    try:
        resolution = PS.resolve("default", None, "api.github.com", 443, "https")
    except (PS.ProxyResolutionError, OSError, ValueError) as exc:
        raise UpdateError(f"the default proxy cannot be used: {exc}") from None
    if resolution.config is None:
        if resolution.source == "default-none":
            return urllib.request.ProxyHandler()  # the environment's, as urllib does
        return urllib.request.ProxyHandler({})  # bypass list or PAC: direct
    from core.proxy import build_requests_proxies, effective_http_proxy

    try:
        cfg = effective_http_proxy(resolution.config)
        proxies = build_requests_proxies(cfg.proxy_type, cfg.host, cfg.port, cfg.username,
                                         cfg.password)
    except (OSError, ValueError) as exc:
        raise UpdateError(f"the default proxy cannot be used: {exc}") from None
    return urllib.request.ProxyHandler({"https": proxies["https"], "http": proxies["http"]})


def build_opener(*, handlers=(), ssl_context=None) -> urllib.request.OpenerDirector:
    """The opener of every update request: the proxy of :func:`proxy_handler`,
    no automatic redirects (:func:`fetch` follows them itself). *handlers*
    and *ssl_context* are for tests."""
    from core.agent_net import opener_without_redirects

    extra = list(handlers)
    if ssl_context is not None:
        extra.append(urllib.request.HTTPSHandler(context=ssl_context))
    return opener_without_redirects(proxy_handler(), *extra)


def _check_url(url: str, hosts=None) -> str:
    try:
        parts = urllib.parse.urlsplit(url)
        host = (parts.hostname or "").lower()
        port = parts.port
    except ValueError:
        raise UpdateError(f"refused a malformed address: {url[:100]!r}") from None
    if parts.scheme != "https":
        raise UpdateError(f"refused {host or url[:100]}: only https is used for updates")
    if host not in (ALLOWED_HOSTS if hosts is None else hosts) or port not in (None, 443) \
            or parts.username or parts.password:
        raise UpdateError(f"refused {host or url[:100]}: not a GitHub host of the releases")
    return host


def _rate_limit_message(exc: urllib.error.HTTPError) -> str | None:
    headers = exc.headers or {}
    remaining = (headers.get("X-RateLimit-Remaining") or "").strip()
    if exc.code == 403 and remaining != "0":
        return None
    if exc.code not in (403, 429):
        return None
    when = ""
    reset = (headers.get("X-RateLimit-Reset") or "").strip()
    retry = (headers.get("Retry-After") or "").strip()
    if reset.isascii() and reset.isdigit():
        when = f"; try again after {time.strftime('%H:%M', time.localtime(int(reset)))}"
    elif retry.isascii() and retry.isdigit():
        when = f"; try again in {int(retry)} s"
    return f"GitHub's API rate limit is reached for this address{when}"


def fetch(url: str, *, opener, max_bytes: int, timeout: float = READ_TIMEOUT,
          deadline: float | None = None, accept: str = "application/octet-stream",
          sink: Callable[[bytes], None] | None = None,
          progress: Callable[[int, int], None] | None = None, total: int = 0,
          cancel: threading.Event | None = None, hosts=None) -> bytes | int:
    """GET *url* over https from an allowed host (*hosts*, default
    :data:`ALLOWED_HOSTS`), following up to :data:`MAX_REDIRECTS` redirects
    (each target checked). Returns the body, or with *sink* hands each chunk
    to it and returns the byte count. More than *max_bytes*, or past
    *deadline* (time.monotonic), is refused."""
    current = url
    for _hop in range(MAX_REDIRECTS + 1):
        host = _check_url(current, hosts)
        headers = {"Accept": accept, "User-Agent": _user_agent()}
        if host == "api.github.com":
            headers["X-GitHub-Api-Version"] = "2022-11-28"
        request = urllib.request.Request(current, headers=headers)
        try:
            response = opener.open(request, timeout=timeout)
        except urllib.error.HTTPError as exc:
            location = exc.headers.get("Location", "") if exc.headers else ""
            exc.close()
            if exc.code in (301, 302, 303, 307, 308):
                if not location:
                    raise UpdateError(f"{host} redirected without a target") from None
                current = urllib.parse.urljoin(current, location)
                continue
            limited = _rate_limit_message(exc)
            if limited:
                raise RateLimited(limited) from None
            raise UpdateError(f"{host} answered HTTP {exc.code}") from None
        except TimeoutError:
            raise UpdateError(f"{host} sent no answer within {timeout:g} s") from None
        except (urllib.error.URLError, OSError) as exc:
            reason = getattr(exc, "reason", exc)
            if isinstance(reason, TimeoutError):
                raise UpdateError(f"{host} sent no answer within {timeout:g} s") from None
            raise UpdateError(f"cannot reach {host}: {reason}") from None
        with response:
            return _read(response, host, max_bytes, deadline, sink, progress, total, cancel)
    raise UpdateError(f"more than {MAX_REDIRECTS} redirects - refused")


def _read(response, host, max_bytes, deadline, sink, progress, total, cancel) -> bytes | int:
    length = response.headers.get("Content-Length", "") if response.headers else ""
    if length.isascii() and length.isdigit() and int(length) > max_bytes:
        raise UpdateError(f"{host}'s answer is larger than {max_bytes} bytes - refused")
    reader = getattr(response, "read1", None) or response.read
    body = bytearray()
    got = 0
    while True:
        if cancel is not None and cancel.is_set():
            raise Cancelled("cancelled")
        if deadline is not None and time.monotonic() > deadline:
            raise UpdateError(f"{host} sent no complete answer in time")
        try:
            chunk = reader(_CHUNK)
        except TimeoutError:
            raise UpdateError(f"{host} stopped sending (no data for {READ_TIMEOUT:g} s)") from None
        except (OSError, http.client.HTTPException) as exc:
            raise UpdateError(f"the download from {host} broke off: {exc!r}") from None
        if not chunk:
            break
        got += len(chunk)
        if got > max_bytes:
            raise UpdateError(f"{host}'s answer is larger than {max_bytes} bytes - refused")
        if sink is not None:
            try:
                sink(chunk)
            except OSError as exc:
                raise UpdateError(f"cannot write the download: {exc}") from None
        else:
            body += chunk
        if progress is not None:
            progress(got, total or max_bytes)
    return got if sink is not None else bytes(body)


# -- the check ---------------------------------------------------------------------------


def check(current: str | None = None, *, opener=None, timeout: float = API_TIMEOUT) -> CheckResult:
    """Ask GitHub for the latest release (one request). Raises UpdateError
    (RateLimited for the rate limit)."""
    if current is None:
        from axross._version import __version__ as current
    if parse_version(current) is None:
        raise UpdateError(f"this axross's version {current!r} is not x.y.z; nothing to compare")
    opener = opener if opener is not None else build_opener()
    body = fetch(LATEST_URL, opener=opener, max_bytes=MAX_API_BYTES, timeout=timeout,
                 deadline=time.monotonic() + timeout, accept="application/vnd.github+json")
    try:
        data = json.loads(body)
    except (ValueError, RecursionError):
        raise UpdateError("GitHub's answer is not JSON") from None
    if isinstance(data, dict):
        for flag in ("draft", "prerelease"):
            if data.get(flag) is True:
                return CheckResult(current, None, False,
                                   f"The latest release is a {flag}; ignored.")
        _read_more_assets(data, opener, timeout)
    release = parse_release(data)
    if is_newer(release.version, current):
        message = f"axross {release.version} is available (this is {current})."
        return CheckResult(current, release, True, message)
    return CheckResult(current, release, False,
                       f"axross {current} is up to date (latest release: {release.version}).")


def _read_more_assets(data: dict, opener, timeout: float) -> None:
    """Complete ``data["assets"]`` from the release's asset pages - only
    when the answer looks cut off at one page: exactly ASSETS_PAGE assets.
    GitHub's answer holds every asset of the release (see MAX_ASSETS); one
    of fewer or more is complete and makes no further request.

    The address is built here from the repository and the release's numeric
    id, never taken from the answer; every page is size-bounded, the pages
    stop at MAX_ASSETS assets (MAX_ASSETS // ASSETS_PAGE pages), at a short
    or empty page and at a page that brings nothing new. An asset already
    listed (the same id or the same name) is not added again. A page that
    fails ends the reading: the assets read so far stay, and a missing
    SHA256SUMS refuses the update later as before."""
    raw = data.get("assets")
    release_id = data.get("id")
    if (not isinstance(raw, list) or len(raw) != ASSETS_PAGE
            or not isinstance(release_id, int) or isinstance(release_id, bool) or release_id <= 0):
        return
    seen: set = set()
    for entry in raw:
        seen |= _asset_keys(entry)
    for page in range(2, MAX_ASSETS // ASSETS_PAGE + 1):
        if len(raw) >= MAX_ASSETS:
            return
        url = (f"https://api.github.com/repos/{REPOSITORY}/releases/{release_id}/assets"
               f"?per_page={ASSETS_PAGE}&page={page}")
        try:
            body = fetch(url, opener=opener, max_bytes=MAX_API_BYTES, timeout=timeout,
                         deadline=time.monotonic() + timeout,
                         accept="application/vnd.github+json")
            more = json.loads(body)
        except (UpdateError, ValueError, RecursionError) as exc:
            log.info("update check: asset page %d not read: %s", page, exc)
            return
        if not isinstance(more, list) or not more:
            return
        added = 0
        for entry in more[:ASSETS_PAGE]:
            keys = _asset_keys(entry)
            if not keys or keys & seen or len(raw) >= MAX_ASSETS:
                continue
            seen |= keys
            raw.append(entry)
            added += 1
        if len(more) < ASSETS_PAGE or not added:
            return


def _asset_keys(entry) -> set:
    """What makes an asset entry the same as another: its id and its name."""
    if not isinstance(entry, dict):
        return set()
    keys = set()
    asset_id, name = entry.get("id"), entry.get("name")
    if isinstance(asset_id, int) and not isinstance(asset_id, bool):
        keys.add(("id", asset_id))
    if isinstance(name, str):
        keys.add(("name", name))
    return keys


# -- download, verify, replace -----------------------------------------------------------


@dataclass(frozen=True)
class Downloaded:
    path: Path
    asset: Asset
    sha256: str
    version: str


@dataclass(frozen=True)
class Installed:
    path: Path  # where the new version is
    previous: Path | None  # the kept old binary
    replaced: bool  # True: it takes effect at the next start
    how_to_finish: str  # what the user still has to do ("" when replaced)
    sha256: str = ""
    version: str = ""
    #: Installed units (core.units names) the new release no longer has
    #: (dropped or renamed): not brought along, named in the window.
    dropped_units: tuple[str, ...] = ()


@dataclass(frozen=True)
class CarriedPacks:
    """What :func:`_carry_packs` brought along to the new version."""

    blobs: list[str] = field(default_factory=list)  # fetched and unpacked
    dropped: list[str] = field(default_factory=list)  # units the new release does not have
    #: The pack-manifest issue (core.packs.PACKS_ISSUE_PREFIX) of the signed
    #: SHA256SUMS the packs were checked against; None when none were carried.
    issue: int | None = None


#: The first line of a release's SHA256SUMS: the version the signature is
#: for. Without it a signed SHA256SUMS of any old release could be published
#: under a new tag (a downgrade to a known-vulnerable build).
RELEASE_LINE_PREFIX = "# axross-release "


def release_of_sums(text: str) -> str | None:
    """The version the ``# axross-release X.Y.Z`` line of SHA256SUMS names;
    None without one."""
    for line in text.splitlines():
        if line.startswith(RELEASE_LINE_PREFIX):
            return line[len(RELEASE_LINE_PREFIX):].strip() or None
    return None


def parse_sums(text: str) -> dict[str, str]:
    """``{name: sha256}`` of a ``sha256sum`` output (``*`` binary marker too)."""
    sums: dict[str, str] = {}
    for line in text.splitlines():
        digest, sep, name = line.strip().partition(" ")
        name = name.strip()
        if name.startswith("*"):
            name = name[1:]
        digest = digest.lower()
        if sep and _HEX64.fullmatch(digest) and _ASSET_NAME.fullmatch(name):
            sums.setdefault(name, digest)
    return sums


def cache_dir() -> Path:
    from core.xdg_dirs import base_dir

    return base_dir("XDG_CACHE_HOME") / "axross" / "update"  # a relative one is ignored


def private_dir_problem(folder: Path, *, create: bool = True) -> str:
    """Why *folder* may not hold a download ("" = it may): it must be a real
    directory (no symlink) of this user that no one else may write to, like
    the extension code cache. It is made with 0o700 when *create* and
    missing; a folder another user owns, a group- or world-writable one or a
    symlink is refused - not used, not "repaired" (someone else may have put
    files in it). Its parents must not be writable by others either (unless
    sticky, as /tmp), or the folder could be renamed away and replaced."""
    folder = Path(folder)
    try:
        if create and not os.path.lexists(folder):
            folder.parent.mkdir(parents=True, exist_ok=True)
            os.mkdir(folder, 0o700)
        st = os.lstat(folder)
    except FileExistsError:
        return private_dir_problem(folder, create=False)
    except OSError as exc:
        return f"{folder} cannot be used: {exc.strerror or exc}"
    if stat.S_ISLNK(st.st_mode):
        return f"{folder} is a symbolic link: not used"
    if not stat.S_ISDIR(st.st_mode):
        return f"{folder} is not a folder: not used"
    from core.posix_compat import effective_uid

    uid = effective_uid()
    if uid is None:
        return ""  # no owners and modes to check here (Windows)
    if st.st_uid != uid:
        return f"{folder} belongs to another user: not used"
    if st.st_mode & 0o022:
        return (f"{folder} is writable by other users: not used "
                f"(make it private: chmod 700 '{folder}')")
    parent = folder.parent
    for _ in range(64):
        try:
            pst = os.stat(parent)
        except OSError:
            break
        if pst.st_uid not in (uid, 0) or (pst.st_mode & 0o002 and not pst.st_mode & 0o1000):
            return f"{parent} can be changed by other users: {folder} is not used"
        if parent.parent == parent:
            break
        parent = parent.parent
    return ""


def _plain_mode(path: Path) -> int:
    """The read/write/execute bits of *path* - never setuid, setgid or
    sticky onto a downloaded file."""
    return stat.S_IMODE(path.stat().st_mode) & 0o777


def _writable(folder: Path) -> bool:
    return os.access(folder, os.W_OK | os.X_OK)


def _fsync_dir(folder: Path) -> None:
    if os.name != "posix":
        return
    try:
        fd = os.open(folder, os.O_RDONLY)
    except OSError:
        return
    try:
        os.fsync(fd)
    except OSError:
        pass
    finally:
        os.close(fd)


def _unlink(path) -> None:
    try:
        os.unlink(path)
    except OSError:
        pass


def _remove_stale(folder: Path, name: str) -> None:
    """Partial files an interrupted run left (the process ended mid-download)."""
    for stale in folder.glob(f".{name}.update-*.part"):
        _unlink(stale)


def _public_keys(keys) -> list:
    """The usable Ed25519 keys among *keys* (base64 of the raw 32 bytes);
    an entry that is none is skipped, never trusted."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    usable = []
    for key in keys:
        try:
            raw = b64decode(key, validate=True) if isinstance(key, str) else b""
        except (Base64Error, ValueError):
            raw = b""
        if len(raw) != 32:
            log.error("update: a pinned release key is not 32 bytes of base64 - skipped")
            continue
        try:
            usable.append(Ed25519PublicKey.from_public_bytes(raw))
        except ValueError:
            log.error("update: a pinned release key is not an Ed25519 key - skipped")
    return usable


def verify_signature(data: bytes, signature, keys=None) -> None:
    """Refuse (:class:`SignatureError`) unless *signature* is a valid
    Ed25519 signature of exactly *data* by one of *keys* (default
    :data:`TRUSTED_KEYS`)."""
    from cryptography.exceptions import InvalidSignature

    keys = TRUSTED_KEYS if keys is None else keys
    if not isinstance(signature, (bytes, bytearray)) or len(signature) != SIG_BYTES:
        size = len(signature) if isinstance(signature, (bytes, bytearray)) else "no"
        raise SignatureError(f"{SIG_NAME} has {size} bytes; a signature is exactly "
                             f"{SIG_BYTES} bytes - refused")
    public_keys = _public_keys(keys)
    if not public_keys:
        raise SignatureError("this axross has no usable release key to check the signature "
                             "with - refused")
    for public_key in public_keys:
        try:
            public_key.verify(bytes(signature), bytes(data))
        except InvalidSignature:
            continue
        return
    raise SignatureError(f"the signature in {SIG_NAME} does not verify with the axross "
                         f"release key: {SUMS_NAME} was not signed by it - refused")


def _signed_sums(release: Release, opener) -> bytes:
    """The bytes of the release's SHA256SUMS, after its signature verified."""
    sums_asset = release.asset(SUMS_NAME)
    if sums_asset is None:
        raise ChecksumError(f"release {release.version} has no {SUMS_NAME} - refused")
    if sums_asset.size > MAX_SUMS_BYTES:
        raise ChecksumError(f"{SUMS_NAME} is larger than {MAX_SUMS_BYTES} bytes - refused")
    sig_asset = release.asset(SIG_NAME)
    if sig_asset is None:
        raise SignatureError(f"release {release.version} has no {SIG_NAME}: it is not signed "
                             "- refused")
    if sig_asset.size > SIG_BYTES:
        raise SignatureError(f"{SIG_NAME} is larger than {SIG_BYTES} bytes - refused")
    data = fetch(sums_asset.url, opener=opener, max_bytes=sums_asset.size,
                 deadline=time.monotonic() + API_TIMEOUT, timeout=API_TIMEOUT)
    if sums_asset.digest and hashlib.sha256(data).hexdigest() != sums_asset.digest:
        raise ChecksumError(f"{SUMS_NAME} differs from GitHub's digest of it - refused")
    signature = fetch(sig_asset.url, opener=opener, max_bytes=sig_asset.size,
                      deadline=time.monotonic() + API_TIMEOUT, timeout=API_TIMEOUT)
    if sig_asset.digest and hashlib.sha256(signature).hexdigest() != sig_asset.digest:
        raise ChecksumError(f"{SIG_NAME} differs from GitHub's digest of it - refused")
    verify_signature(data, signature)
    return data


def _expected_sha256(release: Release, asset: Asset, opener,
                     packs_issue: int | None = None) -> str:
    data = _signed_sums(release, opener)
    text = data.decode("utf-8", errors="replace")
    signed_for = release_of_sums(text)
    if signed_for is None:
        raise SignatureError(f"the signed {SUMS_NAME} of release {release.version} names no "
                             "release version - an older release's checksums under a new tag? "
                             "Refused")
    if signed_for != release.version:
        raise SignatureError(f"the signed {SUMS_NAME} is for axross {signed_for}, the release says "
                             f"{release.version} - refused")
    if packs_issue is not None:
        # The packs carried along were checked against a SHA256SUMS fetched
        # before this one: both must name the same manifest issue, or the
        # packs are of another issue than the release being installed (an
        # earlier signed issue served to the pack check).
        from core.packs import PackError, packs_issue_of_sums

        try:
            issue = packs_issue_of_sums(text)
        except PackError as exc:
            raise SignatureError(f"the signed {SUMS_NAME}: {exc} - refused") from None
        if issue != packs_issue:
            raise SignatureError(f"the packs brought along are of manifest issue {packs_issue}, "
                                 f"the signed {SUMS_NAME} of release {release.version} names "
                                 f"issue {issue} - refused (it changed during the update)")
    expected = parse_sums(text).get(asset.name)
    if expected is None:
        raise ChecksumError(f"the {SUMS_NAME} of release {release.version} has no entry for "
                            f"{asset.name} - refused")
    if asset.digest and asset.digest != expected:
        raise ChecksumError(f"GitHub's digest of {asset.name} differs from {SUMS_NAME} - refused")
    return expected


def _require_newer(release: Release, current: str | None) -> None:
    """UpdateError unless *release* is newer than *current* (the running
    version): a signed older release is a downgrade to its known bugs."""
    if current is None:
        from axross._version import __version__ as current
    if not is_newer(release.version, current):
        raise UpdateError(f"release {release.version} is not newer than this axross "
                          f"({current}) - refused")


def download(release: Release, inst: Install, *, dest_dir, opener=None,
             progress: Callable[[int, int], None] | None = None,
             cancel: threading.Event | None = None, current: str | None = None,
             packs_issue: int | None = None) -> Downloaded:
    """Fetch this build's asset of *release* into a hidden file in
    *dest_dir* and check it against the release's signed SHA256SUMS. The
    file is removed on any failure. Only a release newer than *current*
    (the running version) is fetched. *packs_issue*: the manifest issue the
    packs brought along were checked against - the signed SHA256SUMS must
    name the same one."""
    if not inst.can_download:
        raise UpdateError(inst.why_not())
    _require_newer(release, current)
    asset = release.asset(inst.asset)
    if asset is None:
        raise UpdateError(f"release {release.version} has no {inst.asset}")
    if asset.size > MAX_ASSET_BYTES:
        raise UpdateError(f"{asset.name} is larger than {MAX_ASSET_BYTES} bytes - refused")
    opener = opener if opener is not None else build_opener()
    expected = _expected_sha256(release, asset, opener, packs_issue)
    folder = Path(dest_dir)
    _remove_stale(folder, asset.name)
    fd, tmp_name = tempfile.mkstemp(dir=folder, prefix=f".{asset.name}.update-", suffix=".part")
    hasher = hashlib.sha256()
    try:
        with os.fdopen(fd, "wb") as out:
            def sink(chunk: bytes) -> None:
                hasher.update(chunk)
                out.write(chunk)

            got = fetch(asset.url, opener=opener, max_bytes=asset.size, sink=sink,
                        progress=progress, total=asset.size, cancel=cancel)
            if got != asset.size:
                raise UpdateError(f"{asset.name} has {got} bytes, the release states "
                                  f"{asset.size}")
            out.flush()
            os.fsync(out.fileno())
        if hasher.hexdigest() != expected:
            raise ChecksumError(f"the SHA-256 of {asset.name} differs from the release's "
                                f"{SUMS_NAME} - refused")
    except BaseException:
        _unlink(tmp_name)
        raise
    log.info("update: %s %s downloaded and verified (sha256 %s)", asset.name, release.version,
             expected)
    return Downloaded(Path(tmp_name), asset, expected, release.version)


def _copy_verified(source: Path, folder: Path, name: str, sha256: str, mode: int) -> Path:
    """A copy of *source* in *folder* (hidden temp name), fsynced, with
    *mode*, whose SHA-256 is checked again."""
    fd, tmp_name = tempfile.mkstemp(dir=folder, prefix=f".{name}.update-", suffix=".part")
    hasher = hashlib.sha256()
    try:
        with os.fdopen(fd, "wb") as out, open(source, "rb") as src:
            while chunk := src.read(_CHUNK * 16):
                hasher.update(chunk)
                out.write(chunk)
            out.flush()
            os.fsync(out.fileno())
        if hasher.hexdigest() != sha256:
            raise ChecksumError(f"the copy of {name} differs from the verified file - refused")
        os.chmod(tmp_name, mode)
    except BaseException:
        _unlink(tmp_name)
        raise
    return Path(tmp_name)


def versioned_name(name: str, version: str) -> str:
    """``axross-full-0.14.0``, ``axross-slim-windows-x64-0.14.0.exe``."""
    stem, dot, suffix = name.rpartition(".") if name.endswith(".exe") else (name, "", "")
    return f"{stem}-{version}{dot}{suffix}"


def install(downloaded: Downloaded, inst: Install) -> Installed:
    """Put a verified download in place of the running binary (Windows:
    next to it). Raises NotWritable when its folder cannot take it."""
    target = inst.executable
    if target is None or not inst.can_download:
        raise UpdateError(inst.why_not())
    folder = target.parent
    if not _writable(folder):
        raise NotWritable(f"the folder {folder} is not writable")
    mode = _plain_mode(target)
    source = downloaded.path
    if source.parent != folder:
        source = _copy_verified(source, folder, downloaded.asset.name, downloaded.sha256, mode)
        _unlink(downloaded.path)
    try:
        if inst.platform == "win32":
            final = folder / versioned_name(target.name, downloaded.version)
            os.replace(source, final)
            return Installed(
                final, None, False,
                f"Windows cannot replace a running program. Close axross, then replace "
                f"{target.name} with {final.name} - or start {final.name} directly.",
                downloaded.sha256, downloaded.version)
        os.chmod(source, mode)
        previous = target.with_name(target.name + ".previous")
        _unlink(previous)
        try:
            os.link(target, previous)
        except OSError:
            shutil.copy2(target, previous)
        os.replace(source, target)
    except BaseException:
        _unlink(source)
        raise
    _fsync_dir(folder)
    log.info("update: %s replaced by %s, the old one kept as %s", target, downloaded.version,
             previous)
    return Installed(target, previous, True, "", downloaded.sha256, downloaded.version)


def update(release: Release, inst: Install, *, opener=None,
           progress: Callable[[int, int], None] | None = None,
           cancel: threading.Event | None = None, current: str | None = None) -> Installed:
    """Download, verify and install *release* for *inst*. A folder that is
    not writable gets nothing: the verified file goes to :func:`cache_dir`
    and the result says so (the window offers Save to…). A release that is
    not newer than *current* (the running version) is refused."""
    if not inst.can_download:
        raise UpdateError(inst.why_not())
    _require_newer(release, current)
    carried = _carry_packs(release, opener, progress, cancel)
    result = _update_binary(release, inst, opener=opener, progress=progress, cancel=cancel,
                            current=current, packs_issue=carried.issue)
    if carried.dropped:
        result = replace(result, dropped_units=tuple(carried.dropped))
    return result


def _update_binary(release: Release, inst: Install, *, opener, progress, cancel,
                   current: str | None = None, packs_issue: int | None = None) -> Installed:
    folder = inst.executable.parent
    issue = {} if packs_issue is None else {"packs_issue": packs_issue}
    if _writable(folder):
        downloaded = download(release, inst, dest_dir=folder, opener=opener, progress=progress,
                              cancel=cancel, current=current, **issue)
        return install(downloaded, inst)
    cache = cache_dir()
    problem = private_dir_problem(cache)
    if problem:
        raise UpdateError(problem)
    downloaded = download(release, inst, dest_dir=cache, opener=opener, progress=progress,
                          cancel=cancel, current=current, **issue)
    final = cache / versioned_name(inst.asset, release.version)
    try:
        os.chmod(downloaded.path, _plain_mode(inst.executable))
        os.replace(downloaded.path, final)
    except BaseException:
        _unlink(downloaded.path)
        raise
    return Installed(
        final, None, False,
        f"The folder {folder} is not writable, so {inst.executable.name} was not replaced. "
        f"The verified new version is {final}: use Save to… to put it where you want, or "
        f"replace {inst.executable.name} with it yourself.",
        downloaded.sha256, release.version)


def _carry_packs(release: Release, opener, progress=None, cancel=None, *, current: str | None = None,
                 root=None, verify=None) -> CarriedPacks:
    """The packs installed for the running version, fetched and checked for
    *release* before its binary is fetched (core.packs) - an update that
    cannot bring a unit along stops here, nothing is replaced. A unit the
    new release no longer has (dropped, renamed) cannot be brought along
    and does not stop the update: it is left out and named in the result.

    Each blob may be large: no overall deadline, as for the binary's
    :func:`download` - each read times out (:data:`READ_TIMEOUT`) and
    *cancel* stops it between reads."""
    from core import packs

    if current is None:
        from axross._version import __version__ as current
    units = packs.installed(current, root)
    if not units:
        return CarriedPacks()

    sums_asset = release.asset(SUMS_NAME)
    sums_url = sums_asset.url if sums_asset is not None else None
    checked: list[bytes] = []

    def get(url, max_bytes, hosts):
        if cancel is not None and cancel.is_set():
            raise Cancelled("cancelled")
        data = fetch(url, opener=opener or build_opener(), max_bytes=max_bytes, hosts=hosts,
                     cancel=cancel)
        if url == sums_url and not checked:
            checked.append(data)
        return data
    try:
        done, dropped = packs.install_available(release, units, fetch=packs.Fetcher(get),
                                                root=root, verify=verify, progress=progress)
    except packs.PackError as exc:
        raise UpdateError(f"the packs of {release.version} could not be brought along ({exc}); "
                          "axross was not updated") from None
    if dropped:
        log.warning("update: release %s has no unit %s; not brought along", release.version,
                    ", ".join(dropped))
    # The issue of the SHA256SUMS the packs were checked against (core.packs
    # verified its signature): the binary's download must see the same one.
    issue = packs.packs_issue_of_sums(checked[0].decode("utf-8", "replace")) if checked else None
    return CarriedPacks(done, dropped, issue)


def save_copy(installed: Installed, destination) -> Path:
    """Copy a verified update to *destination* (Save to…), checked again,
    with the mode it has."""
    source = Path(installed.path)
    dest = Path(destination)
    mode = _plain_mode(source) | stat.S_IRUSR | stat.S_IWUSR
    tmp = _copy_verified(source, dest.parent, dest.name, installed.sha256, mode)
    try:
        os.replace(tmp, dest)
    except BaseException:
        _unlink(tmp)
        raise
    _fsync_dir(dest.parent)
    return dest


def check_restartable(path, expected_sha256: str = "") -> Path:
    """*path* as it may be started: an executable file whose SHA-256 is
    still *expected_sha256* (the verified one) when that is given."""
    exe = Path(path)
    if not exe.is_file() or not os.access(exe, os.X_OK):
        raise UpdateError(f"{exe} is not an executable file")
    if expected_sha256:
        hasher = hashlib.sha256()
        with open(exe, "rb") as fh:
            while chunk := fh.read(_CHUNK * 16):
                hasher.update(chunk)
        if hasher.hexdigest() != expected_sha256:
            raise ChecksumError(f"{exe} changed since it was verified - not started")
    return exe


def restart(path, *, expected_sha256: str = "", popen=None) -> None:
    """Start the installed binary as a new, independent process (Restart
    Now); the caller then quits. Its SHA-256 is checked once more right
    before. A frozen child unpacks itself afresh
    (core.subprocess_env.relaunch_env)."""
    from core.subprocess_env import relaunch_env

    exe = check_restartable(path, expected_sha256)
    popen = popen if popen is not None else subprocess.Popen
    popen([str(exe)], env=relaunch_env(os.environ, frozen=True), start_new_session=True,
          stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
          close_fds=True)


# -- settings ----------------------------------------------------------------------------


def _bool_setting(key: str, default: bool) -> bool:
    value = OL.read_setting(key, default)
    return value if type(value) is bool else default


def _set_bool(key: str, value) -> None:
    if type(value) is not bool:
        raise ValueError(f"{key} must be true or false, not {value!r}")
    OL.write_setting(key, value)


def check_at_start() -> bool:
    return _bool_setting(SETTING_CHECK, True)


def set_check_at_start(value: bool) -> None:
    _set_bool(SETTING_CHECK, value)


def auto_download() -> bool:
    return _bool_setting(SETTING_AUTO, False)


def set_auto_download(value: bool) -> None:
    _set_bool(SETTING_AUTO, value)


def skipped_version() -> str:
    value = OL.read_setting(SETTING_SKIPPED, "")
    return value if isinstance(value, str) and _CANONICAL.fullmatch(value) else ""


def set_skipped_version(value: str) -> None:
    if value != "" and not (isinstance(value, str) and _CANONICAL.fullmatch(value)):
        raise ValueError(f"a skipped version must be x.y.z, not {value!r}")
    OL.write_setting(SETTING_SKIPPED, value)


def last_check() -> tuple[float | None, str]:
    """(when, what) of the last check; (None, "") when none is stored."""
    value = OL.read_setting(SETTING_LAST)
    if not isinstance(value, dict):
        return None, ""
    when, text = value.get("time"), value.get("text")
    if type(when) not in (int, float) or not math.isfinite(when) or when <= 0:
        return None, ""
    return float(when), clean_text(text, MAX_STATUS_CHARS)


def record_check(text: str, when: float | None = None) -> None:
    OL.write_setting(SETTING_LAST, {
        "time": float(time.time() if when is None else when),
        "text": clean_text(text, MAX_STATUS_CHARS),
    })


def start_check_allowed(environ=None) -> tuple[bool, str]:
    """Whether the check at start may run, and why not."""
    environ = os.environ if environ is None else environ
    if (environ.get(NO_CHECK_ENV) or "").strip().lower() in _TRUTHY:
        return False, f"{NO_CHECK_ENV} is set"
    if not check_at_start():
        return False, "switched off in Settings > Updates"
    from core.security_mode import is_paranoid

    if is_paranoid():
        return False, "paranoid security mode: no automatic network request at start"
    return True, ""


__all__ = [
    "ALLOWED_HOSTS",
    "Asset",
    "Cancelled",
    "CarriedPacks",
    "CheckResult",
    "ChecksumError",
    "Downloaded",
    "FLAVOR_FILE",
    "Install",
    "Installed",
    "NotWritable",
    "RateLimited",
    "Release",
    "SIG_NAME",
    "SignatureError",
    "TRUSTED_KEYS",
    "UpdateError",
    "asset_name",
    "build_opener",
    "check",
    "detect_install",
    "download",
    "install",
    "is_newer",
    "parse_release",
    "parse_sums",
    "parse_version",
    "proxy_handler",
    "restart",
    "save_copy",
    "update",
    "verify_signature",
]
