"""Self-update of the one-file binaries (axross-full, axross-slim).

Once per start (Settings > Updates, on by default) axross asks GitHub for
the latest release of ``c0decave/axross``, in the background, with one
request. When it is newer, the window says so; *Download* fetches the
binary of this build's kind, checks it and puts it in place. It takes
effect at the next start - nothing that was downloaded is ever run before
its checksum matched, and only on *Restart Now*.

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
  (:data:`MAX_API_BYTES`, :data:`MAX_SUMS_BYTES`, :data:`MAX_ASSET_BYTES`)
  and a download must have exactly the size the release states;
* the SHA-256 must equal the entry of the release's ``SHA256SUMS`` (no
  entry, no file: refused) and, where the API gives one, its ``digest``
  of the same asset - both from the same release;
* a refused or cut download leaves nothing behind.

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
from dataclasses import dataclass
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
#: Written into the bundle by build/axross.spec: "full" or "slim". In the
#: first-party folder "axross" (core.third_party.FIRST_PARTY): a file at
#: the bundle root would be an unclaimed part of the bundle to the release
#: gate (tests/test_third_party_bundle.py).
FLAVOR_FILE = "axross-bundle-flavor.txt"
FLAVOR_PATH = ("axross", FLAVOR_FILE)
FLAVORS = ("full", "slim")

MAX_API_BYTES = 1 << 20
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
    flavor: str = ""  # "full", "slim", "" (unknown or not frozen)
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


def asset_name(platform: str, machine: str, flavor: str) -> str:
    """The release asset of a binary of *flavor* on *platform*/*machine*."""
    machine = (machine or "").lower()
    if platform.startswith("linux") and machine in ("x86_64", "amd64") and flavor in FLAVORS:
        return f"axross-{flavor}"
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
    return Install(True, flavor, asset_name(platform, machine, flavor), exe, platform, machine)


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
        raise UpdateError(f"the latest release's tag {clean_text(tag, 40)!r} is not a version")
    page = data.get("html_url")
    if page != f"{RELEASES_PREFIX}tag/{tag}":
        raise UpdateError("the latest release names no page of c0decave/axross")
    raw_assets = data.get("assets")
    if not isinstance(raw_assets, list):
        raise UpdateError("the latest release has no list of files")
    assets = tuple(a for a in (_asset(r, tag) for r in raw_assets[:100]) if a is not None)
    return Release(
        version="%d.%d.%d" % version,
        tag=tag,
        page_url=page,
        notes=clean_text(data.get("body"), MAX_NOTES_CHARS, lines=True),
        assets=assets,
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


def _check_url(url: str) -> str:
    try:
        parts = urllib.parse.urlsplit(url)
        host = (parts.hostname or "").lower()
        port = parts.port
    except ValueError:
        raise UpdateError(f"refused a malformed address: {url[:100]!r}") from None
    if parts.scheme != "https":
        raise UpdateError(f"refused {host or url[:100]}: only https is used for updates")
    if host not in ALLOWED_HOSTS or port not in (None, 443) or parts.username or parts.password:
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
          cancel: threading.Event | None = None) -> bytes | int:
    """GET *url* over https from an allowed host, following up to
    :data:`MAX_REDIRECTS` redirects (each target checked). Returns the body,
    or with *sink* hands each chunk to it and returns the byte count. More
    than *max_bytes*, or past *deadline* (time.monotonic), is refused."""
    current = url
    for _hop in range(MAX_REDIRECTS + 1):
        host = _check_url(current)
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
    except ValueError:
        raise UpdateError("GitHub's answer is not JSON") from None
    if isinstance(data, dict):
        for flag in ("draft", "prerelease"):
            if data.get(flag) is True:
                return CheckResult(current, None, False,
                                   f"The latest release is a {flag}; ignored.")
    release = parse_release(data)
    if is_newer(release.version, current):
        message = f"axross {release.version} is available (this is {current})."
        return CheckResult(current, release, True, message)
    return CheckResult(current, release, False,
                       f"axross {current} is up to date (latest release: {release.version}).")


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
    base = os.environ.get("XDG_CACHE_HOME") or os.path.join(os.path.expanduser("~"), ".cache")
    return Path(base) / "axross" / "update"


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


def _expected_sha256(release: Release, asset: Asset, opener) -> str:
    sums_asset = release.asset(SUMS_NAME)
    if sums_asset is None:
        raise ChecksumError(f"release {release.version} has no {SUMS_NAME} - refused")
    if sums_asset.size > MAX_SUMS_BYTES:
        raise ChecksumError(f"{SUMS_NAME} is larger than {MAX_SUMS_BYTES} bytes - refused")
    data = fetch(sums_asset.url, opener=opener, max_bytes=sums_asset.size,
                 deadline=time.monotonic() + API_TIMEOUT, timeout=API_TIMEOUT)
    if sums_asset.digest and hashlib.sha256(data).hexdigest() != sums_asset.digest:
        raise ChecksumError(f"{SUMS_NAME} differs from GitHub's digest of it - refused")
    expected = parse_sums(data.decode("utf-8", errors="replace")).get(asset.name)
    if expected is None:
        raise ChecksumError(f"the {SUMS_NAME} of release {release.version} has no entry for "
                            f"{asset.name} - refused")
    if asset.digest and asset.digest != expected:
        raise ChecksumError(f"GitHub's digest of {asset.name} differs from {SUMS_NAME} - refused")
    return expected


def download(release: Release, inst: Install, *, dest_dir, opener=None,
             progress: Callable[[int, int], None] | None = None,
             cancel: threading.Event | None = None) -> Downloaded:
    """Fetch this build's asset of *release* into a hidden file in
    *dest_dir* and check it against the release's SHA256SUMS. The file is
    removed on any failure."""
    if not inst.can_download:
        raise UpdateError(inst.why_not())
    asset = release.asset(inst.asset)
    if asset is None:
        raise UpdateError(f"release {release.version} has no {inst.asset}")
    if asset.size > MAX_ASSET_BYTES:
        raise UpdateError(f"{asset.name} is larger than {MAX_ASSET_BYTES} bytes - refused")
    opener = opener if opener is not None else build_opener()
    expected = _expected_sha256(release, asset, opener)
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
           cancel: threading.Event | None = None) -> Installed:
    """Download, verify and install *release* for *inst*. A folder that is
    not writable gets nothing: the verified file goes to :func:`cache_dir`
    and the result says so (the window offers Save to…)."""
    if not inst.can_download:
        raise UpdateError(inst.why_not())
    folder = inst.executable.parent
    if _writable(folder):
        downloaded = download(release, inst, dest_dir=folder, opener=opener, progress=progress,
                              cancel=cancel)
        return install(downloaded, inst)
    cache = cache_dir()
    cache.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(cache, 0o700)
    except OSError:
        pass
    downloaded = download(release, inst, dest_dir=cache, opener=opener, progress=progress,
                          cancel=cancel)
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
    "CheckResult",
    "ChecksumError",
    "Downloaded",
    "FLAVOR_FILE",
    "Install",
    "Installed",
    "NotWritable",
    "RateLimited",
    "Release",
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
]
