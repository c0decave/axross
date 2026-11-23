"""Updates of axross-markdown's one-file programs from its signed GitHub releases.

The design is axross's (core.self_update) and axross-amp's (src/update.rs):
nothing that was downloaded runs, or replaces anything, before the
release's ``SHA256SUMS`` verified with the pinned key and the file had its
signed SHA-256.

Which file (:func:`detect_install`, :func:`asset_name` - the version in the
name: an older release's file can never stand for a newer one):

====================  ==========================================================
pip, pipx, a source   never replaced: the notice says ``pip install -U axross-markdown``
Linux binary          ``axross-markdown-X.Y.Z-linux-x86_64``
the AppImage          ``axross-markdown-X.Y.Z-x86_64.AppImage``, put in place of
                      ``$APPIMAGE`` (the AppImage file itself, not the binary in it)
macOS binary          ``axross-markdown-X.Y.Z-macos-arm64``
the macOS app         not in place: the program inside ``axross Markdown.app``
                      is part of its signed seal - the notice points to the release
Windows               ``axross-markdown-X.Y.Z-windows-x64.exe``; axross-mdcat.exe
                      ``axross-mdcat-X.Y.Z-windows-x64.exe``
====================  ==========================================================

No archive is ever fetched or unpacked: the files are the bare programs.

Checks, in this order, before a byte of the program is fetched:

* every request and every redirect goes over https to one of
  :data:`ALLOWED_HOSTS` (no user name, no port but 443); redirects are
  followed here one by one (at most :data:`MAX_REDIRECTS`), urllib's own
  handling is off; every answer is bounded (:data:`MAX_API_BYTES`,
  :data:`MAX_SUMS_BYTES`, :data:`SIG_BYTES`, :data:`MAX_ASSET_BYTES`);
* the release is strictly newer than the running program (no downgrade, no
  same version again);
* a file's URL is the release's own download URL;
* ``SHA256SUMS.sig`` is the raw 64-byte Ed25519 signature of the exact bytes
  of ``SHA256SUMS`` by a key of :data:`TRUSTED_KEYS` (core.ed25519_pure) -
  checked before a line of ``SHA256SUMS`` is read;
* the program's file has its entry in the signed ``SHA256SUMS``, the size the
  release states (below the cap) and that SHA-256 - and GitHub's ``digest``
  where the API gives one.

Then (:func:`install`): the file, written beside the program (the same file
system), is hashed once more and run once - ``--self-test`` must answer
``axross-markdown X.Y.Z ok`` within :data:`SELF_TEST_SECONDS` - before one
rename puts it in place; the old program stays as ``<name>.previous``.
Windows lets a running program be renamed, not overwritten: the running
``.exe`` is renamed aside first. Should the program in place not be the
checked one, or not answer its self-test there, the old one is put back
(:func:`roll_back`). It takes effect at the next start.

Settings (``~/.config/axross-markdown/settings.json``, core.markdown_settings,
written only when the user sets it): ``update_mode`` - "off", "notify" (the
default: say so when a newer release is out) or "auto" (download, check and
install it, say so). The time of the last check and the newer version it found
are the program's state (``~/.local/state/axross-markdown/state.json``). The window checks at its start and every 24 hours
(:class:`Scheduler`), always off its thread; ``AXROSS_MARKDOWN_NO_UPDATE_CHECK=1``
keeps those checks off whatever the setting says. ``--check-update`` and
``--update`` ask at once.
"""

from __future__ import annotations

import contextlib
import hashlib
import http.client
import json
import logging
import os
import platform as _platform
import re
import secrets
import ssl
import stat
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from base64 import b64decode
from binascii import Error as Base64Error
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

log = logging.getLogger(__name__)

PROGRAM = "axross-markdown"
TERMINAL_PROGRAM = "axross-mdcat"
REPOSITORY = "c0decave/axross-markdown"
LATEST_URL = f"https://api.github.com/repos/{REPOSITORY}/releases/latest"
RELEASES_PAGE = f"https://github.com/{REPOSITORY}/releases"
DOWNLOAD_PREFIX = f"https://github.com/{REPOSITORY}/releases/download/"
#: The only hosts a request or a redirect may reach (https only).
ALLOWED_HOSTS = frozenset({
    "api.github.com",
    "github.com",
    "release-assets.githubusercontent.com",
    "objects.githubusercontent.com",
})
SUMS_NAME = "SHA256SUMS"
#: The detached signature of SHA256SUMS: the raw 64 bytes of an Ed25519 signature.
SIG_NAME = SUMS_NAME + ".sig"
SIG_BYTES = 64
#: The public halves (raw 32 bytes, base64) of the keys a SHA256SUMS may be signed with; one verifying
#: is enough. More than one only while a key is rotated: the new key is pinned here a release before the
#: releases are signed with it. The private key never leaves the maintainer's machine (scripts/sign_release.py).
TRUSTED_KEYS: tuple[str, ...] = (
    "G+6OeUD/+0CE1UsDsnVTl7HBOOXtphDXycrBnk6EbGQ=",  # md-update-signing, from 0.17.0 on
)
MAX_API_BYTES = 1 << 20
MAX_SUMS_BYTES = 64 << 10
#: The largest program file fetched (the window's binary is about 90 MB, its AppImage a little more).
MAX_ASSET_BYTES = 400 << 20
MAX_REDIRECTS = 5
MAX_ASSETS = 200
MAX_SUMS_LINES = 500
MAX_NOTES_CHARS = 20_000
API_TIMEOUT = 15.0
READ_TIMEOUT = 60.0
SELF_TEST_SECONDS = 30.0
#: How long the new program runs before the old one (.previous) goes.
KEEP_PREVIOUS_SECONDS = 60
_CHUNK = 1 << 16

NO_CHECK_ENV = "AXROSS_MARKDOWN_NO_UPDATE_CHECK"
SETTING_MODE = "update_mode"
SETTING_LAST = "update_last_check"
SETTING_SEEN = "update_available"
MODES = ("off", "notify", "auto")
DEFAULT_MODE = "notify"
#: The checks' interval: once a day.
INTERVAL = 24 * 3600
#: How a pip install is updated: the release's own wheel - the releases since 0.17.0 are on GitHub only, so
#: "pip install -U axross-markdown" upgraded nothing (PyPI's latest was 0.16.8). pip_hint names the file.
PIP_HINT = f"pip install --upgrade the wheel of the latest release ({RELEASES_PAGE}/latest)"


def pip_hint(version: str | None = None) -> str:
    """The pip command that installs *version*'s wheel from its release (else PIP_HINT)."""
    if not version or parse_version(version) is None:
        return PIP_HINT
    return f"pip install --upgrade {DOWNLOAD_PREFIX}v{version}/axross_markdown-{version}-py3-none-any.whl"


_VERSION = re.compile(r"v?([0-9]{1,6})\.([0-9]{1,6})\.([0-9]{1,6})", re.ASCII)
_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,199}", re.ASCII)
_HEX = re.compile(r"[0-9a-f]{64}", re.ASCII)
_TRUTHY = {"1", "true", "yes", "on"}
#: What the updater never fetches: an archive is never unpacked here.
ARCHIVE_SUFFIXES = (".zip", ".tar", ".gz", ".tgz", ".bz2", ".xz", ".zst", ".7z", ".rar", ".dmg", ".pkg",
                    ".msi", ".whl", ".deb", ".rpm")


class UpdateError(Exception):
    """An update refused or failed: its text is what the user is told."""


class HostRefused(UpdateError):
    """A request or redirect to anything but https on GitHub's hosts."""


class TooLarge(UpdateError):
    """An answer above its cap."""


class SignatureError(UpdateError):
    """SHA256SUMS not signed with a pinned key."""


class ChecksumError(UpdateError):
    """A file whose SHA-256 or size is not the signed one."""


class DowngradeRefused(UpdateError):
    """A release that is not newer than the running program."""


class SelfTestFailed(UpdateError):
    """The new program did not run here."""


class NotWritable(UpdateError):
    """The program's folder cannot be written."""


class Cancelled(UpdateError):
    pass


# -- versions -------------------------------------------------------------------------------------

def parse_version(text) -> tuple[int, int, int] | None:
    """``X.Y.Z`` or ``vX.Y.Z`` (each at most six digits), nothing else."""
    if not isinstance(text, str):
        return None
    found = _VERSION.fullmatch(text.strip())
    return tuple(int(part) for part in found.groups()) if found else None  # type: ignore[return-value]


def is_newer(candidate, current) -> bool:
    new, now = parse_version(candidate), parse_version(current)
    return new is not None and now is not None and new > now


def current_version() -> str:
    from core.markdown_cli import program_version

    return program_version()


# -- what runs here -------------------------------------------------------------------------------

@dataclass(frozen=True)
class Install:
    """How the running program was installed: *kind* "pip" (pip, pipx, a source tree), "binary", "appimage",
    "macapp" (not replaced in place) or "unsupported"; the *system* ("linux", "macos", "windows"), the
    *program* (axross-markdown or axross-mdcat) and the *target* file an update replaces."""

    kind: str
    system: str
    program: str = PROGRAM
    target: Path | None = None
    why: str = ""

    @property
    def can_update(self) -> bool:
        return self.kind in ("binary", "appimage") and self.target is not None

    def why_not(self) -> str:
        if self.kind == "pip":
            return f"installed with pip - to update it: {PIP_HINT}"
        if self.kind == "macapp":
            return f"the app is updated from the disk image of the release: {RELEASES_PAGE}/latest"
        return self.why or "no release file for this system"


def _system(platform: str) -> str:
    if platform.startswith("linux"):
        return "linux"
    if platform == "darwin":
        return "macos"
    if platform in ("win32", "cygwin"):
        return "windows"
    return platform


def detect_install(*, frozen=None, executable=None, environ=None, platform=None, machine=None) -> Install:
    """The Install of the running program."""
    frozen = bool(getattr(sys, "frozen", False)) if frozen is None else frozen
    environ = os.environ if environ is None else environ
    system = _system(sys.platform if platform is None else platform)
    machine = (_platform.machine() if machine is None else machine).lower()
    executable = Path(sys.executable if executable is None else executable)
    program = TERMINAL_PROGRAM if executable.name.lower().startswith(TERMINAL_PROGRAM) else PROGRAM
    if not frozen:
        return Install("pip", system, program)
    wanted = {"linux": ("x86_64", "amd64"), "windows": ("amd64", "x86_64"), "macos": ("arm64", "aarch64")}
    if system not in wanted or machine not in wanted[system]:
        return Install("unsupported", system, program, why=f"no release file for {system} {machine}")
    if program == TERMINAL_PROGRAM and system != "windows":
        return Install("unsupported", system, program, why="axross-mdcat is a program of its own on Windows only")
    if system == "linux":
        image = appimage_of(executable, environ)
        if image is not None:
            return Install("appimage", system, program, image)
    if system == "macos" and _in_app_bundle(executable):
        return Install("macapp", system, program, executable)
    return Install("binary", system, program, executable)


def appimage_of(executable: Path, environ) -> Path | None:
    """The AppImage file the program runs from: ``$APPIMAGE``, when the program runs inside ``$APPDIR``
    and $APPIMAGE is an absolute path to a regular file named ``*.AppImage`` - else None."""
    image, appdir = environ.get("APPIMAGE", ""), environ.get("APPDIR", "")
    if not image or not appdir or not os.path.isabs(image) or not os.path.isabs(appdir):
        return None
    try:
        inside = os.path.commonpath([os.path.realpath(executable), os.path.realpath(appdir)]) \
            == os.path.realpath(appdir)
    except ValueError:
        return None
    path = Path(image)
    try:
        regular = stat.S_ISREG(path.lstat().st_mode)
    except OSError:
        return None
    if not inside or not regular or not path.name.endswith(".AppImage"):
        return None
    return path


def _in_app_bundle(executable: Path) -> bool:
    parts = executable.parts
    return len(parts) >= 4 and parts[-2] == "MacOS" and parts[-3] == "Contents" and parts[-4].endswith(".app")


def asset_name(install: Install, version: str) -> str | None:
    """The release's file for *install* at *version* (None: none is fetched)."""
    if parse_version(version) is None:
        return None
    version = ".".join(map(str, parse_version(version)))
    if install.kind == "appimage":
        return f"{PROGRAM}-{version}-x86_64.AppImage"
    if install.kind != "binary":
        return None
    if install.system == "linux":
        return f"{PROGRAM}-{version}-linux-x86_64"
    if install.system == "macos":
        return f"{PROGRAM}-{version}-macos-arm64"
    if install.system == "windows":
        return f"{install.program}-{version}-windows-x64.exe"
    return None


# -- the network: https to GitHub only, redirects one by one ---------------------------------------

@dataclass
class Reply:
    """One answer, its redirect not followed."""

    status: int
    location: str = ""
    length: int | None = None
    body: object = None  # a readable (read(n))

    def close(self) -> None:
        closing = getattr(self.body, "close", None)
        if closing is not None:
            try:
                closing()
            except OSError:
                pass


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: D401 - urllib's
        return None  # (urllib raises the 3xx as an HTTPError: followed by fetch, checked first)


def tls_context(environ=None, *, candidates=None, count=None, certifi_path: str | None = None) -> ssl.SSLContext:
    """The TLS context the updater asks GitHub with: the default one - and, when that holds no CA certificate
    (a one-file program's OpenSSL, built on Ubuntu, looks for Ubuntu's bundle: on Fedora, Arch, openSUSE or
    macOS it found none, and every check failed with CERTIFICATE_VERIFY_FAILED, said only in the log), the
    host's own bundle (core.tls_env.HOST_CA_FILES: a CA the administrator added is trusted), else certifi's
    when it is there. The user's SSL_CERT_FILE / SSL_CERT_DIR are the user's choice: kept as they are."""
    environ = os.environ if environ is None else environ
    context = ssl.create_default_context()
    if "SSL_CERT_FILE" in environ or "SSL_CERT_DIR" in environ:
        return context
    loaded = (count or (lambda found: int(found.cert_store_stats().get("x509_ca", 0))))
    if loaded(context) > 0:
        return context
    try:
        from core.tls_env import HOST_CA_FILES
    except ImportError:  # (an export without it)
        HOST_CA_FILES = ("/etc/ssl/certs/ca-certificates.crt", "/etc/pki/tls/certs/ca-bundle.crt",
                         "/etc/ssl/ca-bundle.pem", "/etc/ssl/cert.pem")
    if certifi_path is None:
        try:
            import certifi

            certifi_path = certifi.where()
        except ImportError:
            certifi_path = ""
    for path in [*(HOST_CA_FILES if candidates is None else candidates), certifi_path]:
        if not path:
            continue
        try:
            if os.path.isfile(path) and os.path.getsize(path) > 0:
                context.load_verify_locations(cafile=path)
                log.info("updates: the CA certificates of %s", path)
                return context
        except (OSError, ssl.SSLError, ValueError):
            continue
    log.warning("updates: no CA certificates found - GitHub's answer cannot be checked")
    return context


def _network_error(exc: BaseException) -> UpdateError:
    """An error of the network (a connection reset, a time-out, a cut answer) as what the user is told."""
    if isinstance(exc, UpdateError):
        return exc
    if isinstance(exc, TimeoutError) or "timed out" in str(exc):
        what = "GitHub did not answer in time"
    elif isinstance(exc, ssl.SSLError):
        what = f"the secure connection to GitHub failed ({getattr(exc, 'reason', None) or exc})"
    elif isinstance(exc, http.client.HTTPException):
        what = f"GitHub's answer broke off ({type(exc).__name__})"
    else:
        what = f"the connection to GitHub broke off ({getattr(exc, 'strerror', None) or exc})"
    return UpdateError(f"{what} - try again later")


class Web:
    """The real network: urllib without its redirect handling, the environment's proxies, TLS checked with
    tls_context()."""

    def __init__(self, timeout: float = READ_TIMEOUT, context: ssl.SSLContext | None = None) -> None:
        self.timeout = timeout
        self.context = tls_context() if context is None else context
        self.opener = urllib.request.build_opener(urllib.request.ProxyHandler(), _NoRedirect(),
                                                  urllib.request.HTTPSHandler(context=self.context))

    def get(self, url: str) -> Reply:
        request = urllib.request.Request(url, headers={
            "User-Agent": f"{PROGRAM}-updater", "Accept": "application/vnd.github+json, */*"})
        try:
            response = self.opener.open(request, timeout=self.timeout)
        except urllib.error.HTTPError as exc:
            location = exc.headers.get("Location", "") if exc.headers else ""
            exc.close()
            return Reply(exc.code, location or "")
        except (urllib.error.URLError, OSError, ValueError, http.client.HTTPException) as exc:
            reason = getattr(exc, "reason", exc)
            if isinstance(reason, ssl.SSLCertVerificationError):
                raise UpdateError(f"cannot reach GitHub: its certificate could not be checked ({reason.verify_message}"
                                  f") - no CA certificates on this system?") from None
            raise UpdateError(f"cannot reach GitHub: {reason}") from None
        length = response.headers.get("Content-Length")
        try:
            size = int(length) if length is not None else None
        except ValueError:
            size = None
        return Reply(response.status, "", size, response)


def check_url(url: str) -> str:
    """*url* when it may be asked (https, a host of ALLOWED_HOSTS, no user part, no port but 443) - else
    HostRefused."""
    try:
        parts = urllib.parse.urlsplit(url)
        port = parts.port
    except ValueError:
        raise HostRefused("not a valid address - refused") from None
    host = (parts.hostname or "").lower()
    if parts.scheme != "https":
        raise HostRefused(f"not an https address ({parts.scheme or 'none'}) - refused")
    if parts.username is not None or parts.password is not None or "@" in parts.netloc:
        raise HostRefused("an address with a user name - refused")
    if port not in (None, 443):
        raise HostRefused("an address with a port - refused")
    if host not in ALLOWED_HOSTS:
        raise HostRefused(f"{host[:80] or 'no host'} is not GitHub - refused")
    return url


def fetch(url: str, fetcher, max_bytes: int, *, sink=None, progress=None, cancel=None) -> bytes | int:
    """*url*'s body (or, with *sink*, the number of bytes written to it): redirects followed here, each
    checked (check_url); more than *max_bytes*: TooLarge."""
    for _hop in range(MAX_REDIRECTS + 1):
        check_url(url)
        try:
            reply = fetcher.get(url)
        except (OSError, http.client.HTTPException) as exc:  # (a fetcher's own: said as the network's)
            raise _network_error(exc) from None
        if reply.status in (301, 302, 303, 307, 308):
            reply.close()
            if not reply.location:
                raise UpdateError("a redirect without an address - refused")
            url = urllib.parse.urljoin(url, reply.location)
            continue
        try:
            if reply.status != 200:
                if reply.status in (403, 429):
                    raise UpdateError("GitHub refused the request (its rate limit) - try again later")
                raise UpdateError(f"GitHub answered {reply.status} for {url.rsplit('/', 1)[-1][:80]}")
            if reply.length is not None and reply.length > max_bytes:
                raise TooLarge(f"{url.rsplit('/', 1)[-1][:80]} is {reply.length} bytes, more than "
                               f"{max_bytes} - refused")
            try:
                return _read(reply, max_bytes, sink, progress, cancel, url)
            except (OSError, http.client.HTTPException) as exc:
                # (a connection reset, a time-out in the body: the worker died with no word, the controller
                # stuck "busy" for the session, --update a traceback - an UpdateError, as every other failure)
                raise _network_error(exc) from None
        finally:
            reply.close()
    raise UpdateError(f"more than {MAX_REDIRECTS} redirects - refused")


def _read(reply: Reply, max_bytes: int, sink, progress, cancel, url: str):
    data = bytearray()
    count = 0
    while True:
        if cancel is not None and cancel():
            raise Cancelled("cancelled")
        chunk = reply.body.read(_CHUNK)
        if not chunk:
            break
        count += len(chunk)
        if count > max_bytes:
            raise TooLarge(f"{url.rsplit('/', 1)[-1][:80]} is more than {max_bytes} bytes - refused")
        if sink is None:
            data += chunk
        else:
            sink(chunk)
        if progress is not None:
            progress(count)
    return bytes(data) if sink is None else count


# -- the release ----------------------------------------------------------------------------------

@dataclass(frozen=True)
class Asset:
    name: str
    url: str
    size: int
    digest: str = ""  # GitHub's sha256, where the API gives one


@dataclass(frozen=True)
class Release:
    version: str
    tag: str
    assets: dict = field(default_factory=dict)
    notes: str = ""

    @property
    def page(self) -> str:
        return f"{RELEASES_PAGE}/tag/{self.tag}"


def parse_release(data) -> Release:
    """The release of the API's answer *data* (a dict): its version from the tag, its assets with their
    own download URLs only."""
    if not isinstance(data, dict):
        raise UpdateError("GitHub's answer is no release")
    tag = data.get("tag_name")
    version = parse_version(tag)
    if version is None:
        raise UpdateError("the latest release has no vX.Y.Z tag")
    if data.get("draft") or data.get("prerelease"):
        raise UpdateError("the latest release is a draft or a pre-release")
    assets = {}
    raw_assets = data.get("assets") if isinstance(data.get("assets"), list) else []
    for raw in raw_assets[:MAX_ASSETS]:
        if not isinstance(raw, dict):
            continue
        name, url, size = raw.get("name"), raw.get("browser_download_url"), raw.get("size")
        if not isinstance(name, str) or not _NAME.fullmatch(name) or type(size) is not int or size < 0:
            continue
        if url != f"{DOWNLOAD_PREFIX}{tag}/{name}" or name in assets:
            continue
        digest = raw.get("digest") if isinstance(raw.get("digest"), str) else ""
        digest = digest[7:] if digest.startswith("sha256:") and _HEX.fullmatch(digest[7:]) else ""
        assets[name] = Asset(name, url, size, digest)
    notes = data.get("body") if isinstance(data.get("body"), str) else ""
    return Release(".".join(map(str, version)), tag, assets, notes[:MAX_NOTES_CHARS])


@dataclass(frozen=True)
class CheckResult:
    release: Release
    current: str
    newer: bool

    @property
    def text(self) -> str:
        if self.newer:
            return f"{PROGRAM} {self.release.version} is available (this is {self.current})"
        return f"{PROGRAM} {self.current} is up to date"


def check(current: str | None = None, fetcher=None) -> CheckResult:
    """The latest release, and whether it is newer than *current* (the running program's version)."""
    current = current_version() if current is None else current
    fetcher = Web(API_TIMEOUT) if fetcher is None else fetcher
    body = fetch(LATEST_URL, fetcher, MAX_API_BYTES)
    try:
        data = json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, ValueError, RecursionError):
        raise UpdateError("GitHub's answer is no JSON") from None
    release = parse_release(data)
    return CheckResult(release, current, is_newer(release.version, current))


# -- the signature and the checksums --------------------------------------------------------------

def _keys(keys) -> list[bytes]:
    usable = []
    for key in keys:
        try:
            raw = b64decode(key, validate=True) if isinstance(key, str) else b""
        except (Base64Error, ValueError):
            raw = b""
        if len(raw) == 32:
            usable.append(raw)
        else:
            log.error("update: a pinned key is not 32 bytes of base64 - skipped")
    return usable


def verify_signature(data: bytes, signature, keys=None) -> None:
    """SignatureError unless *signature* is a valid Ed25519 signature of exactly *data* by one of *keys*
    (default TRUSTED_KEYS)."""
    from core import ed25519_pure

    keys = TRUSTED_KEYS if keys is None else keys
    if not isinstance(signature, (bytes, bytearray)) or len(signature) != SIG_BYTES:
        size = len(signature) if isinstance(signature, (bytes, bytearray)) else "no"
        raise SignatureError(f"{SIG_NAME} has {size} bytes, an Ed25519 signature {SIG_BYTES} - refused")
    public = _keys(keys)
    if not public:
        raise SignatureError("no usable release key to check the signature with - refused")
    if not any(ed25519_pure.verify(key, bytes(data), bytes(signature)) for key in public):
        raise SignatureError(f"{SUMS_NAME} is not signed with axross-markdown's release key - refused")


def parse_sums(text: str) -> dict[str, str]:
    """``<sha256>  <name>`` (or `` *<name>``) lines: {name: sha256}; anything else refused."""
    sums: dict[str, str] = {}
    for number, line in enumerate(text.splitlines()):
        if number >= MAX_SUMS_LINES:
            raise UpdateError(f"{SUMS_NAME} has more than {MAX_SUMS_LINES} lines - refused")
        if not line.strip():
            continue
        digest, _sep, name = line.partition(" ")
        name = name[1:] if name[:1] in (" ", "*") else name
        if not _HEX.fullmatch(digest) or not _NAME.fullmatch(name):
            raise UpdateError(f"{SUMS_NAME}: a line that is not '<sha256>  <name>' - refused")
        if name in sums:
            raise UpdateError(f"{SUMS_NAME} names {name} twice - refused")
        sums[name] = digest
    return sums


def signed_sums(release: Release, fetcher) -> dict[str, str]:
    """The release's checksums, after their signature verified."""
    sums_asset, sig_asset = release.assets.get(SUMS_NAME), release.assets.get(SIG_NAME)
    if sig_asset is None:
        raise SignatureError(f"the release has no {SIG_NAME} - refused")
    if sums_asset is None:
        raise ChecksumError(f"the release has no {SUMS_NAME} - refused")
    if sig_asset.size != SIG_BYTES:
        raise SignatureError(f"{SIG_NAME} is {sig_asset.size} bytes, a signature {SIG_BYTES} - refused")
    if sums_asset.size > MAX_SUMS_BYTES:
        raise TooLarge(f"{SUMS_NAME} is {sums_asset.size} bytes, more than {MAX_SUMS_BYTES} - refused")
    signature = fetch(sig_asset.url, fetcher, SIG_BYTES)
    data = fetch(sums_asset.url, fetcher, MAX_SUMS_BYTES)
    verify_signature(data, signature)
    try:
        return parse_sums(data.decode("utf-8"))
    except UnicodeDecodeError:
        raise UpdateError(f"{SUMS_NAME} is no text - refused") from None


# -- download, install ----------------------------------------------------------------------------

@dataclass(frozen=True)
class Downloaded:
    path: Path
    sha256: str
    version: str
    target: Path


@dataclass(frozen=True)
class Installed:
    path: Path
    previous: Path
    sha256: str
    version: str


def previous_of(target: Path) -> Path:
    return target.with_name(target.name + ".previous")


def _part_prefix(target: Path) -> str:
    return f".{target.name}.update-"


def sha256_of(path: Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        while True:
            chunk = handle.read(1 << 20)
            if not chunk:
                return digest.hexdigest()
            digest.update(chunk)


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


def _unlink(path: Path) -> None:
    try:
        os.unlink(path)
    except OSError:
        pass


def download(release: Release, install: Install, current: str, fetcher=None, *, progress=None,
             cancel=None) -> Downloaded:
    """The program's file of *release*, checked (signature, entry, size, SHA-256), beside the program."""
    if not install.can_update:
        raise UpdateError(install.why_not())
    if not is_newer(release.version, current):
        raise DowngradeRefused(f"{release.version} is not newer than {current} - refused")
    name = asset_name(install, release.version)
    if name is None or name.lower().endswith(ARCHIVE_SUFFIXES):
        raise UpdateError(install.why_not())
    asset = release.assets.get(name)
    if asset is None:
        raise UpdateError(f"the release {release.version} has no {name}")
    if asset.size > MAX_ASSET_BYTES:
        raise TooLarge(f"{name} is {asset.size} bytes, more than {MAX_ASSET_BYTES} - refused")
    if asset.size == 0:
        raise ChecksumError(f"{name} is empty - refused")
    fetcher = Web() if fetcher is None else fetcher
    sums = signed_sums(release, fetcher)
    expected = sums.get(name)
    if expected is None:
        raise ChecksumError(f"{name} has no entry in the signed {SUMS_NAME} - refused")
    if asset.digest and asset.digest != expected:
        raise ChecksumError(f"GitHub's digest of {name} is not the signed one - refused")
    target = install.target
    folder = target.parent
    if not os.access(folder, os.W_OK):
        raise NotWritable(f"{folder} cannot be written: the program stays as it is "
                          f"(the release: {release.page})")
    cleanup_partials(target)
    # (Windows runs a program by its contents, but its self-test is run as an .exe - the name says so)
    suffix = ".part.exe" if install.system == "windows" else ".part"
    # (a random part: an Install click while auto mode's own download ran had the same name - FileExistsError)
    temp = folder / f"{_part_prefix(target)}{release.version}-{os.getpid()}-{secrets.token_hex(4)}{suffix}"
    try:
        fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0), 0o700)
    except PermissionError:  # (Windows: os.access says Program Files may be written)
        raise NotWritable(f"{folder} cannot be written: the program stays as it is "
                          f"(the release: {release.page})") from None
    except OSError as exc:
        raise UpdateError(f"the download cannot be kept in {folder}: {exc.strerror or exc}") from None
    digest = hashlib.sha256()
    try:
        with os.fdopen(fd, "wb") as handle:
            def sink(chunk: bytes) -> None:
                digest.update(chunk)
                try:
                    handle.write(chunk)
                except OSError as exc:  # (the disk full: no network's fault)
                    raise UpdateError(f"the download cannot be kept in {folder}: {exc.strerror or exc}") from None

            got = fetch(asset.url, fetcher, asset.size, sink=sink, progress=progress, cancel=cancel)
            try:
                handle.flush()
                os.fsync(handle.fileno())
            except OSError as exc:
                raise UpdateError(f"the download cannot be kept in {folder}: {exc.strerror or exc}") from None
        if got != asset.size:
            raise ChecksumError(f"{name}: {got} bytes came, the release says {asset.size} - refused")
        if digest.hexdigest() != expected:
            raise ChecksumError(f"{name}: its SHA-256 is not the signed one - refused")
        try:
            mode = stat.S_IMODE(target.stat().st_mode) | 0o700
        except OSError:
            mode = 0o755
        os.chmod(temp, mode & 0o755 | 0o700)
    except BaseException:
        _unlink(temp)
        raise
    return Downloaded(temp, expected, release.version, target)


def self_test_answer(version: str, program: str = PROGRAM) -> str:
    """What ``--self-test`` of *program* at *version* says when it can run here."""
    return f"{program} {version} ok"


def _child_env() -> dict:
    """The environment for a child program: core.subprocess_env's clean one (no loader path of a one-file
    build inherited) - the environment as it is where an export has no such module."""
    try:
        from core.subprocess_env import clean_child_env

        return clean_child_env()
    except Exception:  # noqa: BLE001 - (an export without it)
        return dict(os.environ)


def _run_alone(args, *, timeout: float, env: dict | None = None, **kwargs):
    """subprocess.run of *args* in a process group of its own, all of it ended at the time-out: a one-file
    program is its bootloader's child - killing the bootloader alone left the program running. *env*: the
    child's environment (else _child_env)."""
    if os.name == "nt":
        kwargs["creationflags"] = kwargs.get("creationflags", 0) | getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
    else:
        kwargs["start_new_session"] = True
    capture = kwargs.pop("capture_output", False)
    if capture:
        kwargs["stdout"] = kwargs["stderr"] = subprocess.PIPE
    check = kwargs.pop("check", False)
    with subprocess.Popen(args, env=_child_env() if env is None else env, **kwargs) as process:
        try:
            out, err = process.communicate(timeout=timeout)
        except subprocess.TimeoutExpired:
            _end_group(process)
            process.communicate()
            raise
        if check and process.returncode:
            raise subprocess.CalledProcessError(process.returncode, args, out, err)
        return subprocess.CompletedProcess(args, process.returncode, out, err)


def _end_group(process) -> None:
    """*process* and every process it started (its group; on Windows its tree) ended."""
    try:
        if os.name == "nt":
            subprocess.run(["taskkill", "/T", "/F", "/PID", str(process.pid)], capture_output=True, timeout=30,
                           check=False, env=_child_env())
        else:
            import signal

            os.killpg(process.pid, signal.SIGKILL)
    except (OSError, subprocess.SubprocessError):
        pass
    try:
        process.kill()
    except OSError:
        pass


def self_test(path: Path, version: str, program: str = PROGRAM, *, timeout: float = SELF_TEST_SECONDS,
              run=None) -> None:
    """*path* run once with ``--self-test``: it must answer :func:`self_test_answer` - else SelfTestFailed."""
    env = _child_env()
    env[NO_CHECK_ENV] = "1"
    env.setdefault("QT_QPA_PLATFORM", "offscreen")
    run = _run_alone if run is None else run
    try:
        done = run([str(path), "--self-test"], stdin=subprocess.DEVNULL, capture_output=True,
                   timeout=timeout, env=env, check=False)
    except subprocess.TimeoutExpired:
        raise SelfTestFailed(f"it did not answer within {timeout:.0f} s") from None
    except OSError as exc:
        raise SelfTestFailed(f"it cannot be run here ({exc.strerror or exc})") from None
    out = (done.stdout or b"")[-4096:].decode("utf-8", "replace").strip().splitlines()
    if done.returncode == 0 and out and out[-1].strip() == self_test_answer(version, program):
        return
    said = next((line.strip() for line in (done.stderr or b"")[-4096:].decode("utf-8", "replace").splitlines()
                 if line.strip()), "")
    raise SelfTestFailed(f"it does not run here (status {done.returncode}{': ' + said[:200] if said else ''})")


def install(downloaded: Downloaded, inst: Install, *, test=None, after=None) -> Installed:
    """*downloaded* put in place of the program: hashed again and run once (*test*: self_test), the old
    program kept as ``<name>.previous``, one rename. *after(path)*: a check of the program in place - its
    failure (an exception) puts the old one back."""
    test = (lambda path, version: self_test(path, version, inst.program)) if test is None else test
    path, target = downloaded.path, downloaded.target
    try:
        if sha256_of(path) != downloaded.sha256:
            raise ChecksumError("the downloaded file changed since it was checked - refused")
        try:
            test(path, downloaded.version)
        except SelfTestFailed as failed:
            raise SelfTestFailed(f"{PROGRAM} {downloaded.version} was not installed: {failed}; "
                                 "this one is kept") from None
    except BaseException:
        _unlink(path)
        raise
    previous = previous_of(target)
    try:
        mode = previous.lstat().st_mode
    except OSError:
        mode = None
    if mode is not None:
        # (a symlink planted there: the copy below wrote through it - removed, the link itself; a folder: refused)
        if stat.S_ISREG(mode) or stat.S_ISLNK(mode):
            try:
                os.unlink(previous)
            except OSError:
                pass
        else:
            _unlink(path)
            raise UpdateError(f"{previous} is in the way (no file) - the program stays as it is")
    if inst.system == "windows" or os.name == "nt":
        # (a running program may be renamed, not overwritten)
        try:
            os.replace(target, previous)
        except OSError as exc:
            _unlink(path)
            raise UpdateError(f"{target}: {exc.strerror or exc}") from None
        try:
            os.replace(path, target)
        except OSError as exc:
            _unlink(path)
            for attempt in range(3):  # (an antivirus holding the file a moment: tried again)
                try:
                    os.replace(previous, target)
                    break
                except OSError:
                    if attempt == 2:
                        raise UpdateError(f"{target}: {exc.strerror or exc}; the program could not be put back "
                                          f"either: it is {previous} - rename it to {target.name}") from None
                    time.sleep(0.5)
            raise UpdateError(f"{target}: {exc.strerror or exc}; this one is kept") from None
    else:
        try:
            try:
                os.link(target, previous)
            except OSError:
                import shutil

                shutil.copy2(target, previous)
            os.replace(path, target)
        except OSError as exc:
            _unlink(path)
            raise UpdateError(f"{target}: {exc.strerror or exc}; this one is kept") from None
    _fsync_dir(target.parent)
    installed = Installed(target, previous, downloaded.sha256, downloaded.version)
    try:
        if sha256_of(target) != downloaded.sha256:
            raise ChecksumError("the program in place is not the file checked")
        if after is not None:
            after(target)
    except Exception as exc:  # noqa: BLE001 - whatever failed: the old one back
        roll_back(installed)
        raise SelfTestFailed(f"{PROGRAM} {downloaded.version} did not run in place ({exc}); "
                             "the old one is back") from None
    return installed


def roll_back(installed: Installed) -> None:
    """The old program (.previous) put back in place of the new one."""
    try:
        regular = stat.S_ISREG(installed.previous.lstat().st_mode)
    except OSError:
        regular = False
    if not regular:
        raise UpdateError(f"{installed.previous} is not there - the new program stays")
    os.replace(installed.previous, installed.path)
    _fsync_dir(installed.path.parent)


def cleanup_previous(target: Path) -> None:
    """The old program (.previous) removed - a regular file of that name only (the new one has run)."""
    previous = previous_of(Path(target))
    try:
        if stat.S_ISREG(previous.lstat().st_mode):
            os.unlink(previous)
    except OSError:
        pass


def cleanup_partials(target: Path, older_than: float = 3600.0) -> None:
    """What a download cut off (the program ended, a crash) left beside *target*, an hour old."""
    target = Path(target)
    try:
        entries = list(os.scandir(target.parent))
    except OSError:
        return
    now = time.time()
    for entry in entries:
        if not entry.name.startswith(_part_prefix(target)) or not entry.name.endswith((".part", ".part.exe")):
            continue
        try:
            st = entry.stat(follow_symlinks=False)
        except OSError:
            continue
        if stat.S_ISREG(st.st_mode) and now - st.st_mtime > older_than:
            _unlink(Path(entry.path))


def update(install_: Install | None = None, current: str | None = None, fetcher=None, *, progress=None,
           cancel=None, test=None, after=None, check_result: CheckResult | None = None) -> str:
    """Check and, when a newer release is out, download, check and install it: what happened, said."""
    install_ = detect_install() if install_ is None else install_
    current = current_version() if current is None else current
    result = check(current, fetcher) if check_result is None else check_result
    record_check(result)
    if not result.newer:
        return result.text
    if not install_.can_update:
        return f"{result.text} - {install_.why_not()}"
    with _updating(install_.target):
        downloaded = download(result.release, install_, current, fetcher, progress=progress, cancel=cancel)
        installed = install(downloaded, install_, test=test, after=after)
    return f"{PROGRAM} {installed.version} is installed - it starts the next time"


@contextlib.contextmanager
def _updating(target: Path):
    """One update of *target* at a time across processes (two windows, a window and --update): a lock file
    beside it held while one downloads and installs - another's cleanup deleted the download, one rolled back
    over the other's install. Held already: UpdateError."""
    lock = Path(target).with_name(f".{Path(target).name}.update-lock")
    try:
        fd = os.open(lock, os.O_RDWR | os.O_CREAT, 0o600)
    except OSError:  # (an unwritable folder: download() says so)
        yield
        return
    try:
        try:
            if os.name == "nt":
                import msvcrt

                msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)
            else:
                import fcntl

                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            raise UpdateError("another axross-markdown is updating it now - try again later") from None
        yield
    finally:
        os.close(fd)  # (the lock goes with the descriptor; the file stays, empty)


# -- the settings ---------------------------------------------------------------------------------

def mode(path=None) -> str:
    """"off", "notify" (the default) or "auto"."""
    from core.markdown_settings import read_setting

    value = read_setting(SETTING_MODE, DEFAULT_MODE, path)
    return value if value in MODES else DEFAULT_MODE


def set_mode(value: str, path=None) -> None:
    if value not in MODES:
        raise ValueError(f"the update mode is one of {', '.join(MODES)}, not {value!r}")
    from core.markdown_settings import write_setting

    write_setting(SETTING_MODE, value, path)


def last_check(path=None) -> float | None:
    from core.markdown_settings import read_setting, state_path

    value = read_setting(SETTING_LAST, None, state_path() if path is None else path)
    return float(value) if type(value) in (int, float) and value > 0 else None


def record_check(result: CheckResult | None = None, when: float | None = None, path=None) -> None:
    """The time of a check (and, with *result*, the newer version it found - "" when none): the program's
    state (core.markdown_settings.state_path), not the user's settings."""
    from core.markdown_settings import state_path, write_settings

    values = {SETTING_LAST: float(time.time() if when is None else when)}
    if result is not None:
        values[SETTING_SEEN] = result.release.version if result.newer else ""
    try:
        write_settings(values, state_path() if path is None else path)
    except OSError:
        log.info("update: the time of the check is not kept (the settings cannot be written)")


def seen_newer(current: str, path=None) -> str:
    """The newer version the last check found, if it still is newer than *current* - else ""."""
    from core.markdown_settings import read_setting, state_path

    value = read_setting(SETTING_SEEN, "", state_path() if path is None else path)
    return value if isinstance(value, str) and is_newer(value, current) else ""


def checks_allowed(environ=None) -> tuple[bool, str]:
    """Whether the checks at the start and every day may run (the environment's say)."""
    environ = os.environ if environ is None else environ
    if (environ.get(NO_CHECK_ENV) or "").strip().lower() in _TRUTHY:
        return False, f"{NO_CHECK_ENV} is set"
    return True, ""


def due(last: float | None, now: float, interval: float = INTERVAL) -> bool:
    """Whether a check is due: none yet, *interval* since the last - or a last one in the future (a clock
    put back)."""
    return last is None or now - last >= interval or last > now + 300


class Scheduler:
    """The checks at the start and every *interval*, each on a thread of its own - never on the caller's
    (the GUI's). *tick()* is called often (a timer): it starts a check when one is due, the mode is not
    "off" and none runs. *run_check()* does the check (and, in "auto", the update); its exceptions are
    logged."""

    def __init__(self, run_check: Callable[[], object], *, clock=time.time, interval: float = INTERVAL,
                 get_mode=mode, get_last=last_check, record=None, environ=None,
                 start=None) -> None:
        self.run_check, self.clock, self.interval = run_check, clock, interval
        self.get_mode, self.get_last = get_mode, get_last
        self.record = (lambda when: record_check(when=when)) if record is None else record
        self.environ = environ
        self.start = start or (lambda target: threading.Thread(target=target, name="markdown-update-check",
                                                               daemon=True).start())
        self.running = False
        self._lock = threading.Lock()
        self.started = 0

    def tick(self) -> bool:
        """Start a check when one is due: whether one was started."""
        allowed, _why = checks_allowed(self.environ)
        if not allowed or self.get_mode() == "off":
            return False
        now = self.clock()
        with self._lock:
            if self.running or not due(self.get_last(), now, self.interval):
                return False
            self.running = True
        self.started += 1
        self.start(lambda: self._run(now))
        return True

    def _run(self, now: float) -> None:
        try:
            try:
                self.record(now)  # (kept first, on the worker: a check that crashes is not asked again at once)
            except Exception:  # noqa: BLE001
                log.info("update: the time of the check is not kept", exc_info=True)
            self.run_check()
        except Exception:  # noqa: BLE001 - a check that failed: said in the log, asked again tomorrow
            log.info("update: the check failed", exc_info=True)
        finally:
            with self._lock:
                self.running = False

    def seconds_to_next(self) -> float:
        """How long until a check is due (0: now)."""
        last = self.get_last()
        if due(last, self.clock(), self.interval):
            return 0.0
        return max(0.0, last + self.interval - self.clock())


__all__ = ["ALLOWED_HOSTS", "Asset", "Cancelled", "CheckResult", "ChecksumError", "DEFAULT_MODE",
           "DowngradeRefused", "Downloaded", "HostRefused", "Install", "Installed", "MODES", "NO_CHECK_ENV",
           "NotWritable", "PIP_HINT", "pip_hint", "Release", "Reply", "Scheduler", "SelfTestFailed", "SignatureError",
           "TRUSTED_KEYS", "TooLarge", "UpdateError", "Web", "asset_name", "check", "check_url", "checks_allowed",
           "cleanup_partials", "cleanup_previous", "detect_install", "download", "due", "fetch", "install",
           "is_newer", "last_check", "mode", "parse_release", "parse_sums", "parse_version", "record_check",
           "roll_back", "seen_newer", "self_test", "self_test_answer", "set_mode", "signed_sums", "update",
           "verify_signature"]
