"""MTP (Media Transfer Protocol) backend via an external FUSE mounter.

MTP is how most Android phones expose their filesystem over USB. The
protocol is stateful + non-POSIX — native libmtp bindings exist in
Python but are unmaintained, platform-specific, and prone to quirks
around transfer timeouts. The simplest robust path is to let a real
MTP-FUSE mounter handle the protocol and talk to the resulting
mount path as if it were a plain local directory.

Supported mounters (auto-detected via ``shutil.which``):

* ``jmtpfs`` — actively maintained C mounter. Preferred.
* ``simple-mtpfs`` — older but widespread Linux-distro package.
* ``go-mtpfs`` — Go-based alternative.

At least one of the above must be on ``PATH`` for :func:`is_available`
to return True and for the UI to expose the "Connect MTP Device…"
action.

Scope
-----
V1 is Linux-only. Windows has native WPD; macOS uses Android File
Transfer. Cross-platform MTP wouldn't be fatal but the native
libraries are very different — out of scope for this iteration.

Class :class:`MtpSession` subclasses :class:`~core.local_fs.LocalFS`.
The FileBackend contract is proxied through LocalFS on the mount
path: every list_dir / open_read / open_write / rename etc. works
because the kernel FUSE layer translates to MTP primitives
internally. The subclass overrides ``name`` (to surface "MTP:
<device>"), ``home`` (to point at the mount dir), and ``close`` /
``disconnect`` (which run the unmount + cleanup).
"""
from __future__ import annotations

import logging
import os
import re
import shutil
import subprocess
import tempfile
import threading
from dataclasses import dataclass

from core.local_fs import LocalFS

log = logging.getLogger("core.mtp_client")


# Mounter binaries we know how to drive. Order matters — the first
# one found on PATH wins. jmtpfs is the best-maintained option and
# has the cleanest ``-l`` device listing.
_KNOWN_MOUNTERS: tuple[str, ...] = ("jmtpfs", "simple-mtpfs", "go-mtpfs")

# Wall-clock ceiling on the mount subprocess. jmtpfs normally returns
# within a second or two; a hang indicates kernel FUSE trouble OR a
# phone that never accepted the "allow access" prompt. 30 s gives
# the phone prompt enough time to appear + get tapped.
MOUNT_TIMEOUT_SECONDS = 30.0

# Per-device listing timeout — usually completes in <2 s because it
# skips mount. Tight deadline so a hung mounter doesn't block the
# "pick a device" UI.
LIST_DEVICES_TIMEOUT_SECONDS = 10.0

# Device-id format allowlist. subprocess.run([...], ...) protects
# against shell injection by itself, but a hostile value can still
# crash the mounter OR be interpolated into log / UI strings that
# render untrusted input for the user. Restrict to the characters
# all three supported mounters actually emit:
#   * jmtpfs indexes:  pure digits, 1-based
#   * simple-mtpfs:    pure digits
#   * go-mtpfs:        "1" fallback
# USB bus locations shown by ``lsusb`` style output are
# "BUS-DEV[.PORT...]" — letters are never involved. If a future
# mounter uses a different form, widen the regex here intentionally.
_DEVICE_ID_SAFE = re.compile(r"^[0-9:.\-]+$")


def _strip_control(text: str) -> str:
    """Remove ASCII control characters (newlines / tabs / NUL / etc.)
    from *text*. Used to sanitise user-visible labels built from
    attacker-influenced mounter output so a crafted USB descriptor
    like ``"Google\\n[ERROR] sudo rm"`` can't escape its log-line
    bounds."""
    return "".join(c for c in (text or "") if ord(c) >= 0x20)


@dataclass
class MtpDevice:
    """One MTP device reported by the mounter's device-listing
    output. ``device_id`` is whatever identifier the mounter
    accepts on the subsequent mount call — for jmtpfs it's the
    zero-based index; for simple-mtpfs it's the USB bus+device
    path.
    """
    device_id: str
    vendor: str
    product: str
    serial: str = ""
    mounter: str = ""


# --------------------------------------------------------------------------
# Availability / detection
# --------------------------------------------------------------------------


def available_mounters() -> list[str]:
    """Return the mounter binaries currently on ``PATH``, in
    priority order. Empty list when MTP isn't usable on this host."""
    return [m for m in _KNOWN_MOUNTERS if shutil.which(m)]


def is_available() -> bool:
    return bool(available_mounters())


def _preferred_mounter() -> str | None:
    mounters = available_mounters()
    return mounters[0] if mounters else None


# --------------------------------------------------------------------------
# Device listing
# --------------------------------------------------------------------------


# jmtpfs -l output shape:
#   Available devices (busLocation, devNum, productId, vendorId, product, vendor):
#   1, 5, 0x4ee7, 0x18d1, Pixel 7, Google
# The first line is a header; following lines are comma-separated.
_JMTPFS_HEADER_RE = re.compile(r"^Available devices")

# simple-mtpfs -l output shape:
#   1: Google: Pixel 7
# Leading integer is the device ID.
_SIMPLE_MTPFS_LINE_RE = re.compile(
    r"^(?P<id>\d+):\s*(?P<vendor>[^:]+):\s*(?P<product>.+?)\s*$",
)


def list_devices(mounter: str | None = None) -> list[MtpDevice]:
    """Enumerate connected MTP devices.

    Raises :class:`FileNotFoundError` when no supported mounter is
    on PATH — caller should show a clear "install jmtpfs" message
    instead of a generic failure.
    """
    chosen = mounter or _preferred_mounter()
    if chosen is None:
        raise FileNotFoundError(
            "no MTP FUSE mounter on PATH (tried "
            f"{', '.join(_KNOWN_MOUNTERS)}) — "
            "install jmtpfs or simple-mtpfs from your distro",
        )
    try:
        result = subprocess.run(
            [chosen, "-l"],
            capture_output=True, text=True, check=False,
            timeout=LIST_DEVICES_TIMEOUT_SECONDS,
        )
    except subprocess.TimeoutExpired as exc:
        raise OSError(
            f"{chosen} -l timed out after "
            f"{LIST_DEVICES_TIMEOUT_SECONDS}s",
        ) from exc
    stdout = (result.stdout or "") + "\n" + (result.stderr or "")
    return _parse_device_listing(chosen, stdout)


def _parse_device_listing(mounter: str, raw: str) -> list[MtpDevice]:
    out: list[MtpDevice] = []
    if mounter == "jmtpfs":
        for line in raw.splitlines():
            line = line.strip()
            if not line or _JMTPFS_HEADER_RE.match(line):
                continue
            parts = [p.strip() for p in line.split(",")]
            if len(parts) < 6:
                continue
            # Fields: busLocation, devNum, productId, vendorId,
            # product, vendor
            out.append(MtpDevice(
                # jmtpfs mount expects the device id = bus/devnum
                # combination expressed as "--device=N" where N is
                # the 1-based index in THIS list. Use the list
                # position at call time rather than busLocation so
                # the mount call matches what the user selected.
                device_id=str(len(out) + 1),
                vendor=parts[5],
                product=parts[4],
                serial=f"{parts[0]}-{parts[1]}",
                mounter="jmtpfs",
            ))
    elif mounter == "simple-mtpfs":
        for line in raw.splitlines():
            m = _SIMPLE_MTPFS_LINE_RE.match(line)
            if m:
                out.append(MtpDevice(
                    device_id=m.group("id"),
                    vendor=m.group("vendor"),
                    product=m.group("product"),
                    mounter="simple-mtpfs",
                ))
    elif mounter == "go-mtpfs":
        # go-mtpfs doesn't emit a stable machine-readable listing —
        # operators typically mount the first device. Expose a
        # single "unknown" entry so the UI still works.
        out.append(MtpDevice(
            device_id="1", vendor="unknown", product="unknown",
            mounter="go-mtpfs",
        ))
    return out


# --------------------------------------------------------------------------
# Session (subclass of LocalFS)
# --------------------------------------------------------------------------


class MtpSession(LocalFS):
    """MTP device exposed as a FileBackend via a FUSE mount.

    Construction flow:

    1. Pick a mounter (explicit ``mounter=`` wins; else the first
       available binary on PATH).
    2. Allocate a tempdir under ``tempfile.gettempdir()``.
    3. Run the mounter with the device id + tempdir. Timeout at
       ``MOUNT_TIMEOUT_SECONDS``.
    4. Delegate every subsequent FileBackend call to LocalFS rooted
       at the tempdir.

    The tempdir is removed on ``close()`` AFTER a best-effort
    ``fusermount -u`` tears down the mount. A double-close is a
    no-op so callers can tear down idempotently.

    MTP isn't a proper POSIX filesystem — permissions / ownership
    aren't meaningful on the mount and many backends report empty
    chmod / readlink. The class inherits LocalFS's symlinks /
    hardlinks flags as True, but real MTP mounts will typically
    raise OSError on those mutation calls. Consumers filter via
    the flag only as a rough optimisation.
    """

    def __init__(
        self,
        device: MtpDevice | str,
        *,
        mounter: str | None = None,
        mount_timeout: float = MOUNT_TIMEOUT_SECONDS,
    ) -> None:
        super().__init__()
        if isinstance(device, str):
            device_id = device
            device_label = device
        else:
            device_id = device.device_id
            device_label = f"{device.vendor} {device.product}".strip() or device_id
            if mounter is None:
                mounter = device.mounter or None
        # subprocess.run with a list argv already prevents shell
        # injection, but a hostile device_id from a tampered profiles
        # .json can still (a) crash the mounter in weird ways or
        # (b) render attacker-controlled text into log lines and
        # status bars. Gate on a strict allowlist — all supported
        # mounters only emit digits / colons / dots / dashes.
        if not _DEVICE_ID_SAFE.match(device_id or ""):
            raise ValueError(
                f"MTP device_id must match {_DEVICE_ID_SAFE.pattern!r}; "
                f"got {device_id!r}",
            )
        self._device_id = device_id
        # Sanitise the user-visible label — vendor / product strings
        # come from the mounter's device-listing output and can be
        # influenced by a USB device that picked deliberately weird
        # descriptor strings. Strip ASCII control chars so a fake
        # "\r\nERROR hacked!" label can't forge log lines.
        self._device_label = _strip_control(device_label)
        self._mounter = mounter or _preferred_mounter()
        if self._mounter is None:
            raise FileNotFoundError(
                "no MTP FUSE mounter on PATH (tried "
                f"{', '.join(_KNOWN_MOUNTERS)})",
            )
        self._mount_dir = tempfile.mkdtemp(prefix="axross-mtp-")
        self._mounted = False
        self._close_lock = threading.Lock()
        try:
            self._mount(mount_timeout)
        except BaseException:
            # Failure anywhere in the mount path → remove the empty
            # tempdir we just created. Don't leave stray dirs under
            # /tmp on repeated retries.
            try:
                os.rmdir(self._mount_dir)
            except OSError:
                pass
            raise

    # ------------------------------------------------------------------
    # Mount / unmount
    # ------------------------------------------------------------------
    def _mount(self, timeout: float) -> None:
        cmd = self._build_mount_command()
        log.info(
            "MTP mount via %s: device=%s target=%s",
            self._mounter, self._device_id, self._mount_dir,
        )
        try:
            result = subprocess.run(
                cmd, capture_output=True, text=True, check=False,
                timeout=timeout,
            )
        except subprocess.TimeoutExpired as exc:
            raise OSError(
                f"MTP mount via {self._mounter} timed out after "
                f"{timeout}s — is the device unlocked and 'allow "
                "file access' accepted on the phone?",
            ) from exc
        if result.returncode != 0:
            raise OSError(
                f"MTP mount via {self._mounter} failed: "
                f"rc={result.returncode} "
                f"stderr={(result.stderr or '').strip()!r}",
            )
        # The mounter backgrounds itself on success. Confirm the
        # mount actually materialised — a zero exit with no mount
        # means the FUSE layer rejected it silently.
        if not os.path.ismount(self._mount_dir):
            raise OSError(
                f"MTP mounter {self._mounter} returned 0 but "
                f"{self._mount_dir} isn't a mount point — check "
                "dmesg / journalctl for kernel-side errors",
            )
        self._mounted = True

    def _build_mount_command(self) -> list[str]:
        if self._mounter == "jmtpfs":
            return [
                self._mounter, self._mount_dir,
                f"--device={self._device_id}",
            ]
        if self._mounter == "simple-mtpfs":
            return [
                self._mounter, "--device", self._device_id,
                self._mount_dir,
            ]
        if self._mounter == "go-mtpfs":
            return [self._mounter, self._mount_dir]
        raise OSError(
            f"unsupported mounter {self._mounter!r} — add a case "
            "in _build_mount_command",
        )

    def _unmount(self, timeout: float = 5.0) -> None:
        if not self._mounted:
            return
        # fusermount -u is the right tool on Linux; umount works as
        # a fallback. Don't raise on failure — the best the UI can
        # do is warn.
        for cmd in (("fusermount", "-u", self._mount_dir),
                    ("umount", self._mount_dir)):
            try:
                result = subprocess.run(
                    cmd, capture_output=True, text=True, check=False,
                    timeout=timeout,
                )
            except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
                log.debug(
                    "MTP unmount %s: %s failed: %s",
                    self._mount_dir, cmd[0], exc,
                )
                continue
            if result.returncode == 0:
                self._mounted = False
                return
            log.debug(
                "MTP unmount %s: %s rc=%d stderr=%r",
                self._mount_dir, cmd[0], result.returncode,
                (result.stderr or "").strip(),
            )
        log.warning(
            "MTP unmount %s: all attempts failed; leaking mount",
            self._mount_dir,
        )

    def close(self) -> None:
        """Unmount the device and remove the tempdir. Idempotent."""
        with self._close_lock:
            self._unmount()
            try:
                os.rmdir(self._mount_dir)
            except OSError as exc:
                # tempdir might still contain traces of a partial
                # mount; log but don't re-raise — cleanup is
                # best-effort at teardown.
                log.debug(
                    "MTP close: could not remove %s: %s",
                    self._mount_dir, exc,
                )

    def disconnect(self) -> None:
        """Alias for :meth:`close` matching the convention the rest
        of the codebase uses."""
        self.close()

    def __del__(self) -> None:
        # Defensive last-ditch cleanup. GC order is undefined so we
        # swallow all exceptions here — the important work happens
        # in explicit close() calls.
        try:
            self.close()
        except Exception:  # noqa: BLE001
            pass

    # ------------------------------------------------------------------
    # FileBackend surface — only overrides needed beyond LocalFS.
    # ------------------------------------------------------------------
    @property
    def name(self) -> str:
        return f"MTP: {self._device_label}"

    def home(self) -> str:
        return self._mount_dir

    @property
    def mount_dir(self) -> str:
        """Read-only accessor for the underlying mount path. Handy
        for the UI / tests so they don't have to reach into the
        private attribute."""
        return self._mount_dir

    # ------------------------------------------------------------------
    # MTP-specific verbs (API_GAPS round 2)
    # ------------------------------------------------------------------

    def device_info(self) -> dict:
        """Return what we know about the connected MTP device:
        ``{vendor_id, product_id, label, mounter, mount_dir,
        device_id}``. Most fields come from the ``MtpDevice`` we were
        constructed with — MTP has no protocol-level richer-than-this
        device-info query without dropping into libmtp directly."""
        return {
            "device_id": self._device_id,
            "label": self._device_label,
            "mounter": self._mounter,
            "mount_dir": self._mount_dir,
        }

    def storage_list(self) -> list[dict]:
        """List the storage areas the device exposes (Internal
        storage, SD card, …). After mount, each top-level directory
        in ``mount_dir`` corresponds to one MTP storage. Returns
        ``{name, path, total_bytes, free_bytes}`` per storage.

        ``total_bytes`` / ``free_bytes`` may be 0 when the underlying
        FUSE mount doesn't expose statvfs through the storage root —
        on those mounts the user sees only the names.
        """
        import os as _os
        out: list[dict] = []
        try:
            entries = sorted(_os.listdir(self._mount_dir))
        except OSError as exc:
            raise OSError(
                f"MTP storage_list: cannot read mount {self._mount_dir!r}: {exc}"
            ) from exc
        for name in entries:
            full = _os.path.join(self._mount_dir, name)
            if not _os.path.isdir(full):
                continue
            try:
                stat = _os.statvfs(full)
                block_size = stat.f_frsize or stat.f_bsize or 0
                total = (stat.f_blocks or 0) * block_size
                free = (stat.f_bavail or 0) * block_size
            except OSError:
                total = 0
                free = 0
            out.append({
                "name": name,
                "path": full,
                "total_bytes": int(total),
                "free_bytes": int(free),
            })
        return out


__all__ = [
    "LIST_DEVICES_TIMEOUT_SECONDS",
    "MOUNT_TIMEOUT_SECONDS",
    "MtpDevice",
    "MtpSession",
    "available_mounters",
    "is_available",
    "list_devices",
]
