"""iSCSI connect+mount wrapper backend implementing the FileBackend protocol.

Uses the iscsiadm CLI (open-iscsi) to discover, log in to, and optionally mount
an iSCSI target.  Once the target filesystem is mounted, all file operations
delegate to standard local-filesystem calls (os, shutil, open).

No extra Python packages required -- only the system tools:
  iscsiadm, mount, umount, blkid, lsblk
"""
from __future__ import annotations

import glob
import grp
import logging
import os
import pwd
import re
import shutil
import stat as stat_module
import subprocess
import tempfile
import time
from datetime import datetime
from pathlib import Path
from typing import IO

from models.file_item import FileItem

log = logging.getLogger(__name__)

_DEVICE_POLL_INTERVAL = 0.5  # seconds
_DEVICE_POLL_TIMEOUT = 30.0  # seconds

# Allowlist for the iqn/ip values that get interpolated into a shell
# glob when resolving the node-config file path. iqn grammar per
# RFC 3721 is a superset of what we accept here, but every character
# in this set is safe inside a shell glob AND matches every iqn we've
# ever encountered; anything outside this set falls through to the
# argv-based CHAP flow so we never feed shell metacharacters to sudo.
_IQN_SAFE = re.compile(r"^[a-zA-Z0-9.:_\-]+$")
_IP_SAFE = re.compile(r"^[0-9a-fA-F.:]+$")


class IscsiSession:
    """iSCSI block-storage backend implementing the FileBackend protocol.

    Workflow:
        1. ``iscsiadm`` discovers and logs in to the remote target.
        2. The kernel exposes a block device (``/dev/sdX``).
        3. (optionally) the block device is mounted to a local directory.
        4. All file operations go through the mounted path.
    """

    def __init__(
        self,
        target_ip: str,
        target_iqn: str,
        port: int = 3260,
        username: str = "",
        password: str = "",
        mount_point: str = "",
        auto_mount: bool = True,
    ):
        self._target_ip = target_ip
        self._target_iqn = target_iqn
        self._port = port
        self._username = username
        self._password = password
        self._auto_mount = auto_mount
        self._device_path: str = ""
        self._mounted = False
        self._logged_in = False
        self._tmp_dir_created = False

        if mount_point:
            self._mount_point = mount_point
        else:
            self._mount_point = tempfile.mkdtemp(prefix="axross-iscsi-")
            self._tmp_dir_created = True
        self.connect()

    # ------------------------------------------------------------------
    # FileBackend protocol -- identity / state
    # ------------------------------------------------------------------

    @property
    def name(self) -> str:  # noqa: D401
        return f"{self._target_iqn} @ {self._target_ip} (iSCSI)"

    @property
    def connected(self) -> bool:
        return self._logged_in and (not self._auto_mount or self._mounted)

    # ------------------------------------------------------------------
    # Connect / disconnect
    # ------------------------------------------------------------------

    def connect(self) -> None:
        """Discover the target, log in, wait for the device, and mount."""
        if self.connected:
            return
        self._discover()
        self._set_chap_if_needed()
        self._login()
        self._wait_for_device()
        if self._auto_mount:
            self._mount()
        log.info("iSCSI session ready: %s", self.name)

    def close(self) -> None:
        """Alias for :meth:`disconnect`."""
        self.disconnect()

    def disconnect(self) -> None:
        """Unmount, log out of the target, and clean up."""
        if self._mounted:
            self._unmount()
        if self._logged_in:
            self._logout()
        if self._tmp_dir_created and os.path.isdir(self._mount_point):
            try:
                os.rmdir(self._mount_point)
                log.info("Removed temp mount dir: %s", self._mount_point)
            except OSError as exc:
                log.warning("Could not remove temp dir %s: %s", self._mount_point, exc)
            self._tmp_dir_created = False

    # ------------------------------------------------------------------
    # File operations (delegate to mounted local filesystem)
    # ------------------------------------------------------------------

    def list_dir(self, path: str) -> list[FileItem]:
        real = self._real(path)
        items: list[FileItem] = []
        try:
            with os.scandir(real) as it:
                for entry in it:
                    try:
                        items.append(self._entry_to_item(entry))
                    except OSError as exc:
                        log.warning("Cannot stat %s: %s", entry.path, exc)
        except OSError as exc:
            raise OSError(f"Cannot list {path}: {exc}") from exc
        return items

    def stat(self, path: str) -> FileItem:
        real = self._real(path)
        st = os.lstat(real)
        name = os.path.basename(real) or path
        return self._stat_to_item(name, st, full_path=real)

    def is_dir(self, path: str) -> bool:
        try:
            return stat_module.S_ISDIR(os.lstat(self._real(path)).st_mode)
        except OSError:
            return False

    def exists(self, path: str) -> bool:
        return os.path.lexists(self._real(path))

    def mkdir(self, path: str) -> None:
        os.makedirs(self._real(path), exist_ok=True)

    def remove(self, path: str, recursive: bool = False) -> None:
        real = self._real(path)
        st = os.lstat(real)
        if stat_module.S_ISLNK(st.st_mode):
            os.remove(real)
        elif stat_module.S_ISDIR(st.st_mode):
            if recursive:
                shutil.rmtree(real)
            else:
                os.rmdir(real)
        else:
            os.remove(real)

    def rename(self, src: str, dst: str) -> None:
        os.rename(self._real(src), self._real(dst))

    def open_read(self, path: str) -> IO[bytes]:
        return open(self._real(path), "rb")

    def open_write(self, path: str, append: bool = False) -> IO[bytes]:
        real = self._real(path)
        os.makedirs(os.path.dirname(real), exist_ok=True)
        return open(real, "ab" if append else "wb")

    def normalize(self, path: str) -> str:
        return os.path.normpath(path) if path else "/"

    def separator(self) -> str:
        return "/"

    def join(self, *parts: str) -> str:
        return os.path.join(*parts)

    def parent(self, path: str) -> str:
        return str(Path(path).parent)

    def home(self) -> str:
        return "/"

    def chmod(self, path: str, mode: int) -> None:
        os.chmod(self._real(path), mode)

    def readlink(self, path: str) -> str:
        return os.readlink(self._real(path))

    def list_versions(self, path: str) -> list:
        return []

    def open_version_read(self, path: str, version_id: str):
        raise OSError(
            f"{type(self).__name__} does not expose file version history"
        )

    def copy(self, src: str, dst: str) -> None:
        """Server-side copy on the mounted block device."""
        shutil.copy2(self._real(src), self._real(dst))

    # ------------------------------------------------------------------
    # iSCSI-specific verbs (API_GAPS round 2)
    # ------------------------------------------------------------------

    @staticmethod
    def targets_discover(portal_ip: str, *,
                         portal_port: int = 3260,
                         timeout: float = 10.0) -> list[dict]:
        """Discover iSCSI targets advertised at ``portal_ip:portal_port``
        via ``iscsiadm -m discovery -t sendtargets``. Static method so
        a script can browse before logging in to a specific target.

        Returns list of dicts ``{portal, iqn}`` — one entry per
        target endpoint (a single IQN can advertise multiple
        portals).

        Requires ``iscsiadm`` (open-iscsi) on PATH and root/sudo
        privileges (the SCSI mid-layer + initiator config require
        them on Linux). Raises ``OSError`` when missing.
        """
        if "\r" in portal_ip or "\n" in portal_ip or " " in portal_ip:
            raise ValueError(
                "targets_discover portal_ip must not contain CR/LF/space"
            )
        binary = shutil.which("iscsiadm")
        if not binary:
            raise OSError(
                "targets_discover requires the system 'iscsiadm' binary "
                "(install open-iscsi)"
            )
        cmd = [
            binary, "-m", "discovery",
            "-t", "sendtargets",
            "-p", f"{portal_ip}:{int(portal_port)}",
        ]
        try:
            proc = subprocess.run(
                cmd, capture_output=True, text=True,
                timeout=float(timeout),
            )
        except subprocess.TimeoutExpired as exc:
            raise OSError(f"iscsiadm discovery timed out: {exc}") from exc
        if proc.returncode != 0:
            raise OSError(
                f"iscsiadm discovery rc={proc.returncode}: "
                f"{(proc.stderr or proc.stdout).strip()[:300]}"
            )
        # Output lines: ``10.0.0.5:3260,1 iqn.2026-04.lab.axross:disk1``
        out: list[dict] = []
        for line in proc.stdout.splitlines():
            line = line.strip()
            if not line or " " not in line:
                continue
            portal_part, iqn_part = line.split(" ", 1)
            # ``portal,group``  — drop the group id.
            portal_only = portal_part.split(",", 1)[0]
            out.append({"portal": portal_only, "iqn": iqn_part.strip()})
        return out

    def portal_login(self) -> None:
        """Explicit login to the configured target (already done by
        ``connect()`` for normal flows). Returns None on success;
        raises OSError with iscsiadm's stderr on failure.

        Useful when a script wants to re-login after an iSCSI
        connection drop without tearing down + rebuilding the
        session."""
        binary = shutil.which("iscsiadm")
        if not binary:
            raise OSError("portal_login requires iscsiadm (open-iscsi)")
        cmd = [
            binary, "-m", "node",
            "-T", self._target_iqn,
            "-p", f"{self._target_ip}:{self._port}",
            "--login",
        ]
        proc = subprocess.run(cmd, capture_output=True, text=True,
                              timeout=30.0)
        if proc.returncode != 0:
            raise OSError(
                f"iscsiadm login rc={proc.returncode}: "
                f"{(proc.stderr or proc.stdout).strip()[:300]}"
            )

    def lun_list(self) -> list[dict]:
        """List the SCSI LUNs the kernel currently sees from this
        session. Returns dicts ``{device, size_bytes, scsi_id}``.

        Walks ``lsblk -J`` to find block devices whose model / vendor
        matches a typical iSCSI initiator pattern. Heuristic — the
        kernel doesn't expose a clean "which devices belong to which
        iSCSI session?" interface without parsing
        ``/sys/class/iscsi_session/<id>/device/target*/...``.
        """
        binary = shutil.which("lsblk")
        if not binary:
            raise OSError("lun_list requires lsblk (util-linux)")
        proc = subprocess.run(
            [binary, "-J", "-O"],
            capture_output=True, text=True, timeout=10.0,
        )
        if proc.returncode != 0:
            raise OSError(
                f"lsblk rc={proc.returncode}: "
                f"{proc.stderr.strip()[:300]}"
            )
        import json as _json
        try:
            data = _json.loads(proc.stdout)
        except _json.JSONDecodeError as exc:
            raise OSError(f"lsblk JSON parse: {exc}") from exc
        out: list[dict] = []
        for d in data.get("blockdevices", []):
            transport = (d.get("tran") or "").lower()
            if transport != "iscsi":
                continue
            out.append({
                "device": "/dev/" + d.get("name", ""),
                "size_bytes": int(d.get("size") or 0),
                "scsi_id": d.get("wwn") or "",
            })
        return out

    def checksum(self, path: str, algorithm: str = "sha256") -> str:
        """Stream-hash via the mounted block device. Kernel-cached
        so cheap compared to re-fetching over iSCSI."""
        import hashlib
        try:
            h = hashlib.new(algorithm)
        except ValueError as exc:
            raise OSError(f"Unsupported algorithm: {algorithm}") from exc
        with open(self._real(path), "rb") as f:
            for chunk in iter(lambda: f.read(1024 * 1024), b""):
                h.update(chunk)
        return f"{algorithm}:{h.hexdigest()}"

    def disk_usage(self, path: str) -> tuple[int, int, int]:
        usage = shutil.disk_usage(self._mount_point)
        return (usage.total, usage.used, usage.free)

    # ------------------------------------------------------------------
    # Internal helpers -- path mapping
    # ------------------------------------------------------------------

    def _real(self, path: str) -> str:
        """Map a virtual path (``/``, ``/foo/bar``) to the mounted filesystem."""
        clean = path.lstrip("/")
        real = os.path.abspath(os.path.join(self._mount_point, clean))
        mount_root = os.path.abspath(self._mount_point)
        if os.path.commonpath([mount_root, real]) != mount_root:
            raise PermissionError(f"Path traversal detected: {path}")
        return real

    @staticmethod
    def _redact_command(cmd: list[str]) -> str:
        masked: list[str] = []
        for index, part in enumerate(cmd):
            if (
                index >= 1
                and cmd[index - 1] == "-v"
                and index >= 2
                and "password" in cmd[index - 2].lower()
            ):
                masked.append("******")
            else:
                masked.append(part)
        return " ".join(masked)

    # ------------------------------------------------------------------
    # Internal helpers -- subprocess
    # ------------------------------------------------------------------

    @staticmethod
    def _is_root() -> bool:
        return os.geteuid() == 0

    def _run_privileged(
        self,
        cmd: list[str],
        *,
        check: bool = True,
        capture: bool = True,
    ) -> subprocess.CompletedProcess[str]:
        """Run *cmd*, prepending ``sudo`` when not running as root."""
        if not self._is_root():
            cmd = ["sudo", "-n"] + cmd
        log.debug("Running: %s", self._redact_command(cmd))
        return subprocess.run(
            cmd,
            check=check,
            capture_output=capture,
            text=True,
        )

    # ------------------------------------------------------------------
    # Internal helpers -- iSCSI lifecycle
    # ------------------------------------------------------------------

    def _discover(self) -> None:
        """Discover iSCSI targets on the portal."""
        portal = f"{self._target_ip}:{self._port}"
        log.info("Discovering iSCSI targets on %s", portal)
        result = self._run_privileged(
            ["iscsiadm", "-m", "discovery", "-t", "sendtargets", "-p", portal],
        )
        log.debug("Discovery output:\n%s", result.stdout)

        if self._target_iqn not in result.stdout:
            raise OSError(
                f"Target {self._target_iqn} not found on portal {portal}. "
                f"Discovered:\n{result.stdout}"
            )
        log.info("Target %s found on %s", self._target_iqn, portal)

    def _set_chap_if_needed(self) -> None:
        """Configure CHAP authentication on the node record if
        credentials are set.

        Two-phase write so secrets never land on argv:

        1. ``authmethod=CHAP`` goes via the usual ``iscsiadm --op=update``
           CLI (non-secret).
        2. Username + password are patched directly into the
           open-iscsi node config file (``/etc/iscsi/nodes/<iqn>/
           <ip>,<port>,<tpgt>/default``) via a ``sudo cat`` / ``sudo
           tee`` pair where the secret text traverses stdin/stdout
           only — never appearing in ``/proc/<pid>/cmdline``.

        Fallback: when the node config path cannot be resolved (the
        record doesn't exist yet, the iqn/ip contain characters we
        refuse to pass to a shell glob, or sudo is unavailable) we
        log a warning and fall back to the argv-based
        ``iscsiadm --op=update -v <password>`` flow. That retains
        the original behaviour on restricted systems while opting
        into the safer path everywhere else.
        """
        if not self._username:
            return

        portal = f"{self._target_ip}:{self._port}"
        base = [
            "iscsiadm", "-m", "node",
            "-T", self._target_iqn,
            "-p", portal,
            "--op=update",
        ]
        # Step 1: non-secret authmethod update via iscsiadm.
        self._run_privileged(base + [
            "-n", "node.session.auth.authmethod", "-v", "CHAP",
        ])
        # Step 2: attempt secret-via-stdin write to the node config.
        if self._write_chap_secrets_to_node_file():
            log.info(
                "CHAP credentials configured for %s via node-file "
                "(secrets via stdin, not argv)",
                self._target_iqn,
            )
            return
        # Step 2 fallback: argv-based update. Secrets brief-appear in
        # /proc/<pid>/cmdline; same-user exposure only, but a known
        # downgrade from the file-based path.
        log.warning(
            "Falling back to argv-based CHAP update for %s — "
            "secrets will be briefly visible in /proc/<pid>/cmdline "
            "during the iscsiadm call. Run this host with sudo access "
            "to /etc/iscsi/nodes to switch to the file-based path.",
            self._target_iqn,
        )
        for flags in [
            ("-n", "node.session.auth.username", "-v", self._username),
            ("-n", "node.session.auth.password", "-v", self._password),
        ]:
            self._run_privileged(base + list(flags))

    def _node_config_paths(self) -> list[str]:
        """Resolve the open-iscsi node-config files that correspond to
        this target. Returns an empty list when sudo isn't available
        or the iqn/ip values would otherwise need escaping before
        going into a shell glob."""
        if not _IQN_SAFE.match(self._target_iqn or ""):
            log.debug(
                "IQN %r contains characters we refuse to glob",
                self._target_iqn,
            )
            return []
        if not _IP_SAFE.match(self._target_ip or ""):
            log.debug(
                "IP %r contains characters we refuse to glob",
                self._target_ip,
            )
            return []
        if not isinstance(self._port, int):
            return []
        pattern = (
            f"/etc/iscsi/nodes/{self._target_iqn}/"
            f"{self._target_ip},{self._port},*/default"
        )
        # Try non-privileged glob first. If the on-disk perms let us
        # read the node directory we get the paths without sudo.
        local = sorted(glob.glob(pattern))
        if local:
            return local
        # Fall back to running the glob via sudo -n. ``printf '%s\n'``
        # writes each expanded name on its own line and stays silent
        # on non-matches.
        cmd = ["sh", "-c", f"printf '%s\\n' {pattern}"]
        if not self._is_root():
            cmd = ["sudo", "-n"] + cmd
        try:
            result = subprocess.run(
                cmd, capture_output=True, text=True, check=False,
            )
        except Exception as exc:  # noqa: BLE001
            log.debug("sudo glob of node config failed: %s", exc)
            return []
        if result.returncode != 0:
            return []
        out_paths: list[str] = []
        for line in result.stdout.splitlines():
            line = line.strip()
            # ``printf '%s\n' <pattern>`` echoes the pattern literally
            # when no matches are found — filter that out explicitly.
            if not line or "*" in line:
                continue
            out_paths.append(line)
        return sorted(out_paths)

    def _write_chap_secrets_to_node_file(self) -> bool:
        """Patch username + password lines of every node-config file
        that applies to this target, keeping the secret values on
        stdin/stdout only. Returns True on success, False when no
        files resolved or any sudo call failed. Caller falls back to
        argv-based iscsiadm updates on False."""
        paths = self._node_config_paths()
        if not paths:
            return False
        for path in paths:
            try:
                current = self._sudo_cat(path)
            except OSError as exc:
                log.debug("Cannot read %s under sudo: %s", path, exc)
                return False
            rewritten = self._rewrite_chap_lines(
                current, self._username, self._password,
            )
            try:
                self._sudo_tee(path, rewritten)
            except OSError as exc:
                log.debug("Cannot write %s under sudo: %s", path, exc)
                return False
        return True

    def _sudo_cat(self, path: str) -> str:
        """Read ``path`` via ``sudo -n cat``. Raises OSError on failure
        so the caller falls back to the argv path."""
        cmd = ["cat", "--", path]
        if not self._is_root():
            cmd = ["sudo", "-n"] + cmd
        result = subprocess.run(
            cmd, capture_output=True, text=True, check=False,
        )
        if result.returncode != 0:
            raise OSError(
                f"sudo cat {path}: rc={result.returncode} "
                f"stderr={result.stderr!r}",
            )
        return result.stdout

    def _sudo_tee(self, path: str, content: str) -> None:
        """Write ``content`` to ``path`` via ``sudo -n tee``. The
        payload flows on stdin so the bytes never show up in any
        process's argv. Raises OSError on failure."""
        cmd = ["tee", "--", path]
        if not self._is_root():
            cmd = ["sudo", "-n"] + cmd
        result = subprocess.run(
            cmd, input=content, capture_output=True, text=True,
            check=False,
        )
        if result.returncode != 0:
            raise OSError(
                f"sudo tee {path}: rc={result.returncode} "
                f"stderr={result.stderr!r}",
            )

    @staticmethod
    def _rewrite_chap_lines(current: str, username: str, password: str) -> str:
        """Replace (or append) the iscsiadm ``node.session.auth.username``
        and ``.password`` lines inside a node-config file's content.

        open-iscsi uses ``key = value`` lines (with whitespace-tolerant
        ``=``). We preserve every other line verbatim so any future
        iscsiadm-managed setting — CHAP-inbound secrets, recovery
        timeouts, iser toggles — survives the rewrite.
        """
        targets = {
            "node.session.auth.username": username,
            "node.session.auth.password": password,
        }
        seen: set[str] = set()
        out_lines: list[str] = []
        for raw in current.splitlines():
            # Match ``key[whitespace]=[whitespace]value``. Tolerant
            # of trailing whitespace + comments; open-iscsi itself
            # writes ``<key> = <value>`` with single spaces.
            match = re.match(r"^\s*([A-Za-z0-9_.]+)\s*=", raw)
            if match and match.group(1) in targets:
                key = match.group(1)
                out_lines.append(f"{key} = {targets[key]}")
                seen.add(key)
            else:
                out_lines.append(raw)
        for key, value in targets.items():
            if key not in seen:
                out_lines.append(f"{key} = {value}")
        # Preserve trailing newline behaviour: open-iscsi writes the
        # file with a terminating newline; ensure we do too.
        text = "\n".join(out_lines)
        if not text.endswith("\n"):
            text += "\n"
        return text

    def _login(self) -> None:
        """Log in to the iSCSI target.

        If a session already exists (exit 15 / ``ISCSI_ERR_SESSION_EXISTS``)
        we reuse it instead of failing — typical when the previous run
        left a kernel session behind (a crash, or a disconnect that could
        not free the block device because it was still open).
        """
        portal = f"{self._target_ip}:{self._port}"
        log.info("Logging in to %s via %s", self._target_iqn, portal)
        try:
            self._run_privileged(
                ["iscsiadm", "-m", "node", "-T", self._target_iqn,
                 "-p", portal, "--login"],
            )
        except subprocess.CalledProcessError as exc:
            if exc.returncode == 15:
                log.info(
                    "iSCSI session already exists for %s; reusing",
                    self._target_iqn,
                )
            else:
                raise
        self._logged_in = True
        log.info("iSCSI login successful")

    def _logout(self) -> None:
        """Log out from the iSCSI target."""
        portal = f"{self._target_ip}:{self._port}"
        log.info("Logging out from %s", self._target_iqn)
        try:
            self._run_privileged(
                ["iscsiadm", "-m", "node", "-T", self._target_iqn, "-p", portal, "--logout"],
            )
        except subprocess.CalledProcessError as exc:
            log.warning("iSCSI logout failed: %s", exc)
        self._logged_in = False

    def _wait_for_device(self) -> None:
        """Poll until the iSCSI-attached block device appears.

        Primary path: the udev-maintained symlink under
        ``/dev/disk/by-path/ip-<portal>-iscsi-<iqn>-lun-*`` (present on
        any standard desktop / server).

        Fallback path: when udev is not running (minimal / container
        environments), iscsiadm itself reports the kernel-assigned device
        name. We parse ``iscsiadm -m session -P 3`` output for the
        ``Attached scsi disk sdX`` line and promote it to ``/dev/sdX``.
        """
        pattern = (
            f"/dev/disk/by-path/ip-{self._target_ip}:{self._port}"
            f"-iscsi-{self._target_iqn}-lun-*"
        )
        log.info("Waiting for block device matching %s", pattern)

        deadline = time.monotonic() + _DEVICE_POLL_TIMEOUT
        while time.monotonic() < deadline:
            matches = glob.glob(pattern)
            if matches:
                # Resolve the symlink to get the real device (e.g. /dev/sdb)
                self._device_path = os.path.realpath(matches[0])
                log.info(
                    "Block device found: %s -> %s",
                    matches[0], self._device_path,
                )
                return
            dev = self._query_device_via_iscsiadm()
            if dev:
                self._device_path = dev
                log.info(
                    "Block device resolved via iscsiadm session info: %s",
                    dev,
                )
                return
            time.sleep(_DEVICE_POLL_INTERVAL)

        raise OSError(
            f"Timed out waiting for iSCSI block device after "
            f"{_DEVICE_POLL_TIMEOUT}s (pattern: {pattern})"
        )

    def _query_device_via_iscsiadm(self) -> str:
        """Ask iscsiadm which scsi disk is attached to our session.

        Returns an empty string when no device is visible yet.
        """
        try:
            result = self._run_privileged(
                ["iscsiadm", "-m", "session", "-P", "3"],
                check=False,
            )
        except OSError:
            return ""
        if result.returncode != 0:
            return ""
        # Filter: only parse the block for OUR target IQN to avoid
        # picking up a stale session from some other target.
        output = result.stdout or ""
        want = self._target_iqn
        in_our_target = False
        for line in output.splitlines():
            stripped = line.strip()
            if stripped.startswith("Target:"):
                in_our_target = want in stripped
            elif in_our_target and "Attached scsi disk" in stripped:
                # Example: "Attached scsi disk sdb\t\tState: running"
                parts = stripped.split()
                for i, tok in enumerate(parts):
                    if tok == "disk" and i + 1 < len(parts):
                        disk = parts[i + 1]
                        candidate = f"/dev/{disk}"
                        if os.path.exists(candidate):
                            return candidate
        return ""

    def _detect_filesystem(self) -> str:
        """Return the filesystem type on the block device (via ``blkid``)."""
        result = self._run_privileged(
            ["blkid", "-o", "value", "-s", "TYPE", self._device_path],
            check=False,
        )
        fs_type = result.stdout.strip()
        if result.returncode != 0 or not fs_type:
            raise OSError(
                f"Cannot detect filesystem on {self._device_path}. "
                f"blkid returned: {result.stdout.strip()} (rc={result.returncode})"
            )
        log.info("Detected filesystem: %s on %s", fs_type, self._device_path)
        return fs_type

    def _mount(self) -> None:
        """Mount the iSCSI block device to :attr:`_mount_point`.

        If the device is already mounted elsewhere (stale session left a
        mount behind after a crash, or the test harness reuses a kernel
        session that still holds the mount), we bind-mount the existing
        mount point onto the session's temp dir so callers get a
        consistent view without double-mounting the fs.
        """
        fs_type = self._detect_filesystem()
        os.makedirs(self._mount_point, exist_ok=True)

        existing = self._existing_mountpoint_for_device()
        if existing and os.path.abspath(existing) != os.path.abspath(self._mount_point):
            log.info(
                "%s is already mounted at %s; bind-mounting to %s",
                self._device_path, existing, self._mount_point,
            )
            self._run_privileged(
                ["mount", "--bind", existing, self._mount_point],
            )
            self._mounted = True
            return
        if existing and os.path.abspath(existing) == os.path.abspath(self._mount_point):
            log.info("%s already mounted at %s; nothing to do",
                     self._device_path, self._mount_point)
            self._mounted = True
            return

        log.info("Mounting %s (%s) on %s", self._device_path, fs_type, self._mount_point)
        self._run_privileged(
            ["mount", "-t", fs_type, self._device_path, self._mount_point],
        )
        self._mounted = True
        log.info("Mounted successfully at %s", self._mount_point)

    def _existing_mountpoint_for_device(self) -> str:
        """Return the first mountpoint where our block device is mounted,
        or an empty string if none."""
        try:
            with open("/proc/mounts") as fh:
                for line in fh:
                    parts = line.split()
                    if len(parts) < 2:
                        continue
                    dev = parts[0]
                    if dev == self._device_path:
                        return parts[1]
        except OSError:
            pass
        return ""

    def _unmount(self) -> None:
        """Unmount the filesystem."""
        log.info("Unmounting %s", self._mount_point)
        try:
            self._run_privileged(["umount", self._mount_point])
        except subprocess.CalledProcessError as exc:
            log.warning("umount failed: %s", exc)
        self._mounted = False

    # ------------------------------------------------------------------
    # Internal helpers -- stat / FileItem construction
    # ------------------------------------------------------------------

    def _entry_to_item(self, entry: os.DirEntry) -> FileItem:
        st = entry.stat(follow_symlinks=False)
        return self._stat_to_item(entry.name, st, full_path=entry.path)

    @staticmethod
    def _stat_to_item(
        name: str,
        st: os.stat_result,
        full_path: str = "",
    ) -> FileItem:
        is_link = stat_module.S_ISLNK(st.st_mode)
        is_dir = stat_module.S_ISDIR(st.st_mode)

        link_target = ""
        if is_link and full_path:
            try:
                link_target = os.readlink(full_path)
            except OSError:
                pass

        try:
            owner = pwd.getpwuid(st.st_uid).pw_name
        except (KeyError, AttributeError):
            owner = str(getattr(st, "st_uid", ""))

        try:
            group = grp.getgrgid(st.st_gid).gr_name
        except (KeyError, AttributeError):
            group = str(getattr(st, "st_gid", ""))

        accessed = (
            datetime.fromtimestamp(st.st_atime) if getattr(st, "st_atime", 0) else None
        )
        birth = getattr(st, "st_birthtime", 0)
        created = datetime.fromtimestamp(birth) if birth else None
        return FileItem(
            name=name,
            size=st.st_size if not is_dir else 0,
            modified=datetime.fromtimestamp(st.st_mtime),
            permissions=st.st_mode & 0o7777,
            is_dir=is_dir,
            is_link=is_link,
            link_target=link_target,
            owner=owner,
            group=group,
            accessed=accessed,
            created=created,
        )
