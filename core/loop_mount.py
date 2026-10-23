"""Loop-mount one partition of a local disk image - read-only by default.

The partition is mapped on its own: a loop device over exactly its bytes
(offset and size from core.disk_image), so no partition scan and no udev
wait is needed, and the same call mounts a bare file system (offset 0).

Methods - the first that works is used, and every failure is reported when
none does. With the sudo password remembered (core.sudo_password, the
default) axross prefers what does not ask again:

1. ``udisksctl loop-setup`` + ``udisksctl mount`` with
   ``--no-user-interaction``: works without any prompt where polkit allows
   it; the mount lands where udisks puts it (``/run/media/<user>/...``).
2. ``sudo`` running :data:`MOUNT_SCRIPT` (losetup + mount) into a folder of
   ours. No password with a valid sudo ticket (``sudo -n -v``); else the
   remembered one or the user's, checked with ``sudo -S -v`` first (three
   tries) and kept for the next call. It goes to sudo's stdin, never on the
   command line.
3. ``pkexec`` with the same script: polkit's agent asks (axross never sees,
   and cannot remember, that password).
4. ``udisksctl`` again, now letting polkit ask - only when step 1 was
   refused for want of authorization.

With remembering switched off the chain decided for item 6 runs:
udisksctl (polkit asks), pkexec, sudo (asked every time).

sudo, pkexec and udisksctl are taken only from root-owned system folders
(core.elevated_io.trusted_which), never from ``$PATH``: a planted ``sudo``
early in ``$PATH`` would otherwise receive the password.

The script is a constant; the image path, numbers and folder are its
positional arguments, so nothing the user named is ever parsed by a shell.
Writing needs ``writable=True`` - the caller asks first.
"""

from __future__ import annotations

import json
import logging
import os
import re
import subprocess
import tempfile
import threading
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from core import sudo_password as SP
from core.subprocess_env import clean_child_env

log = logging.getLogger(__name__)

#: Seconds a command may take - polkit and sudo wait for the user.
COMMAND_TIMEOUT = 300

#: Where the kernel shows loop devices and mounts; tests point these elsewhere.
SYS_ROOT = "/sys"
MOUNTINFO = "/proc/self/mountinfo"

MOUNT_SCRIPT = (
    'set -u\n'
    'if [ "$4" = ro ]; then\n'
    '  dev=$(losetup --find --show --read-only --offset "$2" --sizelimit "$3" -- "$1") || exit 31\n'
    '  opts=ro\n'
    'else\n'
    '  dev=$(losetup --find --show --offset "$2" --sizelimit "$3" -- "$1") || exit 31\n'
    '  opts=rw\n'
    'fi\n'
    'if mount -o "$opts" -- "$dev" "$5"; then echo "$dev"; else losetup -d "$dev"; exit 32; fi\n'
)
UNMOUNT_SCRIPT = 'set -u\numount -- "$1" && losetup -d "$2"\n'


class MountError(OSError):
    pass


@dataclass(frozen=True)
class Result:
    returncode: int
    stdout: str
    stderr: str


@dataclass(frozen=True)
class Mount:
    image: str
    device: str
    mountpoint: str
    method: str
    read_only: bool


Runner = Callable[..., Result]

_ACTIVE: list[Mount] = []
_LOCK = threading.Lock()


def run_command(argv, *, input_text=None, timeout=COMMAND_TIMEOUT) -> Result:
    try:
        proc = subprocess.run(argv, input=input_text, capture_output=True, text=True,
                              timeout=timeout, check=False, env=clean_child_env())
    except subprocess.TimeoutExpired:
        return Result(124, "", f"{argv[0]} did not finish within {timeout} s")
    except OSError as exc:
        return Result(127, "", str(exc))
    return Result(proc.returncode, proc.stdout, proc.stderr)


def _which(name: str) -> str | None:
    """*name* from a root-owned system folder only, as an absolute path."""
    from core.elevated_io import trusted_which

    return trusted_which(name)


def parse_loop(text: str) -> str | None:
    """The loop device from ``udisksctl loop-setup``'s line."""
    match = re.search(r"\bas (/dev/loop\d+)\.?\s*$", text.strip())
    return match.group(1) if match else None


def parse_mountpoint(text: str) -> str | None:
    """The folder from ``udisksctl mount``'s line."""
    match = re.search(r"^Mounted \S+ at (.+?)\.?\s*$", text.strip(), re.MULTILINE)
    return match.group(1) if match else None


def default_mount_root() -> str:
    return str(Path.home() / ".local" / "state" / "axross" / "mounts")


def mount_folder(root: str, image: str) -> str:
    """A new, safe folder name under *root* for *image*."""
    base = re.sub(r"[^A-Za-z0-9_.-]", "_", os.path.basename(image)) or "image"
    base = base.lstrip(".")[:60] or "image"
    n = 1
    while os.path.exists(os.path.join(root, f"{base}-{n}")):
        n += 1
    return os.path.join(root, f"{base}-{n}")


_LOADED = False
_METHODS = ("udisksctl", "pkexec", "sudo")


def mounts_file() -> Path:
    """Where the mounts made by axross are kept across restarts."""
    return Path.home() / ".config" / "axross" / "mounts.json"


def _load_locked() -> None:
    """Read the stored mounts once per process; keep those still mounted."""
    global _LOADED
    if _LOADED:
        return
    _LOADED = True
    try:
        data = json.loads(mounts_file().read_text(encoding="utf-8"))
    except FileNotFoundError:
        return
    except (OSError, ValueError) as exc:
        log.warning("Mounts: %s is unreadable (%s); ignored", mounts_file(), exc)
        return
    entries = data.get("mounts") if isinstance(data, dict) else None
    for raw in entries if isinstance(entries, list) else []:
        try:
            mount = Mount(*(raw[k] for k in ("image", "device", "mountpoint", "method")),
                          raw["read_only"])
        except (TypeError, KeyError):
            continue
        if not (all(isinstance(v, str) for v in (mount.image, mount.device, mount.mountpoint))
                and mount.method in _METHODS and isinstance(mount.read_only, bool)
                and re.fullmatch(r"/dev/loop\d+", mount.device)):
            continue
        if os.path.ismount(mount.mountpoint) and mount not in _ACTIVE:
            _ACTIVE.append(mount)


def _save_locked() -> None:
    path = mounts_file()
    payload = {"mounts": [{"image": m.image, "device": m.device, "mountpoint": m.mountpoint,
                           "method": m.method, "read_only": m.read_only} for m in _ACTIVE]}
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp = tempfile.mkstemp(prefix=".mounts.", dir=str(path.parent))
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, indent=1)
        os.chmod(tmp, 0o600)
        os.replace(tmp, path)
    except OSError as exc:
        log.warning("Mounts: could not store %s: %s", path, exc)


def reset_for_tests() -> None:
    """Forget the in-memory list so the next call reads the file again."""
    global _LOADED
    with _LOCK:
        _ACTIVE.clear()
        _LOADED = False


def active_mounts() -> list[Mount]:
    with _LOCK:
        _load_locked()
        return list(_ACTIVE)


def forget(mount: Mount) -> None:
    with _LOCK:
        _load_locked()
        if mount in _ACTIVE:
            _ACTIVE.remove(mount)
            _save_locked()


def _remember(mount: Mount) -> Mount:
    with _LOCK:
        _load_locked()
        _ACTIVE.append(mount)
        _save_locked()
    log.info("Mounted %s (%s) at %s via %s", mount.image, mount.device, mount.mountpoint,
             mount.method)
    return mount


def _check(image: str, offset, size) -> None:
    if not isinstance(image, str) or not os.path.isabs(image) or image.startswith("-"):
        raise ValueError("the image path must be absolute")
    for name, value in (("offset", offset), ("size", size)):
        if not isinstance(value, int) or isinstance(value, bool):
            raise ValueError(f"{name} must be a whole number")
    if offset < 0 or size <= 0:
        raise ValueError("offset must be >= 0 and size > 0")


def _err(result: Result) -> str:
    """The last line the tool printed, or its exit code."""
    text = (result.stderr or result.stdout).strip()
    return text.splitlines()[-1] if text else f"exit {result.returncode}"


#: udisksctl's flag for "fail instead of letting polkit ask".
QUIET = "--no-user-interaction"
#: Wrong sudo passwords accepted before a mount gives up.
SUDO_TRIES = 3


class _Refused(MountError):
    """udisksctl was refused for want of authorization (polkit would ask)."""


def _not_authorized(result: Result) -> bool:
    # The D-Bus error name (org.freedesktop.UDisks2.Error.NotAuthorized...)
    # is not translated; "Not authorized" is its English text.
    return bool(re.search(r"not\s*authori[sz]ed", f"{result.stderr}\n{result.stdout}",
                          re.IGNORECASE))


def _udisks_error(result: Result) -> MountError:
    return (_Refused if _not_authorized(result) else MountError)(_err(result))


def _udisks(tool, image, offset, size, writable, runner, quiet) -> Mount:
    flag = [QUIET] if quiet else []
    argv = [tool, "loop-setup", *flag, "--file", image, "--offset", str(offset),
            "--size", str(size)]
    if not writable:
        argv.append("--read-only")
    result = runner(argv, timeout=COMMAND_TIMEOUT)
    if result.returncode != 0:
        raise _udisks_error(result)
    device = parse_loop(result.stdout)
    if device is None:
        raise MountError(f"no loop device in {result.stdout.strip()!r}")
    argv = [tool, "mount", *flag, "--block-device", device]
    if not writable:
        argv += ["--options", "ro"]
    result = runner(argv, timeout=COMMAND_TIMEOUT)
    point = parse_mountpoint(result.stdout) if result.returncode == 0 else None
    if point is None:
        freed = runner([tool, "loop-delete", *flag, "--block-device", device],
                       timeout=COMMAND_TIMEOUT)
        if freed.returncode != 0:
            log.warning("Mount: %s stays attached (%s); free it with "
                        "'udisksctl loop-delete -b %s'", device, _err(freed), device)
        if result.returncode:
            raise _udisks_error(result)
        raise MountError(f"no mount folder in {result.stdout.strip()!r}")
    return Mount(image, device, point, "udisksctl", not writable)


def _privileged(prefix, method, image, offset, size, writable, runner, root, stdin) -> Mount:
    try:
        os.makedirs(root, mode=0o700, exist_ok=True)
        point = mount_folder(root, image)
        os.mkdir(point, 0o700)
    except OSError as exc:
        # A MountError like every other failure of a method: the next one
        # (udisksctl mounts elsewhere) still gets its turn.
        raise MountError(f"no mount folder under {root}: {exc.strerror or exc}") from None
    argv = [*prefix, "/bin/sh", "-c", MOUNT_SCRIPT, "axross-mount", image, str(offset),
            str(size), "rw" if writable else "ro", point]
    result = runner(argv, input_text=stdin, timeout=COMMAND_TIMEOUT)
    device = result.stdout.strip().splitlines()[-1] if result.stdout.strip() else ""
    if result.returncode != 0 or not re.fullmatch(r"/dev/loop\d+", device):
        try:
            os.rmdir(point)
        except OSError:
            pass
        raise MountError(_err(result))
    return Mount(image, device, point, method, not writable)


def _ask(password, retry: bool) -> str | None:
    if password is None:
        return None
    return password(retry=True) if retry else password()


def _sudo_access(sudo: str, runner: Runner, password) -> tuple[list[str], str | None]:
    """The sudo prefix and stdin for one privileged run.

    No password while sudo's own ticket is valid; else the remembered
    password, or the user's (asked through *password*, ``retry=True`` after
    a wrong one), checked with ``sudo -v`` before anything runs as root. An
    accepted password is remembered (if remembering is on); a stale one is
    forgotten and the user asked."""
    if runner([sudo, "-n", "-v"], timeout=COMMAND_TIMEOUT).returncode == 0:
        return [sudo, "-n"], None
    secret = SP.remembered()
    from_memory = secret is not None
    retry, tries = False, 0
    while True:
        if secret is None:
            secret = _ask(password, retry)
            if not secret:
                raise MountError("no password given")
            tries += 1
        result = runner([sudo, "-S", "-p", "", "-v"], input_text=secret + "\n",
                        timeout=COMMAND_TIMEOUT)
        if result.returncode == 0:
            SP.remember(secret)
            return [sudo, "-S", "-p", ""], secret + "\n"
        secret = None
        if from_memory:  # remembered, but no longer right: ask as if new
            SP.forget()
            from_memory = False
            continue
        if tries >= SUDO_TRIES:
            SP.forget()
            raise MountError(f"the password was not accepted ({_err(result)})")
        retry = True


def _stop_if(cancelled: Callable[[], bool] | None) -> None:
    if cancelled is not None and cancelled():
        raise MountError("cancelled")


def mount_partition(image: str, *, offset: int, size: int, writable: bool = False,
                    runner: Runner = run_command, which=_which, mount_root: str | None = None,
                    password: Callable[..., str | None] | None = None,
                    cancelled: Callable[[], bool] | None = None) -> Mount:
    """Mount *size* bytes at *offset* of *image*; the Mount, or MountError
    naming why each tried method failed. *password* is called - as
    ``password()``, or ``password(retry=True)`` after a wrong one - only
    when sudo needs it. Once *cancelled()* is true (the dialog closed) no
    further method is tried: MountError("cancelled")."""
    _check(image, offset, size)
    tools = {name: which(name) for name in ("udisksctl", "pkexec", "sudo")}
    if not any(tools.values()):
        raise MountError("Mounting needs udisksctl, pkexec or sudo; none is installed.")
    root = mount_root or default_mount_root()
    remember = SP.remember_enabled()
    if remember:
        plan = [("udisksctl", True), ("sudo", False), ("pkexec", False), ("udisksctl", False)]
    else:
        plan = [("udisksctl", False), ("pkexec", False), ("sudo", False)]
    errors = []
    quiet_refused = False
    for method, quiet in plan:
        tool = tools[method]
        if tool is None:
            continue
        if remember and method == "udisksctl" and not quiet and not quiet_refused:
            continue  # the quiet try failed for another reason: asking changes nothing
        # Between methods: a closed dialog must not lead to a polkit prompt
        # or a mount nobody waits for (a refused password ends sudo's turn).
        _stop_if(cancelled)
        try:
            if method == "udisksctl":
                return _remember(_udisks(tool, image, offset, size, writable, runner, quiet))
            if method == "pkexec":
                return _remember(_privileged([tool], "pkexec", image, offset, size,
                                             writable, runner, root, None))
            prefix, stdin = _sudo_access(tool, runner, password)
            return _remember(_privileged(prefix, "sudo", image, offset, size,
                                         writable, runner, root, stdin))
        except MountError as exc:
            if quiet:
                quiet_refused = isinstance(exc, _Refused)
            log.info("Mount via %s failed: %s", method, exc)
            errors.append(f"{method}: {exc}")
    raise MountError("Could not mount the image.\n" + "\n".join(errors))


def _unescape(field: str) -> str:
    return re.sub(r"\\([0-7]{3})", lambda m: chr(int(m.group(1), 8)), field)


def _mounts_on(point: str) -> list[tuple[str, str, str]]:
    """``(mount id, parent id, source)`` of every mount on *point*, from
    the kernel's mountinfo, in its order."""
    try:
        with open(MOUNTINFO, encoding="utf-8", errors="replace") as fh:
            lines = fh.read().splitlines()
    except OSError:
        return []
    found = []
    for line in lines:
        head, sep, tail = line.partition(" - ")
        fields, rest = head.split(), tail.split()
        if sep and len(fields) >= 5 and len(rest) >= 2 and _unescape(fields[4]) == point:
            found.append((fields[0], fields[1], _unescape(rest[1])))
    return found


def _mounted_from(point: str) -> list[str]:
    """The sources mounted on *point*, from the kernel's mountinfo."""
    return [source for _id, _parent, source in _mounts_on(point)]


def _top_source(point: str) -> str:
    """The source of the topmost mount on *point* - the one ``umount
    <point>`` takes: no other mount there has it as its parent."""
    mounts = _mounts_on(point)
    parents = {parent for _id, parent, _source in mounts}
    tops = [source for mount_id, _parent, source in mounts if mount_id not in parents]
    return (tops or [source for _id, _parent, source in mounts] or [""])[-1]


def still_ours(mount: Mount) -> str:
    """Empty when *mount* is still what axross mounted, else why not.

    mounts.json outlives the mount: after a reboot or a manual umount the
    loop device and the folder may belong to something else, and a
    privileged unmount must not hit that."""
    if not re.fullmatch(r"/dev/loop\d+", mount.device):
        return f"{mount.device} is no loop device"
    backing_file = os.path.join(SYS_ROOT, "block", os.path.basename(mount.device),
                                "loop", "backing_file")
    try:
        with open(backing_file, encoding="utf-8", errors="replace") as fh:
            backing = fh.read().rstrip("\n")
    except OSError:
        return f"{mount.device} is no longer attached"
    if backing.endswith(" (deleted)"):
        backing = backing[: -len(" (deleted)")]
    if backing != os.path.realpath(mount.image):
        return f"{mount.device} no longer shows {mount.image}"
    # umount takes the topmost mount on the folder: something mounted over
    # ours since would be what a privileged unmount hits.
    top = _top_source(mount.mountpoint)
    if top and top != mount.device:
        return f"{mount.mountpoint} is no longer mounted from {mount.device}"
    return ""


def _run_unmount_script(prefix, stdin, mount: Mount, runner: Runner) -> None:
    result = runner([*prefix, "/bin/sh", "-c", UNMOUNT_SCRIPT, "axross-unmount",
                     mount.mountpoint, mount.device], input_text=stdin,
                    timeout=COMMAND_TIMEOUT)
    if result.returncode != 0:
        raise MountError(_err(result))


def _unmount_udisks(mount: Mount, runner: Runner, which, password, cancelled=None) -> None:
    """udisksctl unmount + loop-delete; while the sudo password is
    remembered without a polkit prompt first, and a refusal goes to sudo
    before polkit is allowed to ask."""
    tool = which("udisksctl")
    remember = SP.remember_enabled()

    def by_udisks(quiet: bool) -> Result:
        flag = [QUIET] if quiet else []
        result = runner([tool, "unmount", *flag, "--block-device", mount.device],
                        timeout=COMMAND_TIMEOUT)
        if result.returncode == 0:
            runner([tool, "loop-delete", *flag, "--block-device", mount.device],
                   timeout=COMMAND_TIMEOUT)
        return result

    if tool is not None:
        result = by_udisks(quiet=remember)
        if result.returncode == 0:
            return
        if not (remember and _not_authorized(result)):
            raise MountError(_err(result))
    sudo = which("sudo") if remember else None
    if sudo is not None:
        try:
            prefix, stdin = _sudo_access(sudo, runner, password)
            _run_unmount_script(prefix, stdin, mount, runner)
            return
        except MountError:
            if tool is None:
                raise
    if tool is None:
        raise MountError("udisksctl is not installed in a system folder")
    _stop_if(cancelled)  # no polkit prompt for a closed dialog
    result = by_udisks(quiet=False)  # polkit may ask now
    if result.returncode != 0:
        raise MountError(_err(result))


def unmount(mount: Mount, *, runner: Runner = run_command,
            password: Callable[..., str | None] | None = None, which=_which,
            cancelled: Callable[[], bool] | None = None) -> None:
    """Unmount and free the loop device, the way *mount* was made.

    The stored mount is checked against the kernel first: one that is gone
    is just forgotten, one whose device or folder now belongs to something
    else is refused (and forgotten) instead of unmounted. Once
    *cancelled()* is true no further way (a polkit prompt) is tried."""
    if not _mounted_from(mount.mountpoint):
        forget(mount)
        log.info("Mount %s is already gone", mount.mountpoint)
        return
    problem = still_ours(mount)
    if problem:
        forget(mount)
        # Paths go after the first line: Qt renders markup in a message box's first line.
        raise MountError(f"Not unmounted, the stored mount no longer matches:\n{problem}")
    if mount.method == "udisksctl":
        _unmount_udisks(mount, runner, which, password, cancelled)
    else:
        tool = which(mount.method)
        if tool is None:
            raise MountError(f"{mount.method} is not installed in a system folder")
        if mount.method == "sudo":
            prefix, stdin = _sudo_access(tool, runner, password)
        else:
            prefix, stdin = [tool], None
        _run_unmount_script(prefix, stdin, mount, runner)
        try:
            os.rmdir(mount.mountpoint)
        except OSError:
            pass
    forget(mount)
    log.info("Unmounted %s", mount.mountpoint)
