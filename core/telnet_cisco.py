"""Cisco-IOS-style Telnet helper.

Sits next to :mod:`core.telnet_client` and exposes an IOS-flavoured
read-only "filesystem" via Telnet. The user-visible layout::

    /show/                        — every ``show <cmd>`` we recognise
    /show/running-config.txt      — output of ``show running-config``
    /show/version.txt             — output of ``show version``
    /show/interfaces.txt          — output of ``show interfaces``
    /show/ip-route.txt            — output of ``show ip route``
    /show/<custom>.txt            — lazy: any ``show <custom>`` works

Authentication:

* ``username`` + ``password`` go through the IOS login banner (login
  prompt, then password prompt). If the device is in
  ``no aaa new-model`` line-password mode, leave ``username`` empty
  and supply ``password`` only.
* ``enable_password`` (if set) is sent after a successful login so
  the privileged-mode commands (``show running-config`` in
  particular) become available.

Always issues ``terminal length 0`` on connect so multi-page output
doesn't trip over the ``--More--`` paging prompt.

This is read-mostly by design — there's no ``write`` semantics for
``show`` output. Profile changes (``configure terminal``) are
explicitly out of scope.
"""
from __future__ import annotations

import io
import logging
import posixpath
import re
from datetime import datetime
from typing import IO

from models.file_item import FileItem

log = logging.getLogger(__name__)


# Cap on a single show-output read. ``show running-config`` on a
# packed core router can return ~500 KiB; 4 MiB is comfortable.
MAX_SHOW_BYTES = 4 * 1024 * 1024

# Curated list of common ``show`` commands so list_dir can present a
# usable starting menu. Anything not here still works via ``open_read``
# of an arbitrary ``/show/<cmd>.txt`` path.
_KNOWN_SHOWS: list[tuple[str, str]] = [
    ("running-config",     "show running-config"),
    ("startup-config",     "show startup-config"),
    ("version",            "show version"),
    ("interfaces",         "show interfaces"),
    ("ip-interface-brief", "show ip interface brief"),
    ("ip-route",           "show ip route"),
    ("vlan-brief",         "show vlan brief"),
    ("arp",                "show arp"),
    ("mac-address-table",  "show mac address-table"),
    ("cdp-neighbors",      "show cdp neighbors detail"),
    ("lldp-neighbors",     "show lldp neighbors detail"),
    ("inventory",          "show inventory"),
    ("clock",              "show clock"),
    ("logging",            "show logging"),
]


# IOS prompt: hostname>  (user-mode) or hostname#  (privileged). We
# match against the trailing line of output so neither of the chars
# inside command text accidentally trigger.
_PROMPT_RE = re.compile(r"\r?\n[A-Za-z][\w\-.]*[>#] *$")
_PRIV_PROMPT_RE = re.compile(r"\r?\n[A-Za-z][\w\-.]*# *$")
# IOS-XE shows a generic "Password:" prompt for both login + enable;
# we re-use the existing module-level pattern instead of duplicating.


def _strip_trailing_prompt(text: str) -> str:
    """Drop the IOS prompt that follows a command's output."""
    m = _PROMPT_RE.search(text)
    return text[:m.start()] if m else text


def _safe_show_subcmd(name: str) -> str:
    """Translate a filename like ``ip-route`` back to a ``show``
    sub-command. Strict allow-list so a hostile filename can't
    smuggle an extra Cisco command via the outgoing line."""
    cleaned = name[:-4] if name.endswith(".txt") else name
    if not re.fullmatch(r"[A-Za-z0-9 _\-]+", cleaned):
        raise OSError(
            f"Cisco-show name {name!r} contains characters outside "
            "[A-Za-z0-9 _-]"
        )
    # Translate dashes back to spaces so /show/ip-route.txt → "ip route"
    return cleaned.replace("-", " ").strip()


class CiscoTelnetSession:
    """Read-only IOS / IOS-XE / IOS-XR FileBackend via Telnet."""

    supports_symlinks = False
    supports_hardlinks = False

    def __init__(
        self,
        host: str,
        port: int = 23,
        username: str = "",
        password: str = "",
        enable_password: str = "",
        proxy_type: str = "none",
        proxy_host: str = "",
        proxy_port: int = 0,
        proxy_username: str = "",
        proxy_password: str = "",
        timeout: float = 15.0,
        **_ignored,
    ):
        from core.proxy import ProxyConfig
        from core.telnet_client import _TelnetTransport
        self._host = host
        self._port = int(port)
        self._username = username
        self._password = password
        self._enable_password = enable_password
        self._timeout = float(timeout)
        self._proxy = ProxyConfig(
            proxy_type=proxy_type or "none",
            host=proxy_host, port=int(proxy_port or 0),
            username=proxy_username, password=proxy_password,
        )
        self._transport = _TelnetTransport(
            host, self._port, proxy=self._proxy,
        )
        self._privileged = False
        try:
            self._login()
            self._enable_paging_off()
            if enable_password:
                self._enter_enable_mode()
        except Exception:
            try:
                self._transport.close()
            except Exception:  # noqa: BLE001
                pass
            raise
        log.info(
            "Cisco-Telnet session ready: %s@%s:%d (priv=%s)",
            username or "(line-pw)", host, self._port,
            self._privileged,
        )

    # ------------------------------------------------------------------
    # Identity / lifecycle
    # ------------------------------------------------------------------

    @property
    def name(self) -> str:
        return f"Cisco-Telnet: {self._username or '(line)'}@{self._host}:{self._port}"

    @property
    def connected(self) -> bool:
        return not self._transport.closed

    def close(self) -> None:
        try:
            self._transport.close()
        except Exception:  # noqa: BLE001
            pass

    def disconnect(self) -> None:
        self.close()

    # ------------------------------------------------------------------
    # Login + enable
    # ------------------------------------------------------------------

    def _login(self) -> None:
        """Walk the standard IOS login dance: optional username, then
        password, until we see a prompt suffix (``>`` or ``#``)."""
        # Header-injection guard: a tainted username/password with
        # CR/LF would smuggle a second IOS command (e.g. cause the
        # device to enter config mode) by being broken across lines.
        for label, value in (("username", self._username),
                             ("password", self._password),
                             ("enable_password", self._enable_password)):
            if "\r" in value or "\n" in value:
                raise OSError(
                    f"Cisco-Telnet {label!r} must not contain CR/LF — "
                    "refusing to login to avoid command smuggling."
                )
        from core.telnet_client import _LOGIN_RE, _PASSWORD_RE
        # Read until either a username or password prompt — IOS-XE
        # skips username when ``no aaa new-model`` is in effect.
        text = self._transport.read_some(timeout=self._timeout)
        if _LOGIN_RE.search(text):
            self._transport.send(self._username)
            self._transport.read_until_re(_PASSWORD_RE, timeout=self._timeout)
        elif not _PASSWORD_RE.search(text):
            # No prompts surfaced yet — keep reading until one does.
            blob, _m = self._transport.read_until_re(
                re.compile(_LOGIN_RE.pattern + "|" + _PASSWORD_RE.pattern,
                           re.IGNORECASE),
                timeout=self._timeout,
            )
            if _LOGIN_RE.search(blob):
                self._transport.send(self._username)
                self._transport.read_until_re(_PASSWORD_RE, timeout=self._timeout)
        self._transport.send(self._password)
        # Wait for an IOS prompt suffix.
        self._transport.read_until_re(_PROMPT_RE, timeout=self._timeout)

    def _enter_enable_mode(self) -> None:
        """Send ``enable`` + the enable-secret, raise if the device
        rejects it."""
        from core.telnet_client import _PASSWORD_RE
        self._transport.send("enable")
        self._transport.read_until_re(_PASSWORD_RE, timeout=self._timeout)
        self._transport.send(self._enable_password)
        text, _m = self._transport.read_until_re(_PROMPT_RE, timeout=self._timeout)
        # The promoted prompt ends in ``#`` instead of ``>``.
        if _PRIV_PROMPT_RE.search(text):
            self._privileged = True
        else:
            raise OSError(
                "Cisco-Telnet: enable-password rejected "
                "(prompt did not flip to privileged mode)"
            )

    def _enable_paging_off(self) -> None:
        """``terminal length 0`` so ``--More--`` doesn't trip us up."""
        self._send_show("terminal length 0")

    # ------------------------------------------------------------------
    # Show-command execution
    # ------------------------------------------------------------------

    # ------------------------------------------------------------------
    # Cisco-IOS-specific verbs (API_GAPS round 2)
    # ------------------------------------------------------------------

    def show(self, command: str) -> str:
        """Run an arbitrary ``show`` sub-command and return the raw
        IOS response. Bypasses the curated ``_KNOWN_SHOWS`` allow-list
        used by ``list_dir``, but still defends the wire frame against
        CR/LF smuggling — every Cisco command is line-terminated, so a
        tainted argument with embedded CR/LF would smuggle a second
        IOS command on the same connection.

        Pass the sub-command WITHOUT the leading ``show`` (i.e.
        ``show("ip arp")`` not ``show("show ip arp")``). The cap on
        response size matches what ``open_read`` enforces (4 MiB).
        """
        if "\r" in command or "\n" in command:
            raise ValueError(
                "Cisco show(cmd): refusing CR/LF (would smuggle a "
                "second IOS command on the same line)"
            )
        return self._send_show(f"show {command}")

    def save_running_config(self) -> str:
        """``write memory`` — persist the running-config to NVRAM as
        the new startup-config. Requires privileged mode (caller
        must have supplied ``enable_password`` at session creation).

        Returns the IOS confirmation text (``[OK]`` on success;
        ``Building configuration...\\n[OK]`` on most platforms).
        """
        if not self._privileged:
            raise OSError(
                "Cisco save_running_config: privileged mode required "
                "(supply enable_password when constructing the session)"
            )
        return self._send_show("write memory")

    def clear_counters(self, interface: str | None = None) -> str:
        """``clear counters [interface]`` — reset the interface
        statistics counters. Without ``interface`` clears every
        interface; with ``interface`` clears just that one.

        Privileged mode required. CR/LF in interface refused for
        the same wire-frame reason as ``show``.
        """
        if not self._privileged:
            raise OSError(
                "Cisco clear_counters: privileged mode required "
                "(supply enable_password when constructing the session)"
            )
        if interface is not None:
            if "\r" in interface or "\n" in interface:
                raise ValueError(
                    "clear_counters interface must not contain CR/LF"
                )
            return self._send_show(f"clear counters {interface}")
        return self._send_show("clear counters")

    def _send_show(self, command: str) -> str:
        """Send a single command line + read until the prompt comes
        back. Returns the raw response *minus* the trailing prompt."""
        self._transport.send(command)
        # IOS echoes the command back, so the prompt-end RE is the
        # cleanest delimiter.
        blob, _m = self._transport.read_until_re(
            _PROMPT_RE, timeout=self._timeout,
        )
        if len(blob) > MAX_SHOW_BYTES:
            raise OSError(
                f"Cisco-show response exceeds {MAX_SHOW_BYTES} byte cap"
            )
        # Strip leading echo of our own command.
        first_line_end = blob.find("\n")
        if first_line_end != -1 and command in blob[:first_line_end + 1]:
            blob = blob[first_line_end + 1:]
        return _strip_trailing_prompt(blob)

    # ------------------------------------------------------------------
    # FileBackend — read surface
    # ------------------------------------------------------------------

    def home(self) -> str:
        return "/show"

    def separator(self) -> str:
        return "/"

    def join(self, *parts: str) -> str:
        cleaned = [s for s in (p.strip("/") for p in parts) if s]
        if not cleaned:
            return "/"
        return "/" + "/".join(cleaned)

    def parent(self, path: str) -> str:
        return posixpath.dirname(path.rstrip("/")) or "/"

    def normalize(self, path: str) -> str:
        if not path:
            return "/"
        if not path.startswith("/"):
            path = "/" + path
        return posixpath.normpath(path) or "/"

    def list_dir(self, path: str) -> list[FileItem]:
        path = self.normalize(path)
        if path == "/":
            return [FileItem(
                name="show", is_dir=True, is_link=False, size=0,
                modified=datetime.fromtimestamp(0), permissions=0o555,
            )]
        if path == "/show":
            return [
                FileItem(
                    name=f"{name}.txt", is_dir=False, is_link=False,
                    size=0, modified=datetime.fromtimestamp(0),
                    permissions=0o444,
                )
                for name, _cmd in _KNOWN_SHOWS
            ]
        return []

    def stat(self, path: str) -> FileItem:
        path = self.normalize(path)
        if path in ("/", "/show"):
            return FileItem(
                name=posixpath.basename(path) or "/", is_dir=True,
                is_link=False, size=0,
                modified=datetime.fromtimestamp(0), permissions=0o555,
            )
        if path.startswith("/show/"):
            return FileItem(
                name=posixpath.basename(path), is_dir=False,
                is_link=False, size=0,
                modified=datetime.fromtimestamp(0), permissions=0o444,
            )
        raise OSError(f"Cisco stat({path}): only /show/* paths exist")

    def is_dir(self, path: str) -> bool:
        return self.normalize(path) in ("/", "/show")

    def exists(self, path: str) -> bool:
        try:
            self.stat(path)
            return True
        except OSError:
            return False

    def open_read(self, path: str) -> IO[bytes]:
        path = self.normalize(path)
        if not path.startswith("/show/"):
            raise OSError(f"Cisco read({path}): only /show/<cmd>.txt is readable")
        leaf = posixpath.basename(path)
        # Curated commands take priority; fall back to free-form
        # ``show <name>``.
        cmd = next(
            (full for n, full in _KNOWN_SHOWS if leaf == f"{n}.txt"),
            f"show {_safe_show_subcmd(leaf)}",
        )
        log.debug("Cisco %s -> %r", path, cmd)
        return io.BytesIO(self._send_show(cmd).encode("utf-8"))

    def readlink(self, path: str) -> str:
        raise OSError("Cisco-Telnet has no symlinks")

    def list_versions(self, path: str) -> list:
        return []

    def open_version_read(self, path: str, version_id: str):
        raise OSError("Cisco-Telnet has no version history")

    def disk_usage(self, path: str) -> tuple[int, int, int]:
        return (0, 0, 0)

    def checksum(self, path: str, algorithm: str = "sha256") -> str:
        return ""

    # ------------------------------------------------------------------
    # FileBackend — write surface (refused)
    # ------------------------------------------------------------------

    def open_write(self, path: str, append: bool = False) -> IO[bytes]:
        raise OSError(
            "Cisco-Telnet is read-only. Use a real terminal session "
            "for ``configure terminal`` workflows."
        )

    def mkdir(self, path: str) -> None:
        raise OSError("Cisco-Telnet is read-only — mkdir not supported")

    def remove(self, path: str, recursive: bool = False) -> None:
        raise OSError("Cisco-Telnet is read-only — remove not supported")

    def rename(self, src: str, dst: str) -> None:
        raise OSError("Cisco-Telnet is read-only — rename not supported")

    def chmod(self, path: str, mode: int) -> None:
        raise OSError("Cisco-Telnet has no POSIX permissions")

    def copy(self, src: str, dst: str) -> None:
        raise OSError("Cisco-Telnet is read-only — copy not supported")
