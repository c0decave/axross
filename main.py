#!/usr/bin/env python3
"""Axross — Flexible multi-protocol file manager."""

from __future__ import annotations

import argparse
import logging
import logging.handlers
import os
import sys
from pathlib import Path

LOG_DIR = Path.home() / ".local" / "state" / "axross" / "logs"
LOG_FILE = LOG_DIR / "axross.log"


def setup_logging(debug: bool = False) -> None:
    level = logging.DEBUG if debug else logging.INFO
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(LOG_DIR, 0o700)
    except OSError:
        pass

    root = logging.getLogger()
    root.setLevel(level)
    for handler in list(root.handlers):
        if getattr(handler, "_axross_handler", False):
            root.removeHandler(handler)

    file_handler = logging.handlers.RotatingFileHandler(
        LOG_FILE, maxBytes=5 * 1024 * 1024, backupCount=3, encoding="utf-8"
    )
    file_handler._axross_handler = True  # type: ignore[attr-defined]
    file_handler.setFormatter(
        logging.Formatter("%(asctime)s [%(levelname)s] %(name)s: %(message)s")
    )
    root.addHandler(file_handler)
    try:
        os.chmod(LOG_FILE, 0o600)
    except OSError:
        pass

    if debug:
        console = logging.StreamHandler(sys.stderr)
        console._axross_handler = True  # type: ignore[attr-defined]
        console.setFormatter(logging.Formatter("[%(levelname)s] %(name)s: %(message)s"))
        root.addHandler(console)


CRASH_FILE_NAME = "crash.log"
CRASH_FILE_MAX_BYTES = 1024 * 1024
# faulthandler writes to this file's descriptor at the moment of a fatal
# signal, so it stays open for the life of the process.
_crash_file = None


def enable_crash_traces() -> Path | None:
    """Have a segfault or abort write every thread's Python stack to
    <log dir>/crash.log, after a header with version and platform.

    A crash in Qt ends the process without a Python traceback, and the
    regular log stops at whatever ran last. The file is private (0600),
    appended to, and moved to crash.log.1 once it passes 1 MiB. Returns
    its path, or None when it cannot be opened - a start never fails
    over its crash log.
    """
    global _crash_file
    import faulthandler
    import platform
    import time

    from axross._version import __version__

    path = LOG_DIR / CRASH_FILE_NAME
    try:
        LOG_DIR.mkdir(parents=True, exist_ok=True)
        if path.exists() and path.stat().st_size > CRASH_FILE_MAX_BYTES:
            path.replace(path.with_name(CRASH_FILE_NAME + ".1"))
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
        os.chmod(path, 0o600)
        handle = os.fdopen(fd, "a", encoding="utf-8")
        handle.write(
            f"--- axross {__version__}, pid {os.getpid()}, started "
            f"{time.strftime('%Y-%m-%d %H:%M:%S %z')}, {sys.platform} "
            f"({platform.platform()}), Python {platform.python_version()} ---\n"
        )
        handle.flush()
        faulthandler.enable(file=handle, all_threads=True)
    except OSError:
        return None
    if _crash_file is not None and _crash_file is not handle:
        _crash_file.close()
    _crash_file = handle
    return path


def _load_app_icon():
    """Build a multi-resolution :class:`PyQt6.QtGui.QIcon` from the
    constellation PNGs that ship under ``resources/logo/``. We attach
    every available size so taskbars / window managers can pick the
    sharpest match. Falls back to an empty icon if the resources
    tree is absent (slim wheel / repo-less install)."""
    from PyQt6.QtGui import QIcon, QPixmap

    icon = QIcon()
    base = Path(__file__).resolve().parent / "resources" / "logo"
    # The SVG works as a vector source; PyQt rasterises on demand
    # when the SVG plugin is present. We add explicit PNGs too so
    # the build still has crisp sizes if SVG plugin is unavailable.
    svg = base / "axross-logo.svg"
    if svg.exists():
        icon.addFile(str(svg))
    for size in (16, 32, 48, 64, 128, 256, 512):
        png = base / f"axross-logo-{size}.png"
        if png.exists():
            icon.addPixmap(QPixmap(str(png)))
    return icon


def _install_excepthook() -> None:
    """Keep Qt from aborting the process on unhandled slot exceptions.

    PyQt 6.5+ aborts (``core dumped``) when an exception escapes a
    Python slot. Without this hook a single bug during a button click
    can kill the whole app mid-session and discard unsaved state. The
    hook logs the traceback and — if a QApplication is up — shows a
    QMessageBox. KeyboardInterrupt still stops the app; only
    non-interactive errors are caught.
    """
    import traceback

    log = logging.getLogger("axross.excepthook")

    def _hook(exc_type, exc, tb):
        if issubclass(exc_type, (KeyboardInterrupt, SystemExit)):
            sys.__excepthook__(exc_type, exc, tb)
            return
        text = "".join(traceback.format_exception(exc_type, exc, tb))
        log.error("Unhandled exception:\n%s", text)
        # REPL-originating exceptions: render inline + log only; never
        # pop a dialog. The user is at an interactive prompt — a modal
        # dialog interrupts the typing flow and is the wrong UX for a
        # typo like ``axross.list_scrips()``.
        walker = tb
        while walker is not None:
            fname = walker.tb_frame.f_code.co_filename
            if fname == "<repl>" or fname.endswith("repl_widget.py"):
                return
            walker = walker.tb_next
        # Only pop a dialog when we're safely in the GUI thread AND
        # the app isn't already closing. Cross-thread modal dialogs
        # are undefined behaviour in Qt; showing a dialog during
        # shutdown can deadlock.
        try:
            from PyQt6.QtCore import QThread
            from PyQt6.QtWidgets import QApplication, QMessageBox

            app = QApplication.instance()
            if (
                app is not None
                and not app.closingDown()
                and app.thread() == QThread.currentThread()
            ):
                QMessageBox.critical(
                    None,
                    "Axross — Unexpected Error",
                    f"{exc_type.__name__}: {exc}\n\n(Details in the log.)",
                )
                return
        except Exception:  # noqa: BLE001
            # PyQt import failed, or the dialog itself raised — fall
            # through to the console-style traceback. Never crash the
            # excepthook itself.
            pass
        sys.__excepthook__(exc_type, exc, tb)

    sys.excepthook = _hook


MCP_HTTP_TOKEN_ENV = "AXROSS_MCP_HTTP_TOKEN"


def _parse_mcp_http(value: str) -> tuple[str, int]:
    """``HOST:PORT`` of --mcp-http as (host, port); an IPv6 host goes in
    brackets (``[::1]:7331``), an empty host is 127.0.0.1. ValueError
    with the one-line message otherwise."""
    if value.startswith("["):
        host, sep, rest = value[1:].partition("]")
        if not sep or not rest.startswith(":"):
            raise ValueError(f"--mcp-http expects [IPV6]:PORT, got {value!r}")
        port_str = rest[1:]
    else:
        if ":" not in value:
            raise ValueError(f"--mcp-http expects HOST:PORT, got {value!r}")
        host, _, port_str = value.rpartition(":")
        if ":" in host:
            raise ValueError(
                f"--mcp-http: an IPv6 address goes in brackets ([::1]:7331), got {value!r}"
            )
    if not port_str:
        raise ValueError(f"--mcp-http expects HOST:PORT, got {value!r}")
    try:
        port = int(port_str)
    except ValueError:
        raise ValueError(f"--mcp-http port {port_str!r} is not an integer") from None
    # Port 0 means "OS picks an ephemeral port" which is pointless for a
    # server you want to connect to; negative and >65535 are invalid by
    # the TCP spec. Reject up-front rather than letting bind() surface a
    # cryptic error.
    if not (1 <= port <= 65535):
        raise ValueError(f"--mcp-http port must be 1..65535, got {port}")
    return host or "127.0.0.1", port


def _mcp_http_token(args, port: int) -> str | None:
    """The bearer token of an ``--mcp-http`` server.

    Plain HTTP (no mTLS) always gets one: ``$AXROSS_MCP_HTTP_TOKEN`` when
    set, else a fresh random token. It is written to a 0600 file and
    shown once on stderr, for the client's ``Authorization: Bearer``
    header. An mTLS server uses the variable only when it is set."""
    import secrets

    from core import mcp_http as MH

    token = os.environ.get(MCP_HTTP_TOKEN_ENV, "").strip()
    if args.mcp_cert and args.mcp_key and args.mcp_ca:
        return token or None
    token = token or secrets.token_urlsafe(32)
    path = MH.publish_token(token, port)
    print(
        "MCP HTTP: every request needs the header 'Authorization: Bearer <token>'.\n"
        f"Token: {token}\n(also in {path}, readable only by you)",
        file=sys.stderr,
    )
    return token


def _resolve_mcp_root(backend, raw_root: str | None) -> str:
    if not raw_root:
        return backend.home()
    root = Path(raw_root).expanduser()
    return str(root.resolve(strict=False))


def _gui_smoke_ms() -> int | None:
    """AXROSS_SMOKE_GUI_MS: open the window, report, quit after that many ms.

    For the bundle smoke (scripts/bundle_smoke.py --native): a CI run on
    macOS and Windows starts the real window and sees it come up. None
    when unset, -1 (after a message) when it is no number.
    """
    raw = os.environ.get("AXROSS_SMOKE_GUI_MS")
    if raw is None:
        return None
    try:
        value = int(raw)
    except ValueError:
        value = -1
    if value < 0:
        print(f"AXROSS_SMOKE_GUI_MS must be a number of milliseconds, not {raw!r}", file=sys.stderr)
        return -1
    return value


def _arm_gui_smoke(app, ms: int) -> None:
    from PyQt6.QtCore import QTimer

    def shown() -> None:
        print(f"gui smoke: window shown on {app.platformName()}", flush=True)
        QTimer.singleShot(ms, app.quit)

    QTimer.singleShot(0, shown)  # runs once the event loop has painted the window


def _no_screen_message(app) -> str | None:
    """The message for a platform without a screen, None when there is one.

    Without a screen Qt aborts on the first window ("Cannot create window:
    no screens available") - on macOS that is a start over SSH without a
    desktop session, and the abort leaves crash reports that look like a
    bug in axross.
    """
    if app.screens():
        return None
    return (
        f"axross: no screen to open the window on (Qt platform '{app.platformName()}'). "
        "Start axross in a desktop session - over SSH on macOS only the user logged in "
        "at the screen has one - or run it without a window: --mcp-server, --script FILE, "
        "or QT_QPA_PLATFORM=offscreen."
    )


def main() -> int:
    if sys.argv[1:] == ["--agent-worker"]:
        # The agent in its own process (core.agent_sandbox starts it, mostly
        # in a sandbox): no GUI, no log files, stdin/stdout are its channel.
        from core.agent_worker import main as agent_worker_main

        return agent_worker_main()
    parser = argparse.ArgumentParser(description="Axross File Manager")
    from axross._version import __version__

    parser.add_argument(
        "--version",
        action="version",
        version=f"axross {__version__}",
    )
    parser.add_argument("--debug", action="store_true", help="Enable debug logging")
    parser.add_argument(
        "--script",
        default=None,
        help="Run a Python script against the axross scripting surface "
        "(headless, no GUI). Use '-' to read from stdin. Inside the script "
        "the curated API is reachable as `axross.*`.",
    )
    parser.add_argument(
        "--mcp-server",
        action="store_true",
        help="Run as an MCP (Model Context Protocol) server on stdio instead "
        "of launching the GUI. Can also be enabled via AXROSS_MCP=1.",
    )
    parser.add_argument(
        "--mcp-write",
        action="store_true",
        help="When running as an MCP server, expose the nine write tools "
        "(write_file, mkdir, remove, rename, copy, bulk_copy, symlink, "
        "hardlink, chmod) and the mutating tools of the --mcp-tools groups. "
        "Needs --mcp-root. Off by default — read-only is safe.",
    )
    parser.add_argument(
        "--mcp-allow-scripts",
        action="store_true",
        help="Expose the script_list/api_schema/read/write/run/delete tools to the "
        "MCP client. script_run executes arbitrary Python as you (in a "
        "child process), so this is gated behind its own opt-in (separate from "
        "--mcp-write). stdio only: refused together with --mcp-http.",
    )
    parser.add_argument(
        "--mcp-allow-exec",
        action="store_true",
        help="Serve the exec group (remote_exec, remote_script, exec_backends): "
        "commands and scripts on remote hosts over SSH, SCP, Telnet, rsh, ADB, "
        "WinRM and Cisco (show only). Needs --mcp-tools exec (or all); its own "
        "opt-in, separate from --mcp-write. Refused in the paranoid security mode.",
    )
    parser.add_argument(
        "--mcp-tools",
        action="append",
        default=None,
        metavar="GROUP[,GROUP...]",
        help="Add optional MCP capability groups on top of the file tools; "
        "repeatable or comma-separated, also via AXROSS_MCP_TOOLS. Groups: "
        "metadata, duplicates, packer, archive, crypto, index, filetype, "
        "transfer, remote, exec, agent, extensions; 'all' is every group. Mutating tools "
        "of a group additionally need --mcp-write (exec: --mcp-allow-exec). "
        "Default: no group (the file tools only).",
    )
    parser.add_argument(
        "--mcp-list-tools",
        action="store_true",
        help="Print a JSON manifest of the MCP tools that --mcp-server with the "
        "same --mcp-tools / --mcp-write / --mcp-allow-scripts / --mcp-allow-exec "
        "flags (and their AXROSS_MCP_* variables) would serve - name, group, "
        "read-only or mutating, required flags, input schema, timeout class, "
        "description - and exit without starting a server. docs/mcp-tools.json "
        "is this output for '--mcp-tools all --mcp-write --mcp-allow-scripts "
        "--mcp-allow-exec'.",
    )
    parser.add_argument(
        "--mcp-root",
        default=None,
        help="Filesystem root exposed to MCP file tools. Defaults to the "
        "backend home directory.",
    )
    parser.add_argument(
        "--mcp-http",
        default=None,
        help="Run the MCP server as HTTP on HOST:PORT (e.g. 127.0.0.1:7331, "
        "[::1]:7331) instead of stdio. Non-loopback hosts require TLS flags; "
        "without TLS every request needs the bearer token printed at start.",
    )
    parser.add_argument(
        "--mcp-cert",
        default=None,
        help="Server certificate file for mTLS (PEM).",
    )
    parser.add_argument(
        "--mcp-key",
        default=None,
        help="Server private-key file for mTLS (PEM).",
    )
    parser.add_argument(
        "--mcp-ca",
        default=None,
        help="CA bundle that signs valid client certificates. mTLS is "
        "enabled when all three of --mcp-cert / --mcp-key / --mcp-ca "
        "are supplied.",
    )
    args = parser.parse_args()

    setup_logging(args.debug)
    log = logging.getLogger("axross")
    crash_log = enable_crash_traces()
    if crash_log is not None:
        log.info("Crash traces go to %s", crash_log)
        if args.debug:
            print(f"axross: a crash writes every thread's stack to {crash_log}", file=sys.stderr)

    # Interface language, before any window is built. Precedence and the
    # reasoning behind it live in core.i18n: a deliberate locale
    # outranks the timezone, because a timezone says where the machine
    # is and not what its owner reads.
    from core.i18n import detect_language, install, stored_language

    install(detect_language(configured=stored_language()))

    # Apply the SSH banner override globally before any Transport is
    # instantiated downstream. Safe to call when paramiko is absent
    # (headless MCP builds that drop it) — the helper is a no-op then.
    from core.client_identity import apply_paramiko_banner_override

    apply_paramiko_banner_override()

    # Route tempfile to tmpfs if the user opted in (off by default),
    # tmpfs is available and TMPDIR is not set. Affects every subsequent
    # tempfile / NamedTemporaryFile / mkdtemp call (archive extracts,
    # FUSE flush buffers, download spools, …) so temp data doesn't land
    # on disk - and takes RAM, which is why it is an opt-in.
    try:
        from core.tmpfs_detect import apply_tempdir_preference

        apply_tempdir_preference()
    except Exception as exc:  # noqa: BLE001 — never block boot for this
        log.debug("tmpfs tempdir routing skipped: %s", exc)

    # Feature flag: the MCP path must be explicitly opted into, either
    # via --mcp-server or via AXROSS_MCP={1,true,yes,on}. Anything
    # else boots the GUI as before — PyQt isn't imported on the MCP
    # path so the server runs on headless machines without a display.
    truthy = {"1", "true", "yes", "on"}
    mcp_env = os.environ.get("AXROSS_MCP", "").strip().lower()
    write_env = os.environ.get("AXROSS_MCP_WRITE", "").strip().lower()
    if args.mcp_list_tools or args.mcp_server or mcp_env in truthy:
        log.info(
            "%s Axross MCP server (read-only=%s, http=%s)",
            "Listing the tools of the" if args.mcp_list_tools else "Starting",
            not args.mcp_write,
            bool(args.mcp_http),
        )
        _install_excepthook()
        from core.backend_registry import init_registry

        init_registry()
        from core import mcp_server as M

        allow_write = args.mcp_write or write_env in truthy
        from core.security_mode import current_policy

        if args.mcp_allow_scripts and not current_policy().allow_scripts:
            print(
                "Security mode 'paranoid' blocks MCP script execution.",
                file=sys.stderr,
            )
            return 2
        if args.mcp_allow_exec and not current_policy().allow_remote_exec:
            print(
                "Security mode 'paranoid' blocks MCP remote command execution.",
                file=sys.stderr,
            )
            return 2
        if args.mcp_allow_scripts and args.mcp_http:
            # The HTTP transport never wires the script tools. Accepting
            # the flag there would let an operator believe scripts are
            # reachable (or, worse, later wire them by accident) — and
            # Python execution over a network transport is not offered.
            print(
                "--mcp-allow-scripts is stdio-only: script execution over a "
                "network transport (--mcp-http) is not offered.",
                file=sys.stderr,
            )
            return 2
        from core import mcp_groups as MG

        try:
            tool_groups = MG.groups_from(args.mcp_tools, env_value=os.environ.get(MG.ENV_VAR))
        except MG.GroupError as exc:
            print(str(exc), file=sys.stderr)
            return 2
        backend = M.default_backend()
        if args.mcp_list_tools:
            # The manifest of exactly what this start would serve; nothing
            # is served, so the write root is not demanded here.
            tools = M._build_tools(
                backend,
                allow_write=allow_write,
                root=_resolve_mcp_root(backend, args.mcp_root),
                allow_scripts=args.mcp_allow_scripts,
                tool_groups=tool_groups,
                allow_exec=args.mcp_allow_exec,
            )
            manifest = MG.tool_manifest(
                tools,
                groups=tool_groups,
                allow_write=allow_write,
                allow_scripts=args.mcp_allow_scripts,
                allow_exec=args.mcp_allow_exec,
            )
            sys.stdout.write(MG.manifest_json(manifest))
            return 0
        # Default the MCP root to the backend's home() so an LLM
        # cannot read or write outside what we deliberately exposed
        # (e.g. read_file("/etc/passwd")). Users who want a wider
        # surface have to lower the root explicitly.
        if allow_write and not args.mcp_root:
            # The default root is $HOME. A writable $HOME lets a
            # prompt-injected client plant ~/.bashrc, ~/.ssh/authorized_keys
            # or an autostart entry, which the user then executes.
            print(
                "MCP write tools need an explicit --mcp-root DIR: the default "
                "root (your home directory) is too wide to be writable.",
                file=sys.stderr,
            )
            return 2
        root = _resolve_mcp_root(backend, args.mcp_root)
        if args.mcp_http:
            # CLI-usage errors go to stderr regardless of the logging
            # config - the user may not have --debug on, and a silent
            # failure with exit 2 is worse than a one-line complaint. A
            # refusal is one line, never a traceback.
            try:
                host, port = _parse_mcp_http(args.mcp_http)
            except ValueError as exc:
                print(str(exc), file=sys.stderr)
                return 2
            from core import mcp_http as MH

            config = MH.HTTPServerConfig(
                backend=backend,
                host=host,
                port=port,
                allow_write=allow_write,
                root=root,
                cert_file=args.mcp_cert,
                key_file=args.mcp_key,
                ca_file=args.mcp_ca,
                tool_groups=tool_groups,
                allow_exec=args.mcp_allow_exec,
            )
            try:
                # Refused before a token is handed out for nothing.
                MH.check_config(config)
                config.auth_token = _mcp_http_token(args, port)
                MH.serve_http(config)
            except (ValueError, OSError) as exc:
                print(f"--mcp-http {args.mcp_http}: {exc}", file=sys.stderr)
                return 2
            return 0
        return M.serve(
            M.ServerConfig(
                backend=backend,
                allow_write=allow_write,
                allow_scripts=args.mcp_allow_scripts,
                root=root,
                tool_groups=tool_groups,
                allow_exec=args.mcp_allow_exec,
            )
        )

    if args.script:
        from core.security_mode import current_policy

        if not current_policy().allow_scripts:
            print(
                "Security mode 'paranoid' blocks --script execution.",
                file=sys.stderr,
            )
            return 2
        log.info("Running Axross script %s", args.script)
        from core.backend_registry import init_registry

        init_registry()
        if args.script == "-":
            source = sys.stdin.read()
            filename = "<stdin>"
        else:
            with open(args.script, "r", encoding="utf-8") as fh:
                source = fh.read()
            filename = args.script
        # Shared with the Scripts dock's child process: one namespace and
        # one SystemExit mapping (None is 0, an int is the status, anything
        # else is a message on stderr and status 1).
        from core.script_runner import execute_source

        return execute_source(source, filename)

    log.info("Starting Axross")
    _install_excepthook()
    smoke_ms = _gui_smoke_ms()
    if smoke_ms == -1:
        return 2

    from core.backend_registry import init_registry

    init_registry()

    from PyQt6.QtWidgets import QApplication

    from ui.main_window import MainWindow

    app = QApplication(sys.argv)
    app.setApplicationName("Axross")
    app.setOrganizationName("axross")
    no_screen = _no_screen_message(app)
    if no_screen:
        print(no_screen, file=sys.stderr)
        return 1

    # Load the constellation logo at every standard icon size so the
    # window manager / taskbar / Wayland xdg-toplevel pick the closest
    # match without re-scaling. Falls back silently if the resources
    # tree is missing (e.g. a slim wheel).
    _icon = _load_app_icon()
    if not _icon.isNull():
        app.setWindowIcon(_icon)

    window = MainWindow()
    if not _icon.isNull():
        window.setWindowIcon(_icon)
    # The last session's layout, before the first paint (File > Restore
    # Layout on Start switches it off). It never connects: remote panes
    # come back as placeholders with a Reconnect button.
    window.restore_layout_on_start()
    window.show()

    log.info("Application ready")
    if smoke_ms is not None:
        _arm_gui_smoke(app, smoke_ms)
    return app.exec()


if __name__ == "__main__":
    raise SystemExit(main())
