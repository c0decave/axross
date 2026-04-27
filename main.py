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
            from PyQt6.QtWidgets import QApplication, QMessageBox
            from PyQt6.QtCore import QThread
            app = QApplication.instance()
            if (
                app is not None
                and not app.closingDown()
                and app.thread() == QThread.currentThread()
            ):
                QMessageBox.critical(
                    None, "Axross — Unexpected Error",
                    f"{exc_type.__name__}: {exc}\n\n"
                    f"(Details in the log.)",
                )
                return
        except Exception:  # noqa: BLE001
            # PyQt import failed, or the dialog itself raised — fall
            # through to the console-style traceback. Never crash the
            # excepthook itself.
            pass
        sys.__excepthook__(exc_type, exc, tb)

    sys.excepthook = _hook


def main() -> int:
    parser = argparse.ArgumentParser(description="Axross File Manager")
    parser.add_argument("--debug", action="store_true", help="Enable debug logging")
    parser.add_argument(
        "--script", default=None,
        help="Run a Python script against the axross scripting surface "
        "(headless, no GUI). Use '-' to read from stdin. Inside the script "
        "the curated API is reachable as `axross.*`.",
    )
    parser.add_argument(
        "--mcp-server", action="store_true",
        help="Run as an MCP (Model Context Protocol) server on stdio instead "
        "of launching the GUI. Can also be enabled via AXROSS_MCP=1.",
    )
    parser.add_argument(
        "--mcp-write", action="store_true",
        help="When running as an MCP server, expose the write tools "
        "(write_file, mkdir, remove). Off by default — read-only is safe.",
    )
    parser.add_argument(
        "--mcp-allow-scripts", action="store_true",
        help="Expose the script_list/read/write/run/delete tools to the "
        "MCP client. script_run executes Python in the server process, "
        "so this is gated behind its own opt-in (separate from "
        "--mcp-write).",
    )
    parser.add_argument(
        "--mcp-http", default=None,
        help="Run the MCP server as HTTP on HOST:PORT (e.g. 127.0.0.1:7331) "
        "instead of stdio. Non-loopback hosts require TLS flags.",
    )
    parser.add_argument(
        "--mcp-cert", default=None,
        help="Server certificate file for mTLS (PEM).",
    )
    parser.add_argument(
        "--mcp-key", default=None,
        help="Server private-key file for mTLS (PEM).",
    )
    parser.add_argument(
        "--mcp-ca", default=None,
        help="CA bundle that signs valid client certificates. mTLS is "
        "enabled when all three of --mcp-cert / --mcp-key / --mcp-ca "
        "are supplied.",
    )
    args = parser.parse_args()

    setup_logging(args.debug)
    log = logging.getLogger("axross")

    # Apply the SSH banner override globally before any Transport is
    # instantiated downstream. Safe to call when paramiko is absent
    # (headless MCP builds that drop it) — the helper is a no-op then.
    from core.client_identity import apply_paramiko_banner_override
    apply_paramiko_banner_override()

    # Route tempfile to tmpfs if the user opted in and tmpfs is
    # available. Affects every subsequent tempfile / NamedTemporaryFile
    # / mkdtemp call (archive extracts, FUSE flush buffers, …) so
    # short-lived temp data doesn't land on disk.
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
    if args.mcp_server or mcp_env in truthy:
        log.info("Starting Axross MCP server (read-only=%s, http=%s)",
                 not args.mcp_write, bool(args.mcp_http))
        _install_excepthook()
        from core.backend_registry import init_registry
        init_registry()
        from core import mcp_server as M
        allow_write = args.mcp_write or write_env in truthy
        backend = M.default_backend()
        # Default the write-tool root to the backend's home() so an
        # LLM cannot write outside what we deliberately exposed
        # (e.g. write_file("/etc/passwd")). Users who want a wider
        # surface have to lower the root explicitly.
        root = backend.home() if allow_write else None
        if args.mcp_http:
            host, _, port_str = args.mcp_http.partition(":")
            if not port_str:
                # CLI-usage errors go to stderr regardless of the
                # logging config — the user may not have --debug on,
                # and a silent failure with exit 2 is worse than a
                # one-line complaint.
                print(
                    f"--mcp-http expects HOST:PORT, got {args.mcp_http!r}",
                    file=sys.stderr,
                )
                return 2
            try:
                port = int(port_str)
            except ValueError:
                print(
                    f"--mcp-http port {port_str!r} is not an integer",
                    file=sys.stderr,
                )
                return 2
            # Port 0 means "OS picks an ephemeral port" which is
            # pointless for a server you want to connect to; negative
            # and >65535 are invalid by the TCP spec. Reject up-front
            # rather than letting bind() surface a cryptic error.
            if not (1 <= port <= 65535):
                print(
                    f"--mcp-http port must be 1..65535, got {port}",
                    file=sys.stderr,
                )
                return 2
            from core import mcp_http as MH
            MH.serve_http(MH.HTTPServerConfig(
                backend=backend,
                host=host or "127.0.0.1",
                port=port,
                allow_write=allow_write,
                root=root,
                cert_file=args.mcp_cert,
                key_file=args.mcp_key,
                ca_file=args.mcp_ca,
            ))
            return 0
        return M.serve(
            M.ServerConfig(
                backend=backend,
                allow_write=allow_write,
                allow_scripts=args.mcp_allow_scripts,
                root=root,
            )
        )

    if args.script:
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
        import core.scripting as _scripting
        ns: dict = {
            "__name__": "__main__",
            "__file__": filename,
            "axross": _scripting,
        }
        try:
            exec(compile(source, filename, "exec"), ns)
        except SystemExit as exc:
            return int(exc.code or 0)
        return 0

    log.info("Starting Axross")
    _install_excepthook()

    from core.backend_registry import init_registry
    init_registry()

    from PyQt6.QtGui import QIcon
    from PyQt6.QtWidgets import QApplication

    from ui.main_window import MainWindow

    app = QApplication(sys.argv)
    app.setApplicationName("Axross")
    app.setOrganizationName("axross")

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
    window.show()

    log.info("Application ready")
    return app.exec()


if __name__ == "__main__":
    raise SystemExit(main())
