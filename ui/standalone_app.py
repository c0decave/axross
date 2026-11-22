"""What a tool of axross needs to run as a program of its own: the Media
Player (ui.media_player_app) and System Information (ui.system_info_app).

Both also live inside axross; scripts/export_standalone.py writes each as an
installable project and a binary. This module is the part of axross's
main.py they share: the interface language, the theme (the program's own
choice - View > Theme, ~/.config/NAME/settings.json -, else the one chosen in
axross, else the desktop's light or dark scheme), the excepthook that keeps PyQt6 from
aborting the process on an exception in a slot, the multimedia probe's child
mode for a frozen build, and an orderly exit.
"""

from __future__ import annotations

import logging
import sys
import traceback
from collections.abc import Callable

log = logging.getLogger(__name__)

#: The argument a frozen build starts itself with as the multimedia probe's
#: child (core.multimedia_probe.probe_command).
PROBE_ARG = "--multimedia-probe"
#: ``--script FILE`` runs a check inside the binary (scripts/bundle_smoke.py:
#: which libraries it unpacked) - only with this variable set to 1, so the
#: program offers no way to run code to anyone else.
BUNDLE_CHECK_ENV = "AXROSS_BUNDLE_SMOKE"


def bundle_check(argv: list[str]) -> int | None:
    """Run the build's check script (see BUNDLE_CHECK_ENV); None when
    *argv* asks for none."""
    import os
    import runpy

    if len(argv) != 3 or argv[1] != "--script" or os.environ.get(BUNDLE_CHECK_ENV) != "1":
        return None
    runpy.run_path(argv[2], run_name="__main__")
    return 0


def install_excepthook(title: str) -> None:
    """Log an exception that escaped (PyQt6 aborts on one in a slot) and
    show it, instead of ending the program with ``core dumped``."""

    def hook(exc_type, exc, tb):
        if issubclass(exc_type, (KeyboardInterrupt, SystemExit)):
            sys.__excepthook__(exc_type, exc, tb)
            return
        log.error("Unhandled exception:\n%s", "".join(traceback.format_exception(exc_type, exc, tb)))
        try:
            from PyQt6.QtCore import QThread
            from PyQt6.QtWidgets import QApplication, QMessageBox

            app = QApplication.instance()
            if app is not None and not app.closingDown() and app.thread() == QThread.currentThread():
                from core.i18n import tr

                QMessageBox.critical(None, tr("{title} – Unexpected Error").format(title=title),
                                     f"{exc_type.__name__}: {exc}")
                return
        except Exception:  # noqa: BLE001 - the hook itself must never fail
            pass
        sys.__excepthook__(exc_type, exc, tb)

    sys.excepthook = hook


def prepare_process(*, multimedia: bool = False) -> None:
    """Before any Qt object: the interface language, the host's CA
    certificates for https (a frozen build's OpenSSL looks for the build
    machine's: core.tls_env - every program, not only one that plays
    sound) and - for a program that plays sound (*multimedia*) - no GPU
    probe in Qt's FFmpeg and the audio backend the user chose, each as
    axross's main.py does it. Without *multimedia*
    nothing of Qt Multimedia is imported (nor bundled)."""
    from core.i18n import detect_language, install, stored_language

    try:  # (every program: an https client of its own - axross-markdown's updates - needs the host's CAs too)
        from core.tls_env import apply_ca_bundle
    except ImportError:  # (a tool exported without it)
        pass
    else:
        apply_ca_bundle()
    if multimedia:
        try:
            from core.audio_settings import apply_saved_backend
            from core.multimedia_env import apply_no_gpu_probe
        except ImportError:   # a tool exported without sound
            log.warning("no multimedia modules: sound is not prepared")
        else:
            apply_no_gpu_probe()
            apply_saved_backend()
    install(detect_language(configured=stored_language()))


def settings_file(name: str):
    """The program's own settings (its theme): ~/.config/NAME/settings.json
    (XDG_CONFIG_HOME's when set; axross-markdown's: $AXROSS_MARKDOWN_SETTINGS
    when set, core.markdown_settings) - not axross's session.json."""
    import os
    from pathlib import Path

    if name == "axross-markdown" and os.environ.get("AXROSS_MARKDOWN_SETTINGS", "").strip():
        return Path(os.environ["AXROSS_MARKDOWN_SETTINGS"].strip()).expanduser()
    base = os.environ.get("XDG_CONFIG_HOME") or str(Path.home() / ".config")
    return Path(base) / name / "settings.json"


def _settings(name: str) -> dict:
    try:
        from core.markdown_settings import read_settings
    except ImportError:  # (a tool exported without it)
        from ui.state_files import _read_json_file

        try:
            data = _read_json_file(settings_file(name))
        except (OSError, ValueError):
            return {}
        return data if isinstance(data, dict) else {}
    return read_settings(settings_file(name))  # (a typo in the file: what can still be read of it)


def stored_theme(name: str) -> str | None:
    """The theme chosen in the program (View > Theme), or None."""
    from ui import themes

    theme = _settings(name).get("theme")
    return themes.normalize(theme) if isinstance(theme, str) else None


def store_theme(name: str, theme: str) -> None:
    """Keep *theme* in the program's own settings."""
    import json

    try:
        from core.markdown_settings import write_settings
    except ImportError:  # (a tool exported without it)
        write_settings = None
    try:
        if write_settings is not None:
            # (the rest kept - a file with a typo kept aside, never taken for empty: core.markdown_settings)
            write_settings({"theme": theme}, settings_file(name))
            return
        from ui.state_files import _write_private_text

        data = _settings(name)
        data["theme"] = theme
        _write_private_text(settings_file(name), json.dumps(data, indent=2, sort_keys=True) + "\n")
    except OSError:
        log.warning("Could not keep the theme in %s", settings_file(name), exc_info=True)


def apply_theme(app, theme: str | None = None, name: str | None = None) -> str:
    """The theme *theme* - else the one chosen in the program (*name*'s own
    settings), else the one chosen in axross, else "modern": the desktop's
    light or dark scheme, light when it cannot tell (a fresh home was dark
    always: "classic"). Its name."""
    from core import i18n
    from ui import themes, window_prefs
    from ui.state_files import _read_json_file

    try:
        data = _read_json_file(i18n.SETTINGS_FILE)
    except (OSError, ValueError):
        data = None
    prefs = window_prefs.parse(data.get("window") if isinstance(data, dict) else None)
    theme = themes.normalize(theme or (stored_theme(name) if name else None) or prefs.theme or "modern")
    scheme = themes.system_scheme() or "light"
    tokens = themes.palette_tokens_for(themes.resolve(theme, scheme))
    if getattr(app, "_ax_desktop_palette", None) is None:  # (the desktop's: Light Mode's, chosen later too)
        from PyQt6.QtGui import QPalette

        app._ax_desktop_palette = QPalette(app.palette())  # noqa: SLF001 - kept with the application
    if tokens is not None:
        app.setStyle("Fusion")
        app.setPalette(themes.qpalette_for(tokens))
    else:  # Light Mode keeps the desktop's palette, with a readable selection
        app.setPalette(themes.readable_palette(app._ax_desktop_palette))  # noqa: SLF001
    app.setStyleSheet(themes.stylesheet_for(theme, scheme, compact=prefs.compact))
    from ui import title_bar

    title_bar.set_own_title_bars(prefs.own_title_bars)
    app.setProperty("axross_theme", theme)
    return theme


def follow_system_scheme(app, name: str | None = None) -> None:
    """The theme made anew when the desktop turns light or dark (for
    "modern": it follows the scheme while the program runs)."""
    hints = app.styleHints()
    signal = getattr(hints, "colorSchemeChanged", None)
    if signal is None:  # (Qt before 6.5)
        return

    def changed(_scheme) -> None:
        if app.property("axross_theme") == "modern":
            apply_theme(app, "modern", name)

    signal.connect(changed)


def fill_theme_menu(menu, app, name: str) -> None:
    """*menu* (View > Theme): axross's themes, the one in use checked - a
    choice applied at once and kept in the program's own settings."""
    from PyQt6.QtGui import QActionGroup

    from core.i18n import tr
    from ui import themes

    group = QActionGroup(menu)
    group.setExclusive(True)
    current = app.property("axross_theme") or "modern"
    for theme_id, label in themes.THEME_CHOICES:
        action = menu.addAction(tr(label))
        action.setCheckable(True)
        action.setChecked(theme_id == current)
        action.setData(theme_id)
        group.addAction(action)

    def chosen(action) -> None:
        theme_id = action.data()
        store_theme(name, theme_id)
        apply_theme(app, theme_id, name)

    group.triggered.connect(chosen)


def run(name: str, title: str, icon_name: str, build: Callable, argv: list[str] | None = None,
        *, smoke_ms: int | None = None, multimedia: bool = False) -> int:
    """Start the program: *build(app, args)* makes and shows its window and
    returns a callable run before the exit (or None). *smoke_ms*: quit after
    that many milliseconds (a start test of a build). *multimedia*: it
    plays sound (and its frozen build starts itself as the probe's child)."""
    argv = list(sys.argv if argv is None else argv)
    # As axross's main(): a frozen build gives the process the environment it
    # started with, so no child (a browser, a file manager, Qt's own) loads
    # the bundle's libraries and plugins (core.subprocess_env).
    from core.subprocess_env import restore_loader_env

    restore_loader_env(bundle_dir=getattr(sys, "_MEIPASS", None) if getattr(sys, "frozen", False)
                       else None)
    checked = bundle_check(argv)
    if checked is not None:
        return checked
    if multimedia and argv[1:] == [PROBE_ARG]:
        try:
            from core.multimedia_probe import _child_main
        except ImportError:   # a tool exported without sound
            return 1
        return _child_main()
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    install_excepthook(title)
    prepare_process(multimedia=multimedia)
    from PyQt6.QtCore import QTimer
    from PyQt6.QtWidgets import QApplication

    app = QApplication(argv)
    app.setApplicationName(name)
    app.setOrganizationName("axross")
    app.setDesktopFileName(name)
    from ui.icon_provider import icon
    from ui.qt_translations import install_qt_translator

    install_qt_translator(app)
    app.setWindowIcon(icon(icon_name, 64))
    apply_theme(app, name=name)
    follow_system_scheme(app, name)
    before_exit = build(app, argv[1:])
    if before_exit is not None:
        app.aboutToQuit.connect(before_exit)
    if smoke_ms is not None:
        QTimer.singleShot(smoke_ms, app.quit)
    status = app.exec()
    from core.qt_exit import delete_python_owned_qobjects

    delete_python_owned_qobjects()
    return status


def smoke_ms_from_env() -> int | None:
    """``AXROSS_SMOKE_MS``: quit after that many ms (a build's start test)."""
    import os

    raw = os.environ.get("AXROSS_SMOKE_MS", "")
    return int(raw) if raw.isdigit() else None


__all__ = ["BUNDLE_CHECK_ENV", "PROBE_ARG", "apply_theme", "bundle_check", "fill_theme_menu", "follow_system_scheme",
           "install_excepthook", "prepare_process", "run", "settings_file", "smoke_ms_from_env", "store_theme",
           "stored_theme"]
