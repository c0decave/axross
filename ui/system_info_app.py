"""System Information as a program of its own: ``axross-system-info``.

The same window as axross's System Information (ui/system_info_window.py):
a dashboard with live gauges and a page per area, search, copy, text and
JSON export with identifiers hidden - its size kept in axross's settings.
"""

from __future__ import annotations

import sys

from ui.standalone_app import run, smoke_ms_from_env

NAME = "axross-system-info"
TITLE = "System Information"


def build(app, args: list[str]):
    """Open the window; closing it ends the program."""
    from ui.system_info_window import open_window

    window = open_window(None)
    window.finished.connect(lambda _code: app.quit())
    app._ax_window = window   # noqa: SLF001 - kept with the application
    if "--json" in args:
        # axross-system-info --json FILE: write the report and quit (scripts).
        index = args.index("--json")
        target = args[index + 1] if index + 1 < len(args) else "system-info.json"
        _export_when_ready(app, window, target)
    return None


#: The longest --json waits for the gathering (a hanging mount, a tool).
JSON_DEADLINE_S = 180.0


def _export_when_ready(app, window, target: str) -> None:
    import time

    from PyQt6.QtCore import QTimer

    deadline = time.monotonic() + JSON_DEADLINE_S

    def poll() -> None:
        if window.report is None:
            error = getattr(window, "gather_error", "")
            if not error and time.monotonic() > deadline:
                error = f"no report within {JSON_DEADLINE_S:.0f} s"
            if error:
                # A script waits for the exit: say why, never wait forever.
                print(f"{NAME}: could not gather the system information: {error}",
                      file=sys.stderr)
                app.exit(1)
                return
            QTimer.singleShot(100, poll)
            return
        ok = window.save_report(target, as_json=True)
        app.exit(0 if ok else 1)

    QTimer.singleShot(100, poll)


def main(argv: list[str] | None = None) -> int:
    return run(NAME, TITLE, "system-info", build, argv, smoke_ms=smoke_ms_from_env())


if __name__ == "__main__":
    sys.exit(main())
