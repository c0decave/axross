"""The program PyInstaller freezes: axross-markdown's own command.

On Windows it is a window program (no console window beside the viewer -
packaging/axross-markdown.spec): Python gives it no standard streams there.
The arguments that read or write them get the ones the shell or the parent
handed on (a file, a pipe) - else, for the terminal view, --html, --version
and --help, the console it was started from (attach_console).
"""

import sys

#: The arguments that write to standard output (the terminal view, --html, --version, --help, the updates).
OUTPUT_ARGS = ("--term", "-t", "--cat", "--html", "--version", "--help", "-h", "--check-update", "--update",
               "--update-mode")
#: ... and those whose streams are a parent's pipes only (an SVG drawn in a child, a build's check, the
#: self-test the updater runs a downloaded program with).
PIPED_ARGS = ("--svg-worker", "--lex-worker", "--image-worker", "--script", "--self-test")


def attach_console(argv, platform=sys.platform, kernel32=None) -> bool:
    """Standard streams for a window program on Windows that needs them
    (OUTPUT_ARGS, PIPED_ARGS): those handed on, else the parent's console
    (AttachConsole) - not for PIPED_ARGS. Whether it has them now."""
    if platform != "win32" or sys.stdout is not None:
        return False
    wanted = [a for a in argv[1:] if a in OUTPUT_ARGS or a in PIPED_ARGS]
    if not wanted:
        return False
    if kernel32 is None:
        import ctypes

        kernel32 = ctypes.windll.kernel32
    if sys.stdin is None:
        sys.stdin = _handed_on(kernel32, -10, "r")  # (STD_INPUT_HANDLE: an SVG to draw, a file's text)
    handed = _handed_on(kernel32, -11, "w")  # (STD_OUTPUT_HANDLE: "> page.html", "| more", a pipe)
    if handed is not None:
        sys.stdout = handed
        if sys.stderr is None:
            sys.stderr = _handed_on(kernel32, -12, "w") or handed
        return True
    if any(a in PIPED_ARGS for a in wanted):
        return False
    if not kernel32.AttachConsole(-1):  # (ATTACH_PARENT_PROCESS: none - started from Explorer)
        return False
    sys.stdout = open("CONOUT$", "w", encoding="utf-8")  # noqa: SIM115 - the program's own output
    sys.stderr = open("CONOUT$", "w", encoding="utf-8")  # noqa: SIM115
    return True


def _handed_on(kernel32, which: int, mode: str):
    """The standard stream *which* as the shell or the parent handed it on - or None."""
    handle = kernel32.GetStdHandle(which)
    if not handle or handle == -1:
        return None
    try:
        import msvcrt
        import os

        flags = os.O_RDONLY if mode == "r" else os.O_WRONLY
        return open(msvcrt.open_osfhandle(handle, flags), mode, encoding="utf-8")  # noqa: SIM115
    except (ImportError, OSError, ValueError):
        return None


def run() -> int:
    attach_console(sys.argv)
    from axross_markdown.__main__ import main

    return main()


if __name__ == "__main__":
    sys.exit(run())
