"""``axross-mdcat`` (also ``axross-markdown --term``): Markdown files shown in
the terminal (core.markdown_term), through ``less -R`` when longer than the
screen. No Qt: it starts fast and works over SSH.

    axross-mdcat README.md docs/*.md
    axross-mdcat --images kitty --width 100 notes.md
    cat notes.md | axross-mdcat -
    axross-mdcat --toc README.md        # the headings only
    axross-mdcat --watch notes.md       # drawn anew whenever the file changes

Colours follow the terminal (NO_COLOR, FORCE_COLOR, COLORTERM, TERM;
``--color``), the theme its background (COLORFGBG; ``--theme``), images its
picture protocol (kitty, iTerm2 / WezTerm, else coloured half-blocks;
``--images``). Through ``less`` (search with ``/``, ``n``), links stay links
only where that less passes them on (566 and later); else they are plain
text with their address beside it.
"""

from __future__ import annotations

import argparse
import os
import re
import shutil
import stat
import subprocess
import sys

#: Bytes of one file that are read (as the Qt viewer).
TEXT_LIMIT = 8 << 20
#: The widest a text is set unless --width says otherwise (long lines read badly).
MAX_WIDTH = 100
#: The narrowest (a bullet, a quote's bar and a table's borders take room:
#: at 3 columns a text came out a few letters a line).
MIN_WIDTH = 20


def _read(name: str) -> tuple[str, str]:
    """(text, "") of the file *name* ("-": standard input), or ("", why)."""
    if name == "-":
        data = sys.stdin.buffer.read(TEXT_LIMIT + 1)
    else:
        try:
            st = os.stat(name)
        except OSError as exc:
            return "", exc.strerror or str(exc)
        if not stat.S_ISREG(st.st_mode):
            return "", "not a regular file"
        # The file the user named is shown, as the viewer shows it (only a
        # regular file; its contents decide nothing - the agent's read policy,
        # core.protected_places.read_refusal, refused a text that only
        # mentioned a private key). What the *document* names - its images -
        # is checked (core.markdown_term.read_picture), as in the viewer.
        with open(name, "rb") as fh:
            data = fh.read(TEXT_LIMIT + 1)
    from core.markdown_doc import decode_text

    text = decode_text(data[:TEXT_LIMIT])
    if len(data) > TEXT_LIMIT:
        text += f"\n\n---\n\n*(only the first {TEXT_LIMIT >> 20} MiB are shown)*\n"
    return text, ""


def program_version() -> str:
    """The version of the program this is: axross-markdown's own (its
    package, written out by scripts/export_standalone.py, is installed with
    one) - or axross's."""
    if "axross_markdown" in sys.modules:
        try:
            from importlib.metadata import version

            return version("axross-markdown")
        except Exception:  # noqa: BLE001 - (not installed: run from its folder)
            pass
    try:
        from axross._version import __version__
    except ImportError:  # pragma: no cover - an export without it
        return "?"
    return __version__


def _parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(
        prog="axross-mdcat", description="Show Markdown files in the terminal, in colour.")
    ap.add_argument("files", nargs="*", default=["-"], help="Markdown files; - for standard input")
    ap.add_argument("-w", "--width", type=_columns, default=0, help=f"columns (default: the terminal's, "
                    f"at most {MAX_WIDTH}; at least {MIN_WIDTH})")
    ap.add_argument("--color", "--colour", dest="color", default="auto",
                    choices=("auto", "always", "never", "truecolor", "256", "16"))
    ap.add_argument("--theme", default="auto", choices=("auto", "dark", "light"))
    ap.add_argument("--images", default="auto", choices=("auto", "kitty", "iterm", "blocks", "none"))
    ap.add_argument("--image-width", type=_columns, default=0, help="columns an image may take")
    ap.add_argument("--no-links", action="store_true", help="no terminal hyperlinks (OSC 8)")
    ap.add_argument("--pager", dest="pager", action="store_true", default=None,
                    help="always page with less -R")
    ap.add_argument("--no-pager", dest="pager", action="store_false")
    ap.add_argument("--toc", action="store_true", help="list the headings only")
    ap.add_argument("--watch", action="store_true",
                    help="draw the file anew whenever it changes (Ctrl+C ends)")
    ap.add_argument("--version", action="store_true")
    return ap


def _columns(value: str) -> int:
    """A number of columns (0: the default); a negative one is refused."""
    try:
        number = int(value)
    except ValueError:
        number = -1
    if number < 0:
        raise argparse.ArgumentTypeError(f"not a number of columns: {value}")
    return number


def _depth(choice: str) -> str:
    from core.markdown_term import colour_depth

    if choice == "never":
        return "none"
    if choice == "always":
        return colour_depth(environ={**os.environ, "FORCE_COLOR": "1"}) or "256"
    if choice in ("truecolor", "256", "16"):
        return choice
    return colour_depth()


#: The first less that passes OSC 8 hyperlinks on with -R (older ones show
#: the escape as text: "ESC]8;;https://…").
LESS_LINKS = 566
_OSC8 = re.compile(r"\x1b\]8;;[^\x1b]*\x1b\\")


def _pager() -> str | None:
    return shutil.which("less")


def _less_version(less: str) -> int:
    """The version number of *less* (0 when it does not say)."""
    try:
        from core.subprocess_env import clean_child_env

        # (a bundle's loader path is not handed on: core.subprocess_env)
        out = subprocess.run([less, "--version"], capture_output=True, text=True, timeout=5,
                             check=False, env=clean_child_env()).stdout
    except (OSError, subprocess.SubprocessError):
        return 0
    found = re.match(r"\s*less (\d+)", out)
    return int(found.group(1)) if found else 0


def _will_page(text_lines: int, rows: int, force: bool | None) -> bool:
    """Whether :func:`_page` will page a text of *text_lines* lines."""
    if force is False or not sys.stdout.isatty() or _pager() is None:
        return False
    return force is True or text_lines >= rows - 1


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    if args.version:
        print(f"axross-mdcat {program_version()}")
        return 0
    from core import markdown_doc as MD

    if not MD.available():
        print("axross-mdcat needs markdown-it-py and mdit-py-plugins: "
              "pip install markdown-it-py mdit-py-plugins", file=sys.stderr)
        return 2
    from core import markdown_term as T

    size = shutil.get_terminal_size((80, 24))
    width = max(MIN_WIDTH, args.width or min(size.columns, MAX_WIDTH))
    depth = _depth(args.color)
    dark = T.dark_background() if args.theme == "auto" else args.theme == "dark"
    paging = args.pager is not False and sys.stdout.isatty() and not args.watch
    images = args.images
    if images == "auto":
        images = T.image_protocol() if depth != "none" else "none"
        if paging and images in ("kitty", "iterm"):
            images = "blocks"  # (less passes colours, not pictures)
    hyperlinks = not args.no_links
    if args.watch:
        if len(args.files) != 1 or args.files[0] == "-":
            print("axross-mdcat: --watch shows one file (not standard input)", file=sys.stderr)
            return 2
        return _watch(args, width, depth, dark, images, hyperlinks)
    status: list[int] = [0]
    # (written as rendered: a long text's first part at once - less once
    # what came is longer than the screen)
    buffered, lines, pager, strip = [], 0, None, False
    can_page = args.pager is not False and sys.stdout.isatty() and _pager() is not None
    for piece in _rendered(args, width, depth, dark, images, hyperlinks, status):
        if not can_page:  # (into a pipe, a file, --no-pager: each part as it is rendered)
            _write(piece)
            continue
        if pager is None:
            buffered.append(piece)
            lines += piece.count("\n")
            if not _will_page(lines, size.lines, args.pager):
                continue
            strip = hyperlinks and _less_version(_pager()) < LESS_LINKS
            pager = _open_pager()
            if pager is None:
                break
            piece, buffered = "".join(buffered), []
        if not _feed(pager, _OSC8.sub("", piece) if strip else piece):
            break  # (less was quit)
    if pager is not None:
        _close_pager(pager)
    else:
        _write("".join(buffered))
    return status[0]


def _open_pager():
    """``less -R`` with a pipe to write to, or None."""
    from core.subprocess_env import clean_child_env

    try:
        return subprocess.Popen([_pager(), "-R", "-F", "-X", "-K"], stdin=subprocess.PIPE,
                                env=clean_child_env(LESSCHARSET="utf-8"))
    except OSError:
        return None


def _feed(pager, text: str) -> bool:
    """*text* written to less; False once it is gone (quit)."""
    try:
        pager.stdin.write(text.encode("utf-8", "replace"))
        pager.stdin.flush()
        return True
    except (BrokenPipeError, OSError, KeyboardInterrupt):
        return False


def _close_pager(pager) -> None:
    try:
        pager.stdin.close()
        pager.wait()
    except (BrokenPipeError, OSError, KeyboardInterrupt):
        pass


def _write(text: str) -> None:
    try:
        sys.stdout.write(text)
        sys.stdout.flush()
    except BrokenPipeError:  # piped into head: fine
        try:
            sys.stdout = open(os.devnull, "w")  # noqa: SIM115 - Python's own advice for EPIPE
        except OSError:
            pass


def _watch(args, width, depth, dark, images, hyperlinks, poll: float = 0.5, rounds: int = 0) -> int:
    """The one file of *args*, drawn anew (the screen cleared first) each
    time it changes - until Ctrl+C (*rounds*: that many checks, for tests)."""
    import time

    name = args.files[0]
    seen = None
    checks = 0
    try:
        while True:
            try:
                st = os.stat(name)
                now = (st.st_mtime_ns, st.st_size, st.st_ino)
            except OSError:
                now = None
            if now != seen:
                seen = now
                text, _status = _render_files(args, width, depth, dark, images, hyperlinks)
                clear = ""
                if sys.stdout.isatty():
                    clear = "\x1b[H\x1b[2J"
                    text = _screenful(text, shutil.get_terminal_size((80, 24)).lines, name)
                _write(clear + text)
            checks += 1
            if rounds and checks >= rounds:
                return 0
            time.sleep(poll)
    except KeyboardInterrupt:
        return 0


def _screenful(text: str, rows: int, name: str) -> str:
    """The top of *text* that fits *rows* lines, and how many lines are not
    shown (--watch: the whole text scrolled the terminal to its end)."""
    lines = text.rstrip("\n").split("\n")
    if len(lines) <= rows - 1:
        return text
    rest = len(lines) - (rows - 2)
    from core.markdown_doc import clean

    note = f"… {rest} more lines - the whole file: axross-mdcat {clean(name)}"
    reset = "\x1b[0m\x1b]8;;\x1b\\" if "\x1b" in text else ""  # (a style or link cut off ends)
    return "\n".join(lines[:rows - 2]) + "\n" + reset + note + "\n"


def _render_files(args, width, depth, dark, images, hyperlinks) -> tuple[str, int]:
    """The text of every file of *args* for the terminal, and the exit status."""
    status = [0]
    text = "".join(_rendered(args, width, depth, dark, images, hyperlinks, status))
    return text, status[0]


def _rendered(args, width, depth, dark, images, hyperlinks, status: list[int]):
    """The text of every file of *args* for the terminal, in parts as they
    are rendered (core.markdown_term.render_parts); *status[0]* the exit
    status."""
    from core import markdown_doc as MD
    from core import markdown_term as T

    for number, name in enumerate(args.files):
        text, why = _read(name)
        shown = MD.clean(name)
        if why:
            print(f"axross-mdcat: {shown}: {why}", file=sys.stderr)
            status[0] = 1
            continue
        folder = os.path.dirname(os.path.abspath(name)) if name != "-" else os.getcwd()
        options = T.Options(width=width, depth=depth, dark=dark, hyperlinks=hyperlinks,
                            images=images, folder=folder,
                            image_columns=args.image_width or min(T.IMAGE_COLUMNS, width))
        if args.toc:
            doc = MD.parse(text)
            painter = T.Painter(depth, T.DARK if dark else T.LIGHT)
            lines = [painter.paint("  " * (h.level - 1) + MD.clean(h.text), T.Style(fg=f"h{h.level}",
                                                                                      bold=h.level <= 2))
                     + painter.paint(f"  #{h.anchor}", T.Style(fg="muted", dim=True)) for h in doc.headings]
            body = iter(["\n".join(lines) + "\n"])
        else:
            body = T.render_parts(text, options)
        if len(args.files) > 1:
            painter = T.Painter(depth, T.DARK if dark else T.LIGHT)
            title = painter.paint(f"━━ {shown} ", T.Style(fg="muted", bold=True))
            yield ("\n" if number else "") + title + "\n\n"
        yield from body


if __name__ == "__main__":
    sys.exit(main())
