"""``axross-mdcat`` (also ``axross-markdown --term``): Markdown files shown in
the terminal (core.markdown_term), through ``less -R`` when longer than the
screen. No Qt: it starts fast and works over SSH.

    axross-mdcat README.md docs/*.md
    axross-mdcat --images kitty --width 100 notes.md
    cat notes.md | axross-mdcat -
    axross-mdcat --toc README.md        # the headings only
    axross-mdcat --watch notes.md       # drawn anew whenever the file changes

Colours follow the terminal (NO_COLOR, FORCE_COLOR, COLORTERM, TERM;
``--color``) and the theme (``--theme NAME``, ``--list-themes``: one of
core.markdown_themes, its ground painted; ``auto``: the terminal's own
ground, dark or light as COLORFGBG says), images its
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
#: What is said of a file that is no text.
BINARY = "not a text file (it holds binary data) – not shown"
#: The widest a text is set unless --width says otherwise (long lines read badly).
MAX_WIDTH = 100
#: The narrowest (a bullet, a quote's bar and a table's borders take room:
#: at 3 columns a text came out a few letters a line).
MIN_WIDTH = 20


#: The page of a folder: its README (a link to the folder opens it, and so does the folder given to the
#: program).
FOLDER_PAGES = ("README.md", "readme.md", "Readme.md", "README.markdown", "index.md")


def folder_page(path: str) -> str:
    """*path* - or, a folder, its first page of FOLDER_PAGES there (*path* itself: none)."""
    if not os.path.isdir(path):
        return path
    for name in FOLDER_PAGES:
        page = os.path.join(path, name)
        if os.path.isfile(page):
            return page
    return path


def _read(name: str) -> tuple[str, str]:
    """(text, "") of the file *name* ("-": standard input), or ("", why)."""
    if name == "-":
        data = sys.stdin.buffer.read(TEXT_LIMIT + 1)
    else:
        try:
            st = os.stat(name)
        except OSError as exc:
            return "", exc.strerror or str(exc)
        if stat.S_ISDIR(st.st_mode):  # (a folder: its README, as the window opens a link to one)
            page = folder_page(name)
            if page == name:
                return "", "a folder without a README"
            return _read(page)
        if not stat.S_ISREG(st.st_mode):
            return "", "not a regular file"
        # The file the user named is shown, as the viewer shows it (only a
        # regular file; its contents decide nothing - the agent's read policy,
        # core.protected_places.read_refusal, refused a text that only
        # mentioned a private key). What the *document* names - its images -
        # is checked (core.markdown_term.read_picture), as in the viewer.
        with open(name, "rb") as fh:
            data = fh.read(TEXT_LIMIT + 1)
    from core.markdown_doc import decode_text, looks_binary

    if looks_binary(data):  # (a picture, a program: said - it was shown as garbage)
        return "", BINARY
    text = decode_text(data[:TEXT_LIMIT])
    if len(data) > TEXT_LIMIT:
        text += f"\n\n---\n\n*(only the first {TEXT_LIMIT >> 20} MiB are shown)*\n"
    return text, ""


def program_version() -> str:
    """The version of the program this is: axross-markdown's own (its
    package, written out by scripts/export_standalone.py, says it - run
    from a checkout's src/ as installed) - or axross's."""
    if "axross_markdown" in sys.modules:
        own = getattr(sys.modules["axross_markdown"], "__version__", "")
        if isinstance(own, str) and own:  # (before the metadata: src/ said axross's or an installed older one's)
            return own
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


#: The program's name in what it says (its messages, --help, --version): axross-mdcat - or the program that
#: ran it ("axross-markdown --term" said "axross-mdcat: missing.md: ...").
PROG = ["axross-mdcat"]


def _parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(
        prog=PROG[0], description="Show Markdown files in the terminal, in colour.")
    ap.add_argument("files", nargs="*", default=["-"], help="Markdown files; - for standard input")
    ap.add_argument("-w", "--width", type=_columns, default=0, help=f"columns (default: the terminal's, "
                    f"at most {MAX_WIDTH}; at least {MIN_WIDTH})")
    ap.add_argument("--color", "--colour", dest="color", default="auto",
                    choices=("auto", "always", "never", "truecolor", "256", "16"),
                    help="colours: auto (a terminal's, NO_COLOR / FORCE_COLOR / COLORTERM), always, never, "
                         "or a depth (default: auto)")
    from core.markdown_themes import CHOICES

    ap.add_argument("--theme", default=None, choices=CHOICES, metavar="NAME",
                    help="the colours: auto (the terminal's own ground - COLORFGBG says dark or light, else dark) "
                         "or a theme (--list-themes), its ground painted; default: $AXROSS_MDCAT_THEME, else "
                         "terminal_theme in ~/.config/axross-markdown/settings.json, else auto")
    ap.add_argument("--list-themes", action="store_true", help="list the themes, with their contrast, and exit")
    ap.add_argument("--background", default="auto", choices=("auto", "on", "off"),
                    help="paint the theme's ground behind the text (default: auto - for a theme, not for auto)")
    ap.add_argument("--images", default="auto", choices=("auto", "kitty", "iterm", "blocks", "none"),
                    help="pictures with kitty's or iTerm2's protocol, in coloured half-blocks, or none "
                         "(default: auto - the terminal's)")
    ap.add_argument("--image-width", type=_columns, default=0, help="columns an image may take")
    ap.add_argument("--no-links", action="store_true", help="no terminal hyperlinks (OSC 8)")
    ap.add_argument("--pager", dest="pager", action="store_true", default=None,
                    help="always page with less -R")
    ap.add_argument("--no-pager", dest="pager", action="store_false",
                    help="never page (default: less -R when the text is longer than the screen)")
    ap.add_argument("--toc", action="store_true", help="list the headings only")
    ap.add_argument("--watch", action="store_true",
                    help="draw the file anew whenever it changes (Ctrl+C ends)")
    ap.add_argument("--version", action="store_true", help="show the version and exit")
    ap.add_argument("--check-update", action="store_true",
                    help="ask GitHub whether a newer release is out, and exit")
    ap.add_argument("--update", action="store_true",
                    help="install a newer release (the one-file programs; pip: says the command), and exit")
    ap.add_argument("--update-mode", choices=("off", "notify", "auto"),
                    help="the window's checks for updates: off, notify (the default) or auto (install), kept")
    ap.add_argument("--self-test", action="store_true", help=argparse.SUPPRESS)
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


def main(argv: list[str] | None = None, prog: str | None = None) -> int:
    """The program (*prog*: the name it says it is - another program's, which runs it)."""
    PROG[0] = prog or "axross-mdcat"
    args = sys.argv[1:] if argv is None else list(argv)
    if args[:1] == ["--lex-worker"]:
        # A code block lexed in a child (core.lex_worker): a frozen axross-mdcat (Windows'
        # axross-mdcat.exe) starts it as itself - it answers as the child.
        from core.lex_worker import _child_main

        return _child_main()
    try:
        status = _main(argv)
        _write("")  # (what print left in the buffer - --help, --version: its error said too)
        return status
    except OutputGone as gone:
        return gone.status
    except SystemExit as stop:  # (--help: printed by argparse - a full disk said, not a traceback at the exit)
        try:
            _write("")
        except OutputGone as gone:
            return gone.status or (stop.code if isinstance(stop.code, int) else 1)
        raise


def _main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    if args.version:
        print(f"{PROG[0]} {program_version()}")
        return 0
    if args.self_test:
        return self_test()
    if args.update_mode or args.check_update or args.update:
        return update_main(args)
    if args.list_themes:
        return list_themes(_depth(args.color))
    from core import markdown_doc as MD

    if not MD.available():
        print(f"{PROG[0]} needs markdown-it-py and mdit-py-plugins: "
              "pip install markdown-it-py mdit-py-plugins", file=sys.stderr)
        return 2
    from core import markdown_term as T

    size = shutil.get_terminal_size((80, 24))
    width = max(MIN_WIDTH, args.width or min(size.columns, MAX_WIDTH))
    depth = _depth(args.color)
    from core import markdown_themes as MT

    theme_id = MT.normalize(args.theme or MT.terminal_default())
    theme = MT.get(theme_id)
    dark = T.dark_background() if theme is None else theme.dark
    args.theme_id = theme.id if theme is not None else ""
    args.ground = theme is not None and args.background != "off"
    paging = args.pager is not False and sys.stdout.isatty() and not args.watch
    images = args.images
    if images == "auto":
        images = T.image_protocol() if depth != "none" else "none"
        if paging and images in ("kitty", "iterm"):
            images = "blocks"  # (less passes colours, not pictures)
    hyperlinks = not args.no_links
    if args.watch:
        if len(args.files) != 1 or args.files[0] == "-":
            print(f"{PROG[0]}: --watch shows one file (not standard input)", file=sys.stderr)
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
    notice = newer_notice()
    if notice:
        print(notice, file=sys.stderr)
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


class OutputGone(Exception):
    """Standard output can be written no more: *status* the exit status (0: a pipe closed - "| head" had
    its lines; 1: an error, said)."""

    def __init__(self, status: int):
        super().__init__(status)
        self.status = status


def _write(text: str, program: str = "axross-mdcat") -> None:
    """*text* on standard output - OutputGone once it can be written no more: a pipe closed ("| head
    -2": it rendered all the rest for nothing) or an error ("> /dev/full": a traceback), said."""
    _encodable_output()
    try:
        sys.stdout.write(text)
        sys.stdout.flush()
    except BrokenPipeError:  # piped into head: fine - and no more to do
        _quiet_stdout()
        raise OutputGone(0) from None
    except OSError as exc:  # (a full disk, a closed terminal: said, exit 1)
        _quiet_stdout()
        print(f"{program}: cannot write the output: {exc.strerror or exc}", file=sys.stderr)
        raise OutputGone(1) from None


_ENCODING_SET: list = []


#: The error handler of a console's encoding (_encodable_output): the box, rule and block characters
#: a console of cp1252 lacks as ASCII ("┌─┐" as "+-+", "█" as "#") - not "???" - anything else "?".
ASCII_ERRORS = "axross-ascii"
_ASCII = str.maketrans({**dict.fromkeys("─━═┄┈╌", "-"), **dict.fromkeys("│┃║┆┊╎", "|"),
                        **dict.fromkeys("┌┐└┘├┤┬┴┼╭╮╯╰┏┓┗┛┣┫┳┻╋╔╗╚╝╠╣╦╩╬", "+"),
                        **dict.fromkeys("█▀▄▌▐▓▒░■", "#"), "•": "*", "◦": "o", "▪": "*", "…": "...",
                        "“": '"', "”": '"', "‘": "'", "’": "'", "–": "-", "—": "--", "→": "->", "←": "<-",
                        "✓": "v", "✔": "v", "☐": "[ ]", "☑": "[x]", "☒": "[x]", "▶": ">", "▼": "v"})


def _register_ascii() -> None:
    import codecs

    def ascii_instead(error: UnicodeError):
        if not isinstance(error, UnicodeEncodeError):
            raise error
        bad = error.object[error.start:error.end]
        return "".join(ch.translate(_ASCII) if ch.translate(_ASCII) != ch else "?" for ch in bad), error.end

    try:
        codecs.lookup_error(ASCII_ERRORS)
    except LookupError:
        codecs.register_error(ASCII_ERRORS, ascii_instead)


def _encodable_output() -> None:
    """Standard output (and error) that takes every character, once: UTF-8 into a pipe or a file
    (Windows' default there is its ANSI code page - cp1252 has no "█": axross-mdcat.exe ended in a
    UnicodeEncodeError), a character a console cannot show replaced, never an error."""
    if _ENCODING_SET:
        return
    _ENCODING_SET.append(True)
    for stream in (sys.stdout, sys.stderr):
        try:
            if stream is None or not hasattr(stream, "reconfigure"):
                continue
            if stream.isatty():
                _register_ascii()
                stream.reconfigure(errors=ASCII_ERRORS)
            else:
                stream.reconfigure(encoding="utf-8", errors="replace")
        except (OSError, ValueError, AttributeError):
            continue


def _quiet_stdout() -> None:
    """Standard output to /dev/null: what is left in its buffer is dropped (Python's advice for EPIPE -
    "Exception ignored ... BrokenPipeError" at the exit else)."""
    try:
        null = os.open(os.devnull, os.O_WRONLY)
        os.dup2(null, sys.stdout.fileno())
        os.close(null)
    except (OSError, ValueError, AttributeError):
        pass


def _watch(args, width, depth, dark, images, hyperlinks, poll: float = 0.5, rounds: int = 0) -> int:
    """The one file of *args*, drawn anew (the screen cleared first) each
    time it changes - until Ctrl+C (*rounds*: that many checks, for tests)."""
    import time

    name = args.files[0]
    seen, missing = (), False  # (seen: nothing drawn yet - a file that is not there is said, too)
    checks = 0
    try:
        while True:
            try:
                st = os.stat(name)
                now = (st.st_mtime_ns, st.st_size, st.st_ino)
            except OSError as exc:
                now = None
                if not missing:  # (said once - it was silent for ever - and waited for)
                    from core.markdown_doc import clean

                    print(f"{PROG[0]}: {clean(name)}: {exc.strerror or exc} - waiting for it (Ctrl+C ends)",
                          file=sys.stderr, flush=True)
                    missing = True
                seen = now
            else:
                missing = False
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
            print(f"{PROG[0]}: {shown}: {why}", file=sys.stderr)
            status[0] = 1
            continue
        folder = os.path.dirname(os.path.abspath(name)) if name != "-" else os.getcwd()
        options = T.Options(width=width, depth=depth, dark=dark, hyperlinks=hyperlinks,
                            images=images, folder=folder,
                            image_columns=args.image_width or min(T.IMAGE_COLUMNS, width),
                            theme=getattr(args, "theme_id", ""), background=getattr(args, "ground", False))
        ground = T.ground_of(options)
        if args.toc:
            doc = MD.parse(text)
            painter = T.painter_of(options)
            lines = [painter.paint("  " * (h.level - 1) + MD.clean(h.text), T.Style(fg=f"h{h.level}",
                                                                                      bold=h.level <= 2))
                     + painter.paint(f"  #{h.anchor}", T.Style(fg="muted", dim=True)) for h in doc.headings]
            body = iter([T.on_ground("\n".join(lines) + "\n", ground, width, depth, T.ground_text(options))])
        else:
            body = T.render_parts(text, options)
        if len(args.files) > 1:
            painter = T.painter_of(options)
            title = painter.paint(f"━━ {shown} ", T.Style(fg="muted", bold=True))
            yield T.on_ground(("\n" if number else "") + title + "\n\n", ground, width, depth,
                              T.ground_text(options))
        yield from body


def list_themes(depth: str) -> int:
    """--list-themes: each theme's id, name, ground and the contrast of its text and links (WCAG), a
    sample in its colours where the terminal has them."""
    from core import markdown_term as T
    from core import markdown_themes as MT

    print(f"{'auto':22} the terminal's own ground: Dark's or Light's colours (COLORFGBG says which)")
    for theme in MT.THEMES.values():
        page = theme.term
        text, link = MT.contrast(page["text"], page["page_bg"]), MT.contrast(page["link"], page["page_bg"])
        level = "AAA" if min(text, link) >= 7 else "AA"
        sample = ""
        if depth in ("truecolor", "256"):
            options = T.Options(depth=depth, theme=theme.id, background=True)
            painter = T.painter_of(options, hyperlinks=False)
            sample = "  " + T.on_ground(painter.paint(" Heading ", T.Style(fg="h1", bold=True))
                                        + "text " + painter.paint("link", T.Style(fg="link", underline=True))
                                        + " ", page["page_bg"], 0, depth, page["text"])
        print(f"{theme.id:22} {theme.label:20} {'dark' if theme.dark else 'light':5}  text {text:5.2f}:1  "
              f"links {link:5.2f}:1  {level}{sample}")
    return 0


def self_test() -> int:
    """--self-test (the updater runs a new program so before it replaces this one): a page rendered, the
    answer core.markdown_update.self_test waits for."""
    from core import markdown_doc as MD
    from core import markdown_term as T

    if not MD.available():
        print(f"{PROG[0]}: markdown-it-py is missing", file=sys.stderr)
        return 1
    shown = T.render("# Self-test\n\n| a |\n|---|\n| 1 |\n", T.Options(width=40, depth="none"))
    if "Self-test" not in shown:
        print(f"{PROG[0]}: the page was not rendered", file=sys.stderr)
        return 1
    print(f"{PROG[0]} {program_version()} ok")
    return 0


def update_main(args) -> int:
    """--update-mode, --check-update, --update: said on standard error, the result on standard output."""
    from core import markdown_update as MU

    if args.update_mode:
        try:
            MU.set_mode(args.update_mode)
        except OSError as exc:
            print(f"{PROG[0]}: the setting could not be kept: {exc.strerror or exc}", file=sys.stderr)
            return 1
        print(f"{PROG[0]}: updates: {args.update_mode}")
        if not (args.check_update or args.update):
            return 0
    install = MU.detect_install()
    current = program_version()
    try:
        if args.update:
            def progress(count: int, _last=[0]) -> None:  # noqa: B006 - a counter of this call
                if count - _last[0] >= 8 << 20:
                    _last[0] = count
                    print(f"{PROG[0]}: {count >> 20} MiB…", file=sys.stderr, flush=True)

            print(f"{PROG[0]}: {MU.update(install, current, progress=progress)}")
            return 0
        result = MU.check(current)
        MU.record_check(result)
    except MU.UpdateError as exc:
        print(f"{PROG[0]}: {exc}", file=sys.stderr)
        return 1
    except (OSError, Exception) as exc:  # noqa: BLE001 - (a reset connection, a full disk: said, no traceback)
        print(f"{PROG[0]}: the update failed: {type(exc).__name__}: {exc}"[:400], file=sys.stderr)
        return 1
    if result.newer:
        how = f"{PROG[0]} --update" if install.can_update else (
            f"installed with pip - to update it: {MU.pip_hint(result.release.version)}" if install.kind == "pip"
            else install.why_not())
        print(f"{result.text} - {how}")
    else:
        print(result.text)
    return 0


def newer_notice(stream=None) -> str:
    """What the last check found newer than this program (a line for standard error), or "": the terminal
    view asks no network itself - the window's checks and --check-update keep what they found."""
    from core import markdown_update as MU

    stream = sys.stderr if stream is None else stream
    try:
        if MU.mode() == "off" or not MU.checks_allowed()[0] or not stream.isatty():
            return ""
        newer = MU.seen_newer(program_version())
    except Exception:  # noqa: BLE001 - unreadable settings: nothing to say
        return ""
    if not newer:
        return ""
    install = MU.detect_install()
    how = f"{PROG[0]} --update" if install.can_update else install.why_not()
    return f"{PROG[0]}: axross-markdown {newer} is available - {how}"


if __name__ == "__main__":
    sys.exit(main())
