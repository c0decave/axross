"""``axross-mdcat`` (also ``axross-markdown --term``): Markdown files shown in
the terminal (core.markdown_term), through ``less -R`` when longer than the
screen. No Qt: it starts fast and works over SSH.

    axross-mdcat README.md docs/*.md
    axross-mdcat --images kitty --width 100 notes.md
    cat notes.md | axross-mdcat -
    axross-mdcat --toc README.md        # the headings only

Colours follow the terminal (NO_COLOR, FORCE_COLOR, COLORTERM, TERM;
``--color``), the theme its background (COLORFGBG; ``--theme``), images its
picture protocol (kitty, iTerm2 / WezTerm, else coloured half-blocks;
``--images``).
"""

from __future__ import annotations

import argparse
import os
import shutil
import stat
import subprocess
import sys

#: Bytes of one file that are read (as the Qt viewer).
TEXT_LIMIT = 8 << 20
#: The widest a text is set unless --width says otherwise (long lines read badly).
MAX_WIDTH = 100


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
        from core.protected_places import read_refusal

        refused = read_refusal(os.path.abspath(name))
        if refused:
            return "", "a secret file, not shown"
        with open(name, "rb") as fh:
            data = fh.read(TEXT_LIMIT + 1)
    text = data[:TEXT_LIMIT].decode("utf-8", "replace")
    if len(data) > TEXT_LIMIT:
        text += f"\n\n---\n\n*(only the first {TEXT_LIMIT >> 20} MiB are shown)*\n"
    return text, ""


def _parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(
        prog="axross-mdcat", description="Show Markdown files in the terminal, in colour.")
    ap.add_argument("files", nargs="*", default=["-"], help="Markdown files; - for standard input")
    ap.add_argument("-w", "--width", type=int, default=0, help=f"columns (default: the terminal's, "
                    f"at most {MAX_WIDTH})")
    ap.add_argument("--color", "--colour", dest="color", default="auto",
                    choices=("auto", "always", "never", "truecolor", "256", "16"))
    ap.add_argument("--theme", default="auto", choices=("auto", "dark", "light"))
    ap.add_argument("--images", default="auto", choices=("auto", "kitty", "iterm", "blocks", "none"))
    ap.add_argument("--image-width", type=int, default=0, help="columns an image may take")
    ap.add_argument("--no-links", action="store_true", help="no terminal hyperlinks (OSC 8)")
    ap.add_argument("--pager", dest="pager", action="store_true", default=None,
                    help="always page with less -R")
    ap.add_argument("--no-pager", dest="pager", action="store_false")
    ap.add_argument("--toc", action="store_true", help="list the headings only")
    ap.add_argument("--version", action="store_true")
    return ap


def _depth(choice: str) -> str:
    from core.markdown_term import colour_depth

    if choice == "never":
        return "none"
    if choice == "always":
        return colour_depth(environ={**os.environ, "FORCE_COLOR": "1"}) or "256"
    if choice in ("truecolor", "256", "16"):
        return choice
    return colour_depth()


def _page(text: str, rows: int, force: bool | None) -> bool:
    """Show *text* through ``less -R`` when asked or when it is longer than
    the screen (and less is there); True when it did."""
    if force is False or not sys.stdout.isatty():
        return False
    if force is None and text.count("\n") < rows - 1:
        return False
    less = shutil.which("less")
    if less is None:
        return False
    env = dict(os.environ, LESSCHARSET="utf-8")
    try:
        proc = subprocess.Popen([less, "-R", "-F", "-X", "-K"], stdin=subprocess.PIPE, env=env)
        proc.communicate(text.encode("utf-8", "replace"))
    except (OSError, KeyboardInterrupt):
        return True
    return True


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    if args.version:
        try:
            from axross._version import __version__
        except ImportError:  # pragma: no cover - an export without it
            __version__ = "?"
        print(f"axross-mdcat {__version__}")
        return 0
    from core import markdown_doc as MD

    if not MD.available():
        print("axross-mdcat needs markdown-it-py and mdit-py-plugins: "
              "pip install markdown-it-py mdit-py-plugins", file=sys.stderr)
        return 2
    from core import markdown_term as T

    size = shutil.get_terminal_size((80, 24))
    width = args.width or min(size.columns, MAX_WIDTH)
    depth = _depth(args.color)
    dark = T.dark_background() if args.theme == "auto" else args.theme == "dark"
    paging = args.pager is not False and sys.stdout.isatty()
    images = args.images
    if images == "auto":
        images = T.image_protocol() if depth != "none" else "none"
        if paging and images in ("kitty", "iterm"):
            images = "blocks"  # (less passes colours, not pictures)
    status = 0
    out: list[str] = []
    for number, name in enumerate(args.files):
        text, why = _read(name)
        shown = MD.clean(name)
        if why:
            print(f"axross-mdcat: {shown}: {why}", file=sys.stderr)
            status = 1
            continue
        folder = os.path.dirname(os.path.abspath(name)) if name != "-" else os.getcwd()
        options = T.Options(width=width, depth=depth, dark=dark, hyperlinks=not args.no_links,
                            images=images, folder=folder,
                            image_columns=args.image_width or min(T.IMAGE_COLUMNS, width))
        if args.toc:
            doc = MD.parse(text)
            painter = T.Painter(depth, T.DARK if dark else T.LIGHT)
            lines = [painter.paint("  " * (h.level - 1) + MD.clean(h.text), T.Style(fg=f"h{h.level}",
                                                                                      bold=h.level <= 2))
                     + painter.paint(f"  #{h.anchor}", T.Style(fg="muted", dim=True)) for h in doc.headings]
            body = "\n".join(lines) + "\n"
        else:
            body = T.render(text, options)
        if len(args.files) > 1:
            painter = T.Painter(depth, T.DARK if dark else T.LIGHT)
            title = painter.paint(f"━━ {shown} ", T.Style(fg="muted", bold=True))
            out.append(("\n" if number else "") + title + "\n\n")
        out.append(body)
    text = "".join(out)
    if not _page(text, size.lines, args.pager):
        try:
            sys.stdout.write(text)
            sys.stdout.flush()
        except BrokenPipeError:  # piped into head: fine
            try:
                sys.stdout = open(os.devnull, "w")  # noqa: SIM115 - Python's own advice for EPIPE
            except OSError:
                pass
    return status


if __name__ == "__main__":
    sys.exit(main())
