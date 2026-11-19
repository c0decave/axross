"""axross-mdcat.exe (Windows): the terminal view as a console program of its own (the window
program, axross-markdown.exe, opens no console)."""

import sys

from axross_markdown._ax.core.markdown_cli import main

if __name__ == "__main__":
    sys.exit(main())
