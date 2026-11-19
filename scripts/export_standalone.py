#!/usr/bin/env python3
"""Write an axross tool as a program of its own: ``export_standalone.py APP OUT_DIR``.

APP is ``media-player`` (the Media Player: local files, folders, M3U
playlists and http / https streams) or ``system-info`` (System Information).
Both stay part of axross; this writes the same code as an installable
project with its own command:

    OUT_DIR/
      pyproject.toml          axross-media-player / axross-system-info, its command
      README.md, LICENSE
      src/PACKAGE/__main__.py the command (python -m PACKAGE)
      src/PACKAGE/_ax/        the axross modules the tool runs on - core/,
                              ui/, resources/ - with every import rewritten
                              to PACKAGE._ax.*, and the interface languages
      tests/test_smoke.py     starts the program and checks it ends cleanly
      requirements.lock.txt   when axross locks the tool's dependencies
                              (build/requirements-standalone-APP.txt,
                              scripts/lock_standalone_deps.sh): the hashed lock
                              its CI installs from, and the supply-chain gate
                              (supply-chain-gate.toml) its CI runs on it

Which modules go along is worked out here, not listed by hand: everything
the tool's start module imports at module level, followed through every
module, plus the modules it imports later (inside functions) that it needs
(LAZY). Every other late import must be guarded - inside a ``try`` that
catches ImportError - or the export stops: a program of its own must not
fail when a menu reaches a part of axross it does not carry.

The settings stay axross's: ~/.config/axross (the player's list and
position, the language, the theme, the window sizes), so the program and
axross's panel share them.

``mcp`` (the headless MCP server, ``axross-headless-mcp``) is exported differently
(``layout="path"``): its modules keep their names - core.*, models.*,
security.*, axross.* - under ``src/axross_headless_mcp/_ax/``, which the command puts
first on ``sys.path``. The server names modules in strings (the backend
registry's ``"core.ssh_client"``, the transfer scheduler's class table,
``python -m core.agent_worker`` and the script child's bootstrap), which a
rename of the imports would miss. Every import is followed there, not only
the module-level ones (``follow_all``), nothing of ui/ comes along, and a
module that imports PyQt6 at import time stops the export: the package has
no Qt.
"""

from __future__ import annotations

import argparse
import ast
import hashlib
import json
import re
import shutil
import sys
import tomllib
from dataclasses import dataclass, field
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
#: axross's top-level packages a copied module may import.
PACKAGES = ("core", "ui", "resources", "axross", "models", "security")
#: Packages whose __init__ is written here instead of copied (axross's own
#: imports the scripting API on first use - not part of a tool).
STUB_INITS = {"axross/__init__.py": '"""The version of the axross code this tool comes from."""\n'}


@dataclass(frozen=True)
class App:
    dist: str
    package: str
    start: str                    # the start module (ui/..._app.py)
    title: str
    summary: str
    requires: tuple[str, ...]
    #: modules imported inside functions that the tool needs
    lazy: tuple[str, ...]
    #: (file, old, new): rewrites beyond the imports, each must apply
    rewrites: tuple[tuple[str, str, str], ...] = ()
    readme: str = ""
    smoke_args: tuple[str, ...] = field(default=())
    #: the tool's own repository (its pyproject's Homepage); "" - axross's
    repo: str = ""
    #: more commands: name -> module (relative to the axross tree) with main()
    scripts: tuple[tuple[str, str], ...] = ()
    #: pip extras of the exported project: name -> requirements
    extras: tuple[tuple[str, tuple[str, ...]], ...] = ()
    #: axross's own extras (pyproject.toml) the project offers as well, by
    #: name; "all" of the project is their union
    axross_extras: tuple[str, ...] = ()
    #: "rewrite": imports renamed to PACKAGE._ax.*; "path": names kept,
    #: PACKAGE/_ax first on sys.path (see the module docstring)
    layout: str = "rewrite"
    #: follow every import (inside functions too) and module names in strings
    follow_all: bool = False
    #: path prefixes never exported (an unguarded import of one stops the export)
    exclude: tuple[str, ...] = ()
    #: top-level modules no exported module may import at import time
    forbid_at_import: tuple[str, ...] = ()
    #: the tool's own version ("" - axross's): a build of new code is told apart from an older wheel
    version: str = ""
    #: a folder of the axross tree copied as it is into the project's root
    #: (directory listings: glama.json, llms-install.md, docs/assets/logo.png;
    #: CHANGELOG.md, the release workflow and its packaging/)
    repo_files: str = ""
    #: data files beside the code (globs relative to the axross tree)
    data: tuple[str, ...] = ("resources/i18n/*.json",)
    #: package-data globs of the exported pyproject
    package_data: tuple[str, ...] = ("*.json",)
    #: a windowed program (gui-scripts entry)
    gui: bool = True
    #: the start module's function the command calls
    entry: str = "main"
    #: written into the README before everything else (an HTML comment)
    readme_marker: str = ""
    #: the CI workflow and smoke test kind: "qt" or "mcp"
    kind: str = "qt"
    #: The README's ten punchlines (one line each: "**Lead** - the rest"). With
    #: them README.md is a short front page - the punchlines, a table of
    #: contents, the screenshots, readme_short - and the full text (readme)
    #: goes into docs/README-extended.md, which the contents link first.
    pitch: tuple[str, ...] = ()
    #: Screenshots of the README: (path in the exported repo, caption); the
    #: README is PyPI's description too, so they are shown by absolute
    #: raw.githubusercontent.com URLs of the repo's main branch.
    shots: tuple[tuple[str, str], ...] = ()
    #: The short README's own sections (Markdown, "## " headings) after the screenshots.
    readme_short: str = ""
    #: The README's one line under its title (else the summary).
    tagline: str = ""
    #: axross's own tests of the tool (file names in tests/) that come with it,
    #: their imports renamed as the code's - ``python -m pytest tests`` in the
    #: export runs them - and the folders of tests/ they read (golden pages).
    tests: tuple[str, ...] = ()
    test_data: tuple[str, ...] = ()


def _probe_rewrites(package: str) -> tuple[tuple[str, str, str], ...]:
    # The multimedia probe starts itself as a child: by its new module name.
    return (("core/multimedia_probe.py", '"-m", "core.multimedia_probe"',
             f'"-m", "{package}._ax.core.multimedia_probe"'),)


APPS = {
    "media-player": App(
        dist="axross-media-player",
        package="axross_media_player",
        start="ui/media_player_app.py",
        title="axross Media Player",
        summary="axross's Media Player on its own: playlists, a 10-band equalizer, "
                "visualizations, internet radio",
        requires=("PyQt6>=6.6,<6.12", "numpy>=2.0"),
        lazy=("resources/extensions/media_player.py", "core/secure_storage.py",
              "core/multimedia_probe.py", "core/thread_relay.py", "core/tls_env.py",
              "ui/close_corner.py", "ui/icon_provider.py",
              "ui/window_dock_bar.py", "ui/screen_fit.py", "ui/state_files.py",
              "ui/window_prefs.py", "ui/qt_translations.py", "core/qt_exit.py",
              "core/posix_compat.py", "core/audio_eq.py", "core/subprocess_env.py",
              "core/json_store.py", "core/path_policy.py"),
        rewrites=_probe_rewrites("axross_media_player"),
        readme="""\
Play local files, folders and M3U playlists, and internet radio by its http / https
URL. A 10-band equalizer with presets, animated visualizations (in a window of their
own or full screen), shuffle and repeat; the list, the track and its position come
back at the next start.

```sh
axross-media-player                      # the last list
axross-media-player ~/Music/album/       # add a folder and play it
axross-media-player https://example.org/radio.mp3
```

Keys: Space play / pause, Left / Right seek, Up / Down volume, M mute.
Files on axross's remote connections (SFTP, SMB, S3 ...) are a feature of axross itself.
""",
    ),
    "amp": App(
        dist="axross-amp",
        package="axross_amp",
        repo="https://github.com/c0decave/axross-amp",
        start="ui/amp_app.py",
        title="axross-amp",
        summary="axross's Media Player, Audio Mixer and Bluetooth connector as one program: "
                "playlists, a 10-band equalizer, visualizations, internet radio, a mixer per "
                "source and Bluetooth headphones and speakers",
        requires=("PyQt6>=6.6,<6.12", "numpy>=2.0"),
        lazy=("resources/extensions/media_player.py", "resources/extensions/audio_mixer.py",
              "resources/extensions/bluetooth.py", "core/secure_storage.py",
              "core/multimedia_probe.py", "core/thread_relay.py", "core/tls_env.py",
              "ui/close_corner.py", "ui/icon_provider.py",
              "ui/window_dock_bar.py", "ui/screen_fit.py", "ui/state_files.py",
              "ui/window_prefs.py", "ui/qt_translations.py", "core/qt_exit.py",
              "core/posix_compat.py", "core/audio_eq.py", "core/subprocess_env.py",
              "core/json_store.py", "core/path_policy.py", "core/bluetooth_presence.py",
              "ui/bluetooth_presence.py", "core/bluetooth_adv.py", "core/bluetooth_companies.py",
              "core/bluetooth_direct.py", "ui/system_mixer_page.py", "ui/bluetooth_map.py",
              "ui/bluetooth_details.py", "ui/bluetooth_add.py", "ui/bluetooth_streams.py",
              "core/connect_worker.py", "core/connect_notice.py", "core/voice_audio.py"),
        rewrites=_probe_rewrites("axross_amp"),
        readme="""\
Three tabs in one window:

- **Media Player** - local files, folders and M3U playlists, and internet radio by its
  http / https URL. A 10-band equalizer with presets, animated visualizations (in a
  window of their own or full screen), shuffle, repeat and a sleep timer; the list, the
  track and its position come back at the next start.
- **Audio Mixer** - a volume, mute and output device per source, the shared equalizer
  and the system's sound server (PipeWire / PulseAudio). The player's sound menu
  (*Audio Mixer...*) opens this tab.
- **Bluetooth** - find, pair, trust and connect headphones, speakers and other devices
  through BlueZ (or a USB Bluetooth stick driven directly, with the optional `bumble`),
  battery levels, a presence log of devices in range, the audio profile per device.

```sh
axross-amp                      # the last list
axross-amp ~/Music/album/       # add a folder and play it
axross-amp https://example.org/radio.mp3
```

Keys in the player: Space play / pause, Left / Right seek, Up / Down volume, M mute.
Bluetooth needs BlueZ on the system bus (Linux) or a supported USB stick.
""",
    ),
    "markdown": App(
        dist="axross-markdown",
        package="axross_markdown",
        repo="https://github.com/c0decave/axross-markdown",
        repo_files="scripts/standalone_repo/axross-markdown",
        start="ui/markdown_app.py",
        title="axross-markdown",
        summary="axross's Markdown viewer on its own: GitHub Markdown with an outline, "
                "footnotes, highlighted code and local images - shown, never run",
        requires=("PyQt6>=6.6,<6.12", "markdown-it-py>=3.0", "mdit-py-plugins>=0.4",
                  "Pygments>=2.17", "Pillow>=10.0"),
        extras=(("linkify", ("linkify-it-py>=2.0",)),),
        scripts=(("axross-mdcat", "core/markdown_cli.py"),),
        lazy=("ui/markdown_viewer.py", "ui/markdown_view.py", "ui/markdown_safe.py",
              "ui/markdown_html.py", "core/markdown_doc.py", "core/markdown_term.py",
              "core/markdown_cli.py",
              "ui/editor_window.py", "ui/text_editor.py", "ui/guide_view.py",
              "core/local_fs.py", "core/protected_places.py", "core/security_mode.py",
              "core/desktop_open.py", "core/thread_relay.py", "core/tls_env.py",
              "ui/close_corner.py", "ui/icon_provider.py", "ui/window_dock_bar.py",
              "ui/screen_fit.py", "ui/state_files.py", "ui/window_prefs.py",
              "ui/qt_translations.py", "core/qt_exit.py", "core/posix_compat.py",
              "core/subprocess_env.py", "core/multimedia_env.py", "core/json_store.py",
              "axross/_version.py", "core/backend_guard.py", "core/atomic_io.py",
              "ui/off_gui.py", "core/connect_worker.py", "core/connect_notice.py", "core/secure_storage.py",
              "core/lex_worker.py", "core/image_worker.py", "core/process_launcher.py", "core/previews.py",
              "core/xdg_dirs.py"),
        version="0.16.5",
        pitch=(
            "- **GitHub Markdown, complete** - CommonMark, tables, task lists, footnotes, alerts, "
            "definition lists, front matter.",
            "- **Math without a browser** - `$...$` and `$$...$$`: fractions, integrals, sums, "
            "matrices and cases, drawn as text.",
            "- **An outline beside the text** - every heading one click away; find (Ctrl+F) "
            "marks every match.",
            "- **Highlighted code** - fenced blocks coloured by Pygments, in light and dark themes.",
            "- **Local images** - the pictures beside the file, clickable when linked, bounded "
            "in size.",
            "- **Shown, never run** - no scripts, styles, frames or forms; nothing is loaded "
            "from the network.",
            "- **Links that ask first** - a Markdown link opens in the window; a web link only "
            "after a question showing its real address.",
            "- **Edit with a live preview** - F4 opens an editor with the rendering beside the "
            "text, following the typing.",
            "- **In the terminal too** - `axross-mdcat`: colours, box-drawn tables, links and "
            "pictures, no Qt needed.",
            "- **Export** - the page as HTML with its images inside, as PDF, or printed.",
        ),
        shots=(
            ("docs/screenshots/viewer-light.png", "The viewer: outline, alerts, tables, task lists"),
            ("docs/screenshots/viewer-dark.png", "Dark theme: code coloured by Pygments, footnotes"),
            ("docs/screenshots/viewer-math.png", "Math: fractions, integrals, cases, matrices"),
            ("docs/screenshots/mdcat.png", "axross-mdcat: the same file in the terminal"),
        ),
        readme_short="""\
## Install and run

```sh
pip install axross-markdown                    # or: pipx install axross-markdown
axross-markdown README.md docs/*.md            # a window for each
axross-mdcat README.md                         # in the terminal, in colour (no Qt needed)
axross-markdown --html notes.md > notes.html   # the page for a web browser
```

Or a one-file program without Python - Linux (also as an AppImage), macOS (also as a disk
image) and Windows - from the [latest release](https://github.com/c0decave/axross-markdown/releases/latest).

Every dependency is pinned and reviewed in `requirements.lock.txt`
([how to install exactly those]({extended}#the-exact-reviewed-dependencies)).
""",
        tagline="GitHub Markdown in a window of its own - or in the terminal: read, never run.",
        # (axross's tests of the reader that need nothing of axross but the reader - the release runs them)
        tests=("test_markdown_corpus.py", "test_markdown_full.py", "test_markdown_golden.py",
               "test_markdown_image_safety.py", "test_markdown_raw_html.py", "test_markdown_reader_bugs.py",
               "test_markdown_reader_bugs2.py", "test_markdown_reader_bugs3.py", "test_markdown_reader_bugs4.py",
               "test_markdown_reader_bugs5.py", "test_markdown_reader_bugs6.py", "test_markdown_reader_bugs7.py",
               "test_markdown_reader_bugs8.py", "test_markdown_reader_bugs9.py", "test_markdown_reader_bugs10.py",
               "test_markdown_reader_bugs11.py", "test_markdown_reader_bugs12.py",
               "test_markdown_reader_bugs13.py", "test_markdown_reader_bugs14.py",
               "test_markdown_reader_bugs15.py", "test_markdown_reader_bugs16.py",
               "test_markdown_reader_bugs17.py", "test_markdown_reader_bugs18.py",
               "test_markdown_reader_bugs19.py", "test_markdown_reader_bugs20.py",
               "test_markdown_reader_bugs21.py",
               "test_markdown_reader_features.py",
               "test_markdown_single_tilde_in_link.py", "test_markdown_viewer.py",
               "test_markdown_viewer_window.py"),
        test_data=("golden/markdown",),
        readme="""\
A Markdown file rendered in a window of its own - or in the terminal. The full set:
CommonMark, GitHub's tables (aligned as written), task lists, strike-through and
autolinks, footnotes, alerts, definition lists, YAML / TOML front matter, math; the
headings as an outline beside the text, fenced code coloured by Pygments, the images
beside the file (clickable when linked). Edit (F4) opens an editor with the rendering
beside the text, following the typing. A link to another Markdown file opens it; a web
link opens in the browser only after a question that shows its real address.

- [The window: keys](#the-window-keys)
- [Export and print](#export-and-print)
- [Themes](#themes)
- [In the terminal: axross-mdcat](#in-the-terminal-axross-mdcat)
- [The security model](#the-security-model)
- [Limits](#limits)
- [Install options](#install-options)

## The window: keys

| Key | What it does |
|---|---|
| Ctrl+O | Open Markdown files, each in a window of its own |
| Ctrl+F | Find - every match marked, their count beside the field |
| Enter / Shift+Enter, F3 / Shift+F3 | The next / the previous match (into a folded `<details>` too) |
| Esc | End the find |
| Alt+Left / Alt+Right | Back / Forward through the files and headings visited |
| Ctrl++ / Ctrl+- / Ctrl+0 | Larger / smaller / the original size (the button between − and + shows the size in per cent; a click: the original size) |
| Ctrl+Home / Ctrl+End | The page's start / its end (a long page laid out up to there first) |
| Ctrl+A, Ctrl+C | Select all, copy - tables a row a line, their cells apart by tabs; a formula as its TeX |
| F5 | Read the file and its images again (a file changed on disk is read again by itself) |
| F4 | Edit: the file in an editor, the rendering beside the text - after a pause at the line typed at |
| Ctrl+P | Print |
| Alt+V | The View menu: the theme |
| Ctrl+M | Maximise the window, or back |

A right click on a code block copies the block as written; on a heading, a link to it as
GitHub writes it (`#the-heading`). The outline (the button *Outline*) jumps to a heading;
a window narrower than 700 pixels hides it until asked for.

## Export and print

*Export* (the button) saves the page as **HTML** - one file of its own: the images beside
the Markdown file put inside it, every other image a box naming it, a Content Security
Policy that lets it load nothing, relative links (`notes.md`) kept, any other link that is
no http(s), mailto or `#anchor` link its text - or as **PDF** (A4, light colours), or
**prints** it. A box that crosses a page break (an alert, a code block) is drawn between
the page margins on both pages. A long page is made a part at a time off the window's thread, with a
progress window and *Cancel*. From the command line, without a window:

```sh
axross-markdown --html notes.md > notes.html
```

## Themes

*View > Theme* (Alt+V): **Modern (follow system)** - light or dark as the desktop's
colour scheme is, and anew when it changes; light when the desktop does not say - Modern
Light, Modern Dark, Classic, Light Mode (the desktop's own palette), Hacker and Amber.
The choice is kept in `~/.config/axross-markdown/settings.json` (`$XDG_CONFIG_HOME` when
set); without one, the theme chosen in axross is taken, if axross is installed. The
page, its code and its formulas follow the theme.

## In the terminal: axross-mdcat

```sh
axross-mdcat README.md                  # in colour, through less -R when it is long
axross-mdcat --toc README.md            # the headings only
cat notes.md | axross-mdcat -           # standard input
axross-markdown --term README.md        # the same, from the window's program
```

| Option | What it does |
|---|---|
| `-w N`, `--width N` | Columns (default: the terminal's, at most 100; at least 20) |
| `--color auto/always/never/truecolor/256/16` | Colours (auto follows NO_COLOR, FORCE_COLOR, COLORTERM and whether it is a terminal) |
| `--theme auto/dark/light` | Colours for a dark or a light background (auto: COLORFGBG, else dark) |
| `--images auto/kitty/iterm/blocks/none` | Pictures with kitty's or iTerm2's protocol, in coloured half-blocks, or none |
| `--image-width N` | Columns a picture may take |
| `--no-links` | No terminal hyperlinks (OSC 8) |
| `--pager` / `--no-pager` | Always / never page with `less -R` |
| `--toc` | The headings only, with their anchors |
| `--watch` | Draw the file anew whenever it changes (Ctrl+C ends); a file not there yet is said and waited for |
| `--version` | The version |

Headings, emphasis, inline and fenced code (coloured), quotes and alerts, nested and task
lists, tables drawn with box characters (wrapped to fit; a long one drawn as it goes, a
row after the other when it cannot fit), definition lists, footnotes, math as text;
links are terminal hyperlinks with their address beside them. A long text is drawn a
part at a time - the first part at once, inline footnotes (`^[...]`) or not. Nothing in
a file can send the terminal an escape sequence of its own.

- At most 200 pictures a text, as in the window; then a line says the rest are not drawn.
- It stops as soon as the program it writes into has ended (`axross-mdcat big.md | head`).
- Output that cannot be written (a full disk) is said; the exit status is 1.

## The security model

What a file holds is shown, never run:

- **Raw HTML** is kept to a safe subset - no scripts, styles, frames, forms, event
  handlers or `javascript:` / `vbscript:` / `file:` / `data:` links (but data: images);
  what is left of it is shown as its text.
- **Nothing from the network**: a remote image is a box naming its address; no page,
  font or style sheet is fetched.
- **Images** are read only relative to the file, regular files only, never a secret file
  (an SSH key, a keyring, a password store), bounded in bytes (8 MiB), pixels (40 million
  one, 100 million a page) and count (200); an SVG that names other files is not shown,
  and an SVG is drawn in a process of its own that is ended after 10 seconds. A PDF or
  PostScript file is never taken for a picture.
- **Links**: a Markdown file opens in the window; any other link asks first, showing
  the real address (a host of look-alike letters in punycode, as it really is).
- **The terminal** gets no control character of the file: no escape sequence of its own.
- A text that would hold the window up (a table of a million cells, lists nested
  thousands deep, a formula nested a thousand deep) is shown as written or flatter,
  said in a notice - never a frozen window, never a blank page.

## Limits

- 8 MiB of a file are read (the rest: said at the end).
- Math is drawn as text and tables - fractions, roots, sums and integrals with their
  limits, matrices, cases, aligned lines, colours, accents - not by TeX: what it does not
  know is shown as written; a formula nested more than 64 groups deep is shown as
  written, with a note.
- A table of more than 64 columns is shown as written (in the window also one of more
  than 300,000 cells); lists nested more than 16 levels and quotes more than 8 are shown
  flatter.
- Mermaid, PlantUML, GeoJSON and STL blocks are shown as their source.
- Code is coloured in a process of its own; a block that takes longer than 5 seconds is
  shown without colours.
- An emoji short code (`:tada:`) of an emoji no installed font has stays as written.
- A file that is no text (a picture, a program) is said to be one, not shown.

## Install options

```sh
pip install axross-markdown              # or: pipx install axross-markdown
pip install "axross-markdown[linkify]"   # bare addresses linked as GitHub links them
```

- **Python 3.11 or newer** with PyQt6 6.6 to 6.11, markdown-it-py, mdit-py-plugins,
  Pygments and Pillow (installed with it).
- **One-file programs without Python** from the
  [latest release](https://github.com/c0decave/axross-markdown/releases/latest): Linux
  x86-64 (also as an AppImage), macOS arm64 (also as a disk image with the app) and
  Windows x64, with `SHA256SUMS`. On Windows the viewer is a window program (no console
  window beside it) and the terminal view a console program of its own, `axross-mdcat.exe`
  (or `axross-markdown --term` from a console).
- **The exact, reviewed dependencies**: `requirements.lock.txt` (below).
- On Linux the window needs Qt's system libraries (EGL, xkbcommon, fontconfig, D-Bus,
  xcb-cursor); a missing one is named with the package that brings it. `axross-mdcat`
  and `--html` need none of them.

The Markdown view started as the Markdown viewer of
[sandbox-ai](https://github.com/c0decave/sandbox-ai)'s Files page (MIT, the same
author), ported to PyQt6 and axross's backends.
""",
    ),
    "mcp": App(
        dist="axross-headless-mcp",
        package="axross_headless_mcp",
        repo="https://github.com/c0decave/axross-headless-mcp",
        repo_files="scripts/standalone_repo/axross-headless-mcp",
        start="core/mcp_cli.py",
        title="axross-headless-mcp",
        summary="axross's headless MCP server: file tools on the local disk and on SFTP, SMB, "
                "WebDAV, S3 and more for any MCP client, over stdio or HTTP - without Qt",
        # What the server needs for the file tools, the groups and its
        # SSH / SFTP backend; the floors are axross's (security floors,
        # pyproject.toml). Everything else is an extra, as in axross.
        requires=("paramiko>=5.0,<6.0", "cryptography>=50.0.0", "jsonschema>=4.21",
                  "keyring>=25.0", "PySocks>=1.7"),
        axross_extras=("smb", "webdav", "s3", "azure", "onedrive", "gdrive", "dropbox",
                       "winrm", "wmi", "exchange", "adb", "archive", "tftp", "postgres",
                       "redis", "mongo", "git", "dns", "magic", "encoding", "snmp", "ldap",
                       "metadata"),
        # Image metadata and the preview's fallback decoder: axross has
        # Pillow as a dependency, the headless server as an extra.
        extras=(("images", ("Pillow>=13.0.0",)),),
        lazy=(),
        layout="path",
        follow_all=True,
        # thread_relay is Qt through and through; ui_helpers reaches it only
        # with a GUI running, behind a guarded import.
        exclude=("ui/", "main.py", "core/thread_relay.py"),
        forbid_at_import=("PyQt6",),
        data=("resources/i18n/*.json", "resources/mcp/*.json", "resources/wordlists/*.txt",
              "resources/scripts/*.py", "resources/scripts/*.md",
              "resources/extensions/*.py", "resources/extensions/*.json",
              "resources/extensions/*.md"),
        package_data=("*.json", "*.txt", "*.md", "*.py"),
        gui=False,
        readme_marker="<!-- mcp-name: io.github.c0decave/axross-headless-mcp -->",
        kind="mcp",
        pitch=(
            "- **Your files for any MCP client** - Claude Desktop, Claude Code, Cursor, VS Code: "
            "list, read, search and hash files.",
            "- **Almost every file system** - the local disk, SFTP built in, and 40 backends "
            "from SMB, NFS and S3 to cloud drives, Git and databases as extras.",
            "- **Read-only by default** - the write tools only with `--mcp-write` and an "
            "explicit `--mcp-root`.",
            "- **Confined to one folder** - every path stays under `--mcp-root`; SSH and GnuPG "
            "keys and tokens are refused.",
            "- **50+ tools in groups** - metadata, duplicates, archives, crypto, file types, "
            "transfers, remote profiles and more.",
            "- **stdio or HTTP** - streamable HTTP with a bearer token, mTLS for anything but "
            "loopback.",
            "- **No GUI, no Qt** - runs on a server, in a container or in CI: `pipx`, `uvx` "
            "or Docker.",
            "- **Current MCP** - 2025-11-25: tool annotations, structured results, progress, "
            "cancellation, resources.",
            "- **An audit trail** - what each tool did or refused, on stderr and in the log.",
            "- **The same code as axross** - axross's settings and saved connection profiles, "
            "credentials from the keyring.",
        ),
        shots=(
            ("docs/screenshots/terminal.png",
             "The tools of every group, and a client's tools/call over stdio"),
        ),
        readme_short="""\
## What it supports and does

- **Almost every file system:** the local disk plus 40 backends - protocols, cloud services, devices.
- **Classic network storage:** SFTP, SCP, SMB / CIFS with DFS namespaces, NFS, WebDAV, FTP / FTPS, rsync, iSCSI.
- **Object storage and the cloud:** S3 and S3-compatible stores, Azure Blob and Files, OneDrive, SharePoint, Google Drive, Dropbox.
- **Code and data as folders:** Git and Subversion repositories, PostgreSQL, SQLite, Redis, MongoDB GridFS, LDAP.
- **Devices and mail:** Android (ADB, MTP), IMAP, POP3, Exchange (EWS), NNTP, TFTP, Gopher, printers (PJL), WinRM, WMI, Cisco IOS.
- **The same tools everywhere:** list, read, stat, search, grep, walk, hash and preview work alike on every backend.
- **Your saved connections:** axross's connection profiles, credentials from the system keyring, never shown to the model.
- **Read-only by default:** writing, moving and deleting need `--mcp-write` and an explicit `--mcp-root`.
- **Confined to one folder:** every path stays under `--mcp-root`, checked through the folder's own descriptors.
- **Secrets stay put:** SSH and GnuPG keys, tokens and `.env` files are refused; every stream is scanned for keys.
- **55 tools in 15 groups, opt in:** only the core tools are on until you name more groups or `all`.
- **Search and grep across servers:** name, size and date search, content grep, an offline index for repeated searches.
- **Checksums without downloading:** SHA-256 on the server where the backend offers it, recursive checksums of whole trees.
- **Duplicate finder:** duplicate groups by wasted space, dedupe to the trash, every copy re-verified first, a dry run by default.
- **Metadata, read and removed:** EXIF / GPS / XMP / IPTC, Office and PDF properties, media tags; removal writes a cleaned copy.
- **Archives, safely:** list and extract zip, tar.*, 7z and rar, guarded against zip-slip, bombs, link members and spoofing names.
- **Packing:** zip, tar.gz / .zst / .xz / .bz2 and 7z, optionally AES-256 with encrypted file names.
- **Encryption:** encrypt and decrypt files (AES-256-GCM, PBKDF2-SHA256).
- **File types by content:** magic-byte detection that flags files whose extension lies.
- **Copy and move between any two backends:** SFTP to S3, SMB to Google Drive - atomic, resumable, never half-written under the final name.
- **Earlier versions:** list and read previous versions where the storage keeps them.
- **Remote commands, only if allowed:** SSH, WinRM (PowerShell), ADB and more with `--mcp-allow-exec`, off by default.
- **Current MCP over stdio or HTTP:** protocol 2025-11-25, 2025-06-18, 2024-11-05; bearer token, mTLS off loopback, an audit trail.
- **Runs anywhere, no GUI:** `uvx`, `pipx` or the container image; the same code as the axross desktop app and its tests.

**The 55 tools** (only the file tools are on until `--mcp-tools GROUP,...` or `all` adds groups): **files (always on)** `list_dir`, `stat`, `read_file`, `checksum`, `search`, `walk`, `recursive_checksum`, `preview`, `grep`, `list_versions`, `open_version_read`; **write (`--mcp-write`)** `write_file`, `mkdir`, `remove`, `rename`, `copy`, `bulk_copy`, `symlink`, `hardlink`, `chmod`; **metadata** `metadata_read`, `metadata_export`, `metadata_export_file`, `metadata_remove`; **duplicates** `duplicates_scan`, `duplicates_scans`, `duplicates_groups`, `duplicates_dedupe`; **archives** `archive_list`, `archive_extract`; **packing** `pack_formats`, `pack`; **crypto** `encrypt`, `decrypt`; **file types** `file_type`, `file_type_scan`; **index** `index_build`; **transfers** `transfer_copy`, `transfer_move`; **remote profiles** `remote_profiles`, `remote_open`, `remote_close`, `list_backends`; **remote commands (`--mcp-allow-exec`)** `remote_exec`, `remote_script`, `exec_backends`; **scripts (`--mcp-allow-scripts`)** `script_list`, `script_api_schema`, `script_read`, `script_write`, `script_delete`, `script_run`; **agent** `agent_run`; **extensions** `extensions_list`, `extensions_info`.

## Install

```sh
pipx install axross-headless-mcp            # or: pip install axross-headless-mcp
pipx install 'axross-headless-mcp[all]'     # with every remote protocol and format
axross-headless-mcp --mcp-list-tools --mcp-tools all   # what it would serve, as JSON
```

## Connect a client

```sh
claude mcp add axross -- axross-headless-mcp --mcp-root ~/projects --mcp-tools all
```

Claude Desktop, Cursor, VS Code and other clients: [the JSON
configuration]({extended}#connect-a-client-stdio). Over HTTP (a bearer token, mTLS off
loopback): [Over HTTP]({extended}#over-http). In a container:

```sh
docker run -i --rm -v "$PWD:/data" ghcr.io/c0decave/axross-headless-mcp:latest \\
    --mcp-server --mcp-root /data --mcp-tools all
```

## Documentation

| Page | What it covers |
|---|---|
| [Extended README]({extended}) | every tool group, the protocol, HTTP, Docker, settings |
| [docs/MCP.md](https://github.com/c0decave/axross/blob/main/docs/MCP.md) | the full reference of axross's MCP server |
| [docs/mcp-tools.json](https://github.com/c0decave/axross/blob/main/docs/mcp-tools.json) | the tool catalogue, generated from the manifest |
| [llms-install.md](https://github.com/c0decave/axross-headless-mcp/blob/main/llms-install.md) | setup steps for AI agents (Cline and others) |
""",
        readme="""\
The MCP (Model Context Protocol) server of [axross](https://github.com/c0decave/axross)
on its own: an LLM client - Claude Desktop, Claude Code, Cursor, VS Code, any MCP client -
lists, reads, searches and hashes files on this machine and on axross's remote
connections, and with `--mcp-write` writes them. No GUI and no Qt: it runs on a server,
in a container or in CI.

- **File tools** (always on, read-only): `list_dir`, `stat`, `read_file`, `checksum`,
  `search`, `walk`, `recursive_checksum`, `grep`, `list_versions`, `open_version_read`,
  and `preview` (image thumbnails; with the `images` extra, which brings Pillow).
- **Write tools** (`--mcp-write --mcp-root DIR`): `write_file`, `mkdir`, `remove`,
  `rename`, `copy`, `bulk_copy`, `symlink`, `hardlink`, `chmod`.
- **Capability groups** (`--mcp-tools GROUP,...` or `all`): metadata, duplicates,
  packer, archive, crypto, index, filetype, transfer, remote (axross's saved
  connection profiles as further backends), exec (`--mcp-allow-exec`), agent,
  extensions.
- Every path is confined to `--mcp-root` (default: your home folder); secret files
  (SSH and GnuPG private keys, tokens) are refused unless `--mcp-allow-secret-reads`.

The protocol: MCP 2025-11-25, 2025-06-18 and 2024-11-05 (the client's version is
answered when it is one of them), tool annotations (read-only, destructive,
idempotent, open-world), structured results with output schemas, progress,
cancellation, logging and `axross://` resources. Long jobs run in the background
through axross's own `axross/tasks/start` / `status` / `cancel` / `list`. A file
name that is not UTF-8 is shown with U+FFFD and comes with its raw bytes
(`name_b64`, `path_b64`); every path argument takes them back (`path_b64`, ...).
The audit trail (what each tool did or refused) goes to stderr and to the log.

### Install

```sh
pipx install axross-headless-mcp                  # or: pip install axross-headless-mcp
pipx install 'axross-headless-mcp[all]'           # with every remote protocol and format
axross-headless-mcp --version
axross-headless-mcp --mcp-list-tools --mcp-tools all   # what it would serve, as JSON
```

The extras are axross's: `smb`, `webdav`, `s3`, `azure`, `onedrive`, `gdrive`,
`dropbox`, `winrm`, `wmi`, `exchange`, `adb`, `archive`, `tftp`, `postgres`, `redis`,
`mongo`, `git`, `dns`, `magic`, `encoding`, `snmp`, `ldap`, `metadata`, plus `images`
(Pillow); `all` holds what axross's own `all` holds (not `winrm`, `wmi`, `exchange`)
plus `images`. SFTP / SSH (paramiko) is always there.

### Connect a client (stdio)

Claude Code:

```sh
claude mcp add axross -- axross-headless-mcp --mcp-root ~/projects --mcp-tools all
```

Claude Desktop, Cursor, VS Code and the like (`claude_desktop_config.json`,
`.cursor/mcp.json`, ...):

```json
{
  "mcpServers": {
    "axross": {
      "command": "axross-headless-mcp",
      "args": ["--mcp-root", "/home/me/projects", "--mcp-tools", "all"]
    }
  }
}
```

Add `--mcp-write` for the write tools (it needs an explicit `--mcp-root`).
`uvx axross-headless-mcp ...` works as the command as well, without installing first.

### Over HTTP

```sh
axross-headless-mcp --mcp-http 127.0.0.1:7331 --mcp-root ~/projects --mcp-tools all
# prints a bearer token (or set AXROSS_MCP_HTTP_TOKEN); the endpoint is
# http://127.0.0.1:7331/messages (streamable HTTP, Mcp-Session-Id, SSE)
```

A client sends `Authorization: Bearer <token>`. Anything but loopback needs mTLS:
`--mcp-cert server.pem --mcp-key server-key.pem --mcp-ca clients-ca.pem`.
`--mcp-allow-scripts` and `--mcp-allow-secret-reads` are stdio-only.

### Docker

```sh
docker run -i --rm -v "$PWD:/data" ghcr.io/c0decave/axross-headless-mcp:latest \
    --mcp-server --mcp-root /data --mcp-tools all
```

### Settings

The server reads axross's settings (`~/.config/axross`): the saved connection
profiles of the `remote` group (credentials from the system keyring), the metadata
and duplicate indexes, the security mode. The log goes to
`~/.local/state/axross/logs/axross.log` (`--debug` / `-v`: also stderr; stdout is the
protocol's).

Full reference: [docs/MCP.md](https://github.com/c0decave/axross/blob/main/docs/MCP.md)
and the tool catalogue [docs/mcp-tools.json](https://github.com/c0decave/axross/blob/main/docs/mcp-tools.json).
Setup steps for AI agents (Cline and others):
[llms-install.md](https://github.com/c0decave/axross-headless-mcp/blob/main/llms-install.md).
""",
    ),
    "system-info": App(
        dist="axross-system-info",
        package="axross_system_info",
        start="ui/system_info_app.py",
        title="axross System Information",
        summary="axross's System Information on its own: everything about this computer's "
                "hardware, live gauges, text and JSON export",
        requires=("PyQt6>=6.6,<6.12",),
        lazy=("ui/system_info_window.py", "core/thread_relay.py", "ui/close_corner.py",
              "core/secure_storage.py", "core/remote_name.py",
              "ui/icon_provider.py", "ui/window_dock_bar.py", "ui/screen_fit.py",
              "ui/state_files.py", "ui/window_prefs.py", "ui/qt_translations.py",
              "core/qt_exit.py", "core/posix_compat.py", "axross/_version.py",
              "core/subprocess_env.py", "core/multimedia_env.py", "core/tls_env.py",
              "core/json_store.py"),
        readme="""\
CPU, memory, disks, graphics and displays, network, sound, USB, PCI, battery, sensors,
firmware, the OS and virtualisation - as a dashboard with live gauges and a page per
area. Reads /proc and /sys without root and starts no program. Search across all
pages, copy a page or everything, save a text or JSON report; serial numbers, MAC and
IP addresses and UUIDs stay hidden until *Show identifiers* is ticked.

```sh
axross-system-info                       # the window
axross-system-info --json report.json    # write the report (identifiers hidden) and quit
```
""",
        smoke_args=(),
    ),
}

_IMPORT_LINE = re.compile(
    r"^(?P<indent>[ \t]*)(?P<kw>from|import)[ \t]+(?P<top>" + "|".join(PACKAGES) + r")(?P<rest>[.\s])",
    re.MULTILINE)


class ExportError(SystemExit):
    pass


def _module_file(name: str) -> str | None:
    for candidate in (ROOT / (name.replace(".", "/") + ".py"),
                      ROOT / name.replace(".", "/") / "__init__.py"):
        if candidate.is_file():
            return candidate.relative_to(ROOT).as_posix()
    return None


def _type_checking_ids(tree: ast.Module) -> set[int]:
    """The nodes inside ``if TYPE_CHECKING:`` blocks: never run."""
    ids: set[int] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.If) and getattr(node.test, "id",
                                                getattr(node.test, "attr", "")) == "TYPE_CHECKING":
            for inner in node.body:
                ids.update(id(sub) for sub in ast.walk(inner))
    return ids


def _imports(tree: ast.Module, roots: tuple[str, ...] = PACKAGES):
    """(node, module names, guarded, top level) for every import of a module
    under *roots* (axross's packages), outside ``if TYPE_CHECKING:``."""
    skipped = _type_checking_ids(tree)
    guarded_ids: set[int] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Try):
            catches = any(_catches_import_error(h) for h in node.handlers)
            if catches:
                for inner in node.body:
                    for sub in ast.walk(inner):
                        guarded_ids.add(id(sub))
    top_ids: set[int] = set()

    def visit(body):
        for n in body:
            if isinstance(n, (ast.Import, ast.ImportFrom)):
                top_ids.add(id(n))
            elif isinstance(n, (ast.If, ast.Try)):
                visit(n.body)
                visit(getattr(n, "orelse", []))
                visit(getattr(n, "finalbody", []))
                for h in getattr(n, "handlers", []):
                    visit(h.body)
    visit(tree.body)
    for node in ast.walk(tree):
        names = []
        if isinstance(node, ast.Import):
            names = [a.name for a in node.names]
        elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
            names = [node.module] + [f"{node.module}.{a.name}" for a in node.names]
        names = [n for n in names if n.split(".")[0] in roots]
        if names and id(node) not in skipped:
            yield node, names, id(node) in guarded_ids, id(node) in top_ids


def _module_strings(tree: ast.Module) -> list[str]:
    """String constants that name an axross module exactly ("core.ssh_client"):
    imported by name at run time (importlib, ``-m``, sys.modules)."""
    out = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            value = node.value
            if (value.split(".")[0] in PACKAGES and re.fullmatch(r"[a-z_][a-z0-9_.]*", value)
                    and _module_file(value)):
                out.append(value)
    return out


def import_time_imports(text: str, roots: tuple[str, ...]) -> list[tuple[int, str]]:
    """(line, module) of every import of *roots* a module runs when it is
    imported - at module level, outside ``if TYPE_CHECKING:`` and not in a
    ``try`` that catches ImportError."""
    return [(node.lineno, name)
            for node, names, guarded, top in _imports(ast.parse(text), roots)
            if top and not guarded for name in names[:1]]


def _excluded(app: App, rel: str) -> bool:
    return any(rel == prefix or rel.startswith(prefix) for prefix in app.exclude)


def _catches_import_error(handler: ast.ExceptHandler) -> bool:
    # (a handler that raises again - "except BaseException: clean up; raise" - guards nothing: the import
    # failed at the user's, the editor's Save always, and the export said nothing)
    if any(isinstance(node, ast.Raise) and node.exc is None for node in handler.body):
        return False
    if handler.type is None:
        return True
    names = [handler.type] if not isinstance(handler.type, ast.Tuple) else handler.type.elts
    return any(getattr(n, "id", getattr(n, "attr", "")) in
               ("ImportError", "ModuleNotFoundError", "Exception", "BaseException") for n in names)


def closure(app: App) -> list[str]:
    """The files the tool runs on: its start module, everything imported at
    module level from there, the LAZY modules and their imports, and the
    __init__ of every package on the way."""
    wanted = set(app.lazy)
    seen: set[str] = set()
    todo = [app.start, *app.lazy]
    while todo:
        rel = todo.pop()
        if rel in seen:
            continue
        if not (ROOT / rel).is_file():
            raise ExportError(f"export: {rel} does not exist - update LAZY")
        seen.add(rel)
        parts = Path(rel).parts
        for i in range(1, len(parts)):
            init = Path(*parts[:i], "__init__.py").as_posix()
            if (ROOT / init).is_file() or init in STUB_INITS:
                todo.append(init)
        if rel in STUB_INITS:
            continue
        tree = ast.parse((ROOT / rel).read_text(encoding="utf-8"))
        for _node, names, _guarded, top in _imports(tree):
            for name in names:
                found = _module_file(name)
                if found and (top or found in wanted or app.follow_all) \
                        and not _excluded(app, found):
                    todo.append(found)
        if app.follow_all:
            for name in _module_strings(tree):
                found = _module_file(name)
                if found and not _excluded(app, found):
                    todo.append(found)
    return sorted(seen)


def rewrite_imports(text: str, package: str) -> str:
    """``from core.x import y`` -> ``from PACKAGE._ax.core.x import y`` (and
    ``import ui.x as z``); a plain ``import core.x`` would bind another name
    and is refused."""
    def sub(m: re.Match) -> str:
        if m.group("kw") == "import":
            line_end = text.find("\n", m.end())
            line = text[m.start():line_end if line_end != -1 else len(text)]
            if " as " not in line:
                raise ExportError(f"export: refusing to rewrite {line.strip()!r} (no 'as')")
        return f"{m.group('indent')}{m.group('kw')} {package}._ax.{m.group('top')}{m.group('rest')}"

    return _IMPORT_LINE.sub(sub, text)


_LINE_START = r"(?:(?<=\\n)|(?<=\\t)|(?<![\w.]))"  # (after a written "\n" too)
_STRING_IMPORT = re.compile(
    _LINE_START + r"from (?P<from>(?:" + "|".join(PACKAGES) + r")(?:\.\w+)*) import"
    r"|" + _LINE_START + r"import (?P<dotted>(?:" + "|".join(PACKAGES) + r")(?:\.\w+)+)(?P<as> as )?"
    r"|" + _LINE_START + r"import (?P<bare>" + "|".join(PACKAGES) + r")(?![\w.])")
_STRING_MODULE = re.compile(r"(?P<quote>[rbuRBU]*['\"])(?P<name>(?:" + "|".join(PACKAGES) + r")\.[\w.]+)(?P=quote)\Z")


def rewrite_string_imports(text: str, package: str) -> str:
    """The module names inside *text*'s string literals as :func:`rewrite_imports`
    renames its imports: the code a test runs in a child (``"from ui.x import y"``,
    ``"import core.x as c"``, ``"import core.x"``, ``"import ui"``) and a literal that
    is a module's dotted name (``monkeypatch.setattr("core.x.f", ...)``,
    ``mock.patch("ui.x.f")``, ``__import__("core.x")``) - an exported test ran
    axross's modules there, which the export has not."""
    import io
    import tokenize

    prefix = f"{package}._ax"

    def code(match: re.Match) -> str:
        if match.group("from"):
            return f"from {prefix}.{match.group('from')} import"
        if match.group("bare"):
            return f"from {prefix} import {match.group('bare')}"
        dotted = match.group("dotted")
        if match.group("as"):
            return f"import {prefix}.{dotted} as "
        # (the name it binds - "core" - as the original's: core.x.y works after it)
        return f"import {prefix}.{dotted}; from {prefix} import {dotted.split('.')[0]}"

    def literal(value: str) -> str:
        whole = _STRING_MODULE.match(value)
        if whole:
            return f"{whole.group('quote')}{prefix}.{whole.group('name')}{whole.group('quote')}"
        return _STRING_IMPORT.sub(code, value)

    kinds = {tokenize.STRING} | ({tokenize.FSTRING_MIDDLE} if hasattr(tokenize, "FSTRING_MIDDLE") else set())
    lines = text.splitlines(keepends=True)
    starts = [0]
    for line in lines:
        starts.append(starts[-1] + len(line))
    changes = []
    before = tokenize.NEWLINE
    for token in tokenize.generate_tokens(io.StringIO(text).readline):
        statement = before in (tokenize.NEWLINE, tokenize.INDENT, tokenize.DEDENT, tokenize.ENCODING)
        if token.type not in (tokenize.NL, tokenize.COMMENT):
            before = token.type
        if token.type in kinds and not statement:  # (a docstring: prose, kept)
            new = literal(token.string)
            if new != token.string:
                changes.append((starts[token.start[0] - 1] + token.start[1],
                                starts[token.end[0] - 1] + token.end[1], new))
    for begin, end, new in reversed(changes):
        text = text[:begin] + new + text[end:]
    return text


def check_exported(rel: str, text: str, package: str, files: set[str], *,
                   rewritten: bool = True, forbid: tuple[str, ...] = ()) -> list[str]:
    """What is wrong with an exported module: an axross import left as it
    was (*rewritten*), an unguarded import of a module that did not come
    along, or an import of a *forbid* module at import time."""
    problems = [f"{rel}:{line}: imports {name} when it is imported (guard it or move it "
                "into the function that needs it)"
                for line, name in import_time_imports(text, forbid)] if forbid else []
    tree = ast.parse(text)
    prefix = f"{package}._ax."
    for node in ast.walk(tree) if rewritten else ():
        names = []
        if isinstance(node, ast.Import):
            names = [a.name for a in node.names]
        elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
            names = [node.module]
        for name in names:
            if name.split(".")[0] in PACKAGES:
                problems.append(f"{rel}:{node.lineno}: import of {name} not rewritten")
    for node, names, guarded, _top in _imports(ast.parse(_unprefix(text, prefix))):
        module_names = [names[0]] if isinstance(node, ast.ImportFrom) else names
        for name in module_names:
            found = _module_file(name)
            if found is None:
                # "from core import x" where x is a module: names[1:] cover it
                continue
            if found not in files and not guarded:
                problems.append(f"{rel}:{node.lineno}: {name} is not exported and its import "
                                "is not guarded (try/except ImportError)")
        if isinstance(node, ast.ImportFrom):
            for name in names[1:]:
                found = _module_file(name)
                if found is not None and found not in files and not guarded:
                    problems.append(f"{rel}:{node.lineno}: {name} is not exported and its "
                                    "import is not guarded (try/except ImportError)")
    return problems


def _unprefix(text: str, prefix: str) -> str:
    return text.replace(prefix, "")


def axross_extras() -> dict[str, list[str]]:
    """axross's own pip extras (pyproject.toml)."""
    with open(ROOT / "pyproject.toml", "rb") as fh:
        return tomllib.load(fh)["project"]["optional-dependencies"]


def project_extras(app: App) -> list[tuple[str, tuple[str, ...]]]:
    """The exported project's extras: its own, axross's by name, and "all"
    when it takes any of axross's: its own and what of axross's is in
    axross's own "all" (which leaves out some on purpose: impacket, WinRM,
    exchangelib)."""
    extras = list(app.extras)
    if app.axross_extras:
        known = axross_extras()
        missing = [name for name in app.axross_extras if name not in known]
        if missing:
            raise ExportError(f"export: axross has no extra {', '.join(missing)}")
        own = list(extras)
        extras += [(name, tuple(known[name])) for name in app.axross_extras]
        union: list[str] = []
        for name, reqs in extras:
            union += [r for r in reqs
                      if r not in union and ((name, reqs) in own or r in known["all"])]
        extras.append(("all", tuple(union)))
    return extras


def requirements_in(app: App) -> str:
    """What the exported project can install - its dependencies and every
    extra, one requirement a line: the input of its lock
    (scripts/lock_standalone_deps.sh)."""
    lines = list(app.requires)
    for _name, reqs in project_extras(app):
        lines += [r for r in reqs if r not in lines]
    return "\n".join(lines) + "\n"


def lock_path(name: str) -> Path:
    """axross's lock of the dependencies of exported tool *name*: one of the
    supply-chain gate's locks (security/supply_chain_gate.py LOCKS)."""
    return ROOT / "build" / f"requirements-standalone-{name}.txt"


def locked_requirements(name: str) -> str | None:
    """The lock of *name*, or None when axross locks none for it; an
    ExportError when it was made for other requirements than the ones the
    export writes (run scripts/lock_standalone_deps.sh NAME)."""
    path = lock_path(name)
    if not path.is_file():
        return None
    text = path.read_text(encoding="utf-8")
    want = hashlib.sha256(requirements_in(APPS[name]).encode()).hexdigest()
    if f"# input sha256 {want} " not in text:
        shown = path.relative_to(ROOT) if path.is_relative_to(ROOT) else path
        raise ExportError(f"export: {shown} was locked for other requirements than "
                          f"the tool's - run scripts/lock_standalone_deps.sh {name} and review the "
                          "new pins (docs/SUPPLY_CHAIN_GATE.md)")
    return text


#: The gate's settings in an exported project: axross's gate, checked out by
#: its CI next to the project (.axross), on the project's lock and axross's
#: reviewed baseline - the same review the lock passed in axross.
GATE_CONFIG = """\
# axross's supply-chain gate (docs/SUPPLY_CHAIN_GATE.md in axross) on this
# program's lock. The CI checks out axross's security/ folder and its
# scanners' lock into .axross and runs
#   python -I .axross/security/supply_chain_gate.py --config supply-chain-gate.toml check
# Every pin must have a reviewed entry in axross's baseline: the lock is
# axross's (build/requirements-standalone-{name}.txt), written here by
# scripts/export_standalone.py {name}.
root = "."
locks = ["requirements.lock.txt"]
scanner_lock = ".axross/build/requirements-scan-tools.txt"
index_config = ["pyproject.toml", ".github/workflows/tests.yml"]
baseline_dir = ".axross/security/supply_chain_baseline"
cache_dir = ".supply-chain-cache"
min_age_days = 14
user_agent = "{dist}-supply-chain-gate/1"
"""


def _pyproject(app: App, version: str) -> str:
    deps = ",\n    ".join(f'"{d}"' for d in app.requires)
    scripts = "".join(f'{name} = "{app.package}._ax.{module[:-3].replace("/", ".")}:main"\n'
                      for name, module in app.scripts)
    extras = ""
    if app.extras or app.axross_extras:
        extras = "[project.optional-dependencies]\n" + "".join(
            f"{json.dumps(name) if not re.fullmatch(r'[a-z0-9_]+', name) else name} = "
            f"[{', '.join(json.dumps(r) for r in reqs)}]\n"
            for name, reqs in project_extras(app)) + "\n"
    gui = (f"\n[project.gui-scripts]\n{app.dist}-gui = \"{app.package}.__main__:main\"\n"
           if app.gui else "")
    data = ", ".join(json.dumps(g) for g in app.package_data)
    return f'''[build-system]
requires = ["setuptools>=77"]
build-backend = "setuptools.build_meta"

[project]
name = "{app.dist}"
version = "{version}"
description = "{app.summary}"
readme = "README.md"
license = "Apache-2.0"
license-files = ["LICENSE"]
requires-python = ">=3.11"
dependencies = [
    {deps},
]

[project.urls]
Homepage = "{app.repo or AXROSS_URL}"
Source = "{app.repo or AXROSS_URL}"
axross = "{AXROSS_URL}"

{extras}[project.scripts]
{app.dist} = "{app.package}.__main__:main"
{scripts}{gui}
[tool.setuptools.packages.find]
where = ["src"]

[tool.setuptools.package-data]
"*" = [{data}]
'''


AXROSS_URL = "https://github.com/c0decave/axross"

#: What the exported project ignores.
GITIGNORE = """__pycache__/
*.py[cod]
*.egg-info/
build/
dist/
.venv/
.pytest_cache/
"""


#: The CI job of an exported project with a lock: axross's supply-chain gate
#: as scripts/build_dist.sh runs it - the standard-library check first
#: (PyPI, OSV, age, names, provenance, every file against axross's reviewed
#: baseline), then the scanners (GuardDog's and axross's YARA rules,
#: attestations) from a venv of their own lock, installed from the archives
#: the first stage inspected; the report is kept as an artifact.
GATE_JOB = """
  supply-chain:
    runs-on: ubuntu-24.04
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
        with:
          persist-credentials: false
      - name: axross's supply-chain gate and its reviewed baseline
        uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
        with:
          repository: c0decave/axross
          path: .axross
          persist-credentials: false
          sparse-checkout-cone-mode: false
          sparse-checkout: |
            /security/
            /build/requirements-scan-tools.txt
      - uses: actions/setup-python@6d4fd22b20465ccc0f7354476588e8df7c9ca0e0 # v7.1.0
        with:
          python-version: "3.12"
      - name: Gate (PyPI, OSV, age, names, provenance, content against the baseline)
        run: python -I .axross/security/supply_chain_gate.py --config supply-chain-gate.toml check --report supply-chain-report --reduced-locks reduced
      - name: Scanners from their hashed lock
        run: |
          python -m venv "$RUNNER_TEMP/scan-venv"
          "$RUNNER_TEMP/scan-venv/bin/pip" install -q --require-hashes --only-binary=:all: -r reduced/requirements-scan-tools.txt
          python -I .axross/security/supply_chain_gate.py --config supply-chain-gate.toml verify-env --python "$RUNNER_TEMP/scan-venv/bin/python" --lock .axross/build/requirements-scan-tools.txt
      - name: Gate with the scanners (YARA, attestations)
        run: python -I .axross/security/supply_chain_gate.py --config supply-chain-gate.toml check --scan-python "$RUNNER_TEMP/scan-venv/bin/python" --report supply-chain-report
      - uses: actions/upload-artifact@cf430e030ddbb5b0abf93d22962f4752f3646cd9 # v7.0.2
        if: always()
        with:
          name: supply-chain-report
          path: supply-chain-report
"""


def _workflow(app: App, locked: bool = False) -> str:
    """CI of the exported project: its tests on Linux with Qt offscreen -
    or, for the MCP server, on three Pythons without Qt (and a check that
    nothing pulled PyQt6 in). With a lock (*locked*) the tests install
    exactly its pins (``--require-hashes``) and the supply-chain gate runs
    on it (GATE_JOB)."""
    if app.kind == "mcp":
        return """name: tests

on:
  push:
  pull_request:

permissions:
  contents: read

jobs:
  test:
    runs-on: ubuntu-24.04
    strategy:
      fail-fast: false
      matrix:
        python: ["3.11", "3.12", "3.13"]
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
      - uses: actions/setup-python@6d4fd22b20465ccc0f7354476588e8df7c9ca0e0 # v7.1.0
        with:
          python-version: ${{ matrix.python }}
      - name: Install
        run: python -m pip install . pytest
      - name: No Qt in the environment
        run: python -c "import importlib.util, sys; sys.exit(importlib.util.find_spec('PyQt6') is not None)"
      - name: Tests (stdio and HTTP, all tool groups)
        run: python -m pytest -q tests
      - name: Build sdist and wheel
        run: python -m pip install build twine && python -m build && python -m twine check --strict dist/*
"""
    return """name: tests

on:
  push:
  pull_request:

permissions:
  contents: read

jobs:
  test:
    runs-on: ubuntu-24.04
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
      - uses: actions/setup-python@6d4fd22b20465ccc0f7354476588e8df7c9ca0e0 # v7.1.0
        with:
          python-version: "3.12"
      - name: Qt's system libraries
        run: sudo apt-get update && sudo apt-get install -y --no-install-recommends libegl1 libgl1 libxkbcommon0 libfontconfig1 libdbus-1-3 libpulse0
      - name: Install
        run: INSTALL
      - name: Tests
        env:
          QT_QPA_PLATFORM: offscreen
        run: python -m pytest -q tests
      - name: Build sdist and wheel
        run: python -m pip install build && python -m build
""".replace("INSTALL", "python -m pip install --require-hashes -r requirements.lock.txt && "
                       "python -m pip install --no-deps . && python -m pip install pytest"
            if locked else "python -m pip install . pytest") + (GATE_JOB if locked else "")


def _smoke_test(app: App) -> str:
    return f'''"""{app.title} starts, shows its window and ends cleanly."""

import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_happy_the_program_starts_and_ends_cleanly(tmp_path):
    env = dict(os.environ, HOME=str(tmp_path), QT_QPA_PLATFORM="offscreen",
               AXROSS_SMOKE_MS="1500",
               PYTHONPATH=os.pathsep.join([str(ROOT / "src"), os.environ.get("PYTHONPATH", "")]))
    result = subprocess.run([sys.executable, "-m", "{app.package}"], env=env, cwd=tmp_path,
                            capture_output=True, text=True, timeout=120)
    assert result.returncode == 0, result.stderr[-2000:]
    assert "Unhandled exception" not in result.stderr
'''


def _mcp_smoke_test(app: App) -> str:
    return '''"""axross-headless-mcp answers an MCP client over stdio and over HTTP - every tool
group listed, a file read - and PyQt6 is never imported. The installed
package when there is one, else this checkout's src/."""

import importlib.util
import json
import os
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
#: Runs the command in this interpreter and says on stderr whether Qt came in.
PROBE = ("import atexit, sys; atexit.register(lambda: sys.stderr.write("
         "'QT=%s\\\\n' % any(m.split('.')[0] == 'PyQt6' for m in sys.modules))); "
         "from axross_headless_mcp.__main__ import main; sys.exit(main())")
GROUP_TOOLS = {"metadata_read", "duplicates_groups", "pack_formats", "archive_list",
               "index_build", "file_type", "remote_profiles", "agent_run", "extensions_list"}
#: Served only with --mcp-write.
WRITE_TOOLS = {"write_file", "transfer_copy", "pack", "archive_extract", "encrypt"}


def _env(home: Path, **extra) -> dict:
    env = dict(os.environ, HOME=str(home), XDG_CONFIG_HOME=str(home / ".config"),
               XDG_DATA_HOME=str(home / ".local" / "share"), XDG_STATE_HOME=str(home / ".state"),
               XDG_CACHE_HOME=str(home / ".cache"),
               PYTHON_KEYRING_BACKEND="keyring.backends.null.Keyring", **extra)
    if importlib.util.find_spec("axross_headless_mcp") is None:  # not installed: this checkout
        env["PYTHONPATH"] = os.pathsep.join(p for p in (str(ROOT / "src"),
                                                        os.environ.get("PYTHONPATH", "")) if p)
    for name in ("DISPLAY", "WAYLAND_DISPLAY", "QT_QPA_PLATFORM", "AXROSS_MCP_TOOLS"):
        env.pop(name, None)
    return env


def _data(tmp_path: Path) -> Path:
    data = tmp_path / "data"
    data.mkdir()
    (data / "hello.txt").write_text("hello from axross-headless-mcp\\n", encoding="utf-8")
    return data


def test_happy_stdio_initialize_lists_every_group_and_reads_a_file(tmp_path):
    data = _data(tmp_path)
    requests = [
        {"jsonrpc": "2.0", "id": 1, "method": "initialize",
         "params": {"protocolVersion": "2025-11-25", "capabilities": {},
                    "clientInfo": {"name": "smoke", "version": "0"}}},
        {"jsonrpc": "2.0", "method": "notifications/initialized"},
        {"jsonrpc": "2.0", "id": 2, "method": "tools/list"},
        {"jsonrpc": "2.0", "id": 3, "method": "tools/call",
         "params": {"name": "read_file",
                    "arguments": {"path": str(data / "hello.txt"), "encoding": "text"}}},
    ]
    proc = subprocess.run(
        [sys.executable, "-c", PROBE, "--mcp-root", str(data), "--mcp-tools", "all",
         "--mcp-write"],
        input="".join(json.dumps(r) + "\\n" for r in requests), capture_output=True,
        text=True, timeout=120, env=_env(tmp_path), cwd=tmp_path)
    replies = {m.get("id"): m for m in map(json.loads, proc.stdout.splitlines())}
    assert replies[1]["result"]["protocolVersion"] == "2025-11-25", proc.stderr[-2000:]
    names = {t["name"] for t in replies[2]["result"]["tools"]}
    assert GROUP_TOOLS | WRITE_TOOLS <= names, (GROUP_TOOLS | WRITE_TOOLS) - names
    result = replies[3]["result"]
    assert result["isError"] is False
    assert result["structuredContent"]["text"] == "hello from axross-headless-mcp\\n"
    assert "QT=False" in proc.stderr


def test_happy_the_manifest_of_every_group(tmp_path):
    proc = subprocess.run([sys.executable, "-c", PROBE, "--mcp-list-tools", "--mcp-tools", "all"],
                          capture_output=True, text=True, timeout=120, env=_env(tmp_path),
                          cwd=tmp_path)
    assert proc.returncode == 0, proc.stderr[-2000:]
    manifest = json.loads(proc.stdout)
    assert GROUP_TOOLS <= {t["name"] for t in manifest["tools"]}
    assert "QT=False" in proc.stderr


def _free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def _post(url, body, token, session=None, version=None):
    headers = {"Content-Type": "application/json", "Authorization": f"Bearer {token}",
               "Accept": "application/json, text/event-stream"}
    if session:
        headers["Mcp-Session-Id"] = session
    if version:
        headers["MCP-Protocol-Version"] = version
    request = urllib.request.Request(url, data=json.dumps(body).encode(), headers=headers)
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            raw = response.read()
            return response.status, dict(response.headers), json.loads(raw) if raw else None
    except urllib.error.HTTPError as exc:
        return exc.code, dict(exc.headers), None


def test_happy_http_initialize_lists_every_group_and_reads_a_file(tmp_path):
    data = _data(tmp_path)
    port, token = _free_port(), "smoke-token-0123456789"
    proc = subprocess.Popen(
        [sys.executable, "-c", PROBE, "--mcp-http", f"127.0.0.1:{port}", "--mcp-root", str(data),
         "--mcp-tools", "all"], env=_env(tmp_path, AXROSS_MCP_HTTP_TOKEN=token), cwd=tmp_path,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    url = f"http://127.0.0.1:{port}/messages"
    try:
        deadline = time.time() + 60
        while True:
            try:
                urllib.request.urlopen(f"http://127.0.0.1:{port}/health", timeout=2).read()
                break
            except OSError:
                assert proc.poll() is None and time.time() < deadline, "the server did not start"
                time.sleep(0.2)
        status, headers, init = _post(url, {
            "jsonrpc": "2.0", "id": 1, "method": "initialize",
            "params": {"protocolVersion": "2025-06-18", "capabilities": {},
                       "clientInfo": {"name": "smoke", "version": "0"}}}, token)
        assert status == 200 and init["result"]["protocolVersion"] == "2025-06-18"
        session = {k.lower(): v for k, v in headers.items()}["mcp-session-id"]
        status, _h, _b = _post(url, {"jsonrpc": "2.0", "method": "notifications/initialized"},
                               token, session, "2025-06-18")
        assert status == 202
        status, _h, listing = _post(url, {"jsonrpc": "2.0", "id": 2, "method": "tools/list"},
                                    token, session, "2025-06-18")
        assert GROUP_TOOLS <= {t["name"] for t in listing["result"]["tools"]}
        status, _h, read = _post(url, {
            "jsonrpc": "2.0", "id": 3, "method": "tools/call",
            "params": {"name": "read_file",
                       "arguments": {"path": str(data / "hello.txt"), "encoding": "text"}}},
            token, session, "2025-06-18")
        assert read["result"]["structuredContent"]["text"] == "hello from axross-headless-mcp\\n"
        status, _h, _b = _post(url, {"jsonrpc": "2.0", "id": 4, "method": "ping"},
                               token, session, "1999-01-01")
        assert status == 400  # a protocol version the server does not speak
    finally:
        proc.terminate()
        try:
            _out, err = proc.communicate(timeout=30)
        except subprocess.TimeoutExpired:
            proc.kill()
            _out, err = proc.communicate()
    assert "QT=True" not in err
'''


def export(name: str, out: Path) -> Path:
    if name not in APPS:
        raise ExportError(f"export: unknown tool {name!r} (one of {', '.join(APPS)})")
    app = APPS[name]
    if out.exists() and any(out.iterdir()):
        raise ExportError(f"export: {out} is not empty")
    lock = locked_requirements(name)
    files = closure(app)
    pkg = out / "src" / app.package
    ax = pkg / "_ax"
    rewritten = app.layout == "rewrite"
    texts: dict[str, str] = {}
    for rel in files:
        text = STUB_INITS.get(rel) if rewritten else None
        if text is None:
            text = (ROOT / rel).read_text(encoding="utf-8")
            if rewritten:
                text = rewrite_imports(text, app.package)
        texts[rel] = text
    for rel, old, new in app.rewrites:
        if old not in texts.get(rel, ""):
            raise ExportError(f"export: {rel} no longer contains {old!r} - update the rewrites")
        texts[rel] = texts[rel].replace(old, new)
    problems = [p for rel, text in texts.items()
                for p in check_exported(rel, text, app.package, set(files),
                                        rewritten=rewritten, forbid=app.forbid_at_import)]
    if problems:
        raise ExportError("export: " + "\n  ".join(["the tool would break:", *problems]))
    for rel, text in texts.items():
        target = ax / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text, encoding="utf-8")
    (ax / "__init__.py").write_text('"""The axross modules this tool runs on."""\n', encoding="utf-8")
    for pattern in app.data:
        for source in sorted(ROOT.glob(pattern)):
            if source.is_file() and "__pycache__" not in source.parts:
                target = ax / source.relative_to(ROOT)
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(source, target)
    start_module = app.start[:-3].replace("/", ".")
    (pkg / "__init__.py").write_text(f'"""{app.title} (see README.md)."""\n', encoding="utf-8")
    if rewritten:
        main_text = (
            f'"""{app.title}: ``python -m {app.package}`` / ``{app.dist}``."""\n\n'
            "import sys\n\n"
            f"from {app.package}._ax.{start_module} import {app.entry} as main\n\n"
            'if __name__ == "__main__":\n    sys.exit(main())\n')
    else:
        main_text = (
            f'"""{app.title}: ``python -m {app.package}`` / ``{app.dist}``.\n\n'
            "The axross modules keep their names (core, models, security, axross) under\n"
            "_ax/, which goes first on sys.path - only in this process, only when the\n"
            'command starts (importing the package changes nothing)."""\n\n'
            "import sys\n"
            "from pathlib import Path\n\n"
            'AX = str(Path(__file__).resolve().parent / "_ax")\n\n\n'
            "def main() -> int:\n"
            "    if AX not in sys.path:\n"
            "        sys.path.insert(0, AX)\n"
            f"    from {start_module} import {app.entry} as run\n\n"
            "    return run()\n\n\n"
            'if __name__ == "__main__":\n    sys.exit(main())\n')
    (pkg / "__main__.py").write_text(main_text, encoding="utf-8")
    version = app.version or _version()
    (out / "pyproject.toml").write_text(_pyproject(app, version), encoding="utf-8")
    marker = f"{app.readme_marker}\n" if app.readme_marker else ""
    shared = ("its settings are axross's\n(`~/.config/axross`), so both share the "
              "language, the theme and the tool's state.") if app.kind == "qt" else (
              "it reads axross's settings\n(`~/.config/axross`) and axross's saved "
              "connection profiles.")
    origin = (f"It is the same code as in [axross](https://github.com/c0decave/axross), written "
              f"out by\naxross's `scripts/export_standalone.py {name}`; {shared}\n\n")
    install = (f"## Install and run\n\n```sh\npip install {app.dist}      # or, from this folder: "
               f"pip install .\n{app.dist}\n```\n\n{_lock_readme() if lock is not None else ''}")
    tail = f"## Tests\n\n{tests_text(app)}## Licence\n\nApache-2.0, as axross.\n"
    if app.pitch:
        (out / "README.md").write_text(f"{marker}{short_readme(app)}", encoding="utf-8")
        (out / "docs").mkdir(exist_ok=True)
        (out / EXTENDED).write_text(
            f"# {app.dist}: the extended README\n\nEverything on one page; the short version, "
            f"with the screenshots, is the [README](../README.md).\n\n{app.summary}.\n\n"
            f"{app.readme}\n{origin}{install}{tail}", encoding="utf-8")
    else:
        (out / "README.md").write_text(
            f"{marker}# {app.dist}\n\n{app.summary}.\n\n{app.readme}\n{origin}{install}{tail}",
            encoding="utf-8")
    shutil.copyfile(ROOT / "LICENSE", out / "LICENSE")
    if app.repo_files:
        shutil.copytree(ROOT / app.repo_files, out, dirs_exist_ok=True,
                        ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
    (out / ".gitignore").write_text(GITIGNORE, encoding="utf-8")
    workflows = out / ".github" / "workflows"
    workflows.mkdir(parents=True, exist_ok=True)  # repo_files may bring a workflow
    (workflows / "tests.yml").write_text(_workflow(app, lock is not None), encoding="utf-8")
    if lock is not None:
        (out / "requirements.lock.txt").write_text(lock, encoding="utf-8")
        (out / "supply-chain-gate.toml").write_text(GATE_CONFIG.format(name=name, dist=app.dist),
                                                   encoding="utf-8")
        with (out / ".gitignore").open("a", encoding="utf-8") as fh:
            fh.write(".axross/\n.supply-chain-cache/\nsupply-chain-report/\nreduced/\n")
    (out / "tests").mkdir()
    smoke = _smoke_test(app) if app.kind == "qt" else _mcp_smoke_test(app)
    (out / "tests" / "test_smoke.py").write_text(smoke, encoding="utf-8")
    _copy_tests(app, out / "tests")
    return out


#: The conftest of an export with axross's tests: a home of its own for the
#: run (no test writes the user's settings) and the package from src/ (or
#: the installed one) - the tests' imports are renamed as the code's.
TESTS_CONFTEST = '''"""Every test run gets a home of its own; the package is this checkout's src/
when it is not installed."""

import atexit
import os
import shutil
import sys
import tempfile
from pathlib import Path

SRC = Path(__file__).resolve().parents[1] / "src"
if SRC.is_dir() and str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))
    os.environ["PYTHONPATH"] = os.pathsep.join(p for p in (str(SRC), os.environ.get("PYTHONPATH", "")) if p)
_home = tempfile.mkdtemp(prefix="axross-test-home-")
atexit.register(shutil.rmtree, _home, ignore_errors=True)
os.environ["HOME"] = _home
for _name, _sub in (("XDG_CONFIG_HOME", ".config"), ("XDG_DATA_HOME", ".local/share"),
                    ("XDG_CACHE_HOME", ".cache"), ("XDG_STATE_HOME", ".local/state")):
    os.environ[_name] = os.path.join(_home, _sub)
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")


def pytest_collection_modifyitems(config, items):
    """axross's tests of its own export of the tool (test_packaging_*) need axross."""
    import pytest

    for item in items:
        if item.name.startswith("test_packaging_"):
            item.add_marker(pytest.mark.skip(reason="tests axross's export of the tool: run in axross"))
'''


def _copy_tests(app: App, tests: Path) -> None:
    """axross's tests of *app* (App.tests) into the export's *tests*, their
    imports renamed (rewrite_imports), with the data they read and a
    conftest (TESTS_CONFTEST)."""
    if not app.tests:
        return
    for name in app.tests:
        text = (ROOT / "tests" / name).read_text(encoding="utf-8")
        if app.layout == "rewrite":  # (and the module names in its strings: a child's code, a patch's target)
            text = rewrite_string_imports(rewrite_imports(text, app.package), app.package)
        (tests / name).write_text(text, encoding="utf-8")
    for folder in app.test_data:
        shutil.copytree(ROOT / "tests" / folder, tests / folder,
                        ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
    (tests / "__init__.py").write_text("", encoding="utf-8")
    (tests / "conftest.py").write_text(TESTS_CONFTEST, encoding="utf-8")


#: The full README of a tool with a short one (App.pitch).
EXTENDED = "docs/README-extended.md"


def _anchor(heading: str) -> str:
    """GitHub's anchor of a heading."""
    return "#" + re.sub(r"[^\w\- ]", "", heading.strip().lower()).replace(" ", "-")


def short_readme(app: App) -> str:
    """The front page of a tool with punchlines (App.pitch), in the order the
    user's README rule asks: the title, its one-line tagline, the hero
    screenshot, the ten punchlines, the contents (the extended README first),
    the other screenshots - then readme_short, the tests and the licence.
    Images and the extended README by absolute URLs - the README is PyPI's
    description too."""
    if len(app.pitch) != 10 or not all(p.startswith("- **") and "\n" not in p for p in app.pitch):
        raise ExportError(f"export: {app.dist}: the README needs ten one-line punchlines")
    tagline = app.tagline or f"{app.summary}."
    if "\n" in tagline:
        raise ExportError(f"export: {app.dist}: the tagline is one line")
    slug = app.repo.removeprefix("https://github.com/")
    raw = f"https://raw.githubusercontent.com/{slug}/main/"
    extended = f"{app.repo}/blob/main/{EXTENDED}"
    body = app.readme_short.replace("{extended}", extended)
    hero, rest = (app.shots[0], app.shots[1:]) if app.shots else (None, ())
    headings = [*(["Screenshots"] if rest else []), *re.findall(r"^## (.+)$", body, re.M), "Tests", "Licence"]
    contents = [f"- **[Everything in detail: the extended README]({extended})**"]
    contents += [f"  - [{h}]({extended}{_anchor(h)})" for h in re.findall(r"^## (.+)$", app.readme, re.M)]
    if app.repo_files and (ROOT / app.repo_files / "CHANGELOG.md").is_file():
        contents.append(f"- [What changed: the CHANGELOG]({app.repo}/blob/main/CHANGELOG.md)")
    contents += [f"- [{h}]({_anchor(h)})" for h in headings]
    top = f"![{hero[1]}]({raw}{hero[0]})\n\n" if hero else ""
    shots = ""
    pairs, single = rest[:len(rest) // 2 * 2], rest[len(rest) // 2 * 2:]
    rows = []
    for i in range(0, len(pairs), 2):  # two side by side, the captions below
        pair = pairs[i:i + 2]
        rows.append("| " + " | ".join(f"![{c}]({raw}{p})" for p, c in pair) + " |")
        if i == 0:
            rows.append("|:---:|:---:|")
        rows.append("| " + " | ".join(f"*{c}*" for p, c in pair) + " |")
    if rows:
        shots += "\n".join(rows) + "\n\n"
    for path, caption in single:  # an odd one out: full width
        shots += f"![{caption}]({raw}{path})\n\n*{caption}.*\n\n"
    return (f"# {app.dist}\n\n*{tagline}*\n\n{top}" + "\n".join(app.pitch) + "\n\n"
            "## Contents\n\n" + "\n".join(contents) + "\n\n"
            + (f"## Screenshots\n\n{shots}" if shots else "") + f"{body}\n"
            f"## Tests\n\n{tests_text(app)}"
            "## Licence\n\nApache-2.0, as [axross](https://github.com/c0decave/axross): the same "
            f"code, written out by axross's\n`scripts/export_standalone.py`. Everything in detail: "
            f"the [extended README]({extended}).\n")


def tests_text(app: App) -> str:
    """What ``python -m pytest tests`` runs in the export: the start test - and
    axross's own tests of the tool (App.tests), said so."""
    command = "```sh\npython -m pytest tests\n```\n\n"
    if not app.tests:
        return command
    return (command + f"The tool's own tests from axross - {len(app.tests)} files, their imports renamed as the "
            "code's - and a test that the program starts and ends cleanly; Qt's offscreen platform, no "
            "display needed.\n\n")


def _lock_readme() -> str:
    return ("## The exact, reviewed dependencies\n\n"
            "`requirements.lock.txt` pins every dependency (extras included) to one version and the\n"
            "SHA-256 of its files. Each pin passed axross's supply-chain gate - PyPI, OSV advisories\n"
            "and malicious-package entries, a minimum age of 14 days, typosquatting, provenance, and a\n"
            "review of the files' content recorded in axross's baseline - and the CI runs the gate\n"
            "again on every push (`supply-chain-gate.toml`). To install exactly those files:\n\n"
            "```sh\npip install --require-hashes -r requirements.lock.txt\npip install --no-deps .\n```\n\n")


def _version() -> str:
    text = (ROOT / "axross" / "_version.py").read_text(encoding="utf-8")
    match = re.search(r'__version__ = "([^"]+)"', text)
    if not match:
        raise ExportError("export: no version in axross/_version.py")
    return match.group(1)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--requirements", action="store_true",
                    help="print what the exported project installs (the input of its lock) and stop")
    ap.add_argument("app", choices=sorted(APPS))
    ap.add_argument("out", type=Path, nargs="?", help="an empty or new folder")
    args = ap.parse_args(argv)
    if args.requirements:
        sys.stdout.write(requirements_in(APPS[args.app]))
        return 0
    if args.out is None:
        ap.error("OUT is needed")
    out = export(args.app, args.out)
    app = APPS[args.app]
    print(f"{app.dist} written to {out}: cd {out} && python -m pytest tests && pip install .")
    return 0


if __name__ == "__main__":
    sys.exit(main())
