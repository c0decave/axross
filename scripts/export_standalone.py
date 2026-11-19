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
    #: (directory listings: glama.json, llms-install.md, docs/assets/logo.png)
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
              "ui/off_gui.py", "core/connect_worker.py", "core/connect_notice.py"),
        version="0.16.0",
        readme="""\
A Markdown file rendered in a window of its own - or in the terminal. The full set:
CommonMark, GitHub's tables (aligned as written), task lists, strike-through and
autolinks, footnotes, definition lists, YAML / TOML front matter; the headings as an
outline beside the text, fenced code coloured by Pygments, the images beside the file
(clickable when linked), colours for light and dark themes, find (Ctrl+F), zoom
(Ctrl + / - / 0), Reload (F5). Edit (F4) opens an editor with the rendering beside the text, following the
typing. A link to another Markdown file opens it; a web link opens in the browser only
after a question that shows its real address.

What a file holds is shown, never run: raw HTML is kept to a safe subset (no scripts,
styles, frames, forms or event handlers - what is left of it shown as its text), nothing is loaded from
the network (a remote image is a box naming its address), images are read only relative
to the file - regular files, never a secret file such as an SSH key, bounded in size,
pixels and count; an SVG that names other files is not shown.

```sh
axross-markdown README.md docs/*.md     # a window for each
axross-markdown                         # a window with Open... (Ctrl+O)
axross-mdcat README.md                  # in the terminal, in colour (no Qt needed)
axross-mdcat --toc README.md            # the headings only
cat notes.md | axross-mdcat -
```

In the terminal: headings, emphasis, inline and fenced code (coloured), quotes, nested
and task lists, tables drawn with box characters (wrapped to fit), definition lists and
footnotes; links are terminal hyperlinks (OSC 8) with their address beside them;
images are drawn with kitty's or iTerm2's picture protocol where the terminal has one,
else in coloured half-blocks. Colours follow NO_COLOR / FORCE_COLOR / COLORTERM
(`--color`), the theme the background (`--theme`), long texts go through `less -R`
(`--no-pager`). Nothing in a file can send the terminal an escape sequence of its own.

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
        exclude=("ui/", "main.py"),
        forbid_at_import=("PyQt6",),
        data=("resources/i18n/*.json", "resources/mcp/*.json", "resources/wordlists/*.txt",
              "resources/scripts/*.py", "resources/scripts/*.md",
              "resources/extensions/*.py", "resources/extensions/*.json",
              "resources/extensions/*.md"),
        package_data=("*.json", "*.txt", "*.md", "*.py"),
        gui=False,
        readme_marker="<!-- mcp-name: io.github.c0decave/axross-headless-mcp -->",
        kind="mcp",
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
    (out / "README.md").write_text(
        f"{marker}# {app.dist}\n\n{app.summary}.\n\n{app.readme}\n"
        "It is the same code as in [axross](https://github.com/c0decave/axross), written out by\n"
        f"axross's `scripts/export_standalone.py {name}`; {shared}\n\n"
        f"## Install and run\n\n```sh\npip install {app.dist}      # or, from this folder: pip install .\n"
        f"{app.dist}\n```\n\n{_lock_readme() if lock is not None else ''}"
        "## Tests\n\n```sh\npython -m pytest tests\n```\n\n"
        "## Licence\n\nApache-2.0, as axross.\n", encoding="utf-8")
    shutil.copyfile(ROOT / "LICENSE", out / "LICENSE")
    if app.repo_files:
        shutil.copytree(ROOT / app.repo_files, out, dirs_exist_ok=True,
                        ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
    (out / ".gitignore").write_text(GITIGNORE, encoding="utf-8")
    workflows = out / ".github" / "workflows"
    workflows.mkdir(parents=True)
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
    return out


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
