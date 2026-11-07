# axross's tools as programs of their own

The **Media Player** and **System Information** live inside axross and are
also programs of their own: `axross-media-player` and `axross-system-info`.
Same code, same settings (`~/.config/axross`: the player's list and position,
the language, the theme, the window sizes) - the program and axross's panel
share them.

| Program | What it does on its own |
|---|---|
| `axross-media-player [FILE\|FOLDER\|URL ...]` | local files, folders, M3U playlists and internet radio (http / https); equalizer, visualizations, shuffle and repeat. Files on axross's remote connections stay a feature of axross. |
| `axross-system-info` | the hardware dashboard with live gauges, search, copy, text and JSON report |
| `axross-system-info --json FILE` | writes the JSON report (identifiers hidden) and quits - for scripts |

## Where they come from

Each release carries them next to axross (`scripts/build_dist.sh`):

- `glibc-2.34/axross-media-player`, `glibc-2.34/axross-system-info` and the
  same under `glibc-2.36/` - one-file binaries, built like axross's own from the
  venv the supply-chain gate checked, with the target system's libraries;
- `standalone/axross-media-player-VERSION.tar.gz` / `.whl` and the same for
  `axross-system-info` - `pip install` them (PyQt6, and numpy for the player).

## How they are made

`scripts/export_standalone.py media-player|system-info OUT` writes the tool as
a project of its own: `src/axross_media_player/_ax/` holds the axross modules it
runs on with every import rewritten to the new package, the interface
languages, a `pyproject.toml` with its command, a README and a start test.
Which modules go along is worked out from the imports, not listed by hand:
everything the start module (`ui/media_player_app.py`, `ui/system_info_app.py`)
imports at module level, followed through every module, plus the modules it
imports later that it needs (`LAZY` in the script). Every other late import
must be guarded (`try` / `except ImportError`) or the export stops - a program
of its own must not fail when a menu reaches a part of axross it does not carry.

`scripts/build_bundle.sh media-player|system-info` exports into its scratch
folder and runs PyInstaller with `build/standalone.spec` on the exported
project (PyInstaller follows imports inside functions; on the axross tree it
would pull in the whole application). Its checks: the program starts, shows its
window and ends by itself (`AXROSS_SMOKE_MS`), `axross-system-info --json`
writes a report, and every system library the binary needs is bundled or one
the target system provides.

`scripts/build_dist.sh --only standalone` builds just the two tools (sdists,
wheels, binaries of every variant); `--standalone none` leaves them out.

Tests: `tests/test_standalone_apps.py` (the start modules),
`tests/test_export_standalone.py` (the export: no import left that reaches into
the rest of axross, nothing unguarded, the exported program starts with only its
own folder on the path).
