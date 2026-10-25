# axross slideshow

Every screenshot of axross, each with what it shows. Back to the [README](README.md).

## Upload to SFTP

![Upload from a local pane to SFTP with the Transfers dock](docs/screenshots/remote-transfer.png)

Four photos copied from the local pane to the NAS; the Transfers dock lists each file with its direction, size and status.

## Workspaces

![Workspaces as tabs, a file pane and a local shell side by side](docs/screenshots/workspaces.png)

Named pane layouts as tabs - here **Website** with its file pane and a local shell next to it. A workspace detaches into a window of its own and comes back as a tab.

## Toolbar

![The toolbar with an icon per tool above two panes and the bookmark sidebar](docs/screenshots/toolbar.png)

One button per tool - Agent, Analysis (sift), Terminal, Find Files, Scripts, Python console, Tags, Trash, Media Player, Audio & Video Settings, Treemap, Drives, Settings, Features. On a narrow window the tools move to a second row instead of disappearing. The buttons are grouped by category - Connections, Windows & Panes, Files & Search, Media, LLM & Agent, Tools & System, Extensions - with a separator between the groups, and each category's colour is a subtle tint behind its buttons that never makes an icon hard to read. Drag a button along its bar to move it inside its group; the order is kept, and the toolbar's right-click menu has Reset Toolbar Order. Edit → Settings… → Toolbar switches grouping and colours off and sets each category's colour.

## Tags

![The Tagged Files window listing the files of one tag](docs/screenshots/tags.png)

Coloured dots in the Name column; **Tagged Files** lists every tag and its files on any backend, **Go to File** opens the folder in a pane.

## Text editor

![The tabbed text editor with Python highlighting and the find bar](docs/screenshots/editor.png)

Tabs for local and remote files, Pygments highlighting, find and replace with regex, encoding and line endings in the status bar.

## Find Files

![Find Files with type presets and results from several folders](docs/screenshots/find-files.png)

Name, content, size, date, tag and type presets, inside archives too; the search is kept as a **Smart Folder** with one click.

## Media Player

![The Media Player panel with cover, spectrum, equalizer and playlist](docs/screenshots/media-player.png)

An extension panel: cover and title, an animated spectrum, a 10-band equalizer with presets, and a playlist filled by drag & drop.

## Disk images

![The partitions of a disk image, ready for a read-only mount](docs/screenshots/disk-image.png)

The partitions and file systems of an image, read without writing anything; **Mount Read-Only** puts one into a pane.

## Voice

![Settings, Voice page: spoken answers, push-to-talk and the hold key](docs/screenshots/voice.png)

Spoken answers in German or English, a voice per language with its speed, pitch, expressiveness, volume and pause (Listen plays a sample), push-to-talk on a hold key, and where the recognised text goes.

## Bookmarks

![Manage Bookmarks with groups, a terminal bookmark and remote locations](docs/screenshots/bookmarks.png)

Groups, local and remote locations and a terminal bookmark in one manager; sort, move and edit several at once.

## Settings

![Edit, Settings: every setting in one dialog with a search field](docs/screenshots/settings.png)

Every setting in one dialog, with a search field.

## Features

![Help, Features: what is installed, what is missing and how to get it](docs/screenshots/features.png)

What is installed and what is missing, with the command or the download that adds it.

## Amber Mode

![The quad-files layout preset in Amber Mode](docs/screenshots/quad-files.png)

The `quad-files` layout preset: four panes, each with its own path bar, filter, permissions and owner columns. `Ctrl+Alt+L` cycles through the presets.

## Scripts dock

![The Scripts dock with a user script](docs/screenshots/scripts-panel.png)

Your own scripts next to the read-only examples, written against the `axross.*` API; run them in the dock or in the Console.

## Duplicate Finder

![The Duplicate Finder with two groups](docs/screenshots/duplicate-finder.png)

Identical files by content hash, grouped; the oldest copy of each group is shown in bold.

## Metadata

![Metadata of a photo with EXIF and GPS data](docs/screenshots/metadata.png)

EXIF fields and the GPS position of a photo; **Remove Metadata** strips them before you share it — in place, or as a cleaned copy (**Tools → Metadata Settings…**).

## Analysis dock (sift)

![The Analysis dock explaining a CSV file](docs/screenshots/analysis.png)

The optional `sift` extra explains the selected file — here a CSV, without any LLM. Start it with right-click → **Analyse with sift** (a folder: **Analyse Folder with sift**), **Tools → Analyse with sift** or `Ctrl+Shift+I`; its toolbar button and title bar show sift's sieve. Edit → Settings… → Analysis (sift) switches the automatic analysis off and sets sift's read limit, time budget, vision, context, tags, categories, the cache (with *Clear Cache*) and an LLM profile of its own.

## Modern light theme

![Two panes in the thumbnail view, light theme](docs/screenshots/thumbnails.png)

Two panes in the thumbnail view in the Modern light theme. Pictures, videos and PDFs show a preview tile, folders their icon; View → Thumbnail View (Ctrl+Shift+G) switches a pane between list and tiles, and the theme follows the desktop's light or dark scheme.

## Log dock

![The Log dock after a copy and a move](docs/screenshots/log-dock.png)

Every copy and move is logged with its integrity check (sha256) and an entry in the operation journal.

## Topics

![The Topics menu of an Agent tab](docs/screenshots/agent-topics.png)

Ready-made tasks — inventory, services, logs, disk usage, a folder summary — fill the request for you; each tab is its own session.

## A pane's connection, lent to the agent

![The agent reads a file of a remote pane](docs/screenshots/agent-remote-pane.png)

The left pane is connected to a remote store; the agent reads `/reports/q3.txt` through it, without its own login.

## Sandbox profiles

![Agent Settings, Sandboxes page](docs/screenshots/agent-sandboxes.png)

Engine (bubblewrap, podman, docker), level from `lax` to `paranoid`, allowed hosts and extra folders — applied before every task.

## Access per tab

![The Access dialog of one Agent tab](docs/screenshots/agent-access.png)

Which axross functions the agent may use, which hosts it may reach and which folders it sees, read-only or writable.

## MCP servers

![Agent Settings, MCP Servers page](docs/screenshots/agent-mcp-servers.png)

Further MCP servers for the agent — here axross itself over stdio, tested: 11 tools.

## Agent Stats

![The Agent Stats window over the main window](docs/screenshots/agent-stats.png)

The bundled extension counts tasks, tool calls, errors and tokens, for all tabs and the last one.

## Agent profiles

![The Agent dock's + menu with New Tab from Profile and the seven presets](docs/screenshots/agent-profiles.png)

The arrow next to **+** opens a new Agent tab from a profile - seven presets (Files Assistant, Reverse Engineering, Forensics read-only, Network & Web Recon, Code & Secrets, Remote Ops, Research) or your own. The tab names its profile and what is still missing, with **Install from Catalog…**.

## Profiles page

![Settings, Agent, Profiles: the Reverse Engineering preset and what a tab gets](docs/screenshots/agent-profile-settings.png)

A profile bundles LLM, prompt profile, protection mode, sandbox, tool groups, axross functions and MCP servers by category or name. Presets are read-only, **Copy** makes an editable one, and the preview shows what a tab gets within the Access page.

## MCP catalog

![Add MCP Server from Catalog with the servers of the c0decave MCP Hub](docs/screenshots/mcp-catalog.png)

The c0decave MCP Hub adds 17 security tools - binwalk, capa, Nmap, YARA, The Sleuth Kit and more - as images pinned by digest; each runs in podman without capabilities, with a read-only root and no network unless you allow it. A third-party entry such as REA says who maintains it.

## Cut and Paste

![Two files cut in one pane, Paste at the top of the other pane's right-click menu](docs/screenshots/cut-paste.png)

Ctrl+X or right-click **Cut** only marks the files (dimmed); **Paste** in any pane moves them through the transfer queue, and each source is removed only after its copy completed and was checked. Esc clears the filter.

## Icon colours

![Amber Mode with every icon in its own colour and Settings, Appearance](docs/screenshots/icon-colours.png)

**Settings → Appearance → Icon colours**: the theme default, own colours in every theme - here in Amber Mode, whose default draws every icon in amber - or one colour of your own.

## Self-update

![Software Update: a newer axross is available, with Download and Install](docs/screenshots/update.png)

`axross-full` and `axross-slim` look for a new release once per start, show **Update to …** in the status bar and replace themselves after the SHA-256 check; the old binary is kept.

## Examples run directly

![The Scripts dock runs the bundled du example with a call to adjust](docs/screenshots/scripts-example.png)

**Run** on a bundled example shows its Usage call to adjust - paths, hosts, profiles - and runs it; the output appears below.

## Third-party software

![Help, Third-Party Software: the projects axross uses or ships, with licences](docs/screenshots/third-party.png)

**Help → Third-Party Software…** lists the 222 projects axross uses or ships, with purpose, licence, how each reaches you and a link.
