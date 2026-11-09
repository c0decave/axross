"""The tours of Help > Tours…: data only (ui.tour_engine runs them).

Each step names the widget it explains - by objectName (several: the first
one on screen wins, a toolbar button before the menu entry) or by a
function of the window - a title and a text. The text says how to use the
part *well*, and only what the code does: tests/test_tours.py holds every
step to a default window, and the claims follow docs/USAGE.md (the
sections named in the comments). Adding a tour is adding a :class:`Tour`
to :data:`TOURS`.

The texts go through tr() when they are shown (core.i18n); the German
catalogue has the tour names, their summaries and the step titles.
"""

from __future__ import annotations

from PyQt6.QtCore import QPoint, QRect
from PyQt6.QtWidgets import QWidget

from ui.tour_engine import Tour, TourStep


def _in_active_pane(name: str):
    """The widget *name* of the active file pane."""
    def find(window):
        pane = getattr(window, "_active_pane", None)
        return pane.findChild(QWidget, name) if pane is not None else None

    return find


def _active_pane(window):
    return getattr(window, "_active_pane", None)


def _panes(window):
    """The panes of the workspace shown (the two panes of a first start)."""
    return window.findChild(QWidget, "workspaceTabs")


def _other_panes(window) -> list:
    """The panes beside the active one in its window, the target pane first."""
    active = getattr(window, "_active_pane", None)
    target = getattr(window, "_target_pane", None)
    others = [p for p in getattr(window, "_panes", ())
              if p is not active and p.isVisible() and p.window() is window]
    if target in others:
        others.remove(target)
        others.insert(0, target)
    return others


def _target_button(window):
    """The ◎ button of the target pane (another pane than the active one):
    ◎ on the active pane - the source - cannot make it the target, and the
    tours pointed there. With one pane only: that pane."""
    for pane in _other_panes(window):
        button = pane.findChild(QWidget, "axPaneTarget")
        if button is not None and button.isVisible():
            return button
    return _active_pane(window)


def _source_and_target(window):
    """The active pane and the target pane together, as one area."""
    panes = [p for p in (_active_pane(window), *_other_panes(window)[:1])
             if p is not None and p.isVisible() and p.window() is window]
    if not panes:
        return None
    area = QRect()
    for pane in panes:
        area = area.united(QRect(pane.mapTo(window, QPoint(0, 0)), pane.size()))
    return window, area


def _agent_mode(window):
    dock = getattr(window, "_agent_dock", None)
    tab = dock.current_tab() if dock is not None else None
    return tab.mode_combo if tab is not None else None


# USAGE.md: Multi-pane layout, Path bar, Connections, Transfers.
GETTING_STARTED = Tour(
    "getting-started",
    "Getting started",
    "The two panes, the address bar, connecting, copying between panes, the transfer "
    "queue and Undo.",
    (
        TourStep(
            "Panes side by side",
            "Each pane shows one folder on its own connection – local files, SFTP, SMB, S3 "
            "or any other. Ctrl+Shift+H and Ctrl+Shift+V split the active pane, Ctrl+W "
            "closes it; Tab and Shift+Tab in a file list move to the next pane.",
            _panes,
        ),
        TourStep(
            "Source and target",
            "The active pane is the source: a blue border, and SOURCE in its header. The "
            "target pane has a green border and TARGET: F5 copies the selection there, F6 "
            "moves it there. A click into a pane makes it the source and the pane you were "
            "in the target; ◎ in another pane's header makes that pane the target. Look "
            "for TARGET before you press F5.",
            _target_button,
            frame=_source_and_target,
        ),
        TourStep(
            "The address bar",
            "Type a path and press Enter to go there. ↑ goes up, ⌂ home, ☆ bookmarks the "
            "folder, ↻ reloads it and ◉ reloads by itself when the folder changes (on for "
            "local folders). The filter field below it (Ctrl+F) narrows the list as you "
            "type; Esc clears it.",
            _in_active_pane("axPathEdit"),
        ),
        TourStep(
            "Connect to a server",
            "Connection Manager (Ctrl+Shift+N) makes a profile – protocol, host, login, "
            "proxy – and connects; Quick Connect (Ctrl+N) opens a saved profile at once. "
            "Each connection opens in a pane of its own, so a server and your local files "
            "sit side by side.",
            ("axToolbarConnectionManager", "axConnectionManagerAction"),
        ),
        TourStep(
            "Copy between panes",
            "Select files and press F5 (Copy to Target) or F6 (Move to Target), or drag "
            "them onto the other pane – a drag moves, with Ctrl it copies. Before anything "
            "is queued, axross asks about every name that already exists: overwrite, "
            "overwrite if newer, skip or rename. Nothing is replaced without your answer.",
            "axCopyToTargetAction",
        ),
        TourStep(
            "The transfer queue",
            "Every copy and move runs here in the background, with progress, speed and the "
            "time left – you can keep working, even close the pane. Retry Failed resumes "
            "what failed, Cancel All stops the queue, and a right click on a job offers "
            "Cancel, Retry and Open destination folder.",
            "axTransferDock",
        ),
        TourStep(
            "Undo",
            "Edit → Undo Last Operation (Ctrl+Z) reverses the newest move or Move to Trash "
            "whose connection is open. A copy cannot be undone, and Undo says so instead of "
            "guessing – so when in doubt, move to the trash rather than delete.",
            "axUndoAction",
        ),
    ),
)

# USAGE.md: Connections, Keyring auto-detect & re-detect; PROXY_SUPPORT.md.
CONNECT = Tour(
    "connect",
    "Connect to a server",
    "Profiles, saved passwords and the keyring, how a connection is protected, proxies.",
    (
        TourStep(
            "Quick Connect",
            "Ctrl+N lists your saved profiles; a click connects. A right click on a profile "
            "offers Delete Connection Config…, which removes the profile together with its "
            "stored password.",
            ("axToolbarQuickConnect", "axQuickConnectAction"),
        ),
        TourStep(
            "Profiles",
            "Connection Manager (Ctrl+Shift+N) makes and edits profiles: pick the protocol, "
            "fill in host and user, choose a password, an SSH key file or the SSH agent, "
            "give it a name and Save. Tick Production for a server where a slip costs "
            "something: the first delete, move or overwrite then waits with a countdown "
            "that Esc stops.",
            ("axToolbarConnectionManager", "axConnectionManagerAction"),
        ),
        TourStep(
            "Passwords go to the keyring",
            "Save in keyring stores the password in the system keyring (Secret Service, "
            "KWallet, KeePassXC, the macOS Keychain or the Windows Credential Locker); the "
            "profile file never holds it. No keyring found? Install one, for example "
            "gnome-keyring, then File → Re-detect System Keyring.",
            "axReDetectKeyringAction",
        ),
        TourStep(
            "How the connection is protected",
            "The icon at the left of a pane's header says how its connection is protected – "
            "cleartext, signed only, TLS, SSH or end-to-end; its tooltip says whether that "
            "was negotiated or only configured. The first SSH connection to a host shows "
            "its key fingerprint: compare it with the server's before you trust it.",
            _in_active_pane("axSecurityBadge"),
            optional=True,
        ),
        TourStep(
            "Proxies",
            "Tools → Network & Proxy… (also Edit → Settings… → Network & Proxy) sets the "
            "default proxy – SOCKS5, SOCKS4, HTTP CONNECT or HTTPS – with a bypass list and a "
            "PAC script; Test proxy says which stage fails. A profile uses it or a proxy of "
            "its own (Proxy Settings in Connection Manager). A connection that cannot go "
            "through the proxy fails instead of going direct.",
            "axNetworkProxyAction",
        ),
    ),
)

# USAGE.md: Transfers, Right-click actions (Move to Trash, Show Trash…), Compare.
COPY_SAFELY = Tour(
    "copy-safely",
    "Copy and sync safely",
    "The target pane, conflicts, resume, Compare Panes, the trash and Undo.",
    (
        TourStep(
            "Check the target first",
            "F5 and F6 go to the pane marked TARGET, with the green border; the pane you work "
            "in is marked SOURCE. ◎ in another pane's header makes that pane the target – "
            "set it before you copy, and the files land where you meant them to. One pane "
            "only? Split it first (Ctrl+Shift+H).",
            _target_button,
            frame=_source_and_target,
        ),
        TourStep(
            "Conflicts are asked, not guessed",
            "The destination is checked before anything is queued. For each name already "
            "there you choose Overwrite, Overwrite if Newer, Skip or Rename (name (1).ext), "
            "optionally for all; Cancel copies nothing. A move removes its source only "
            "after its copy completed and was checked.",
            "axCopyToTargetAction",
        ),
        TourStep(
            "Resume instead of starting over",
            "Every file is written under a hidden temporary name and renamed into place at "
            "the end, so a broken transfer never leaves half a file under the real name. "
            "Retry Failed resumes failed and cancelled transfers from the bytes already "
            "there.",
            "axTransferRetry",
        ),
        TourStep(
            "Compare before you sync",
            "View → Compare Panes… compares the active pane's folder with the target pane's. "
            "Identical files are hidden; a file on one side only can be copied over. Sync… "
            "shows exactly what it would do before it does anything, and On conflict starts "
            "at Ask me (nothing is overwritten).",
            "axCompareAction",
        ),
        TourStep(
            "The trash first",
            "Del moves the selection to the trash, and Show Trash… restores from it. Delete "
            "Permanently (Shift+Del) counts first, asks with No as the default, and asks "
            "again when hidden files are inside. Use the trash for anything you might want "
            "back.",
            "axTrashAction",
        ),
        TourStep(
            "Undo",
            "Ctrl+Z reverses the newest move or Move to Trash whose connection is open; a "
            "copy is reported as not reversible instead of being guessed at.",
            "axUndoAction",
        ),
    ),
)

# USAGE.md: Find Files, Right-click actions (Tags), Path bar (bookmarks), Workspaces.
FIND_ORGANIZE = Tour(
    "find-organize",
    "Find and organize",
    "Find Files, the live filter, tags, bookmarks and workspaces.",
    (
        TourStep(
            "Find Files",
            "Edit → Find Files… (Alt+F7) searches folders on every open connection at once – "
            "by name, type, content, size and date, also inside archives. Results stream in "
            "while it runs; Save as Smart Folder… keeps the search in the bookmarks.",
            "axFindFilesAction",
        ),
        TourStep(
            "The live filter",
            "Ctrl+F filters the folder you are in as you type – the quickest way to a file "
            "you can see. tag:<name> shows only the files with that tag.",
            _in_active_pane("axPaneFilter"),
        ),
        TourStep(
            "Tags",
            "Right click → Tags marks files on any connection with a coloured tag (Important, "
            "Review later, or a new one). View → Tagged Files… lists the files of every tag "
            "and goes to them. Tags follow files you move in axross.",
            "axTaggedFilesAction",
        ),
        TourStep(
            "Bookmarks",
            "F8 bookmarks the folder you are in (☆ in the address bar does too), F12 shows "
            "or hides this sidebar. Group bookmarks, drag folders in, and drop files onto a "
            "bookmark to move them there (Ctrl copies). A remote bookmark keeps its "
            "connection profile.",
            "BookmarkSidebar",
            # a first start on a small screen hides the empty sidebar (UX
            # round 7): the step opens it instead of being skipped
            reveal=True,
        ),
        TourStep(
            "Workspaces",
            "A workspace is a pane layout of its own: Workspace → New Workspace (Ctrl+Alt+N) "
            "opens one, Ctrl+Alt+PgDown and PgUp switch between them. Keep one per job – a "
            "server, a project – each with its own source and target pane; Detach to Window "
            "puts one on another screen.",
            "axWorkspaceMenu",
        ),
    ),
)

# USAGE.md: Agent dock, Scripting & embedded REPL, MCP server; SCRIPTING.md.
AUTOMATE = Tour(
    "automate",
    "Automate",
    "The Agent dock and its protection modes, scripts, the console and MCP.",
    (
        TourStep(
            "The Agent",
            "A local LLM – LM Studio, Ollama, vLLM, llama.cpp or any OpenAI-compatible "
            "server – works with axross's file tools in the folder shown at the top of its "
            "tab. Choose the LLM profile first; a server that is not on this machine or its "
            "network asks before the first task. View → Panels → Agent shows or hides it.",
            "axAgentDock",
            reveal=True,
        ),
        TourStep(
            "Protection modes",
            "Each tab has its mode: Ask (every change waits for your yes), Plan (it only "
            "reads and writes a plan), Auto (changes run, remote commands still ask). Start "
            "with Ask or Plan; Bypass must be switched on in Agent Settings first.",
            _agent_mode,
            optional=True,
            reveal=True,
        ),
        TourStep(
            "Scripts",
            "Write Python against axross.* and save it here; Run starts the script in its "
            "own process and Stop ends it. Help → Scripting Guide has the API; axross "
            "--script FILE runs a script without the window, View → Scheduled Jobs… on an "
            "interval.",
            "axScriptsDock",
            reveal=True,
        ),
        TourStep(
            "The console",
            "A Python prompt with axross ready – axross.help() lists what there is. .run "
            "<name> runs a saved script here, and the variables it sets stay at the prompt.",
            "axConsoleDock",
            reveal=True,
        ),
        TourStep(
            "MCP",
            "axross --mcp-server lets an LLM client such as Claude Desktop or Cline use your "
            "connections as MCP tools – read-only, unless --mcp-write adds the write tools, "
            "kept to one folder. Tools → MCP Servers… is the other direction: MCP servers "
            "whose tools the Agent may use.",
            "axMcpServersAction",
        ),
    ),
)

# USAGE.md: Connections (Missing features), Updates (packs); EXTENSIONS.md.
EXTENSIONS = Tour(
    "extensions",
    "Extensions and features",
    "The Features window, packs, extensions and where every setting is.",
    (
        TourStep(
            "Features",
            "Help → Features… lists every optional part – protocols, file analysis, "
            "archives, tools such as ripgrep or rsync – as installed or missing, and how to "
            "get it. Install Selected names the pip command before it runs; a one-file build "
            "links its axross-full download instead.",
            "axFeaturesAction",
        ),
        TourStep(
            "Packs",
            "In a one-file build, Features… → Packs… adds or removes signed units of this release "
            "– a protocol, an extension, voice. The release's signature, the pack list and every "
            "file's SHA-256 are checked before anything is unpacked; a pure-Python unit is ready "
            "at once, others after the next start.",
            "axHelpMenu",
        ),
        TourStep(
            "Extensions",
            "Extensions are Python plugins and run with your rights, so every one starts "
            "switched off. Extensions → Manage Extensions… switches them on (and off); the "
            "paranoid security mode loads none.",
            "axManageExtensionsAction",
        ),
        TourStep(
            "Your own extensions",
            "Extensions → Open Extensions Folder opens ~/.config/axross/extensions/: a "
            "<name>.py there appears in the manager as user:<name>. Reload Extensions runs "
            "the current source again; an extension that hangs a start is skipped at the "
            "next one.",
            "axExtensionsMenu",
        ),
        TourStep(
            "Settings and help",
            "Edit → Settings… (Ctrl+,) holds every setting; the field above the list finds "
            "one by name. F1 opens the handbook at the part of the window you are in – also "
            "on a settings page.",
            "axSettingsAction",
        ),
    ),
)

#: Help > Tours…, in this order.
TOURS: tuple[Tour, ...] = (GETTING_STARTED, CONNECT, COPY_SAFELY, FIND_ORGANIZE, AUTOMATE,
                           EXTENSIONS)
#: The tour the first start offers.
FIRST_TOUR = GETTING_STARTED.id


def tour(tour_id: str) -> Tour | None:
    return next((t for t in TOURS if t.id == tour_id), None)


__all__ = ["FIRST_TOUR", "TOURS", "tour"]
