"""Create and verify SHA256SUMS manifests, on any backend."""

from __future__ import annotations

import hashlib
import posixpath

EXTENSION = {
    "name": "Checksum Manifest",
    "version": "1.0",
    "description": "Right-click: write a SHA256SUMS file for the selected files (or the "
    "folder), and verify one - in sha256sum format, on local and remote folders.",
    "author": "axross",
}

MANIFEST_NAME = "SHA256SUMS"
CHUNK = 1024 * 1024
#: A manifest line longer than this is ignored as garbage.
MAX_LINE = 4096


def sha256_of(backend, path: str) -> str:
    digest = hashlib.sha256()
    with backend.open_read(path) as fh:
        while True:
            chunk = fh.read(CHUNK)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


#: What sha256sum escapes in a name (and then starts the line with a backslash).
_ESCAPES = {"\\": "\\\\", "\n": "\\n", "\r": "\\r"}
_UNESCAPES = {"\\": "\\", "n": "\n", "r": "\r"}
_HEX = frozenset("0123456789abcdef")


def manifest_line(digest: str, name: str) -> str:
    """One line as GNU sha256sum writes it: ``<sha256>  <name>``, and for a
    name with a backslash, newline or carriage return those escaped
    (``\\\\``, ``\\n``, ``\\r``) and a backslash in front of the line."""
    if any(c in name for c in _ESCAPES):
        return "\\" + digest + "  " + "".join(_ESCAPES.get(c, c) for c in name)
    return f"{digest}  {name}"


def manifest_text(backend, folder: str, names: list[str]) -> str:
    """``<sha256>  <name>`` lines for *names* in *folder*, sorted."""
    lines = []
    for name in sorted(names):
        lines.append(manifest_line(sha256_of(backend, backend.join(folder, name)), name))
    return "\n".join(lines) + ("\n" if lines else "")


def _unescape(name: str) -> str | None:
    out = []
    chars = iter(name)
    for c in chars:
        if c != "\\":
            out.append(c)
            continue
        plain = _UNESCAPES.get(next(chars, ""))
        if plain is None:  # a lone or unknown escape: sha256sum refuses the line too
            return None
        out.append(plain)
    return "".join(out)


def parse_line(line: str) -> tuple[str, str] | None:
    """``(sha256, name)`` of one manifest line, None when it does not parse
    or its name leaves the folder (``../x``, ``/etc/x``). The name is taken
    exactly as written: sha256sum's ``<hash>  <name>`` (text) or
    ``<hash> *<name>`` (binary), its escaped form (``\\<hash>  a\\\\b``),
    trailing spaces, a leading ``*`` and backslashes in a plain name kept."""
    if line.endswith("\r"):
        line = line[:-1]  # a manifest saved with CRLF line ends
    if len(line) > MAX_LINE:
        return None
    line = line.lstrip(" \t")
    escaped = line.startswith("\\")
    if escaped:
        line = line[1:]
    digest, sep, name = line[:64].lower(), line[64:66], line[66:]
    if len(digest) != 64 or not _HEX.issuperset(digest) or sep not in ("  ", " *"):
        return None
    if escaped:
        name = _unescape(name)
        if name is None:
            return None
    if not name or "\0" in name:
        return None
    norm = posixpath.normpath(name)
    if norm.startswith(("../", "/")) or norm in ("..", ".", ""):
        return None
    return digest, norm


def read_manifest(text: str) -> tuple[list[tuple[str, str]], list[int]]:
    """``(sha256, name)`` pairs and the numbers of the lines that did not
    parse (empty lines are no error)."""
    pairs, bad = [], []
    lines = text.split("\n")
    if lines and lines[-1] == "":
        lines.pop()
    for number, line in enumerate(lines, 1):
        if not line.strip():
            continue
        pair = parse_line(line)
        if pair is None:
            bad.append(number)
        else:
            pairs.append(pair)
    return pairs, bad


def parse_manifest(text: str) -> list[tuple[str, str]]:
    """``(sha256, name)`` pairs; malformed lines and names that leave the
    folder (``../x``, ``/etc/x``) are left out (:func:`read_manifest`
    tells which)."""
    return read_manifest(text)[0]


def verify(backend, folder: str, text: str) -> dict[str, list[str]]:
    """``{"ok": [...], "failed": [...], "missing": [...], "errors": [...]}``
    by name; "errors" names the lines that do not parse ("line 3") - they
    were dropped silently, so a broken manifest looked verified."""
    pairs, bad = read_manifest(text)
    result: dict[str, list[str]] = {"ok": [], "failed": [], "missing": [],
                                    "errors": [f"line {n}" for n in bad]}
    for digest, name in pairs:
        path = backend.join(folder, *name.split("/"))
        try:
            actual = sha256_of(backend, path)
        except OSError:
            result["missing"].append(name)
            continue
        result["ok" if actual == digest else "failed"].append(name)
    return result


def _write(backend, path: str, text: str) -> None:
    with backend.open_write(path) as fh:
        fh.write(text.encode("utf-8"))


def activate(api):
    def create(ctx):
        # Everything that asks the backend runs in the background: the
        # folder listing, the check for an existing manifest, the hashing
        # and the write (on a remote folder each was a round trip that
        # held the window), and the pane is shown again without blocking.
        backend, folder = ctx.backend, ctx.folder
        chosen = [i.name for i in ctx.items if not i.is_dir and i.name not in ("..", ".")]
        whole_folder = not ctx.items  # nothing selected: every file of the folder
        target = backend.join(folder, MANIFEST_NAME)

        def work():
            files = chosen
            if whole_folder:
                files = [
                    i.name
                    for i in backend.list_dir(folder)
                    if not i.is_dir and i.name not in ("..", ".", MANIFEST_NAME)
                ]
            if not files:
                return ("none", 0)
            if backend.exists(target):
                return ("exists", 0)
            _write(backend, target, manifest_text(backend, folder, files))
            return ("written", len(files))

        def done(result):
            kind, count = result
            if kind == "none":
                api.notify("no files to checksum")
                return
            if kind == "exists":
                api.notify(f"{MANIFEST_NAME} already exists here - not overwritten")
                return
            api.notify(f"wrote {MANIFEST_NAME} for {count} file(s)")
            pane = ctx.pane
            if pane is not None:
                refresh = getattr(pane, "refresh_after_change", None) or pane.refresh
                refresh()

        api.notify(f"hashing {len(chosen)} file(s)…" if chosen else "hashing the folder…")
        api.run_in_background(work, on_done=done)

    def check(ctx):
        item = next(i for i in ctx.items if not i.is_dir)
        path = ctx.backend.join(ctx.folder, item.name)

        def work():
            with ctx.backend.open_read(path) as fh:
                text = fh.read(16 * 1024 * 1024).decode("utf-8", "replace")
            return verify(ctx.backend, ctx.folder, text)

        def done(result):
            from PyQt6.QtWidgets import QMessageBox

            summary = (
                f"OK: {len(result['ok'])}\nFAILED: {len(result['failed'])}\n"
                f"Missing: {len(result['missing'])}\n"
                f"Unreadable lines: {len(result['errors'])}"
            )
            bad = result["failed"] + result["missing"] + result["errors"]
            if bad:
                summary += "\n\n" + "\n".join(bad[:30])
            box = QMessageBox.warning if bad else QMessageBox.information
            box(api.window, "Verify SHA256SUMS", summary)

        api.run_in_background(work, on_done=done)

    api.add_context_action("Create SHA256SUMS", create, applies_to="any")
    api.add_context_action(
        "Verify SHA256SUMS", check, applies_to="single_file", extensions=("sha256sums", ".sha256")
    )
