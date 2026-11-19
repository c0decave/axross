"""The gate in front of QtSvg: whether an SVG may be drawn at all.

An SVG is a program for a renderer more than a picture: it can name other
files, expand entities and make its references draw each other again and
again - ten levels of ten ``<use>`` in 2.4 KB drew a billion paths. Before
anything draws one (core.previews for the media viewer, ui.markdown_view
for a document's pictures) it passes :func:`svg_refusal` - or, for the
Markdown reader, which allows what a document's SVG holds by habit (a
DOCTYPE, ``<style>``), :func:`svg_expansion` after its own check of what
the SVG names. Whatever passes is drawn in a killable child process
(core.svg_worker): the gate counts elements, not what each costs.

Pure Python, no Qt: the headless server and the exported tools import it.
"""

from __future__ import annotations

import re

# The most elements ``<use>`` (and ``url(#id)``) references may add to an
# SVG's drawing: each one draws its target again, the target's own
# references included, so ten levels of ten references in a 2.4 KB file
# drew a billion paths and pinned a thumbnail worker for minutes (10^6
# took 12.6 s). The elements written in the file are bounded by its size.
MAX_SVG_USE_EXPANSION = 20_000


# Anything that makes the XML parser expand, include or fetch, or that
# would run in a browser. QtSvg runs no scripts and fetches nothing from
# the network, but the gate does not rely on that: it refuses first.
_SVG_FORBIDDEN = (
    b"<!doctype",
    b"<!entity",
    b"<?xml-stylesheet",
    b"<script",
    b"<foreignobject",
    b"<iframe",
    b"<object",
    b"<embed",
    b"@import",
)
_SVG_HREF = re.compile(rb"""href\s*=\s*(["'])\s*(.*?)\1""", re.S)
_SVG_URL = re.compile(rb"""url\(\s*["']?\s*([^)"'\s]*)""")
_SVG_DATA_IMAGE = (b"data:image/png", b"data:image/jpeg", b"data:image/gif", b"data:image/webp")


_SVG_LOCAL_URL = re.compile(r"url\(\s*[\"']?\s*#([^)\"'\s]*)")


class _DuplicateId(Exception):
    """Two elements of an SVG carry the same id."""


def svg_expansion(data: bytes, *, doctype: bool = False) -> str | None:
    """Why the references of *data* draw too much (see
    :data:`MAX_SVG_USE_EXPANSION`), or ``None``. A streaming parse that
    keeps a few numbers per element, no tree; each element's sizes are
    worked out once, so the time grows with the file, not the drawing.
    *doctype*: a document type declaration is let through (an entity
    declaration never is; expat reads no external DTD)."""
    from xml.parsers import expat

    ids: dict[str, int] = {}
    refs: list = []                     # per element: the ids it references
    children: dict[int, list[int]] = {}  # elements that have any
    open_: list[int] = []
    parser = expat.ParserCreate()

    def start(_name, attrs):
        index = len(refs)
        if open_:
            children.setdefault(open_[-1], []).append(index)
        own = ()
        for key, value in attrs.items():
            local = key.rsplit(":", 1)[-1].lower()
            if local == "id":
                # Counted is the element an id names first; QtSvg draws
                # the last one: an empty <g id=a/> before the real fan-out
                # group drew 10^6 elements past a cap of 20000 (9.4 s).
                # Ids name one element each - two with one id is refused.
                if ids.setdefault(value, index) != index:
                    raise _DuplicateId(value)
            elif local == "href" and value.strip().startswith("#"):
                own += (value.strip()[1:],)
            elif "url(" in value:
                own += tuple(_SVG_LOCAL_URL.findall(value))
        refs.append(own)
        open_.append(index)

    def end(_name):
        open_.pop()

    def refuse_declarations(*_args):
        raise ValueError("declarations are not allowed")

    parser.StartElementHandler = start
    parser.EndElementHandler = end
    parser.EntityDeclHandler = refuse_declarations
    if not doctype:
        parser.StartDoctypeDeclHandler = refuse_declarations
    try:
        parser.Parse(data, True)
    except _DuplicateId as exc:
        return f"SVG gives two elements the same id ({str(exc)[:64]!r})"
    except (expat.ExpatError, ValueError) as exc:
        return f"SVG is not well-formed XML ({exc})"
    if not refs:
        return None
    limit = MAX_SVG_USE_EXPANSION
    # Per element, worked out once (post-order over its children and its
    # references' targets, a target still being worked out is a cycle):
    # size[i] the elements of its subtree, extra[i] what the references in
    # its subtree draw. Both are capped past the limit.
    size: list[int] = [0] * len(refs)
    extra: list[int] = [0] * len(refs)
    state = bytearray(len(refs))        # 0 new, 1 being worked out, 2 done
    stack = [0]
    while stack:
        node = stack[-1]
        if state[node] == 2:
            stack.pop()
            continue
        targets = [t for t in (ids.get(r) for r in refs[node]) if t is not None]
        kids = children.get(node, ())
        if state[node] == 0:
            state[node] = 1
            for dep in (*kids, *targets):
                if state[dep] == 1:
                    return "SVG references itself"
                if state[dep] == 0:
                    stack.append(dep)
            continue
        if any(state[dep] != 2 for dep in (*kids, *targets)):
            return "SVG references itself"
        size[node] = min(1 + sum(size[c] for c in kids), limit + 1)
        extra[node] = min(sum(extra[c] for c in kids)
                          + sum(size[t] + extra[t] for t in targets), limit + 1)
        state[node] = 2
        stack.pop()
    if extra[0] > limit:
        return f"SVG references draw more than {limit} elements"
    return None


def svg_refusal(data: bytes) -> str | None:
    """Why *data* must not reach the SVG renderer, or ``None`` when it may.

    Allowed: a UTF-8 document whose references all stay inside it
    (``#id``) or embed a common raster as a ``data:`` URI, and whose
    references draw at most :data:`MAX_SVG_USE_EXPANSION` elements."""
    if b"\x00" in data:
        return "SVG is not UTF-8 text"
    lowered = data.lower()
    for token in _SVG_FORBIDDEN:
        if token in lowered:
            return f"SVG contains {token.decode()!r}"
    for match in _SVG_HREF.finditer(lowered):
        ref = match.group(2).strip()
        if not (ref.startswith(b"#") or ref.startswith(_SVG_DATA_IMAGE)):
            return "SVG references something outside the file"
    for match in _SVG_URL.finditer(lowered):
        if not match.group(1).startswith(b"#"):
            return "SVG references something outside the file"
    return svg_expansion(data)


def svg_options(qtsvg):
    """The QSvgRenderer options: Tiny 1.2 features only, every animation
    kind off - or ``None`` on a Qt without options (before 6.7).

    The animation kinds are named one by one, never as the combined
    DisableAnimations value: Qt 6.10.0 segfaults in QSvgRenderer.load()
    for every document when the options carry that value (0xF0), while
    the same kinds named singly load (measured on the 0.10.24 bundle).
    PyQt6 exposes the QFlags as a plain Enum: combine by value."""
    option = getattr(qtsvg, "Option", None)
    if option is None:
        return None
    value = 0
    for name in ("Tiny12FeaturesOnly", "DisableSMILAnimations", "DisableCSSAnimations"):
        member = getattr(option, name, None)
        if member is not None:
            value |= member.value
    return option(value)


def options_value() -> int:
    """:func:`svg_options` of this Qt as the int core.svg_worker takes (-1:
    none - Qt before 6.7, or no QtSvg)."""
    try:
        from PyQt6.QtSvg import QtSvg

        found = svg_options(QtSvg)
    except (ImportError, AttributeError, TypeError, ValueError):
        return -1
    return -1 if found is None else int(found.value)


__all__ = ["MAX_SVG_USE_EXPANSION", "options_value", "svg_expansion", "svg_options", "svg_refusal"]
