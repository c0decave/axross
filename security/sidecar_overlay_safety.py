"""Disposition helper for TOML-sidecar overlay loaders.

Defense-in-depth helper for the sidecar-overlay contract: a loader that
overlays a TOML sidecar (e.g. ``.public-export-rules.toml``) onto a
set of in-process defaults MUST NOT silently drop the sidecar when
the runtime's TOML parser is unavailable. Doing so makes the
operator's custom rules silently inactive — on a supported Python
3.10 runtime (per ``pyproject.toml`` ``requires-python = ">=3.10"``)
the stdlib has no ``tomllib`` and no polyfill is bundled, so the
loader's ``if not sidecar.exists() or tomllib is None: return``
combined predicate would silently fail-open.

The 1st-layer fix in d30ad5b split the predicate at the single live
call site (``scripts/export-public.py:Rules._overlay``) so a sidecar
present + missing parser emits a loud stderr warning. That defense
lives inside ``scripts/``. A future loader — a separate scan-mode
sidecar, an audit tool, a CI gate — that copies the natural Python
idiom

    if not sidecar.exists() or parser is None:
        return

re-opens the silent-drop bypass without any code-review signal. The
2nd-layer extracts the disposition decision into this module so any
future caller has a named import to consult and the bypass cannot
regress in code that goes through the helper.

Decision shape (``OverlayDecision``):

* ``status == "absent"`` — sidecar file does not exist (operator did
  not opt into customisation). ``warning is None``: nagging here
  would be startup noise on every repo that runs without
  customisation.
* ``status == "active"`` — sidecar file exists AND ``parser is not
  None``. ``warning is None``: caller should proceed with the
  overlay.
* ``status == "inactive_no_parser"`` — sidecar file exists AND
  ``parser is None``. ``warning`` is the user-facing text that
  identifies BOTH the sidecar path AND the missing-parser root
  cause; caller should print it to stderr and bail.

The helper is intentionally thin — the contract is in the
classification, not the implementation. A future regression that
re-introduces an inline ``if not sidecar.exists() or parser is
None: return`` at another call site reopens the fail-open; one that
calls :func:`decide_sidecar_overlay` cannot, because the
``inactive_no_parser`` branch carries a warning the caller can drop
on the floor only by deliberately ignoring the helper's return value.

The module is stdlib-only and has no side effects at import time —
safe to import from any production loader, any test, and any future
security helper.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal

OverlayStatus = Literal["absent", "active", "inactive_no_parser"]


@dataclass(frozen=True)
class OverlayDecision:
    """Disposition for a sidecar-overlay attempt.

    ``status`` is one of ``"absent"``, ``"active"``,
    ``"inactive_no_parser"``. ``warning`` is the user-facing stderr
    text (``None`` when no warning is appropriate). The dataclass is
    frozen so a caller cannot post-hoc upgrade an
    ``inactive_no_parser`` decision into ``"active"`` after dropping
    the warning on the floor.
    """

    status: OverlayStatus
    warning: str | None


def decide_sidecar_overlay(
    sidecar_path: Path,
    parser: Any,
) -> OverlayDecision:
    """Classify a sidecar-overlay attempt.

    ``sidecar_path`` is the path the loader would consult (e.g.
    ``repo_root / ".public-export-rules.toml"``). It is allowed to
    point into a non-existent parent directory — :meth:`Path.exists`
    handles that and the helper classifies the path as ``absent``.

    ``parser`` is the caller's TOML parser module (or any truthy
    sentinel that represents "parser is available"). The contract is
    the simple identity test ``parser is None``: anything else is
    treated as 'parser available' so a polyfill module (e.g.
    ``tomli``) is handled identically to stdlib ``tomllib``. The
    helper does NOT introspect the parser's shape — that is the
    caller's responsibility at the actual ``parser.loads(...)`` call.

    Returns an ``OverlayDecision`` whose ``warning`` is set ONLY for
    the ``inactive_no_parser`` branch: the attack-of-silence
    shape (sidecar opted in by operator + runtime cannot parse it).
    The other two branches (``absent`` and ``active``) carry no
    warning — they are the no-news-is-good-news paths.
    """
    if not sidecar_path.exists():
        return OverlayDecision(status="absent", warning=None)
    if parser is None:
        return OverlayDecision(
            status="inactive_no_parser",
            warning=format_inactive_no_parser_warning(sidecar_path),
        )
    return OverlayDecision(status="active", warning=None)


def format_inactive_no_parser_warning(sidecar_path: Path) -> str:
    """User-facing stderr text for the inactive-no-parser branch.

    The format identifies BOTH the sidecar path (so an operator with
    multiple repos or multiple sidecars can tell which one is being
    dropped) AND the missing-parser root cause + the two fix paths
    (install ``tomli`` polyfill OR upgrade to Python 3.11+). Goes on
    one logical stderr line so it does not poison `--list-config`-
    style parsers that read stdout. The caller is responsible for
    actually emitting it.

    The text intentionally mirrors the
    ``scripts/export-public.py:Rules._overlay`` warning that
    landed in d30ad5b so callers that lift to the helper preserve
    operator-facing wording. Future callers (a separate sidecar, an
    audit tool) get the same shape for free.
    """
    return (
        f"sidecar {sidecar_path} present but tomllib unavailable "
        "(Python <3.11 without a 'tomli' polyfill); sidecar "
        "customisations are NOT being applied. Install 'tomli' or "
        "upgrade to Python 3.11+."
    )
