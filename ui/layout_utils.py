from __future__ import annotations

from collections.abc import Sequence
from typing import Literal

DropZone = Literal["left", "right", "top", "bottom"]
SplitterAxis = Literal["horizontal", "vertical"]


def detect_drop_zone(x: int, y: int, width: int, height: int) -> DropZone:
    """Return the nearest drop edge for a point inside a pane."""
    rx = x / max(width, 1)
    ry = y / max(height, 1)

    dist_left = rx
    dist_right = 1.0 - rx
    dist_top = ry
    dist_bottom = 1.0 - ry
    min_dist = min(dist_left, dist_right, dist_top, dist_bottom)

    if min_dist == dist_left:
        return "left"
    if min_dist == dist_right:
        return "right"
    if min_dist == dist_top:
        return "top"
    return "bottom"


def splitter_axis_for_zone(zone: str) -> SplitterAxis | None:
    """Map a drop zone to the splitter axis needed to realize it."""
    if zone in ("left", "right"):
        return "horizontal"
    if zone in ("top", "bottom"):
        return "vertical"
    return None


def equal_split_sizes(
    primary_extent: int,
    pane_count: int,
    *,
    fallback_extent: int = 0,
    default_size: int = 100,
) -> list[int]:
    """Return stable equal sizes for a splitter, even before first layout."""
    if pane_count <= 0:
        return []

    extent = primary_extent if primary_extent > 0 else fallback_extent
    if extent <= 0:
        return [default_size] * pane_count

    size = max(extent // pane_count, 1)
    return [size] * pane_count


#: The largest splitter size kept from a saved session. QSplitter takes
#: 32-bit sizes: one above 2**31-1 (a hand edit, a bit flip) raised
#: OverflowError in setSizes and lost the whole restored layout. The sizes
#: are proportions, so a clamp to this keeps the layout.
MAX_SPLITTER_SIZE = 1 << 24


def sanitize_splitter_sizes(
    raw_sizes: object,
    child_count: int,
    *,
    min_size: int = 100,
) -> list[int] | None:
    """Validate persisted splitter sizes and clamp each into
    [*min_size*, MAX_SPLITTER_SIZE]. None when they are no list of integers
    (true / false are no sizes) or do not match *child_count*."""
    if child_count < 0:
        return None
    if child_count == 0:
        return []
    if not isinstance(raw_sizes, Sequence) or isinstance(raw_sizes, (str, bytes, bytearray)):
        return None
    if len(raw_sizes) != child_count:
        return None

    sizes: list[int] = []
    for raw in raw_sizes:
        if not isinstance(raw, int) or isinstance(raw, bool):
            return None
        sizes.append(min(max(raw, min_size), MAX_SPLITTER_SIZE))
    return sizes
