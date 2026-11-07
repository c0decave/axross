"""What can be added to an axross-base one by one: the units of the pack
system (docs/PACKS.md).

A unit is a pip extra (each backend and feature extra of pyproject.toml),
a bundled extension (each file of resources/extensions/) or a feature
group; it names the extras whose packages it needs and the units it builds
on. Which third-party distributions that means is read from the bundle's
lock (build/requirements-bundle.txt): a unit's requirements and everything
they pull in (the lock's "# via" lines), minus what the base already has -
so a package shared by several units is one blob, downloaded once.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
LOCK = ROOT / "build" / "requirements-bundle.txt"
EXTENSIONS = ROOT / "resources" / "extensions"

#: The base: Python, PyQt6/Qt and the core's own requirements
#: (pyproject's dependencies), and the build's tools are never units.
BASE_REQUIREMENTS = ("pyqt6", "paramiko", "pysocks", "keyring", "pillow", "pygments", "cryptography", "watchdog")
BUILD_ONLY = ("pyinstaller", "pyinstaller-hooks-contrib", "altgraph", "packaging", "setuptools")

#: What a bundled extension needs beyond the base: extras and other units.
EXTENSION_NEEDS: dict[str, tuple[str, ...]] = {
    "media_player": ("media",),
    "audio_mixer": ("media",),
    "matrix": ("chat",),
    "xmpp": ("chat",),
    "bluetooth": (),                      # bluetooth-raw is optional: its own unit
    "image_batch": ("metadata",),
}

#: Feature groups that are neither an extra nor an extension.
GROUPS: dict[str, tuple[str, tuple[str, ...]]] = {
    "mail-analysis": ("Mail analysis, projects, mail docks (live DNS checks)", ("dns",)),
}


@dataclass(frozen=True)
class Unit:
    name: str                 # "extra:smb", "extension:matrix", "group:mail-analysis"
    kind: str                 # extra | extension | group
    title: str
    extras: tuple[str, ...]   # the pip extras whose packages it needs
    needs: tuple[str, ...] = ()   # other units
    distributions: frozenset = field(default_factory=frozenset)


def canonical(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def parse_lock(path: Path = LOCK) -> tuple[dict[str, str], dict[str, set[str]]]:
    """({distribution: version}, {distribution: the distributions it pulls in})
    from a uv / pip-compile lock with "# via" comments."""
    versions: dict[str, str] = {}
    children: dict[str, set[str]] = {}
    current = None
    in_via = False
    for line in path.read_text(encoding="utf-8").splitlines():
        m = re.match(r"^([A-Za-z0-9][A-Za-z0-9._-]*)(?:\[[^\]]*\])?==([^\s;\\]+)", line)
        if m:
            current = canonical(m.group(1))
            versions[current] = m.group(2)
            in_via = False
            continue
        stripped = line.strip()
        if stripped.startswith("# via"):
            in_via = True
            rest = stripped[5:].strip()
            if rest and current and not rest.startswith("-r"):
                children.setdefault(canonical(rest.split()[0]), set()).add(current)
            continue
        if in_via and stripped.startswith("#") and current:
            parent = stripped.lstrip("#").strip()
            if parent and not parent.startswith("-r"):
                children.setdefault(canonical(parent.split()[0]), set()).add(current)
            continue
        in_via = False
    return versions, children


def closure(names, children) -> set[str]:
    out, todo = set(), [canonical(n) for n in names]
    while todo:
        n = todo.pop()
        if n in out:
            continue
        out.add(n)
        todo.extend(children.get(n, ()))
    return out


def _requirement_name(req: str) -> str:
    return canonical(re.split(r"[\[<>=!~; ]", req.strip(), maxsplit=1)[0])


def units(lock: Path = LOCK) -> list[Unit]:
    from core.features import EXTRAS

    versions, children = parse_lock(lock)
    base = closure(BASE_REQUIREMENTS, children) | set(BUILD_ONLY)

    def dists(extras) -> frozenset:
        names = [_requirement_name(r) for e in extras for r in EXTRAS.get(e, ())]
        return frozenset(d for d in closure(names, children) if d in versions and d not in base)

    out = [Unit(f"extra:{e}", "extra", e, (e,), (), dists((e,))) for e in sorted(EXTRAS)]
    for path in sorted(EXTENSIONS.glob("*.py")):
        if path.name.startswith("_"):
            continue
        ext = path.stem
        needs = EXTENSION_NEEDS.get(ext, ())
        out.append(Unit(f"extension:{ext}", "extension", ext, needs, tuple(f"extra:{n}" for n in needs),
                        dists(needs)))
    for name, (title, extras) in sorted(GROUPS.items()):
        out.append(Unit(f"group:{name}", "group", title, extras, tuple(f"extra:{e}" for e in extras),
                        dists(extras)))
    return out


def base_distributions(lock: Path = LOCK) -> set[str]:
    versions, children = parse_lock(lock)
    return {d for d in closure(BASE_REQUIREMENTS, children) if d in versions}
