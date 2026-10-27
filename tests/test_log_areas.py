"""The logging areas (core.log_areas): one table maps every logger name of
axross - and the third-party libraries it uses - to the area the Settings >
Logging page and the Log dock's area filter show. No module is an orphan:
each core / ui / models / extension module belongs to exactly one area by
name, never by falling back to its package."""

from __future__ import annotations

import fnmatch
import re
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from core import log_areas as LA  # noqa: E402


def _module_names() -> list[str]:
    names = []
    for folder in ("core", "ui", "models", "resources/extensions", "axross"):
        for path in sorted((ROOT / folder).glob("*.py")):
            dotted = folder.replace("/", ".")
            names.append(dotted if path.stem == "__init__" else f"{dotted}.{path.stem}")
    return names


def _literal_logger_names() -> list[str]:
    """Every getLogger("literal") in the source - names that are not the module's."""
    found = set()
    for folder in ("core", "ui", "models", "resources/extensions", "axross"):
        for path in (ROOT / folder).glob("*.py"):
            for name in re.findall(r"getLogger\(\s*\"([^\"{}]+)\"\s*\)", path.read_text("utf-8")):
                found.add(name)
    main_source = (ROOT / "main.py").read_text("utf-8")
    for name in re.findall(r"getLogger\(\s*\"([^\"{}]+)\"\s*\)", main_source):
        found.add(name)
    return sorted(found)


# -- happy ------------------------------------------------------------------------------------


def test_happy_every_module_belongs_to_exactly_one_area_by_name():
    names = _module_names()
    assert len(names) > 250, "the module scan found too few modules"
    orphans, doubles = [], []
    for name in names:
        hits = LA.explicit_areas(name)
        if not hits:
            orphans.append(name)
        elif len(hits) > 1:
            doubles.append((name, hits))
    assert not orphans, f"modules without an area: {orphans}"
    assert not doubles, f"modules in more than one area: {doubles}"


def test_happy_literal_logger_names_have_an_area():
    names = _literal_logger_names()
    assert "core.mcp_server.audit" in names and "axross" in names
    missing = [n for n in names if LA.area_of(n) is None]
    assert not missing, missing


def test_happy_a_bundled_extension_logs_under_extensions_at_run_time():
    # ui.extension_host runs an extension as axross_extension_<source>_<module>
    # and gives its API the logger axross.ext.<module>.
    assert LA.area_of("axross_extension_bundled_media_player") == "extensions"
    assert LA.area_of("axross_extension_user_mine") == "extensions"
    assert LA.area_of("axross.ext.media_player") == "extensions"


@pytest.mark.parametrize(("name", "area"), [
    ("core.smb_client", "protocols.smb"),
    ("core.ssh_client", "protocols.ssh"),
    ("core.sftp_io", "protocols.ssh"),
    ("core.s3_client", "protocols.cloud"),
    ("core.webdav_client", "protocols.webdav"),
    ("core.ftp_client", "protocols.ftp"),
    ("core.transfer_worker", "transfers"),
    ("core.metadata_index", "search"),
    ("core.agent", "agent"),
    ("core.mcp_client", "mcp.client"),
    ("core.mcp_server", "mcp.server"),
    ("core.scripting", "scripting"),
    ("core.self_update", "update"),
    ("core.credentials", "security"),
    ("ui.main_window", "ui"),
    ("core.extensions", "extensions"),
    ("resources.extensions.media_player", "extensions"),
    ("paramiko", "third_party.ssh"),
    ("urllib3", "third_party.http"),
    ("PIL", "third_party.other"),
    ("asyncio", "third_party.other"),
])
def test_happy_known_names_land_in_their_area(name, area):
    assert LA.area_of(name) == area


def test_happy_a_child_logger_takes_its_parents_area():
    assert LA.area_of("core.mcp_server.audit") == "mcp.server"
    assert LA.area_of("paramiko.transport") == "third_party.ssh"
    assert LA.area_of("botocore.credentials") == "third_party.cloud"


def test_happy_third_party_libraries_are_quiet_by_default():
    assert LA.AREAS_BY_ID["third_party"].default == "WARNING"
    for area in LA.AREAS:
        if area.id != "third_party":
            assert area.default == "inherit", area.id


# -- sad --------------------------------------------------------------------------------------


@pytest.mark.parametrize("name", ["", "test.something", "py.warnings", "coredump", "uix"])
def test_sad_a_name_outside_axross_has_no_area(name):
    assert LA.area_of(name) is None


def test_sad_an_unlisted_core_module_falls_back_to_its_package_at_run_time_only():
    # At run time a new module still gets an area (its package's) ...
    assert LA.area_of("core.not_written_yet") == "app"
    # ... but the orphan test counts it as missing.
    assert LA.explicit_areas("core.not_written_yet") == []


def test_sad_unknown_area_ids_are_rejected():
    with pytest.raises(KeyError):
        LA.ancestors("no.such.area")


# -- edge -------------------------------------------------------------------------------------


def test_edge_ids_and_labels_are_unique_and_parents_exist():
    ids = [a.id for a in LA.AREAS]
    assert len(ids) == len(set(ids))
    labels = [a.label for a in LA.AREAS]
    assert len(labels) == len(set(labels))
    for area in LA.AREAS:
        if area.parent is not None:
            assert area.parent in LA.AREAS_BY_ID, area.id
            assert area.id.startswith(area.parent + ".")
    # Parents come before their children (the page's tree is built in order).
    seen = set()
    for area in LA.AREAS:
        assert area.parent is None or area.parent in seen, area.id
        seen.add(area.id)


def test_edge_no_logger_name_is_listed_twice_or_shadowed_by_a_pattern():
    owners: dict[str, str] = {}
    for area in LA.AREAS:
        for name in area.loggers:
            assert name not in owners, f"{name}: {owners.get(name)} and {area.id}"
            owners[name] = area.id
    for area in LA.AREAS:
        for pattern in area.patterns:
            for name, owner in owners.items():
                if fnmatch.fnmatchcase(name, pattern):
                    assert owner == area.id, f"{pattern} of {area.id} matches {name} of {owner}"


def test_edge_every_listed_module_exists():
    """A renamed or removed module leaves no stale entry behind."""
    modules = set(_module_names())
    prefixes = ("core.", "ui.", "models.", "axross.")
    stale = [name for area in LA.AREAS for name in area.loggers
             if name.startswith(prefixes) and name not in modules and name != "axross.ext"]
    assert not stale, stale


def test_edge_ancestors_run_from_the_area_to_the_top():
    assert LA.ancestors("protocols.smb") == ["protocols.smb", "protocols"]
    assert LA.ancestors("ui") == ["ui"]


def test_edge_a_pattern_beats_the_package_fallback():
    # The Bluetooth modules being built in parallel land in Devices, not in "app".
    assert LA.area_of("core.bluetooth_scan") == "protocols.devices"
    assert LA.explicit_areas("core.bluetooth_scan") == ["protocols.devices"]


def test_edge_lookup_is_cached_but_correct_after_repeat_calls():
    for _ in range(3):
        assert LA.area_of("core.smb_client") == "protocols.smb"
