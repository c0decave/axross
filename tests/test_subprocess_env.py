#!/usr/bin/env python3
"""The environment handed to child processes.

Reported from a real run of the bundled binary: opening the terminal
died with

    /usr/bin/bash: symbol lookup error: /usr/bin/bash:
    undefined symbol: rl_trim_arg_from_keyseq

Reproduced exactly. A PyInstaller one-file bundle extracts its
libraries to a temp directory and points ``LD_LIBRARY_PATH`` at it so
the frozen interpreter finds them. Every child inherits that variable,
so ``bash`` resolved libreadline against OUR bundle instead of the
system's and could not find a symbol its own build expects.

This is not a terminal bug. Ten places in the codebase spawn an
external program — rsync, iscsiadm, showmount, mount.nfs, svn, rsh,
fusermount, the MTP tools, the elevated-write helper and the shell — and
in a shipped binary every one of them was handed the same poisoned
environment. The source tree never sees it, which is why the test suite
was perfectly green while the artifact could not run a single external
tool.

PyInstaller's own contract is what the fix follows: the loader stashes
whatever was there before in ``LD_LIBRARY_PATH_ORIG``, so a child gets
that back, or gets the variable removed when there was none.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core.subprocess_env import clean_child_env  # noqa: E402

# --------------------------------------------------------------------------
# Running from a bundle
# --------------------------------------------------------------------------


def test_sad_bundle_library_path_is_removed_when_there_was_none_before():
    """The reported case: nothing set LD_LIBRARY_PATH before launch, so
    the child must not see one at all."""
    env = clean_child_env({"LD_LIBRARY_PATH": "/tmp/_MEIjw0FuN", "PATH": "/usr/bin"})
    assert "LD_LIBRARY_PATH" not in env
    assert env["PATH"] == "/usr/bin"


def test_happy_the_users_own_library_path_is_restored():
    """When the user had one, PyInstaller saved it — give it back rather
    than dropping a setting they chose."""
    env = clean_child_env({
        "LD_LIBRARY_PATH": "/tmp/_MEIabc",
        "LD_LIBRARY_PATH_ORIG": "/opt/mylibs",
    })
    assert env["LD_LIBRARY_PATH"] == "/opt/mylibs"
    assert "LD_LIBRARY_PATH_ORIG" not in env


def test_edge_the_orig_marker_is_never_passed_on():
    """It is PyInstaller bookkeeping; a child has no use for it and
    seeing it would just be confusing in a debug session."""
    env = clean_child_env({"LD_LIBRARY_PATH_ORIG": "/opt/mylibs"})
    assert "LD_LIBRARY_PATH_ORIG" not in env
    assert env.get("LD_LIBRARY_PATH") == "/opt/mylibs"


def test_edge_the_same_treatment_applies_to_the_other_loader_variables():
    """PyInstaller rewrites more than one; leaving LD_PRELOAD or the
    macOS pair behind breaks children in the same way."""
    env = clean_child_env({
        "LD_PRELOAD": "/tmp/_MEIabc/libfoo.so",
        "LD_PRELOAD_ORIG": "/opt/preload.so",
        "DYLD_LIBRARY_PATH": "/tmp/_MEIabc",
    })
    assert env["LD_PRELOAD"] == "/opt/preload.so"
    assert "DYLD_LIBRARY_PATH" not in env


# --------------------------------------------------------------------------
# Running from source
# --------------------------------------------------------------------------


def test_happy_a_normal_environment_is_passed_through_untouched():
    """Outside a bundle there is nothing to undo, and stripping a
    developer's LD_LIBRARY_PATH would break their setup."""
    source_env = {"PATH": "/usr/bin", "HOME": "/home/x", "LANG": "en_US.UTF-8"}
    assert clean_child_env(source_env) == source_env


def test_edge_a_library_path_without_an_orig_marker_is_still_dropped():
    """A bare LD_LIBRARY_PATH pointing into a bundle temp dir is the
    reported case; there is no way to tell it apart from a user's own
    once the marker is missing, so the rule is uniform: no marker, no
    variable. Callers that need one set it themselves."""
    env = clean_child_env({"LD_LIBRARY_PATH": "/tmp/_MEIxyz"})
    assert "LD_LIBRARY_PATH" not in env


def test_edge_the_input_mapping_is_not_mutated():
    """Call sites pass os.environ; changing it would alter the whole
    process, not just one child."""
    original = {"LD_LIBRARY_PATH": "/tmp/_MEIabc", "PATH": "/usr/bin"}
    snapshot = dict(original)
    clean_child_env(original)
    assert original == snapshot


def test_edge_defaults_to_the_real_environment():
    import os

    env = clean_child_env()
    assert env.get("PATH") == os.environ.get("PATH")


def test_edge_extra_overrides_are_applied_on_top():
    env = clean_child_env({"PATH": "/usr/bin"}, TERM="xterm")
    assert env["TERM"] == "xterm"
    assert env["PATH"] == "/usr/bin"


# --------------------------------------------------------------------------
# Starting axross itself again (the detached start of a terminal launch)
# --------------------------------------------------------------------------
#
# Reproduced 2026-10-22 with dist/axross-full 0.13.22: started from a shell
# without arguments, the re-executed child inherited _PYI_APPLICATION_HOME_DIR,
# the extraction folder of the first process. That process exits at once and
# its bootloader deletes the folder; the child then showed only "Axross -
# Unexpected Error: FileNotFoundError ... _MEI.../base_library.zip" instead of
# the window. PyInstaller's remedy: PYINSTALLER_RESET_ENVIRONMENT=1 makes the
# child a top-level process that extracts itself again.

from core.subprocess_env import relaunch_env  # noqa: E402

_FROZEN = {
    "_PYI_ARCHIVE_FILE": "/opt/axross-full",
    "_PYI_PARENT_PROCESS_LEVEL": "1",
    "_PYI_LINUX_PROCESS_NAME": "axross-full",
    "_PYI_APPLICATION_HOME_DIR": "/tmp/_MEI1234",
    "_MEIPASS2": "/tmp/_MEI1234",
    "LD_LIBRARY_PATH": "/tmp/_MEI1234:/opt/lib",
    "LD_LIBRARY_PATH_ORIG": "/opt/lib",
    "DISPLAY": ":0",
    "HOME": "/home/u",
}


def test_happy_a_frozen_relaunch_forgets_the_extraction_folder():
    env = relaunch_env(_FROZEN, frozen=True)
    assert not [k for k in env if k.startswith("_PYI_") or k == "_MEIPASS2"]
    assert env["PYINSTALLER_RESET_ENVIRONMENT"] == "1"
    assert env["LD_LIBRARY_PATH"] == "/opt/lib"
    assert env["DISPLAY"] == ":0" and env["HOME"] == "/home/u"
    assert "/tmp/_MEI1234" not in "".join(env.values())


def test_sad_a_frozen_relaunch_without_an_own_library_path_gets_none():
    env = relaunch_env({k: v for k, v in _FROZEN.items() if k != "LD_LIBRARY_PATH_ORIG"},
                       frozen=True)
    assert "LD_LIBRARY_PATH" not in env


def test_edge_a_source_relaunch_keeps_the_environment_as_it_is():
    # From the source tree nothing is extracted; the user's own
    # LD_LIBRARY_PATH (no _ORIG marker) must survive.
    mine = {"LD_LIBRARY_PATH": "/home/u/lib", "DISPLAY": ":0"}
    env = relaunch_env(mine, frozen=False)
    assert env == mine and env is not mine
    assert "PYINSTALLER_RESET_ENVIRONMENT" not in env


def test_edge_the_input_of_a_relaunch_is_not_mutated():
    before = dict(_FROZEN)
    relaunch_env(_FROZEN, frozen=True)
    assert _FROZEN == before


# --------------------------------------------------------------------------
# Starting axross itself as a worker this process waits on
# --------------------------------------------------------------------------
#
# Measured 2026-10-22 with dist/axross-full 0.13.22: a frozen child started
# with this process's _PYI_* variables reuses its extraction folder, and its
# bootloader does NOT set LD_LIBRARY_PATH again. With clean_child_env() such
# a child loaded /usr/lib/libssl.so.3 and /usr/lib/libstdc++.so.6.0.36 into
# the bundled interpreter; with the inherited environment it loaded the
# bundled copies. Its own host programs still start cleanly: the child's
# clean_child_env() strips the inherited folder (bash -c true: rc 0).

from core.subprocess_env import worker_env  # noqa: E402


def test_happy_a_worker_keeps_the_bundle_library_path():
    env = worker_env(_FROZEN)
    assert env["LD_LIBRARY_PATH"] == "/tmp/_MEI1234:/opt/lib"
    assert env["_PYI_APPLICATION_HOME_DIR"] == "/tmp/_MEI1234"


def test_happy_a_worker_keeps_the_orig_marker_for_its_own_children():
    # The worker's own clean_child_env() gives its host programs the
    # user's value back only if the marker travels along.
    env = worker_env(_FROZEN)
    assert env["LD_LIBRARY_PATH_ORIG"] == "/opt/lib"
    assert clean_child_env(env)["LD_LIBRARY_PATH"] == "/opt/lib"


def test_sad_a_reset_request_is_never_passed_to_a_worker():
    # It would make the worker extract the whole bundle again on every start.
    env = worker_env({**_FROZEN, "PYINSTALLER_RESET_ENVIRONMENT": "1"})
    assert "PYINSTALLER_RESET_ENVIRONMENT" not in env


def test_edge_a_worker_env_is_a_copy_and_defaults_to_the_real_environment(monkeypatch):
    before = dict(_FROZEN)
    env = worker_env(_FROZEN)
    assert env is not _FROZEN and _FROZEN == before
    monkeypatch.setenv("AXROSS_WORKER_PROBE", "1")
    assert worker_env()["AXROSS_WORKER_PROBE"] == "1"
