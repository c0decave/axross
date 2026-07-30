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
    source_env = {"PATH": "/usr/bin", "HOME": "~", "LANG": "en_US.UTF-8"}
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
