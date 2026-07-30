"""The environment to hand a child process.

A PyInstaller one-file bundle extracts its shared libraries into a temp
directory and points ``LD_LIBRARY_PATH`` at it so the frozen interpreter
can find them. That variable is inherited by every child, so an external
program launched from the bundle resolves ITS libraries against ours.

Observed, not theorised — running the shipped binary and asking it to
open a terminal:

    /usr/bin/bash: symbol lookup error: /usr/bin/bash:
    undefined symbol: rl_trim_arg_from_keyseq

bash found our libreadline instead of the system's. The same applies to
every external tool the app drives: rsync, iscsiadm, showmount,
mount.nfs, svn, rsh, fusermount, the MTP utilities and the elevated-write
helper. In a shipped binary none of them could run, while the source
tree — where the variable is never set — stayed perfectly green.

PyInstaller stashes the pre-launch value in ``<VAR>_ORIG``, and its own
documentation prescribes restoring it before spawning anything. That is
what this does, for every loader variable it rewrites.
"""

from __future__ import annotations

import os

#: Variables PyInstaller rewrites on launch. Each has a ``_ORIG``
#: companion holding whatever was there before, if anything.
_LOADER_VARS = (
    "LD_LIBRARY_PATH",
    "LD_PRELOAD",
    "DYLD_LIBRARY_PATH",
    "DYLD_FRAMEWORK_PATH",
    "LIBPATH",
)


def clean_child_env(env: dict | None = None, **overrides: str) -> dict:
    """A copy of ``env`` safe to hand to an external program.

    For each loader variable: restore the saved original when there is
    one, otherwise remove the variable entirely. The ``_ORIG`` markers
    are dropped either way — they are bookkeeping, and a child has no
    use for them.

    Outside a bundle nothing matches and the environment passes through
    unchanged, so call sites need no "am I frozen?" check. The input
    mapping is never mutated: callers pass ``os.environ``, and changing
    that would affect the whole process rather than one child.
    """
    result = dict(os.environ if env is None else env)

    for var in _LOADER_VARS:
        original = result.pop(f"{var}_ORIG", None)
        if original is not None:
            result[var] = original
        elif var in result:
            # No marker means nothing set it before the bundle did, so
            # the value can only be the extraction directory. There is
            # no way to tell a leftover apart from a user's own once the
            # marker is gone, so the rule stays uniform — a caller that
            # genuinely needs one passes it via ``overrides``.
            del result[var]

    result.update(overrides)
    return result


__all__ = ["clean_child_env"]
