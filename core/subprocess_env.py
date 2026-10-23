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


def relaunch_env(env: dict | None = None, *, frozen: bool) -> dict:
    """A copy of ``env`` for starting axross itself again as an
    independent process (the detached start of a terminal launch).

    A frozen one-file child must not reuse this process's extraction
    folder: this process exits at once and its bootloader deletes that
    folder (dist/axross-full 0.13.22 then showed only "FileNotFoundError
    ... _MEI.../base_library.zip"). PyInstaller's remedy is
    ``PYINSTALLER_RESET_ENVIRONMENT=1``; its ``_PYI_*`` variables and the
    loader variables pointing into the folder go too. From the source tree
    the environment stays as it is - including a user's own
    ``LD_LIBRARY_PATH``."""
    source = os.environ if env is None else env
    if not frozen:
        return dict(source)
    result = clean_child_env(source)
    for name in [k for k in result if k.startswith("_PYI_") or k == "_MEIPASS2"]:
        del result[name]
    result["PYINSTALLER_RESET_ENVIRONMENT"] = "1"
    return result


#: Variables PyInstaller's Qt hook points into the unpacked folder. A host
#: Qt program started from axross (a file manager or viewer behind
#: xdg-open) would load our Qt plugins through them.
_BUNDLE_QT_VARS = ("QT_PLUGIN_PATH", "QML2_IMPORT_PATH")


def _without_bundle(value: str, bundle: str) -> str:
    """*value* (a path list) without the entries inside *bundle*."""
    keep = [p for p in value.split(os.pathsep)
            if p and p.rstrip("/") != bundle and not p.startswith(bundle + "/")]
    return os.pathsep.join(keep)


#: What restore_loader_env took out of ``os.environ`` at start (name ->
#: value): the workers, which are this binary again, get it back
#: (:func:`worker_env`).
_STARTUP_VALUES: dict[str, str] = {}


def restore_loader_env(environ: dict | None = None, *, bundle_dir: str | None) -> list[str]:
    """Give this frozen process back the environment it started with, so
    that EVERY child gets it - also the ones third-party code or Qt starts,
    which no call site can hand :func:`clean_child_env`.

    Called once at the start of ``main()`` with ``sys._MEIPASS`` (``None``
    outside a bundle: nothing happens). Safe for the running process: glibc
    reads ``LD_LIBRARY_PATH`` only at process start, and Qt finds its
    plugins through QLibraryInfo (both measured in the binary).

    Loader variables get their ``_ORIG`` value back (the marker stays, so
    clean_child_env still hands the user's value on); without one, their
    entries inside the bundle go. The same for QT_PLUGIN_PATH and
    QML2_IMPORT_PATH. ``_PYI_*`` describe this process's unpacking and go
    (a relaunch of axross itself uses :func:`relaunch_env`). Mutates
    *environ* (default ``os.environ``); returns the names it changed."""
    if not bundle_dir:
        return []
    environ = os.environ if environ is None else environ
    before = dict(environ)
    bundle = bundle_dir.rstrip("/")
    changed = []
    for var in _LOADER_VARS + _BUNDLE_QT_VARS:
        current = environ.get(var)
        if current is None:
            continue
        original = environ.get(f"{var}_ORIG")
        wanted = original if original is not None else _without_bundle(current, bundle)
        if wanted == current:
            continue
        if wanted:
            environ[var] = wanted
        else:
            del environ[var]
        changed.append(var)
    for name in [k for k in environ if k.startswith("_PYI_") or k == "_MEIPASS2"]:
        del environ[name]
        changed.append(name)
    if environ is os.environ:
        _STARTUP_VALUES.update({name: before[name] for name in changed})
    return changed


def worker_env(env: dict | None = None) -> dict:
    """A copy of ``env`` for starting axross itself as a worker that this
    process waits on and outlives (the analysis and voice children).

    The opposite of :func:`clean_child_env`: the loader variables STAY.
    Measured with dist/axross-full 0.13.22 - a frozen child that inherits
    this process's ``_PYI_*`` variables reuses its extraction folder, and
    its bootloader does not set ``LD_LIBRARY_PATH`` again. Given
    clean_child_env() it loaded /usr/lib/libssl.so.3 and the host's
    libstdc++ into the bundled interpreter; given this environment it
    loaded the bundled copies. The ``_ORIG`` markers travel along, so the
    worker's own clean_child_env() still hands its host programs the
    user's value (its ``bash -c true``: exit status 0).

    Not :func:`relaunch_env` either: that extracts the whole bundle again
    on every start. ``PYINSTALLER_RESET_ENVIRONMENT`` is dropped for the
    same reason - the bootloader consumes it, but a worker must never
    receive it. From the source tree nothing matches and the copy is the
    environment as it is."""
    result = dict(os.environ if env is None else env)
    if env is None:
        # main() took the bundle's own values out of os.environ for host
        # programs (restore_loader_env); a worker is this binary and needs them.
        result.update(_STARTUP_VALUES)
    result.pop("PYINSTALLER_RESET_ENVIRONMENT", None)
    return result


__all__ = ["clean_child_env", "relaunch_env", "restore_loader_env", "worker_env"]
