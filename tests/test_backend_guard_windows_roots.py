"""The root guard knows every Windows spelling of a root (WinRM, WMI, LocalFS
on Windows: backends whose separator is a backslash).

Review round 9 (repro winrm/winrm_roots.py): the guard knew drive-letter
roots only. Remove-Item -Recurse -LiteralPath would have emptied a whole
share or drive for each of ``\\\\fs\\share``, ``\\\\host\\C$``,
``\\\\?\\C:\\``, ``\\\\.\\C:\\``, ``\\\\?\\UNC\\fs\\share``,
``FileSystem::C:\\``, ``Microsoft.PowerShell.Core\\FileSystem::C:\\``,
``HKLM:\\``, ``Cert:\\``, ``C:\\ `` and ``C:\\...`` (Win32 drops trailing dots
and spaces). And a LAST name made only of dots and spaces names the folder
above it there (``C:\\data\\...`` is ``C:\\data``): remove asks first
(ConfirmationRequired, yes is ``confirm_alias=True``, which the guard takes
and never passes on), rename refuses. Such a name in the middle, or with a
separator after it, is a name of its own and goes on. POSIX backends keep
their rules: ``...`` and ``a.`` are ordinary names on them.
"""

from __future__ import annotations

import errno

import pytest

from core.backend import ConfirmationRequired
from core.backend_guard import guard_class, has_parent_component, is_root_path, windows_alias_of


class _Win:
    def separator(self):
        return "\\"


class _Posix:
    literal_backslash_in_names = True

    def separator(self):
        return "/"


class _Smbish:
    def separator(self):
        return "/"


class _Backend:
    """A backend whose separator is a backslash, recording what reached it."""

    def __init__(self, sep="\\"):
        self.sep = sep
        self.calls: list[tuple] = []

    def separator(self):
        return self.sep

    def remove(self, path, recursive=False):
        self.calls.append(("remove", path, recursive))

    def rename(self, src, dst):
        self.calls.append(("rename", src, dst))

    def stat(self, path):
        raise FileNotFoundError(path)

    def open_read(self, path):
        raise FileNotFoundError(path)

    def list_dir(self, path):
        return []


guard_class(_Backend)

ROOTS = [
    "\\\\fileserver\\share", "\\\\fileserver\\share\\", "\\\\localhost\\C$", "\\\\server",
    "\\\\?\\C:\\", "\\\\.\\C:\\", "\\\\?\\C:", "\\\\?\\UNC\\fileserver\\share",
    "\\\\?\\Volume{0b1c}\\", "FileSystem::C:\\", "Microsoft.PowerShell.Core\\FileSystem::C:\\",
    "FileSystem::\\\\fs\\share", "HKLM:\\", "Cert:\\", "Env:", "hkcu:/", "C:\\ ", "C:\\...",
    "C:\\. .", "//fs/share/", "\\\\?\\C:\\...",
]


# -- happy ---------------------------------------------------------------------------------


@pytest.mark.parametrize("path", ROOTS)
def test_happy_every_windows_spelling_of_a_root_is_the_root(path):
    assert is_root_path(_Win(), path)


@pytest.mark.parametrize("path", ROOTS)
def test_happy_remove_and_rename_of_a_windows_root_are_refused(path):
    b = _Backend()
    with pytest.raises(PermissionError, match="refusing") as info:
        b.remove(path, recursive=True)
    assert info.value.errno == errno.EPERM
    with pytest.raises(PermissionError, match="refusing"):
        b.rename(path, "C:\\elsewhere")
    with pytest.raises(PermissionError, match="refusing"):
        b.rename("C:\\data\\x", path)
    assert b.calls == []


@pytest.mark.parametrize("path", [
    "C:\\Users", "\\\\fs\\share\\dir", "HKLM:\\SOFTWARE", "Cert:\\CurrentUser",
    "FileSystem::C:\\Users", "\\\\?\\UNC\\fs\\share\\d", "C:\\data\\report.", "C:\\x\\file::$DATA",
])
def test_happy_a_path_below_a_root_still_goes(path):
    b = _Backend()
    b.remove(path, recursive=True)
    assert b.calls == [("remove", path, True)]


# -- sad -----------------------------------------------------------------------------------


ALIASES = [("C:\\data\\...", "C:\\data"), ("C:\\data\\ ", "C:\\data"),
           ("C:\\data\\. .", "C:\\data"), ("\\\\fs\\share\\d\\..  ", "\\\\fs\\share\\d")]


@pytest.mark.parametrize("path,means", ALIASES)
def test_sad_unconfirmed_a_name_windows_reads_as_the_folder_above_asks(path, means):
    b = _Backend()
    with pytest.raises(ConfirmationRequired) as info:
        b.remove(path, recursive=True)
    exc = info.value
    assert exc.kind == "windows_alias" and exc.option == "confirm_alias"
    assert exc.details == {"means": means} and means in exc.explanation
    assert b.calls == []


@pytest.mark.parametrize("path,means", ALIASES)
def test_happy_confirmed_the_remove_goes_on_without_the_keyword(path, means):
    b = _Backend()
    b.remove(path, recursive=True, confirm_alias=True)
    assert b.calls == [("remove", path, True)]  # the backend never sees confirm_alias


@pytest.mark.parametrize("path,means", ALIASES)
def test_sad_rename_of_such_a_name_is_refused(path, means):
    b = _Backend()
    with pytest.raises(PermissionError, match="refusing") as info:
        b.rename(path, "C:\\x")
    assert not isinstance(info.value, ConfirmationRequired)
    with pytest.raises(PermissionError, match="refusing"):
        b.rename("C:\\x", path)
    assert b.calls == []


@pytest.mark.parametrize("path", ["C:\\data\\...\\", "C:\\a\\...\\b", "C:\\a\\x.",
                                  "C:\\a\\. .\\x"])
def test_edge_a_dots_name_that_is_not_last_is_a_name_of_its_own(path):
    assert windows_alias_of(_Win(), path) is None
    b = _Backend()
    b.remove(path, recursive=True)
    assert b.calls == [("remove", path, True)]


@pytest.mark.parametrize("path", ["FileSystem::C:\\Users\\..", "\\\\?\\C:\\x\\..",
                                  "\\\\fs\\share\\a\\..\\b"])
def test_sad_a_parent_component_behind_a_prefix_is_found(path):
    assert has_parent_component(_Win(), path)


# -- edge ----------------------------------------------------------------------------------


@pytest.mark.parametrize("path", ["/...", "/a.", "/d/. .", "/ "])
def test_edge_posix_backends_keep_dots_and_spaces_as_names(path):
    for backend in (_Posix(), _Smbish()):
        assert windows_alias_of(backend, path) is None
    b = _Backend(sep="/")
    b.remove(path, recursive=True)
    assert b.calls == [("remove", path, True)]


@pytest.mark.parametrize("path", ["\\\\fs\\share", "HKLM:\\", "FileSystem::C:\\"])
def test_edge_posix_rules_are_unchanged_for_windows_spellings(path):
    # Only a backslash backend reads them the Windows way; LocalFS on POSIX
    # takes the backslash as a name character, as before.
    assert not is_root_path(_Posix(), path)


def test_edge_a_drive_relative_parent_is_no_root():
    assert not is_root_path(_Win(), "C:..")
    assert has_parent_component(_Win(), "C:..")
    assert is_root_path(_Win(), "c:.")
