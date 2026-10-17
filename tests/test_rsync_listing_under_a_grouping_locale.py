"""rsync listings parse under a locale that groups digits with '.'.

rsync prints sizes with the locale's thousands separator (LC_NUMERIC).
Under de_DE.UTF-8 a 123456-byte file is listed as ``123.456``; the size
pattern only knew ``,``, the line fell through to the module-listing
parser and the file showed up as a FOLDER named ``-rw-r--r--`` with
size 0. The child now runs with LC_NUMERIC=C (LC_ALL, which would
override it, is narrowed to LC_CTYPE so UTF-8 names keep working) and
the parser accepts any grouping separator.
"""

from __future__ import annotations

import shutil
import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core import rsync_client as R  # noqa: E402
from tests.test_rsync_remove_folder import rsyncd  # noqa: E402,F401 - the daemon fixture

_HAS_RSYNC = shutil.which("rsync") is not None


def _has_locale(name: str) -> bool:
    try:
        out = subprocess.run(["locale", "-a"], capture_output=True, text=True, timeout=5).stdout
    except (OSError, subprocess.SubprocessError):
        return False
    wanted = name.lower().replace("-", "")
    return any(line.lower().replace("-", "") == wanted for line in out.splitlines())


@pytest.fixture
def german(monkeypatch):
    if not _has_locale("de_DE.utf8"):
        pytest.skip("de_DE.UTF-8 locale not installed")
    monkeypatch.setenv("LANG", "de_DE.UTF-8")
    monkeypatch.setenv("LC_ALL", "de_DE.UTF-8")


# -- happy -------------------------------------------------------------------


@pytest.mark.skipif(not _HAS_RSYNC, reason="rsync binary not installed")
def test_happy_a_file_lists_as_a_file_with_its_size_under_de_de(rsyncd, german):  # noqa: F811
    session, data = rsyncd
    (data / "big.bin").write_bytes(b"\0" * 123456)
    items = {i.name: i for i in session.list_dir("/")}
    assert "-rw-r--r--" not in items
    assert items["big.bin"].size == 123456
    assert items["big.bin"].is_dir is False
    assert items["tree"].is_dir is True


@pytest.mark.skipif(not _HAS_RSYNC, reason="rsync binary not installed")
def test_happy_stat_reads_the_size_under_de_de(rsyncd, german):  # noqa: F811
    session, data = rsyncd
    (data / "big.bin").write_bytes(b"\0" * 1234567)
    st = session.stat("/big.bin")
    assert st.size == 1234567 and st.is_dir is False


def test_happy_the_child_env_prints_numbers_in_the_c_locale(monkeypatch):
    monkeypatch.setenv("LANG", "de_DE.UTF-8")
    monkeypatch.setenv("LC_ALL", "de_DE.UTF-8")
    env = R._build_allowlisted_env()
    assert env["LC_NUMERIC"] == "C"
    assert "LC_ALL" not in env
    # Names keep the caller's character set.
    assert env["LC_CTYPE"] == "de_DE.UTF-8"


# -- sad ---------------------------------------------------------------------


@pytest.mark.parametrize(
    "line",
    [
        "-rw-r--r--        123.456 2024/01/15 10:30:00 big.bin",
        "-rw-r--r--        123,456 2024/01/15 10:30:00 big.bin",
        "-rw-r--r--        123'456 2024/01/15 10:30:00 big.bin",
        "-rw-r--r--         123456 2024/01/15 10:30:00 big.bin",
    ],
)
def test_sad_every_grouping_separator_parses_to_the_same_size(line):
    m = R._LIST_RE.match(line)
    assert m is not None
    assert R._size_from_listing(m.group("size")) == 123456
    assert m.group("name") == "big.bin"


def test_sad_progress_lines_with_a_dot_separator_parse(monkeypatch):
    m = R._PROGRESS_RE.match("      1.234.567  42%   12,34MB/s    0:00:03")
    assert m is not None
    assert R._size_from_listing(m.group("bytes")) == 1234567


# -- edge --------------------------------------------------------------------


def test_edge_lc_ctype_wins_over_lang_and_no_locale_stays_empty(monkeypatch):
    for var in ("LANG", "LC_ALL", "LC_CTYPE"):
        monkeypatch.delenv(var, raising=False)
    env = R._build_allowlisted_env()
    assert env["LC_NUMERIC"] == "C"
    assert "LC_CTYPE" not in env and "LC_ALL" not in env
    monkeypatch.setenv("LANG", "fr_FR.UTF-8")
    monkeypatch.setenv("LC_CTYPE", "C.UTF-8")
    env = R._build_allowlisted_env()
    assert env["LC_CTYPE"] == "C.UTF-8" and env["LANG"] == "fr_FR.UTF-8"


def test_edge_a_name_with_digits_and_dots_keeps_its_name():
    m = R._LIST_RE.match("-rw-r--r--          1.024 2024/01/15 10:30:00 1.024 v2.0.tar")
    assert m is not None
    assert R._size_from_listing(m.group("size")) == 1024
    assert m.group("name") == "1.024 v2.0.tar"
