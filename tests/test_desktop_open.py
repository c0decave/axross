"""Opening files and web pages from a frozen build.

QDesktopServices.openUrl and Python's webbrowser start a host program
(xdg-open, a browser, /bin/sh) with this process's environment and take no
other. Reproduced 2026-10-22 with dist/axross-full 0.13.22 and a stub
xdg-open first on PATH: ``QDesktopServices.openUrl`` (xcb) returned True,
``webbrowser.open`` returned False, and both children died with
"/bin/sh: symbol lookup error: /bin/sh: undefined symbol:
rl_trim_arg_from_keyseq" - nothing opened. So Open with Default
Application, the Extensions folder, the download link, the Scripting Guide's
links and every browser-based login (Dropbox, Google Drive, OneDrive) did
nothing in a shipped build.

The stub xdg-open used here is a real program: it records the target and
the LD_LIBRARY_PATH it was started with.
"""

from __future__ import annotations

import os
import sys
import time
import webbrowser
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from core import desktop_open  # noqa: E402

FAKE_BUNDLE = "/tmp/_MEIfake"


@pytest.fixture
def stub_opener(tmp_path, monkeypatch):
    """A recording xdg-open first on PATH; returns a function that waits
    for and returns the recorded lines."""
    bindir = tmp_path / "bin"
    bindir.mkdir()
    log = tmp_path / "opened.log"
    stub = bindir / "xdg-open"
    stub.write_text(
        f"#!{sys.executable}\n"
        "import os, sys\n"
        f"with open({str(log)!r}, 'a') as fh:\n"
        "    fh.write(sys.argv[1] + '|' + os.environ.get('LD_LIBRARY_PATH', '<unset>') + '\\n')\n",
        encoding="utf-8",
    )
    stub.chmod(0o755)
    monkeypatch.setenv("PATH", f"{bindir}{os.pathsep}{os.environ.get('PATH', '')}")

    def opened(count: int = 1, timeout: float = 10.0) -> list[str]:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if log.exists():
                lines = log.read_text().splitlines()
                if len(lines) >= count:
                    return lines
            time.sleep(0.05)
        return log.read_text().splitlines() if log.exists() else []

    return opened


@pytest.fixture
def frozen_bundle(monkeypatch):
    """A frozen one-file build on Linux without an own LD_LIBRARY_PATH."""
    monkeypatch.setattr(sys, "frozen", True, raising=False)
    monkeypatch.setattr(desktop_open.sys, "platform", "linux")
    monkeypatch.setenv("LD_LIBRARY_PATH", FAKE_BUNDLE)
    monkeypatch.delenv("LD_LIBRARY_PATH_ORIG", raising=False)


@pytest.fixture
def qt_open(monkeypatch):
    """Records what reaches QDesktopServices.openUrl."""
    from PyQt6.QtGui import QDesktopServices

    seen: list[str] = []

    def fake(url):
        seen.append(url.toString())
        return True

    monkeypatch.setattr(QDesktopServices, "openUrl", staticmethod(fake))
    return seen


@pytest.fixture
def isolated_webbrowser(monkeypatch):
    """webbrowser's registry is process-wide: give each test its own."""
    monkeypatch.setattr(webbrowser, "_browsers", {})
    monkeypatch.setattr(webbrowser, "_tryorder", [])
    monkeypatch.setattr(desktop_open, "_installed", False)


# -- open_url -------------------------------------------------------------------------------


def test_happy_a_frozen_build_opens_a_file_through_a_clean_xdg_open(
        frozen_bundle, stub_opener, qt_open, tmp_path):
    target = tmp_path / "report one.txt"
    target.write_text("x")
    assert desktop_open.open_url(str(target)) is True
    assert stub_opener() == [f"{target}|<unset>"]
    assert qt_open == []


def test_happy_a_frozen_build_opens_a_web_page_through_a_clean_xdg_open(
        frozen_bundle, stub_opener, qt_open):
    from PyQt6.QtCore import QUrl

    assert desktop_open.open_url(QUrl("https://example.invalid/a b")) is True
    assert stub_opener() == ["https://example.invalid/a%20b|<unset>"]


def test_happy_from_source_qt_opens_as_before(monkeypatch, stub_opener, qt_open, tmp_path):
    monkeypatch.delattr(sys, "frozen", raising=False)
    assert desktop_open.open_url(str(tmp_path)) is True
    assert qt_open == [f"file://{tmp_path}"]
    assert stub_opener(timeout=0.3) == []


def test_sad_without_xdg_open_a_frozen_build_falls_back_to_qt(frozen_bundle, monkeypatch,
                                                             qt_open, tmp_path):
    monkeypatch.setattr(desktop_open.shutil, "which", lambda name: None)
    assert desktop_open.open_url(str(tmp_path)) is True
    assert qt_open == [f"file://{tmp_path}"]


def test_sad_an_xdg_open_that_cannot_start_falls_back_to_qt(frozen_bundle, monkeypatch,
                                                           qt_open, tmp_path):
    def refuse(*args, **kwargs):
        raise PermissionError("not executable")

    monkeypatch.setattr(desktop_open.shutil, "which", lambda name: "/usr/bin/xdg-open")
    monkeypatch.setattr(desktop_open.subprocess, "Popen", refuse)
    assert desktop_open.open_url(str(tmp_path)) is True
    assert qt_open == [f"file://{tmp_path}"]


def test_sad_a_target_that_looks_like_an_option_is_never_handed_to_xdg_open(
        frozen_bundle, stub_opener):
    assert desktop_open.spawn_opener("--version") is False
    assert stub_opener(timeout=0.3) == []


def test_edge_a_frozen_macos_build_keeps_qt(frozen_bundle, monkeypatch, stub_opener, qt_open,
                                           tmp_path):
    """Qt opens through LaunchServices there - no child process."""
    monkeypatch.setattr(desktop_open.sys, "platform", "darwin")
    assert desktop_open.open_url(str(tmp_path)) is True
    assert qt_open == [f"file://{tmp_path}"]
    assert stub_opener(timeout=0.3) == []


def test_edge_the_users_own_library_path_reaches_the_opener(frozen_bundle, monkeypatch,
                                                           stub_opener, tmp_path):
    monkeypatch.setenv("LD_LIBRARY_PATH", f"{FAKE_BUNDLE}:/opt/mine")
    monkeypatch.setenv("LD_LIBRARY_PATH_ORIG", "/opt/mine")
    assert desktop_open.open_url(str(tmp_path)) is True
    assert stub_opener() == [f"{tmp_path}|/opt/mine"]


# -- webbrowser (Dropbox's login; the Google and Microsoft libraries use it too) ------------


def test_happy_webbrowser_opens_through_a_clean_xdg_open_once_installed(
        frozen_bundle, stub_opener, isolated_webbrowser):
    assert desktop_open.install_clean_webbrowser() is True
    assert webbrowser.open("https://login.example.invalid/?a=1") is True
    assert stub_opener() == ["https://login.example.invalid/?a=1|<unset>"]


def test_happy_the_headless_browser_open_uses_the_clean_opener(frozen_bundle, stub_opener,
                                                              isolated_webbrowser):
    assert desktop_open.open_in_browser("https://www.dropbox.com/oauth2/authorize?x=1") is True
    assert stub_opener() == ["https://www.dropbox.com/oauth2/authorize?x=1|<unset>"]


def test_edge_from_source_the_headless_browser_open_is_webbrowsers(monkeypatch,
                                                                  isolated_webbrowser):
    opened = []

    class Fake(webbrowser.BaseBrowser):
        def open(self, url, new=0, autoraise=True):
            opened.append(url)
            return True

    monkeypatch.delattr(sys, "frozen", raising=False)
    webbrowser.register("fake", None, Fake("fake"), preferred=True)
    assert desktop_open.open_in_browser("https://x.invalid/") is True
    assert opened == ["https://x.invalid/"]


def test_sad_from_source_webbrowser_is_left_alone(monkeypatch, isolated_webbrowser):
    monkeypatch.delattr(sys, "frozen", raising=False)
    assert desktop_open.install_clean_webbrowser() is False
    assert webbrowser._tryorder == []


def test_sad_without_xdg_open_webbrowser_is_left_alone(frozen_bundle, monkeypatch,
                                                      isolated_webbrowser):
    monkeypatch.setattr(desktop_open.shutil, "which", lambda name: None)
    assert desktop_open.install_clean_webbrowser() is False
    assert webbrowser._tryorder == []


def test_edge_the_clean_browser_comes_before_every_other_choice(
        frozen_bundle, stub_opener, isolated_webbrowser):
    """Also before $BROWSER, which webbrowser would start with the
    inherited environment - xdg-open itself still honours $BROWSER."""
    webbrowser.register("firefox", None, webbrowser.BackgroundBrowser("firefox"), preferred=True)
    desktop_open.install_clean_webbrowser()
    assert isinstance(webbrowser.get(), desktop_open.CleanEnvBrowser)


def test_edge_installing_twice_registers_the_browser_once(frozen_bundle, stub_opener,
                                                          isolated_webbrowser):
    assert desktop_open.install_clean_webbrowser() is True
    assert desktop_open.install_clean_webbrowser() is True
    assert webbrowser._tryorder.count(desktop_open.BROWSER_NAME) == 1


# -- the call sites, through the real widgets -----------------------------------------------


@pytest.fixture
def qapp():
    from PyQt6.QtWidgets import QApplication

    return QApplication.instance() or QApplication([])


def test_e2e_the_download_button_of_a_frozen_build_opens_the_release_page(
        qapp, frozen_bundle, stub_opener, qt_open):
    from PyQt6.QtCore import Qt
    from PyQt6.QtTest import QTest

    from core import features as F
    from ui.features_dialog import FeaturesDialog

    dialog = FeaturesDialog(version="0.13.38", runner=lambda *a: None)
    try:
        dialog.show()
        assert dialog.download_button.isVisible()  # only a frozen build shows it
        QTest.mouseClick(dialog.download_button, Qt.MouseButton.LeftButton)
        assert stub_opener() == [f"{F.download_url('0.13.38')}|<unset>"]
        assert qt_open == []
    finally:
        dialog.close()
        dialog.deleteLater()


def test_e2e_open_with_default_application_uses_the_clean_opener(frozen_bundle, stub_opener,
                                                                qt_open, tmp_path):
    from core.local_fs import LocalFS
    from core.previews import open_externally

    target = tmp_path / "photo.jpg"
    target.write_bytes(b"\xff\xd8")
    open_externally(LocalFS(), str(target))
    assert stub_opener() == [f"{target}|<unset>"]


def test_e2e_the_extensions_folder_opens_through_the_clean_opener(qapp, frozen_bundle,
                                                                 stub_opener, qt_open):
    from core import extensions as EX
    from ui.extensions_dialog import open_extensions_folder

    open_extensions_folder()
    assert stub_opener() == [f"{EX.extensions_dir()}|<unset>"]


def test_e2e_a_web_link_in_the_scripting_guide_uses_the_clean_opener(qapp, frozen_bundle,
                                                                    stub_opener, qt_open):
    from PyQt6.QtCore import QUrl

    from ui.scripting_guide import ScriptingGuideDialog

    dialog = ScriptingGuideDialog()
    try:
        dialog.guide.anchorClicked.emit(QUrl("https://example.invalid/docs"))
        assert stub_opener() == ["https://example.invalid/docs|<unset>"]
    finally:
        dialog.close()
        dialog.deleteLater()
