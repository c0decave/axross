"""The suite never writes the user's own configuration or keyring.

Before tests/conftest.py, a run wrote the real ~/.config/axross: a test
window's session.json, visit_history.json full of test hosts and an empty
profiles.json. Paths such as core.i18n.SETTINGS_FILE are taken from
Path.home() at import, so the home is swapped before any test module loads.
"""

from __future__ import annotations

import os
import subprocess
import sys
import tempfile
from pathlib import Path


def test_happy_home_is_a_private_temp_dir() -> None:
    home = Path.home().resolve()
    assert home.is_relative_to(Path(tempfile.gettempdir()).resolve()), home
    for name in ("XDG_CONFIG_HOME", "XDG_DATA_HOME", "XDG_CACHE_HOME", "XDG_STATE_HOME"):
        assert Path(os.environ[name]).resolve().is_relative_to(home), name


def test_happy_paths_taken_at_import_are_inside_it() -> None:
    from core import i18n

    assert i18n.SETTINGS_FILE.resolve().is_relative_to(Path.home().resolve())


def test_sad_the_keyring_is_the_null_backend() -> None:
    assert os.environ.get("PYTHON_KEYRING_BACKEND") == "keyring.backends.null.Keyring"


def test_edge_a_child_python_still_finds_the_user_site() -> None:
    # The user site lives under the real home; PYTHONUSERBASE keeps it.
    probe = "import site, sys; print(site.ENABLE_USER_SITE, site.getusersitepackages() in sys.path)"
    out = subprocess.run([sys.executable, "-c", probe], capture_output=True, text=True, check=True)
    import site

    expected = f"{site.ENABLE_USER_SITE} {site.getusersitepackages() in sys.path}"
    assert out.stdout.strip() == expected
