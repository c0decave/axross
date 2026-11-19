"""Second security review: the code of the axross that runs was not a
protected place. Run from a source folder (a checkout, ``pip install -e``)
inside the MCP root or an agent's folder, the agent's write tools could
rewrite ``core/agent.py`` or ``main.py`` - and the next start of axross ran
it with the user's rights, outside any sandbox. (Its venv's site-packages
were protected already, as every site-packages folder in a home on
sys.path.) Now its packages and top-level scripts, a one-file build's
binary and the venv's pyvenv.cfg and bin folder are refused."""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from core import mcp_server as M  # noqa: E402
from core import protected_places as P  # noqa: E402
from core.local_fs import LocalFS  # noqa: E402


@pytest.mark.parametrize("rel", ["core/agent.py", "main.py", "ui/agent_dock.py", "axross/_version.py",
                                 "core/new_module.py", "resources/extensions/x.py"])
def test_sad_the_running_axross_s_code_is_protected(rel):
    assert P.refusal(str(ROOT / rel)) is not None


def test_sad_the_mcp_write_tools_do_not_add_code_to_axross_itself():
    # a new module (never an existing file: the repro must not change axross)
    probe = ROOT / "core" / "_own_code_probe_never_written.py"
    tools = {t.name: t for t in M._build_tools(LocalFS(), allow_write=True, backend_id="local",
                                               root=str(ROOT))}
    try:
        with pytest.raises(PermissionError):
            tools["write_file"].handler({"path": str(probe), "content": "import os\n"},
                                        M._ToolContext())
        assert not probe.exists()
    finally:
        if probe.exists():
            probe.unlink()


def test_happy_other_files_of_the_folder_stay_writable(tmp_path):
    assert P.refusal(str(ROOT / "docs" / "some-notes.md")) is None
    assert P.refusal(str(tmp_path / "core" / "agent.py")) is None


def test_happy_a_one_file_build_protects_its_binary(monkeypatch, tmp_path):
    binary = tmp_path / "axross-full"
    binary.write_bytes(b"\x7fELF")
    monkeypatch.setattr(sys, "frozen", True, raising=False)
    monkeypatch.setattr(sys, "executable", str(binary))
    P.own_code_places.cache_clear()
    try:
        assert (str(binary), False) in P.own_code_places()
        assert P.refusal(str(binary)) is not None
    finally:
        monkeypatch.undo()
        P.own_code_places.cache_clear()
