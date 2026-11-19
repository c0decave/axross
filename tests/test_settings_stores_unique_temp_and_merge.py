"""Settings stores: a temp file of their own per save, settings.json merged
across processes.

Review 2026-11-20 (settings round 2), each reproduced before the fix:

* The RAM-disk, LLM, agent, voice, audio and logging settings and the
  chat server cache saved through one fixed temp name beside the file
  (``NAME.tmp``, ``NAME.json.tmp``), opened with O_TRUNC. Two axross
  processes saving at the same time truncated and wrote the same temp
  file; the first rename moved it into place while the second still
  wrote into it - a store mixed of both or cut short, the second save an
  error. Each save now writes a temp file of its own, named as core's
  atomic writes are (``.tmp-<12 hex>.tmp``, created exclusively, 0600),
  so an interrupted one is swept like theirs.
* The Python console's history compaction did the same with
  ``repl_history.tmp``.
* settings.json is shared by a dozen preferences and every axross
  process: write_setting read, changed and wrote it under a lock of its
  own process only. A second process that had read the file before and
  wrote after dropped the first one's change. The read-merge-write now
  holds a file lock (``settings.json.lock``) the other processes take as
  well.
"""

from __future__ import annotations

import json
import os
import re
import sys
import threading
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

TEMP_NAME = re.compile(r"^\.tmp-[0-9a-f]{12}\.tmp$")


@pytest.fixture
def replaced(monkeypatch):
    """The temp files the saves rename into place."""
    seen: list[str] = []
    real = os.replace

    def spy(src, dst, *a, **kw):
        seen.append(os.path.basename(os.fspath(src)))
        return real(src, dst, *a, **kw)

    monkeypatch.setattr(os, "replace", spy)
    return seen


def _ramfs(tmp_path, monkeypatch):
    from core import ramfs_settings as RS

    monkeypatch.setattr(RS, "CONFIG_DIR", tmp_path)
    monkeypatch.setattr(RS, "SETTINGS_FILE", tmp_path / "ramfs.json")
    RS.RamFsSettings().save()
    return tmp_path / "ramfs.json"


def _llm(tmp_path, monkeypatch):
    from core.llm_profiles import LLMSettings

    LLMSettings().save(tmp_path / "llm.json")
    return tmp_path / "llm.json"


def _agent(tmp_path, monkeypatch):
    from core.agent_settings import AgentSettings

    AgentSettings().save(tmp_path / "settings.json")
    return tmp_path / "settings.json"


def _voice(tmp_path, monkeypatch):
    from core.voice_settings import VoiceSettings

    VoiceSettings().save(tmp_path / "voice.json")
    return tmp_path / "voice.json"


def _audio(tmp_path, monkeypatch):
    from core.audio_settings import AudioSettings

    AudioSettings().save(tmp_path / "audio.json")
    return tmp_path / "audio.json"


def _logging(tmp_path, monkeypatch):
    from core.log_config import LogSettings

    LogSettings().save(tmp_path / "logging.json")
    return tmp_path / "logging.json"


STORES = [_ramfs, _llm, _agent, _voice, _audio, _logging]


@pytest.mark.parametrize("save", STORES, ids=lambda f: f.__name__.strip("_"))
def test_sad_each_save_writes_a_temp_file_of_its_own(save, tmp_path, monkeypatch, replaced):
    target = save(tmp_path, monkeypatch)
    save(tmp_path, monkeypatch)
    assert len(replaced) == 2
    assert all(TEMP_NAME.match(name) for name in replaced), replaced
    assert replaced[0] != replaced[1]
    json.loads(target.read_text(encoding="utf-8"))
    assert sorted(p.name for p in tmp_path.iterdir() if p.name.endswith(".tmp")) == []
    if os.name == "posix":
        assert target.stat().st_mode & 0o777 == 0o600


@pytest.mark.parametrize("save", STORES, ids=lambda f: f.__name__.strip("_"))
def test_edge_a_leftover_fixed_temp_name_does_not_stop_a_save(save, tmp_path, monkeypatch):
    """Another process's temp under the old fixed name (here a folder that
    cannot be opened as a file) is none of this save's business."""
    for name in ("ramfs.json.tmp", "llm.json.tmp", "settings.json.tmp", "voice.json.tmp",
                 "audio.json.tmp", "logging.json.tmp"):
        (tmp_path / name).mkdir()
    target = save(tmp_path, monkeypatch)
    json.loads(target.read_text(encoding="utf-8"))


def test_sad_the_chat_server_cache_writes_a_temp_file_of_its_own(tmp_path, replaced):
    from core import chat_servers as CS

    lists = [CS.bundled(p) for p in ("irc", "xmpp") if CS.bundled(p) is not None]
    if not lists:
        pytest.skip("no bundled chat server list")
    CS.save_cache(lists[0], cache=tmp_path)
    CS.save_cache(lists[0], cache=tmp_path)
    assert all(TEMP_NAME.match(name) for name in replaced), replaced
    assert replaced[0] != replaced[1]


def test_sad_the_console_history_compaction_writes_a_temp_file_of_its_own(
    tmp_path, monkeypatch, replaced
):
    pytest.importorskip("PyQt6.QtWidgets")
    from ui import repl_widget as RW

    monkeypatch.setattr(RW, "HISTORY_PATH", tmp_path / "repl_history")
    console = RW.ReplWidget.__new__(RW.ReplWidget)  # the history part only
    console._history = ["a = 1", "b = 2"]
    console._compact_history_file()
    console._compact_history_file()
    assert all(TEMP_NAME.match(name) for name in replaced), replaced
    assert replaced[0] != replaced[1]


@pytest.mark.skipif(os.name != "posix", reason="flock")
def test_sad_settings_json_keeps_the_change_of_another_process(tmp_path, monkeypatch):
    """Another process holds the store's file lock between its read and its
    write; this process's write waits for it and merges onto its result."""
    import fcntl

    from core import open_limits as OL

    path = tmp_path / "settings.json"
    path.write_text(json.dumps({"old": 1}), encoding="utf-8")
    monkeypatch.setattr(OL, "SETTINGS_PATH", path)

    other = os.open(str(path) + ".lock", os.O_RDWR | os.O_CREAT, 0o600)
    fcntl.flock(other, fcntl.LOCK_EX)  # the other process: read ...
    stale = json.loads(path.read_text(encoding="utf-8"))
    done = threading.Event()
    worker = threading.Thread(target=lambda: (OL.write_setting("ours", 2), done.set()))
    worker.start()
    try:
        time.sleep(0.3)
        stale["theirs"] = 3  # ... change, write, unlock
        path.write_text(json.dumps(stale), encoding="utf-8")
    finally:
        fcntl.flock(other, fcntl.LOCK_UN)
        os.close(other)
    worker.join(10)
    assert done.is_set()
    assert json.loads(path.read_text(encoding="utf-8")) == {"old": 1, "theirs": 3, "ours": 2}


def test_happy_write_setting_keeps_the_other_keys(tmp_path, monkeypatch, replaced):
    from core import open_limits as OL

    path = tmp_path / "settings.json"
    monkeypatch.setattr(OL, "SETTINGS_PATH", path)
    OL.write_setting("a", 1)
    OL.write_setting("b", [1, 2])
    assert json.loads(path.read_text(encoding="utf-8")) == {"a": 1, "b": [1, 2]}
    assert all(TEMP_NAME.match(name) for name in replaced), replaced
    if os.name == "posix":
        assert path.stat().st_mode & 0o777 == 0o600
