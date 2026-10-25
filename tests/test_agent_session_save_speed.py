"""Saving an agent session encodes it in one go, then writes it.

Measured 2026-10-25 (perf/llm-agent, scratch bench_save.py): SessionStore.save
ran on the GUI thread at every Send, at the end of every task and on every
detach/attach, and took 29 ms for a 3.8 MB session (850 transcript lines),
57 ms for 7.7 MB. json.dump streams through the pure-Python encoder;
json.dumps uses the C encoder (also with indent) and gives the same text:
24 ms. Encoding first also means a session that cannot be encoded never
leaves a half-written temporary file behind.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core.agent_session import AgentSession, SessionStore  # noqa: E402


def _session(**kw) -> AgentSession:
    return AgentSession(
        title="Disk report",
        folder="/srv/data",
        transcript=[{"who": "You:", "text": "Größe von 日本 & <b>?", "muted": False},
                    {"who": "Thinking:", "text": "line one\nline two", "muted": True,
                     "kind": "reasoning"}],
        messages=[{"role": "system", "content": "rules"},
                  {"role": "tool", "tool_call_id": "c1", "content": "x" * 5000 + " é"}],
        **kw,
    )


# -- happy ------------------------------------------------------------------------------------


def test_happy_the_file_is_the_same_text_as_before(tmp_path):
    store = SessionStore(tmp_path)
    session = _session()
    store.save(session)
    raw = store.path(session.id).read_bytes()
    # What json.dump(..., ensure_ascii=False, indent=1) wrote before.
    assert raw == json.dumps(session.to_dict(), ensure_ascii=False, indent=1).encode("utf-8")
    back = store.load(session.id)
    assert back.transcript == session.transcript and back.messages == session.messages


@pytest.mark.skipif(json.encoder.c_make_encoder is None, reason="no C JSON encoder here")
def test_happy_saving_does_not_stream_through_the_python_encoder(tmp_path, monkeypatch):
    import json.encoder as E

    def python_encoder(*_a, **_k):
        raise AssertionError("the pure-Python JSON encoder was used")

    monkeypatch.setattr(E, "_make_iterencode", python_encoder)
    store = SessionStore(tmp_path)
    session = _session()
    store.save(session)
    assert store.load(session.id).title == "Disk report"


# -- sad --------------------------------------------------------------------------------------


def test_sad_a_session_that_cannot_be_encoded_leaves_the_old_file_and_no_temp(tmp_path):
    store = SessionStore(tmp_path)
    session = _session()
    store.save(session)
    before = store.path(session.id).read_bytes()
    session.messages.append({"role": "tool", "content": object()})
    with pytest.raises(TypeError):
        store.save(session)
    assert store.path(session.id).read_bytes() == before
    assert sorted(p.name for p in tmp_path.iterdir()) == [f"{session.id}.json"]


def test_sad_text_that_is_no_unicode_is_refused_as_before(tmp_path):
    store = SessionStore(tmp_path)
    session = _session()
    session.transcript.append({"who": "Agent:", "text": "bad \udcff byte", "muted": False})
    with pytest.raises(UnicodeEncodeError):
        store.save(session)
    assert list(tmp_path.iterdir()) == []


def test_sad_a_folder_that_is_a_file_raises_oserror(tmp_path):
    blocker = tmp_path / "sessions"
    blocker.write_text("not a folder")
    with pytest.raises(OSError):
        SessionStore(blocker).save(_session())
    assert blocker.read_text() == "not a folder"


# -- edge -------------------------------------------------------------------------------------


def test_edge_an_empty_session_and_a_large_one_round_trip(tmp_path):
    store = SessionStore(tmp_path)
    empty = AgentSession()
    store.save(empty)
    assert store.load(empty.id).transcript == []
    big = _session()
    big.messages += [{"role": "tool", "content": "ä" * 20000} for _ in range(50)]
    store.save(big)
    raw = store.path(big.id).read_bytes()
    assert raw == json.dumps(big.to_dict(), ensure_ascii=False, indent=1).encode("utf-8")
    assert len(store.load(big.id).messages) == 52


def test_edge_the_file_stays_private(tmp_path):
    store = SessionStore(tmp_path / "sessions")
    session = _session()
    store.save(session)
    store.save(session)  # replaced, still 0600
    assert (store.path(session.id).stat().st_mode & 0o777) == 0o600
    assert ((tmp_path / "sessions").stat().st_mode & 0o777) == 0o700
