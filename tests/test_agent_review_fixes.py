"""The 2026-11-07 Agent test: a server that answers with another model is said once; no two user turns in a row after a failed request; read_file pages with offset / next_offset within the tool-result limit."""

from __future__ import annotations

import pytest

from core import agent as A


@pytest.mark.parametrize("wanted, answered", [
    ("gpt-4o", "gpt-4o-2024-08-06"), ("qwen3", "qwen/qwen3"), ("llama3", "llama3:latest"),
    ("Qwen3.6-35B", "qwen3.6-35b"), ("m", None), ("m", ""), ("m", 5),
])
def test_happy_the_same_model_in_other_spellings_is_no_mismatch(wanted, answered):
    assert A.model_mismatch(wanted, answered) == ""


def test_sad_another_model_is_named():
    assert A.model_mismatch("no-such-model-xyz", "qwen3.6-35b-a3b-mlx@4bit") == "qwen3.6-35b-a3b-mlx@4bit"


def test_edge_the_notice_comes_once_per_agent():
    events = []
    profile = A.LLMProfile(name="x", provider="lmstudio", endpoint="http://127.0.0.1:1", model="wrong")
    payload = {"model": "loaded-one", "choices": [{"message": {"role": "assistant", "content": "hi"},
                                                    "finish_reason": "stop"}]}
    agent = A.Agent(A.AgentConfig(profile=profile, root="/"), on_event=events.append,
                    transport=lambda body: payload)
    agent._complete()
    agent._complete()
    notices = [e for e in events if e.get("type") == "notice" and "loaded-one" in e["text"]]
    assert len(notices) == 1


def test_edge_a_failed_request_leaves_no_two_user_turns_in_a_row():
    profile = A.LLMProfile(name="x", provider="lmstudio", endpoint="http://127.0.0.1:1", model="m")
    answers = iter([A.AgentError("down"), {"model": "m", "choices": [
        {"message": {"role": "assistant", "content": "ok"}, "finish_reason": "stop"}]}])

    def transport(body):
        a = next(answers)
        if isinstance(a, Exception):
            raise a
        return a

    agent = A.Agent(A.AgentConfig(profile=profile, root="/"), transport=transport)
    with pytest.raises(A.AgentError):
        agent.run("first")
    assert agent.run("second").answer == "ok"
    roles = [m["role"] for m in agent.messages]
    assert all(not (a == b == "user") for a, b in zip(roles, roles[1:]))
    assert "first" in agent.messages[1]["content"] and "second" in agent.messages[1]["content"]


def test_happy_the_agent_pages_a_large_file_to_its_end(tmp_path):
    """read_file with offset: a file larger than the tool-result limit is read
    to its end, each answer within the limit and next_offset where it stopped."""
    import json as _json

    big = "".join(f"line {i:05d} äöü\n" for i in range(3000)).encode()
    (tmp_path / "big.txt").write_bytes(big)
    profile = A.LLMProfile(name="x", provider="lmstudio", endpoint="http://127.0.0.1:1", model="m")
    agent = A.Agent(A.AgentConfig(profile=profile, root=str(tmp_path)), transport=lambda b: {})
    agent._ensure_built()
    got, offset, rounds = b"", 0, 0
    while True:
        rounds += 1
        call = {"function": {"name": "read_file",
                             "arguments": _json.dumps({"path": "big.txt", "encoding": "text",
                                                       **({"offset": offset} if offset else {})})}}
        _name, outcome, text = agent._run_tool(call)
        assert outcome == "ok", text
        assert len(agent._cut(text)) == len(text)        # nothing cut away
        body = _json.loads(text[text.index("{"):])
        got += body["text"].encode()
        if not body["truncated"]:
            break
        offset = body["next_offset"]
        assert rounds < 100
    assert got == big and rounds > 1


@pytest.mark.parametrize("seekable", [True, False])
def test_edge_read_file_offset_on_seekable_and_plain_streams(seekable):
    import base64
    import io

    from core import mcp_server as M

    data = bytes(range(256)) * 40

    class Plain(io.RawIOBase):
        def __init__(self):
            self._b = io.BytesIO(data)

        def readable(self):
            return True

        def readinto(self, buf):
            chunk = self._b.read(len(buf))
            buf[:len(chunk)] = chunk
            return len(chunk)

        def seekable(self):
            return False

    fh = io.BytesIO(data) if seekable else Plain()
    M._skip_stream(fh, 1000)
    assert fh.read(10) == data[1000:1010]
    assert M._utf8_tail("aä".encode()[:-1]) == 1 and M._utf8_tail("aä".encode()) == 0
    assert base64  # the tool path itself is held by test_happy_the_agent_pages_a_large_file_to_its_end
