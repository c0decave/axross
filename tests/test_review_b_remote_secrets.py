"""Review B, item 8: on a remote backend a secret file was known by its name
alone: a key in ``site/privkey.pem`` came out through grep and through a
read_file window that started inside the key (no BEGIN line in it).

Now grep hits and read windows of a remote are looked at like local ones
(the window with a margin around it, the walk back over a key block), and
``/proc/*/environ``, ``.bash_history``, ``rclone.conf`` and
``/etc/ssl/private/*`` are secret by their names on a remote too.
"""

from __future__ import annotations

import base64
import json
import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core import agent as A  # noqa: E402
from core import protected_places as P  # noqa: E402
from core.llm_profiles import LLMProfile  # noqa: E402
from core.local_fs import LocalFS  # noqa: E402

BODY = base64.encodebytes(bytes(range(256)) * 12).decode()
_MARK = "PRIVATE " + "KEY"  # split: the file holds no key line of its own
KEY = "-----BEGIN " + _MARK + "-----\n" + BODY + "-----END " + _MARK + "-----\n"


@pytest.fixture
def remote(tmp_path):
    site = tmp_path / "remote" / "site"
    site.mkdir(parents=True)
    (site / "privkey.pem").write_text(KEY)
    (site / "index.html").write_text("<p>hello</p>\n")
    root = tmp_path / "root"
    root.mkdir()
    cfg = A.AgentConfig(profile=LLMProfile(name="x"), root=str(root),
                        remote_backends=(("pane:web", LocalFS(), None),))
    agent = A.Agent(cfg, confirm=lambda n, a: False)
    agent._ensure_built()

    def call(name, **args):
        return agent._run_tool({"function": {"name": name, "arguments": json.dumps(
            {"backend": "pane:web", **args})}})[1:]

    call.site = site
    return call


def test_sad_a_read_window_inside_a_remote_key_is_refused(remote):
    outcome, text = remote("read_file", path=str(remote.site / "privkey.pem"),
                           encoding="text", offset=1200, max_bytes=600)
    assert outcome != "ok" and "private key" in text
    assert BODY[1300:1340] not in text


def test_sad_grep_on_a_remote_does_not_hand_out_a_key(remote):
    outcome, text = remote("grep", path=str(remote.site), pattern="[A-Za-z]")
    assert BODY.splitlines()[3] not in text
    assert "index.html" in text  # the other file is grepped


def test_happy_a_remote_file_without_a_key_is_read(remote):
    outcome, text = remote("read_file", path=str(remote.site / "index.html"), encoding="text")
    assert outcome == "ok" and "hello" in text


@pytest.mark.parametrize("path", ["/proc/1234/environ", "/proc/self/environ",
                                  "/home/u/.bash_history", "/root/.zsh_history",
                                  "/home/u/.config/rclone/rclone.conf", "/srv/rclone.conf",
                                  "/etc/ssl/private/server.key",
                                  "/etc/ssl/private/ssl-cert-snakeoil.key"])
def test_sad_more_names_are_secret_on_a_remote(path):
    assert P.remote_secret_refusal(path)


@pytest.mark.parametrize("path", ["/proc/1234/status", "/etc/ssl/certs/ca.pem",
                                  "/home/u/history.txt", "/srv/rclone.md"])
def test_happy_their_neighbours_are_not(path):
    assert P.remote_secret_refusal(path) is None
