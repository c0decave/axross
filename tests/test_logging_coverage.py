"""Log lines where a failure used to vanish, and at the key operations.

* A backend's ``connected`` probe answered False on any exception without a
  word: the connection lamp went red and the log never said why. Each probe
  now logs the reason at DEBUG (the probe runs every few seconds: DEBUG,
  and the collapse of repeated records, keep it from flooding).
* An agent task logs its start and its end (profile, size of the task, the
  outcome, the tool calls, the time) - never the task's text.
* A further MCP server the agent uses logs when it is up and when it is
  closed; one that does not start says why.
* A transfer job logs its start at DEBUG (its end was already logged).
"""

from __future__ import annotations

import logging
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))


class _Boom:
    """Any attribute is a callable that raises - a dead connection handle."""

    def __init__(self, message="connection reset by peer"):
        self._message = message

    def __getattr__(self, name):
        def fail(*_a, **_k):
            raise ConnectionError(self._message)

        if name.startswith("__"):
            raise AttributeError(name)
        return _Chain(fail)


class _Chain:
    """``x.about().get(...).execute()`` - every step returns another chain,
    the call at the end raises."""

    def __init__(self, fail):
        self._fail = fail

    def __call__(self, *a, **k):
        return self._fail(*a, **k)

    def __getattr__(self, name):
        return _Chain(self._fail)


def _session(module, cls, **attrs):
    """A session object without __init__ (no network), *attrs* set on it."""
    klass = getattr(pytest.importorskip(module), cls)
    obj = object.__new__(klass)
    for key, value in attrs.items():
        setattr(obj, key, value)
    return obj


PROBES = [
    ("core.azure_client", "AzureBlobSession", {"_container": _Boom(), "_container_name": "c"}),
    ("core.azure_client", "AzureFilesSession", {"_share": _Boom(), "_share_name": "s"}),
    ("core.dropbox_client", "DropboxSession", {"_dbx": _Boom()}),
    ("core.gdrive_client", "GDriveSession", {"_service": _Boom()}),
    ("core.s3_client", "S3Session", {"_s3": _Boom(), "_bucket": "b"}),
    ("core.webdav_client", "WebDavSession", {"_client": _Boom()}),
    ("core.pop3_client", "Pop3Session", {"_pop": _Boom()}),
]


@pytest.mark.parametrize(("module", "cls", "attrs"), PROBES, ids=[p[1] for p in PROBES])
def test_sad_a_failed_liveness_probe_says_why(module, cls, attrs, caplog):
    session = _session(module, cls, **attrs)
    with caplog.at_level(logging.DEBUG, logger=module):
        assert session.connected is False
    records = [r for r in caplog.records if r.name == module and r.levelno == logging.DEBUG]
    assert records, f"{cls}.connected failed without a log line"
    assert "connection reset by peer" in records[-1].getMessage()


def test_sad_the_onedrive_probe_says_why(caplog):
    from core import onedrive_client as O

    session = object.__new__(O.OneDriveSession)
    session._drive_prefix = lambda: "/me/drive"
    session._graph_get = lambda url: (_ for _ in ()).throw(ConnectionError("token expired"))
    with caplog.at_level(logging.DEBUG, logger="core.onedrive_client"):
        assert session.connected is False
    assert any("token expired" in r.getMessage() for r in caplog.records)


def test_sad_the_smb_probe_and_exists_say_why(caplog, monkeypatch):
    smb = pytest.importorskip("core.smb_client")
    session = object.__new__(smb.SmbSession)
    session._prefix = "\\\\host\\share"
    session._port = 445
    session._host = "host"
    session._share = "share"
    def gone(*_a, **_k):
        raise OSError("STATUS_USER_SESSION_DELETED")

    monkeypatch.setattr(smb.smbclient, "listdir", gone)
    with caplog.at_level(logging.DEBUG, logger="core.smb_client"):
        assert session.connected is False
    assert any("STATUS_USER_SESSION_DELETED" in r.getMessage() for r in caplog.records)
    caplog.clear()
    monkeypatch.setattr(session, "_unc", lambda path: path, raising=False)
    monkeypatch.setattr(smb.smbclient.path, "exists",
                        lambda *a, **k: (_ for _ in ()).throw(OSError("STATUS_ACCESS_DENIED")))
    with caplog.at_level(logging.DEBUG, logger="core.smb_client"):
        assert session._exists_quietly("/a.txt") is False
    assert any("STATUS_ACCESS_DENIED" in r.getMessage() for r in caplog.records)


def test_sad_the_ftp_imap_and_telnet_probes_say_why(caplog):
    from core import ftp_client, imap_client, telnet_client

    ftp = object.__new__(ftp_client.FtpSession)
    ftp._ftp = _Boom("421 timeout")
    imap = object.__new__(imap_client.ImapSession)
    imap._imap = _Boom("BYE logging out")
    telnet = object.__new__(telnet_client.TelnetSession)
    telnet._connected = True
    telnet._shell = _Boom("telnet EOF")
    with caplog.at_level(logging.DEBUG):
        for session in (ftp, imap, telnet):
            try:
                assert session.connected is False
            except AttributeError:  # a lock the bare object lacks
                pytest.skip("the probe needs the session lock")
    text = "\n".join(r.getMessage() for r in caplog.records)
    for needle in ("421 timeout", "BYE logging out", "telnet EOF"):
        assert needle in text


def test_happy_a_working_probe_logs_nothing(caplog):
    from core import s3_client

    class _Fine:
        def head_bucket(self, **_k):
            return {}

    session = _session("core.s3_client", "S3Session", _s3=_Fine(), _bucket="b")
    with caplog.at_level(logging.DEBUG, logger="core.s3_client"):
        assert session.connected is True
    assert not [r for r in caplog.records if r.name == "core.s3_client"]
    assert s3_client  # imported


def test_edge_a_probe_at_info_makes_no_record(caplog):
    session = _session("core.s3_client", "S3Session", _s3=_Boom(), _bucket="b")
    with caplog.at_level(logging.INFO, logger="core.s3_client"):
        assert session.connected is False
    assert not [r for r in caplog.records if r.name == "core.s3_client"]


# -- the agent --------------------------------------------------------------------------------


def test_happy_an_agent_task_logs_start_and_end_without_its_text(tmp_path, caplog):
    from core import agent as A
    from tests.test_agent_files_read_only import _config, _Script

    secret_task = "summarise the file with password hunter2"
    model = _Script([{"role": "assistant", "content": "done"}])
    with caplog.at_level(logging.INFO, logger="core.agent"):
        result = A.Agent(_config(tmp_path), transport=model, confirm=lambda *_: True).run(
            secret_task)
    assert result.stopped == "answered"
    lines = [r.getMessage() for r in caplog.records if r.name == "core.agent"]
    starts = [ln for ln in lines if "event=agent.task.start" in ln]
    ends = [ln for ln in lines if "event=agent.task.end" in ln]
    assert len(starts) == 1 and len(ends) == 1, lines
    assert f"task_chars={len(secret_task)}" in starts[0]
    assert "stopped='answered'" in ends[0] and f"tool_calls={len(result.calls)}" in ends[0]
    assert all("hunter2" not in ln and "summarise" not in ln for ln in lines)


def test_sad_an_agent_task_that_fails_logs_its_end_with_the_error(tmp_path, caplog):
    from core import agent as A
    from tests.test_agent_files_read_only import _config

    class _Dead:
        def __call__(self, *a, **k):
            raise A.AgentError("the LLM server is not reachable")

        def __getattr__(self, name):
            return self

    with caplog.at_level(logging.INFO, logger="core.agent"):
        with pytest.raises(A.AgentError):
            A.Agent(_config(tmp_path), transport=_Dead(), confirm=lambda *_: True).run("x")
    ends = [r for r in caplog.records if "event=agent.task.end" in r.getMessage()]
    assert len(ends) == 1 and ends[0].levelno == logging.WARNING
    assert "not reachable" in ends[0].getMessage()


# -- MCP client ---------------------------------------------------------------------------------


def test_happy_an_mcp_server_logs_up_and_closed(tmp_path, caplog):
    from core import mcp_client as C
    from tests.test_mcp_client import FAKE

    script = tmp_path / "fake_mcp.py"
    script.write_text(FAKE)
    config = C.McpServerConfig(name="fake", command=(sys.executable, str(script), "normal"))
    with caplog.at_level(logging.INFO, logger="core.mcp_client"):
        client = C.McpClient(config)
        client.close()
    lines = [r.getMessage() for r in caplog.records if r.name == "core.mcp_client"]
    assert any("event=mcp.client.up" in ln and "server='fake'" in ln for ln in lines), lines
    assert any("event=mcp.client.closed" in ln for ln in lines), lines


def test_sad_an_mcp_server_that_does_not_start_says_why(tmp_path, caplog):
    from core import mcp_client as C
    from tests.test_mcp_client import FAKE

    script = tmp_path / "fake_mcp.py"
    script.write_text(FAKE)
    config = C.McpServerConfig(name="dying", command=(sys.executable, str(script), "die"))
    with caplog.at_level(logging.INFO, logger="core.mcp_client"):
        with pytest.raises(C.McpClientError):
            C.McpClient(config)
    warn = [r for r in caplog.records if r.name == "core.mcp_client"
            and r.levelno == logging.WARNING]
    assert warn and "dying" in warn[0].getMessage()


# -- transfers --------------------------------------------------------------------------------


def test_happy_a_transfer_job_logs_its_start_at_debug():
    source = (ROOT / "core" / "transfer_worker.py").read_text(encoding="utf-8")
    body = source[source.index("    def _process_job(self, job"):]
    body = body[:body.index("\n    def ", 10)]
    assert 'log.debug("Transfer started:' in body


# -- smaller silent spots -----------------------------------------------------------------------


def test_sad_an_ftp_hash_command_that_breaks_is_logged_and_the_next_one_tried(caplog):
    from core import ftp_client

    sent = []

    class _Ftp:
        def sendcmd(self, text):
            sent.append(text)
            raise TimeoutError("data channel timed out")

    session = object.__new__(ftp_client.FtpSession)
    session._ensure_connected = lambda: _Ftp()
    with caplog.at_level(logging.DEBUG, logger="core.ftp_client"):
        assert session.checksum("/a.bin", "sha256") == ""
    assert [t.split()[0] for t in sent] == ["HASH", "XSHA256"]
    assert sum("data channel timed out" in r.getMessage() for r in caplog.records) == 2


def test_sad_the_open_as_root_probe_says_why_it_is_hidden(caplog, monkeypatch):
    pytest.importorskip("PyQt6.QtWidgets")
    from core import elevated_io as E
    from ui.file_pane import FilePaneWidget

    def broken(_backend):
        raise RuntimeError("registry not loaded")

    monkeypatch.setattr(E, "_is_local_backend", broken)
    fake = type("Pane", (), {"_backend": object()})()
    with caplog.at_level(logging.DEBUG, logger="ui.file_pane"):
        assert FilePaneWidget._elevated_io_available(fake) is False
    assert any("registry not loaded" in r.getMessage() for r in caplog.records)
