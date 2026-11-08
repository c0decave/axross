"""Connection errors show the cause's sentence, in the user's language.

Measured before (UX review round 4, Test Connection, German UI): SFTP said
"Cannot resolve host 'x': [Errno -2] Name or service not known", "Cannot
connect to 127.0.0.1:1: [Errno 111] Connection refused" (raised without
``from``), and "No existing session" when the server did not finish the
handshake in 10 s. core.proxy now chains its ConnectionError to the socket
error and names the host; core.user_errors.describe follows
``__cause__`` / ``__context__`` before it falls back to the text.
"""

from __future__ import annotations

import errno
import socket
import sys
from pathlib import Path
from unittest import mock

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core import i18n  # noqa: E402
from core.proxy import create_direct_socket  # noqa: E402
from core.user_errors import describe  # noqa: E402


@pytest.fixture(params=["en", "de"])
def lang(request):
    previous = i18n.active().language
    i18n.install(request.param)
    yield request.param
    i18n.install(previous)


def _raised(call):
    with pytest.raises(ConnectionError) as info:
        call()
    return info.value


def test_happy_unknown_host_is_one_translated_sentence(lang):
    gai = socket.gaierror(socket.EAI_NONAME, "Name or service not known")
    with mock.patch("core.proxy.socket.getaddrinfo", side_effect=gai):
        error = _raised(lambda: create_direct_socket("nonexistent.invalid", 22))
    assert error.__cause__ is gai
    text = describe(error)
    assert "nonexistent.invalid" in text
    assert "[Errno" not in text and "Cannot resolve" not in text
    assert ("DNS" in text) and (("auflösen" in text) if lang == "de" else ("resolved" in text))


def test_happy_refused_connection_names_the_host(lang):
    def refuse(self, address):
        raise ConnectionRefusedError(errno.ECONNREFUSED, "Connection refused")

    infos = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 1))]
    with mock.patch("core.proxy.socket.getaddrinfo", return_value=infos), \
            mock.patch.object(socket.socket, "connect", refuse):
        error = _raised(lambda: create_direct_socket("127.0.0.1", 1))
    assert isinstance(error.__cause__, ConnectionRefusedError)
    text = describe(error)
    assert text.startswith("127.0.0.1 ")
    assert "Connection refused" not in text and "[Errno" not in text
    assert ("abgelehnt" if lang == "de" else "refused the connection") in text


def test_sad_handshake_timeout_is_not_no_existing_session(lang):
    import paramiko

    text = describe(paramiko.SSHException("No existing session"), "10.255.255.1")
    assert "No existing session" not in text
    assert "10.255.255.1" in text
    assert ("SSH-Verbindungsaufbau" if lang == "de" else "SSH handshake") in text


def test_sad_banner_error_follows_its_context(lang):
    import paramiko

    try:
        try:
            raise ConnectionResetError(errno.ECONNRESET, "Connection reset by peer")
        except OSError as inner:
            raise paramiko.SSHException("Error reading SSH protocol banner" + str(inner))
    except paramiko.SSHException as outer:
        text = describe(outer)
    assert "banner" not in text and "[Errno" not in text
    assert ("geschlossen" if lang == "de" else "closed by the other side") in text


def test_edge_a_message_of_its_own_keeps_its_text():
    i18n.install("en")
    try:
        try:
            raise FileNotFoundError(errno.ENOENT, "No such file", "/x")
        except OSError:
            raise ValueError("Profile name “default” is reserved.")
    except ValueError as error:
        assert describe(error) == "Profile name “default” is reserved."


def test_edge_unknown_cause_keeps_the_outer_text():
    error = ConnectionError("SOCKS proxy answered 0x5b")
    error.__cause__ = KeyError("x")
    assert describe(error) == "SOCKS proxy answered 0x5b"
