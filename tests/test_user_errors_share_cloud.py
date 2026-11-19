"""core.user_errors.describe for the SMB / WebDAV / S3 / Azure failures
users hit at connect time (connection review, 2026-11).

* A refused port behind requests / urllib3 (WebDAV, Azure) was described
  as "did not answer in time": urllib3's NewConnectionError is a subclass
  of ConnectTimeoutError, and the time-out rule matched it before the
  ConnectionRefusedError it was raised from.
* smbprotocol's LogonFailure (a wrong SMB password) was shown as the raw
  "Received unexpected status from the server: The attempted logon is
  invalid ... (3221225581) STATUS_LOGON_FAILURE: 0xc000006d - Raw: a107...".
"""

from __future__ import annotations

import errno
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core.user_errors import describe  # noqa: E402


def _refused_through_urllib3() -> BaseException:
    """What requests raises for a closed port: requests.ConnectionError
    <- urllib3 MaxRetryError <- NewConnectionError <- ConnectionRefusedError,
    raised the way the libraries raise it."""
    urllib3 = pytest.importorskip("urllib3")
    requests = pytest.importorskip("requests")
    from urllib3.exceptions import MaxRetryError, NewConnectionError

    try:
        try:
            try:
                try:
                    raise ConnectionRefusedError(errno.ECONNREFUSED, "Connection refused")
                except ConnectionRefusedError as sock_err:
                    raise NewConnectionError(
                        None, f"Failed to establish a new connection: {sock_err}"
                    ) from sock_err
            except NewConnectionError as new_err:
                raise MaxRetryError(None, "/dav/", new_err) from new_err
        except MaxRetryError as retry_err:
            raise requests.exceptions.ConnectionError(retry_err)
    except requests.exceptions.ConnectionError as exc:
        assert urllib3  # imported for the skip only
        return exc


def test_sad_a_refused_port_behind_requests_is_refused_not_a_timeout():
    exc = _refused_through_urllib3()
    text = describe(exc)
    assert "refused the connection" in text
    assert "in time" not in text


def test_sad_a_refused_port_wrapped_by_a_backend_is_refused_too():
    inner = _refused_through_urllib3()
    try:
        raise OSError(f"Cannot connect to WebDAV server: {inner}") from inner
    except OSError as exc:
        text = describe(exc)
    assert "refused the connection" in text and "in time" not in text


def test_happy_a_real_connect_timeout_stays_a_timeout():
    pytest.importorskip("urllib3")
    from urllib3.exceptions import ConnectTimeoutError

    assert "did not answer in time" in describe(ConnectTimeoutError("timed out"))


def smb_status_error(status: int) -> BaseException:
    """The exception smbprotocol raises for an SMB2 answer of *status*."""
    exceptions = pytest.importorskip("smbprotocol.exceptions")
    from smbprotocol.header import SMB2HeaderResponse

    header = SMB2HeaderResponse()
    header["status"] = status
    header["data"] = b"\x09\x00\x00\x00\x00\x00\x00\x00\x00"
    return exceptions.SMBResponseException(header)


def test_sad_a_wrong_smb_password_is_a_refused_login():
    exc = smb_status_error(0xC000006D)
    assert type(exc).__name__ == "LogonFailure"
    text = describe(exc)
    assert "refused the login" in text
    assert "0xc000006d" not in text.lower()
