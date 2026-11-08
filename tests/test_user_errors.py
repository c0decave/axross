"""core.user_errors.describe: one plain sentence with a next step.

UX review round 3: message boxes and status lines showed ``str(exc)`` -
"[Errno 28] No space left on device", "ValueError: Profile name ...", an
empty text or a bare class name - and the profile import put "(keyring
unavailable?)" over every failure. describe() names the cause the way a
user can act on it, and never shows a class name.
"""

from __future__ import annotations

import errno
import socket
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core.user_errors import describe  # noqa: E402


def test_happy_file_system_errors_name_the_cause_and_the_next_step():
    text = describe(FileNotFoundError(errno.ENOENT, "No such file or directory", "/srv/a.txt"))
    assert "/srv/a.txt" in text and "not found" in text and "refresh" in text
    text = describe(PermissionError(errno.EACCES, "Permission denied", "/srv/x"))
    assert "Permission denied" in text and "/srv/x" in text and "ask its owner" in text
    assert "space" in describe(OSError(errno.ENOSPC, "No space left on device"))
    assert "read-only" in describe(OSError(errno.EROFS, "Read-only file system", "/mnt/cd"))
    assert "in use" in describe(OSError(errno.EBUSY, "Device or resource busy", "/mnt/x"))
    assert "[Errno" not in describe(OSError(errno.ENOSPC, "No space left on device"))


def test_happy_network_errors_say_what_to_check():
    assert "did not answer in time" in describe(TimeoutError())
    assert "did not answer in time" in describe(socket.timeout("timed out"))
    assert "did not answer in time" in describe(subprocess.TimeoutExpired(["ssh"], 5))
    assert "refused the connection" in describe(
        ConnectionRefusedError(errno.ECONNREFUSED, "Connection refused"))
    assert "could not be resolved" in describe(socket.gaierror(-2, "Name or service not known"))
    assert "Reconnect" in describe(ConnectionResetError(errno.ECONNRESET, "reset"))
    assert describe(TimeoutError(), "db.example").startswith("db.example ")


def test_happy_host_keys_new_changed_revoked():
    from core.ssh_client import HostKeyMismatchError, RevokedHostKeyError, UnknownHostKeyError

    new = describe(UnknownHostKeyError("h.example", "ssh-ed25519", "abc"))
    assert "new host key" in new and "Connect" in new and "h.example" in new
    changed = describe(HostKeyMismatchError("h.example", "ssh-ed25519", "abc"))
    assert "changed" in changed and "attack" in changed
    assert "revoked" in describe(RevokedHostKeyError("h.example", "ssh-ed25519", "abc"))


def test_happy_logins_and_keyrings_are_told_apart():
    paramiko = __import__("paramiko")
    assert "refused the login" in describe(paramiko.AuthenticationException("Authentication failed."))
    assert "passphrase" in describe(paramiko.PasswordRequiredException("private key file is encrypted"))
    keyring_errors = __import__("keyring.errors", fromlist=["NoKeyringError"])
    text = describe(keyring_errors.NoKeyringError("No recommended backend was available."))
    assert "keyring" in text.lower() and "unlock" in text


def test_edge_a_refusal_keeps_its_own_text():
    """A ValueError of a validation is written for the user."""
    text = describe(ValueError("The profile name 'a:proxy' cannot be used."))
    assert text == "The profile name 'a:proxy' cannot be used."


def test_sad_an_exception_without_text_gets_no_class_name():
    """str(RuntimeError()) is "" - the import showed "RuntimeError: "."""
    text = describe(RuntimeError())
    assert "RuntimeError" not in text and text
    assert "Log" in text


def test_happy_describe_speaks_german(monkeypatch):
    from core import i18n

    monkeypatch.setattr(i18n, "_ACTIVE", i18n.Translator("de"))
    assert describe(OSError(errno.ENOSPC, "No space left on device")).startswith(
        "Auf dem Datenträger ist kein Platz mehr")
