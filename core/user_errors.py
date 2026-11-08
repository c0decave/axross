"""One plain sentence for an exception, with what to do next.

Message boxes and status lines showed ``str(exc)``: "[Errno 13] Permission
denied: '/srv/x'", "ValueError: Profile name ...", or a bare class name when
the exception carried no text - and next to it a guess that blamed the wrong
thing ("keyring unavailable?" for a reserved profile name). :func:`describe`
turns the common failures into a sentence a user can act on:

* file system errors by their errno (not found, permission, disk full,
  read-only, busy, exists, name too long, ...);
* time-outs of any library (socket, asyncio, concurrent.futures,
  subprocess, requests);
* a refused, reset or unreachable connection and an unknown host name;
* a refused login (paramiko and the other clients) and a key that needs its
  passphrase;
* SSH host keys: new, changed, revoked;
* keyring failures;
* refusals whose text is written for the user (classes named ``*Refused`` /
  ``*Denied``, ``ValueError`` of a validation) - that text, unchanged.

Anything else keeps its own message; a class name is never the message.
Library classes are recognised by name along the MRO, so this module
imports neither paramiko nor keyring.
"""

from __future__ import annotations

import errno

from core.i18n import tr

__all__ = ["describe"]


def _names(exc: BaseException) -> set[str]:
    return {cls.__name__ for cls in type(exc).__mro__}


def _subject(exc: BaseException, what: str) -> str:
    if what:
        return what
    for attr in ("filename", "host", "hostname"):
        value = getattr(exc, attr, None)
        if isinstance(value, (str, bytes)) and value:
            return value.decode("utf-8", "replace") if isinstance(value, bytes) else value
    return ""


def _own_text(exc: BaseException) -> str:
    """The exception's message without the "[Errno n]" decoration."""
    if isinstance(exc, OSError) and exc.strerror:
        return exc.strerror
    text = str(exc).strip()
    if text.startswith("[Errno") and "]" in text:
        text = text.split("]", 1)[1].strip()
    return text


_TIMEOUT_NAMES = {"TimeoutError", "timeout", "TimeoutExpired", "ReadTimeout",
                  "ConnectTimeout", "ConnectTimeoutError", "ReadTimeoutError", "Timeout"}
_AUTH_NAMES = {"AuthenticationException", "BadAuthenticationType", "AuthenticationError",
               "LoginError", "LogonRefused", "SMBAuthenticationError", "LoginFailure",
               "InvalidCredentials", "Unauthorized"}
_KEYRING_NAMES = {"KeyringError", "NoKeyringError", "KeyringLocked", "InitError",
                  "PasswordSetError", "PasswordDeleteError"}
_DROPPED_NAMES = {"ConnectionResetError", "ConnectionAbortedError", "BrokenPipeError",
                  "EOFError", "IncompleteRead", "RemoteDisconnected", "NoValidConnectionsError"}


def _by_errno(exc: OSError, subject: str) -> str | None:
    code = exc.errno
    name = subject or tr("the item")
    if code == errno.ENOENT:
        return tr("{name} was not found. It may have been moved or deleted; "
                  "refresh the folder and check the path.").format(name=name)
    if code in (errno.EACCES, errno.EPERM):
        return tr("Permission denied for {name}. Your account has no rights to it there; "
                  "choose another place or ask its owner for access.").format(name=name)
    if code == errno.ENOSPC:
        return tr("There is no space left on the disk. Free some space and try again.")
    if code == getattr(errno, "EDQUOT", -1):
        return tr("The disk quota is used up. Free some space, or ask for a larger quota.")
    if code == errno.EROFS:
        return tr("{name} is on a read-only file system. Save it to another place.").format(
            name=name)
    if code == errno.EEXIST:
        return tr("{name} already exists. Choose another name, or remove the old one first."
                  ).format(name=name)
    if code == errno.ENOTEMPTY:
        return tr("The folder {name} is not empty.").format(name=name)
    if code == errno.EISDIR:
        return tr("{name} is a folder, not a file.").format(name=name)
    if code == errno.ENOTDIR:
        return tr("{name} is not a folder.").format(name=name)
    if code == errno.ENAMETOOLONG:
        return tr("The name is too long for this file system. Choose a shorter one.")
    if code == errno.EBUSY:
        return tr("{name} is in use. Close the programs and shells that use it, "
                  "then try again.").format(name=name)
    if code in (errno.EHOSTUNREACH, errno.ENETUNREACH, errno.ENETDOWN):
        return tr("The host cannot be reached over the network. "
                  "Check the network connection and the address.")
    return None


def _chain(exc: BaseException) -> list[BaseException]:
    """*exc* and the exceptions it was raised from (``raise ... from``) or
    while handling, outermost first: "Cannot connect to h:22: [Errno 111]
    ..." is a ``ConnectionError`` whose cause is the ConnectionRefusedError
    that says what happened."""
    chain: list[BaseException] = []
    seen: set[int] = set()
    current: BaseException | None = exc
    while current is not None and id(current) not in seen and len(chain) < 8:
        chain.append(current)
        seen.add(id(current))
        if current.__cause__ is not None:
            current = current.__cause__
        elif not current.__suppress_context__ and _wraps_its_context(current):
            current = current.__context__
        else:
            current = None
    return chain


def _wraps_its_context(exc: BaseException) -> bool:
    """A connection error raised inside an ``except`` (paramiko's "Error
    reading SSH protocol banner") is about that error. A ValueError raised
    there is a message of its own and keeps it."""
    return isinstance(exc, OSError) or "SSHException" in _names(exc)


def describe(exc: BaseException, what: str = "") -> str:
    """One sentence for *exc*, with a next step. *what* names the thing the
    failed operation was about (a path, a host); without it the exception's
    own file name or host is used where it has one.

    A wrapper whose cause is known ("Cannot resolve host 'x': [Errno -2]
    ...", raised from the socket.gaierror) gets the cause's sentence; only
    when nothing in the chain is recognised is the outer text shown. A
    refusal written for the user (``*Refused`` / ``*Denied``) keeps its
    own text."""
    chain = [exc] if _written_for_user(exc) else _chain(exc)
    subject = what or next((s for s in (_subject(e, "") for e in chain) if s), "")
    for link in chain:
        text = _classify(link, subject)
        if text:
            return text
    own = _own_text(exc)
    if own:
        return own
    return tr("The operation failed without saying why. The Log panel may show more.")


def _written_for_user(exc: BaseException) -> bool:
    return any(n.endswith(("Refused", "Denied")) for n in _names(exc))


_SSH_HANDSHAKE_TEXTS = ("No existing session", "Negotiation timed out", "Negotiation failed")


def _classify(exc: BaseException, subject: str) -> str | None:
    """The sentence for one exception of the chain, or None."""
    names = _names(exc)
    host = subject or tr("The server")

    # --- SSH host keys (core.ssh_client), most specific first -------------
    if "RevokedHostKeyError" in names:
        return tr("The host key of {host} is marked revoked in known_hosts. Do not connect; "
                  "ask the server's administrator.").format(host=getattr(exc, "host", host))
    if "HostKeyMismatchError" in names or "BadHostKeyException" in names:
        return tr("The host key of {host} has changed since the last connection. That can "
                  "be an attack: check the new fingerprint with the server's administrator "
                  "before you trust it.").format(host=getattr(exc, "host", host))
    if "UnknownHostKeyError" in names:
        return tr("{host} has a new host key that axross has not seen yet. Use Connect to "
                  "review its fingerprint and trust it.").format(host=getattr(exc, "host", host))

    # --- logins -----------------------------------------------------------
    if "PasswordRequiredException" in names:
        return tr("The key file is protected by a passphrase. Enter the passphrase and "
                  "try again.")
    if "ProxyAuthError" in names:
        return tr("The proxy refused the login. Check the proxy user name and password.")
    if names & _AUTH_NAMES:
        return tr("The server refused the login. Check the user name and the password or "
                  "key, then try again.")

    # --- keyring ----------------------------------------------------------
    if names & _KEYRING_NAMES:
        return tr("The keyring did not store or return the secret ({reason}). Start or "
                  "unlock your keyring (SecretService, KWallet, KeePassXC) and try again."
                  ).format(reason=_own_text(exc) or tr("no keyring answered"))

    # --- SSH handshake (paramiko.SSHException by its text) ----------------
    if "SSHException" in names:
        text = str(exc)
        if text.startswith(_SSH_HANDSHAKE_TEXTS):
            # paramiko's start_client(timeout=...) returns at the time-out
            # without an error; the next call then says "No existing session".
            return tr("{host} did not finish the SSH handshake in time. Check that an SSH "
                      "server listens on that port and the network connection, then try "
                      "again.").format(host=host)
        if text.startswith("Error reading SSH protocol banner") and not (
            exc.__cause__ or exc.__context__
        ):
            return tr("{host} did not answer as an SSH server. Check the port and that an "
                      "SSH server runs there.").format(host=host)

    # --- time-outs --------------------------------------------------------
    if names & _TIMEOUT_NAMES:
        return tr("{host} did not answer in time. Check the network connection and that "
                  "the server is running, then try again.").format(host=host)

    # --- connections ------------------------------------------------------
    if isinstance(exc, ConnectionRefusedError) or getattr(exc, "errno", None) == errno.ECONNREFUSED:
        return tr("{host} refused the connection. Check the host name and the port, and "
                  "that the service runs there.").format(host=host)
    if "gaierror" in names or (
        isinstance(exc, ConnectionError) and str(exc).startswith("Cannot resolve host")
    ):
        if subject:
            return tr("The host name {host} could not be resolved. Check its spelling and "
                      "the network connection (DNS).").format(host=subject)
        return tr("The host name could not be resolved. Check its spelling and the "
                  "network connection (DNS).")
    if names & _DROPPED_NAMES:
        return tr("The connection was closed by the other side. Reconnect and try again.")
    if "SSLCertVerificationError" in names:
        return tr("The server's certificate could not be verified ({reason}). Check the "
                  "host name; trust the certificate only if you know it."
                  ).format(reason=_own_text(exc))

    # --- file system --------------------------------------------------------
    if isinstance(exc, OSError) and exc.errno is not None:
        return _by_errno(exc, subject)
    return None
