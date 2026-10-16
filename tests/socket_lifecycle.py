"""Closing a socket so a thread blocked on it wakes up."""

from __future__ import annotations

import socket


def close_socket(sock: socket.socket | None) -> None:
    """Shut *sock* down, then close it.

    On Linux close() alone does not wake a thread blocked in accept() or
    recvfrom() on the socket; shutdown() does (on an unconnected UDP socket
    it reports ENOTCONN and wakes the reader all the same).
    """
    if sock is None:
        return
    try:
        sock.shutdown(socket.SHUT_RDWR)
    except OSError:
        pass
    try:
        sock.close()
    except OSError:
        pass
