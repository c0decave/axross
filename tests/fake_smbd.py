"""A loopback SMB2 server for the SMB / DFS-N backend tests: impacket's
SimpleSMBServer (a real SMB2 implementation) on 127.0.0.1, one share
backed by a folder, one NTLM user.

impacket answers a CREATE with its create *disposition* where SMB2 puts the
create *action* (smbserver.py: ``respSMBCommand['CreateAction'] =
createDisposition``): FILE_OVERWRITE_IF (5) is no CreateAction, and
smbprotocol refuses the answer (``Enum value 5 does not exist``). The
wrapper below puts the action a server would send.

``stop()`` ends the server and cuts its connections: a server that went
away. impacket is an optional dependency (the ``wmi`` extra): the tests
importorskip it.
"""

from __future__ import annotations

import socket
import threading

USER = "alice"
PASSWORD = "secret-of-the-test"
SHARE = "SHARE"

_ACTION_FOR_DISPOSITION = {0: 0, 1: 1, 2: 2, 3: 2, 4: 3, 5: 3}
_patched = False


def _patch_create_action() -> None:
    global _patched
    if _patched:
        return
    from impacket import smbserver

    original = smbserver.SMB2Commands.smb2Create

    def smb2_create(conn_id, smb_server, recv_packet):
        answer = original(conn_id, smb_server, recv_packet)
        try:
            response = answer[0][0]
            action = response["CreateAction"]
            response["CreateAction"] = _ACTION_FOR_DISPOSITION.get(action, action)
        except Exception:  # noqa: BLE001 - an error answer has no CreateAction
            pass
        return answer

    smbserver.SMB2Commands.smb2Create = staticmethod(smb2_create)
    _patched = True


class FakeSmbd:
    def __init__(self, root: str, share: str = SHARE) -> None:
        from impacket import ntlm, smbserver

        _patch_create_action()
        with socket.socket() as probe:
            probe.bind(("127.0.0.1", 0))
            self.port = probe.getsockname()[1]
        self._server = smbserver.SimpleSMBServer(listenAddress="127.0.0.1", listenPort=self.port)
        self._server.addShare(share, root, "axross test share")
        self._server.setSMB2Support(True)
        self._server.addCredential(USER, 1000, "aad3b435b51404eeaad3b435b51404ee",
                                   ntlm.compute_nthash(PASSWORD).hex())
        self._server.setSMBChallenge("")
        self.connections: list = []
        server = self._server.getServer()
        server.daemon_threads = True
        accept = server.process_request

        def process_request(request, client_address):
            self.connections.append(request)
            accept(request, client_address)

        server.process_request = process_request
        self._thread = threading.Thread(target=self._server.start, daemon=True)
        self._thread.start()
        self._wait_listening()

    def _wait_listening(self) -> None:
        import time

        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            try:
                socket.create_connection(("127.0.0.1", self.port), timeout=0.5).close()
                return
            except OSError:
                time.sleep(0.05)
        raise RuntimeError("the SMB test server did not start")

    def stop(self) -> None:
        server = self._server.getServer()
        server.shutdown()
        # Cut the open connections first: server_close() joins the
        # handler threads, which serve a connection until it ends.
        for connection in self.connections:
            try:
                connection.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
        server.server_close()
