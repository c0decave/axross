"""A fake SNMP v2c agent on 127.0.0.1 for the SNMP fuzz suites.

It decodes each request, answers with ``value`` under the asked OID (or
``walk_oids`` in turn, for GETNEXT walks) and passes the encoded response
through ``mangle(bytes) -> bytes | None`` (None = stay silent).
"""

from __future__ import annotations

import socket
import threading
from tests.socket_lifecycle import close_socket  # noqa: E402

from pyasn1.codec.ber import decoder, encoder
from pysnmp.proto import api

P = api.PROTOCOL_MODULES[api.SNMP_VERSION_2C]


class FakeAgent:
    def __init__(self) -> None:
        self.mangle = lambda b: b
        self.value = P.OctetString(b"fuzz agent")
        self.walk_oids: list[str] | None = None
        self._walk_pos = 0
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(("127.0.0.1", 0))
        self.port = self.sock.getsockname()[1]
        threading.Thread(target=self._serve, daemon=True).start()

    def _serve(self) -> None:
        while True:
            try:
                data, addr = self.sock.recvfrom(65535)
            except OSError:
                return
            try:
                msg, _ = decoder.decode(data, asn1Spec=P.Message())
                req = P.apiMessage.get_pdu(msg)
                rsp_msg = P.apiMessage.get_response(msg)
                rsp = P.apiMessage.get_pdu(rsp_msg)
                binds = []
                for oid, _val in P.apiPDU.get_varbinds(req):
                    if self.walk_oids is not None:
                        nxt = self.walk_oids[min(self._walk_pos, len(self.walk_oids) - 1)]
                        self._walk_pos += 1
                        binds.append((P.ObjectIdentifier(nxt), self.value))
                    else:
                        binds.append((oid, self.value))
                P.apiPDU.set_varbinds(rsp, binds)
                out = self.mangle(encoder.encode(rsp_msg))
            except Exception:  # noqa: BLE001 - a test agent never dies
                continue
            if out is not None:
                self.sock.sendto(out, addr)

    def close(self) -> None:
        close_socket(self.sock)
