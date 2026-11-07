"""Bluetooth connection streams in an HCI capture: which links, which
channels, what protocol, how much traffic when.

Input is a btsnoop file (``btmon -w capture.log``, Android's
``btsnoop_hci.log``, Bumble's snooper, Wireshark's export) - the HCI
packets between a host and its controller. :class:`StreamParser` follows

* the **links**: Connection Complete (Classic) and LE (Enhanced)
  Connection Complete give a connection handle its peer address and
  radio; Disconnection Complete ends it;
* the **L2CAP channels** on each link: the fixed ones (ATT, LE and BR
  signalling, SMP, ...) and the dynamic ones from the signalling channel's
  Connection Request / Response (and LE Credit Based Connection), whose
  PSM names the protocol - SDP, RFCOMM, AVDTP (A2DP audio), AVCTP (AVRCP
  remote control), HID, ATT over BR/EDR, BNEP;
* ACL fragments reassembled per handle into L2CAP frames.

Each (link, channel, direction) is a :class:`Stream` with its frames,
bytes and a per-second rate; :func:`rate_series` makes the curve a graph
or a visualizer shows. For ATT, the stream also counts reads, writes and
notifications. Pure Python, no Qt: the file in, streams out.
"""

from __future__ import annotations

import math
import struct
from dataclasses import dataclass, field
from pathlib import Path

#: btsnoop: the file magic, and the datalink types it may carry.
BTSNOOP_MAGIC = b"btsnoop\x00"
DATALINK_H1 = 1001  # HCI without a packet-type byte (direction flags say)
DATALINK_H4 = 1002  # UART: a packet-type byte first
DATALINK_MONITOR = 2001  # Linux btmon: the opcode in the record's flags
#: microseconds between year 0 (btsnoop's epoch) and 1970
_EPOCH_DELTA_US = 0x00DCDDB30F2F8000

#: Fixed L2CAP channel id -> protocol.
FIXED_CIDS = {0x0001: "L2CAP signalling", 0x0002: "Connectionless", 0x0003: "AMP manager",
              0x0004: "ATT (GATT)", 0x0005: "LE signalling", 0x0006: "SMP (pairing)",
              0x0007: "SMP over BR/EDR"}
#: Protocol/Service Multiplexer -> protocol (Bluetooth Assigned Numbers).
PSMS = {0x0001: "SDP", 0x0003: "RFCOMM", 0x0005: "TCS", 0x000F: "BNEP (networking)",
        0x0011: "HID control", 0x0013: "HID interrupt", 0x0017: "AVCTP (remote control)",
        0x0019: "AVDTP (audio/video stream)", 0x001B: "AVCTP browsing",
        0x001F: "ATT over BR/EDR", 0x0021: "3D sync", 0x0023: "LE PSM IPSP",
        0x0025: "OTS", 0x0027: "EATT", 0x1001: "HID (Wii)"}
#: ATT opcodes -> what they do (the counts of an ATT stream).
ATT_KINDS = {0x0A: "read", 0x0B: "read", 0x0C: "read", 0x0D: "read", 0x08: "read",
             0x09: "read", 0x10: "read", 0x11: "read", 0x12: "write", 0x13: "write",
             0x52: "write", 0xD2: "write", 0x1B: "notify", 0x1D: "indicate",
             0x1E: "indicate", 0x01: "error", 0x02: "mtu", 0x03: "mtu", 0x04: "discover",
             0x05: "discover", 0x06: "discover", 0x07: "discover"}


@dataclass
class Link:
    handle: int
    address: str
    radio: str  # "LE" or "Classic"
    start: float
    end: float | None = None
    role: str = ""


@dataclass
class Stream:
    """One direction of one L2CAP channel on one link."""

    handle: int
    cid: int
    #: "out": host to controller (sent), "in": received
    direction: str
    protocol: str
    address: str = ""
    psm: int | None = None
    frames: int = 0
    bytes: int = 0
    first: float | None = None
    last: float | None = None
    #: (time, size) of each frame, oldest first
    samples: list = field(default_factory=list)
    #: ATT: {"read": n, "write": n, "notify": n, ...}
    att: dict = field(default_factory=dict)

    def note(self, t: float, size: int) -> None:
        self.frames += 1
        self.bytes += size
        self.first = t if self.first is None else self.first
        self.last = t
        self.samples.append((t, size))

    @property
    def key(self) -> tuple:
        return (self.handle, self.cid, self.direction)

    @property
    def rate(self) -> float:
        """Average bytes per second while it ran."""
        if self.first is None or self.last is None or self.last <= self.first:
            return float(self.bytes)
        return self.bytes / (self.last - self.first)


def read_btsnoop(path) -> tuple[int, list[tuple[float, bool, bytes]]]:
    """A btsnoop file -> (datalink, [(unix time, received, H4 packet)]).
    The packets are H4 (type byte first) whatever the file's datalink."""
    data = Path(path).read_bytes()
    return parse_btsnoop(data)


def parse_btsnoop(data: bytes) -> tuple[int, list[tuple[float, bool, bytes]]]:
    if data[:8] != BTSNOOP_MAGIC or len(data) < 16:
        raise ValueError("not a btsnoop file")
    version, datalink = struct.unpack(">II", data[8:16])
    if version != 1 or datalink not in (DATALINK_H1, DATALINK_H4, DATALINK_MONITOR):
        raise ValueError(f"btsnoop version {version}, datalink {datalink} is not supported")
    out = []
    i = 16
    while i + 24 <= len(data):
        orig, incl, flags, _drops, ts = struct.unpack(">IIIIq", data[i:i + 24])
        i += 24
        body = data[i:i + incl]
        i += incl
        if len(body) < incl:
            break
        t = (ts - _EPOCH_DELTA_US) / 1e6
        if datalink == DATALINK_H4:
            packet, received = body, bool(flags & 1)
        elif datalink == DATALINK_H1:
            received = bool(flags & 1)
            kind = (0x04 if received else 0x01) if flags & 2 else 0x02
            packet = bytes([kind]) + body
        else:  # Linux monitor: the opcode in the upper 16 bits of flags
            opcode = flags & 0xFFFF
            mapping = {2: (0x01, False), 3: (0x04, True), 4: (0x02, False), 5: (0x02, True),
                       6: (0x03, False), 7: (0x03, True), 18: (0x05, False), 19: (0x05, True)}
            if opcode not in mapping:
                continue
            kind, received = mapping[opcode]
            packet = bytes([kind]) + body
        out.append((t, received, packet))
    return datalink, out


def write_btsnoop(path, packets) -> None:
    """[(unix time, received, H4 packet)] -> a btsnoop file (datalink H4)."""
    parts = [BTSNOOP_MAGIC, struct.pack(">II", 1, DATALINK_H4)]
    for t, received, packet in packets:
        kind = packet[0] if packet else 0
        flags = (1 if received else 0) | (2 if kind in (0x01, 0x04) else 0)
        parts.append(struct.pack(">IIIIq", len(packet), len(packet), flags, 0,
                                 int(round(t * 1e6)) + _EPOCH_DELTA_US))
        parts.append(packet)
    Path(path).write_bytes(b"".join(parts))


def _address(raw: bytes) -> str:
    return ":".join(f"{b:02X}" for b in reversed(raw))


class StreamParser:
    """Feed H4 packets in time order; read :attr:`links` and :attr:`streams`."""

    def __init__(self) -> None:
        self.links: dict[int, Link] = {}
        #: links that ended, oldest first
        self.closed: list[Link] = []
        self.streams: dict[tuple, Stream] = {}
        #: handle -> {cid: (psm, protocol)} of the dynamic channels
        self._channels: dict[int, dict[int, tuple[int, str]]] = {}
        #: (handle, signalling id) -> (psm, local or remote source cid, direction)
        self._pending: dict[tuple, tuple[int, int, str]] = {}
        #: (handle, direction) -> [expected length, bytes so far]
        self._partial: dict[tuple, list] = {}
        self.packets = 0
        self.errors = 0

    # -- input ---------------------------------------------------------------------------

    def feed(self, t: float, received: bool, packet: bytes) -> None:
        self.packets += 1
        if not packet:
            return
        try:
            if packet[0] == 0x04 and len(packet) >= 3:
                self._event(t, packet[1], packet[3:3 + packet[2]])
            elif packet[0] == 0x02 and len(packet) >= 5:
                self._acl(t, received, packet[1:])
        except (struct.error, IndexError, ValueError):
            self.errors += 1  # a broken packet is counted, not fatal

    def feed_all(self, packets) -> StreamParser:
        for t, received, packet in packets:
            self.feed(t, received, packet)
        return self

    # -- links ---------------------------------------------------------------------------

    def _event(self, t: float, code: int, body: bytes) -> None:
        if code == 0x03 and len(body) >= 11 and body[0] == 0:  # Connection Complete
            handle = struct.unpack("<H", body[1:3])[0] & 0x0FFF
            if body[9] == 0x01:  # ACL (not SCO)
                self._open(Link(handle, _address(body[3:9]), "Classic", t))
        elif code == 0x3E and body:  # LE Meta
            sub = body[0]
            if sub in (0x01, 0x0A) and len(body) >= 12 and body[1] == 0:
                handle = struct.unpack("<H", body[2:4])[0] & 0x0FFF
                role = "central" if body[4] == 0 else "peripheral"
                self._open(Link(handle, _address(body[6:12]), "LE", t, role=role))
        elif code == 0x05 and len(body) >= 4 and body[0] == 0:  # Disconnection Complete
            handle = struct.unpack("<H", body[1:3])[0] & 0x0FFF
            link = self.links.pop(handle, None)
            if link is not None:
                link.end = t
                self.closed.append(link)
            self._channels.pop(handle, None)
            for key in [k for k in self._partial if k[0] == handle]:
                del self._partial[key]

    def _open(self, link: Link) -> None:
        old = self.links.pop(link.handle, None)
        if old is not None:
            old.end = link.start
            self.closed.append(old)
        self.links[link.handle] = link
        self._channels[link.handle] = {}

    # -- ACL and L2CAP ---------------------------------------------------------------------

    def _acl(self, t: float, received: bool, data: bytes) -> None:
        word, length = struct.unpack("<HH", data[:4])
        handle, boundary = word & 0x0FFF, (word >> 12) & 0x3
        payload = data[4:4 + length]
        direction = "in" if received else "out"
        key = (handle, direction)
        if boundary == 0x1:  # a continuing fragment
            part = self._partial.get(key)
            if part is None:
                self.errors += 1
                return
            part[1] += payload  # a bytearray: each fragment is appended, not copied again
        else:  # a first fragment (0x0, 0x2)
            if len(payload) < 4:
                self.errors += 1
                return
            part = self._partial[key] = [struct.unpack("<H", payload[:2])[0] + 4,
                                         bytearray(payload)]
        if len(part[1]) >= part[0]:
            del self._partial[key]
            self._frame(t, handle, direction, bytes(part[1][:part[0]]))

    def _frame(self, t: float, handle: int, direction: str, frame: bytes) -> None:
        length, cid = struct.unpack("<HH", frame[:4])
        body = frame[4:4 + length]
        link = self.links.get(handle)
        if cid in (0x0001, 0x0005):
            self._signalling(handle, direction, cid, body)
        protocol = FIXED_CIDS.get(cid)
        psm = None
        if protocol is None:
            psm, protocol = self._channels.get(handle, {}).get(
                cid, (None, f"Dynamic channel 0x{cid:04X}"))
        key = (handle, cid, direction)
        stream = self.streams.get(key)
        if stream is None:
            stream = self.streams[key] = Stream(handle, cid, direction, protocol,
                                                address=link.address if link else "", psm=psm)
        elif psm is not None and stream.psm is None:
            stream.psm, stream.protocol = psm, protocol
        stream.note(t, len(body))
        if (cid == 0x0004 or psm == 0x001F) and body:
            kind = ATT_KINDS.get(body[0], "other")
            stream.att[kind] = stream.att.get(kind, 0) + 1

    def _signalling(self, handle: int, direction: str, cid: int, body: bytes) -> None:
        """Connection requests and responses: which dynamic channel carries
        which PSM. The CID a side names in its own request or response is
        the one the *other* side sends to."""
        i = 0
        while i + 4 <= len(body):
            code, ident, length = struct.unpack("<BBH", body[i:i + 4])
            data = body[i + 4:i + 4 + length]
            i += 4 + length
            if cid == 0x0001 and code == 0x02 and len(data) >= 4:  # Connection Request
                psm, scid = struct.unpack("<HH", data[:4])
                self._pending[(handle, ident)] = (psm, scid, direction)
            elif cid == 0x0001 and code == 0x03 and len(data) >= 8:  # Connection Response
                dcid, scid, result = struct.unpack("<HHH", data[:6])
                self._link_channel(handle, ident, dcid, result)
            elif cid == 0x0005 and code == 0x14 and len(data) >= 4:  # LE Credit Based Conn.
                psm, scid = struct.unpack("<HH", data[:4])
                self._pending[(handle, ident)] = (psm, scid, direction)
            elif cid == 0x0005 and code == 0x15 and len(data) >= 10:  # its response
                dcid = struct.unpack("<H", data[:2])[0]
                result = struct.unpack("<H", data[8:10])[0]
                self._link_channel(handle, ident, dcid, result)

    def _link_channel(self, handle: int, ident: int, responder_cid: int, result: int) -> None:
        pending = self._pending.pop((handle, ident), None)
        if pending is None or result != 0:
            return
        psm, requester_cid, _direction = pending
        protocol = PSMS.get(psm, f"PSM 0x{psm:04X}")
        channels = self._channels.setdefault(handle, {})
        # frames to the requester carry its cid, frames to the responder carry the other
        channels[requester_cid] = (psm, protocol)
        channels[responder_cid] = (psm, protocol)
        for stream in self.streams.values():
            if stream.handle == handle and stream.cid in (requester_cid, responder_cid) and \
                    stream.psm is None:
                stream.psm, stream.protocol = psm, protocol

    # -- reading -------------------------------------------------------------------------

    def all_links(self) -> list[Link]:
        return sorted([*self.closed, *self.links.values()], key=lambda link: link.start)

    def sorted_streams(self) -> list[Stream]:
        """Busiest first."""
        return sorted(self.streams.values(), key=lambda s: (-s.bytes, s.handle, s.cid))


#: rate_series makes at most this many buckets: a capture whose times span
#: years (a forged or broken timestamp) gets wider buckets, not gigabytes.
MAX_BUCKETS = 10_000


def rate_series(stream: Stream, bucket: float = 1.0, since: float | None = None,
                until: float | None = None) -> list[float]:
    """Bytes per second of *stream* in buckets of *bucket* seconds (wider
    when that would make more than MAX_BUCKETS)."""
    if not stream.samples:
        return []
    start = stream.samples[0][0] if since is None else since
    end = stream.samples[-1][0] if until is None else until
    if not (math.isfinite(start) and math.isfinite(end)) or end < start:
        return []
    bucket = max(bucket, (end - start) / MAX_BUCKETS, 1e-6)
    count = max(1, min(MAX_BUCKETS + 1, int((end - start) / bucket) + 1))
    out = [0.0] * count
    for t, size in stream.samples:
        index = int((t - start) / bucket)
        if 0 <= index < count:
            out[index] += size / bucket
    return out


def parse_file(path) -> StreamParser:
    _datalink, packets = read_btsnoop(path)
    return StreamParser().feed_all(packets)


__all__ = ["ATT_KINDS", "FIXED_CIDS", "Link", "PSMS", "Stream", "StreamParser",
           "parse_btsnoop", "parse_file", "rate_series", "read_btsnoop", "write_btsnoop"]
