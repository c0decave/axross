"""A fake adbd for the ADB backend tests: the ADB wire protocol over TCP.

What a phone's ``adbd`` speaks to ``adb_shell`` (core.adb_client), so the
tests run the real client code without a phone:

* CNXN; AUTH with a token, the signature checked against the authorized
  public keys, and the public key that makes the phone ask "Allow USB
  debugging?" (:attr:`FakeAdbd.prompt_answer`: allow after
  :attr:`~FakeAdbd.accept_delay` seconds, deny - the connection closes -
  or never answer); STLS for Android 11+'s Wireless debugging port;
* OPEN / WRTE / OKAY / CLSE streams;
* ``shell:<command>``: the command runs in ``/bin/sh`` against a local
  folder standing in for the device (``/sdcard``, ``/storage``, ``/data``
  and ``/system`` map into it; GNU ls with long-iso dates prints what
  toybox prints), or answers from :attr:`FakeAdbd.shell_hook`;
* ``sync:`` with STAT, SEND (DATA ... DONE) and RECV.

Each connection has its own thread, as each USB/TCP transport of adbd.
"""

from __future__ import annotations

import base64
import os
import re
import shutil
import socket
import struct
import subprocess
import threading
import time

A_CNXN = 0x4E584E43
A_AUTH = 0x48545541
A_OPEN = 0x4E45504F
A_OKAY = 0x59414B4F
A_CLSE = 0x45534C43
A_WRTE = 0x45545257
A_STLS = 0x534C5453

#: Device folders that live in the fake's root folder.
MAPPED = ("/sdcard", "/storage", "/data", "/system")


def _pack(cmd: int, a0: int, a1: int, data: bytes = b"") -> bytes:
    return struct.pack("<6I", cmd, a0, a1, len(data), sum(data) & 0xFFFFFFFF,
                       cmd ^ 0xFFFFFFFF) + data


def parse_android_pubkey(text: str | bytes) -> tuple[int, int]:
    """``(n, e)`` of an ``adbkey.pub`` line (Android's RSAPublicKey struct,
    base64, then an optional comment)."""
    if isinstance(text, bytes):
        text = text.decode("ascii", "replace")
    raw = base64.b64decode(text.split()[0])
    words = struct.unpack_from("<I", raw, 0)[0]
    off = 8
    n = int.from_bytes(raw[off:off + words * 4], "little")
    off += words * 4 * 2
    e = struct.unpack_from("<I", raw, off)[0]
    return n, e


def make_device_tree(root: str) -> None:
    """A small device: /sdcard -> /storage/self/primary ->
    /storage/emulated/0 with Download/hello.txt and DCIM/Camera."""
    shutil.rmtree(root, ignore_errors=True)
    prim = os.path.join(root, "storage", "emulated", "0")
    os.makedirs(os.path.join(prim, "Download"))
    os.makedirs(os.path.join(prim, "DCIM", "Camera"))
    os.makedirs(os.path.join(root, "data", "local", "tmp"))
    os.makedirs(os.path.join(root, "storage", "self"))
    os.symlink(prim, os.path.join(root, "storage", "self", "primary"))
    os.symlink(os.path.join(root, "storage", "self", "primary"), os.path.join(root, "sdcard"))
    with open(os.path.join(prim, "Download", "hello.txt"), "wb") as fh:
        fh.write(b"hello android\n")


class FakeAdbd:
    """One fake device listening on 127.0.0.1 (:attr:`port`).

    *auth*: ``"none"`` (no key needed), ``"key"`` (keys in *authorized*
    pass, any other key makes the phone ask) or ``"stls"`` (the Wireless
    debugging port: TLS first). *shell_hook(cmd)*: bytes answer the
    command, None runs it. *recv_delay*: seconds after each 64 KiB a RECV
    sends (a slow Wi-Fi link). *remember*: False when "Always allow" was
    not ticked (an allowed key counts for its connection only).
    """

    def __init__(self, root: str, *, auth: str = "none", authorized=(), accept_delay: float = 0.0,
                 prompt_answer: str = "allow", maxdata: int = 4096, shell_hook=None,
                 crlf: bool = False, recv_delay: float = 0.0, remember: bool = True) -> None:
        self.root = os.path.abspath(root)
        self.auth = auth
        self.authorized = [parse_android_pubkey(k) for k in authorized]
        self.accept_delay = accept_delay
        self.prompt_answer = prompt_answer
        self.maxdata = maxdata
        self.shell_hook = shell_hook
        self.crlf = crlf
        self.recv_delay = recv_delay
        #: False: "Always allow from this computer" was not ticked - an
        #: allowed key counts for that one connection only.
        self.remember = remember
        self.commands: list[str] = []
        self.sync_ops: list[tuple] = []
        self.banners: list[bytes] = []
        self.received_pubkeys: list[bytes] = []
        self.connections = 0
        self.prompts = 0
        self.open_conns: list[socket.socket] = []
        self._lock = threading.Lock()
        self._sock = socket.socket()
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind(("127.0.0.1", 0))
        self._sock.listen(16)
        self.port = self._sock.getsockname()[1]
        self._stopped = False
        threading.Thread(target=self._accept, daemon=True).start()

    # -- device paths ----------------------------------------------------
    def local(self, device_path: str) -> str:
        """The local path of *device_path*."""
        for pre in MAPPED:
            if device_path == pre or device_path.startswith(pre + "/"):
                return self.root + device_path
        return device_path

    def _map_cmd(self, cmd: bytes) -> bytes:
        root = self.root.encode()
        return re.sub(rb"(?<![\w/])(/sdcard|/storage|/data|/system)(?=[/'\" ]|$)",
                      lambda m: root + m.group(0), cmd)

    # -- life cycle ------------------------------------------------------
    def stop(self) -> None:
        self._stopped = True
        try:
            self._sock.close()
        except OSError:
            pass
        self.drop_connections()

    def drop_connections(self) -> None:
        """Every connection ends (adbd restarted, Wi-Fi gone and back)."""
        with self._lock:
            conns, self.open_conns = self.open_conns, []
        for conn in conns:
            try:
                conn.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            try:
                conn.close()
            except OSError:
                pass

    def _accept(self) -> None:
        while not self._stopped:
            try:
                conn, _ = self._sock.accept()
            except OSError:
                return
            with self._lock:
                self.connections += 1
                self.open_conns.append(conn)
            threading.Thread(target=self._serve, args=(conn,), daemon=True).start()

    # -- wire ------------------------------------------------------------
    @staticmethod
    def _recv_exact(conn: socket.socket, n: int) -> bytes:
        buf = b""
        while len(buf) < n:
            chunk = conn.recv(n - len(buf))
            if not chunk:
                raise EOFError
            buf += chunk
        return buf

    def _read(self, conn):
        cmd, a0, a1, length, _ck, _magic = struct.unpack("<6I", self._recv_exact(conn, 24))
        return cmd, a0, a1, (self._recv_exact(conn, length) if length else b"")

    def _serve(self, conn: socket.socket) -> None:
        send_lock = threading.Lock()
        state = {"next_id": 100, "streams": {}, "authed": self.auth == "none",
                 "token": os.urandom(20)}

        def send(cmd, a0, a1, data=b""):
            with send_lock:
                conn.sendall(_pack(cmd, a0, a1, data))

        try:
            while True:
                cmd, a0, a1, data = self._read(conn)
                if cmd == A_CNXN:
                    self.banners.append(data)
                    if self.auth == "stls":
                        send(A_STLS, 0x01000000, 0)
                    elif state["authed"]:
                        send(A_CNXN, 0x01000000, self.maxdata, b"device::ro.product.name=fake;")
                    else:
                        send(A_AUTH, 1, 0, state["token"])
                elif cmd == A_AUTH and a0 == 2:  # a signed token
                    sig = int.from_bytes(data, "big")
                    if any(pow(sig, e, n).to_bytes((n.bit_length() + 7) // 8, "big")
                           .endswith(state["token"]) for n, e in self.authorized):
                        state["authed"] = True
                        send(A_CNXN, 0x01000000, self.maxdata, b"device::ro.product.name=fake;")
                    else:
                        state["token"] = os.urandom(20)
                        send(A_AUTH, 1, 0, state["token"])
                elif cmd == A_AUTH and a0 == 3:  # a public key: "Allow USB debugging?"
                    self.prompts += 1
                    self.received_pubkeys.append(data)
                    if self.prompt_answer == "never":
                        continue
                    time.sleep(self.accept_delay)
                    if self.prompt_answer == "deny":
                        conn.close()
                        return
                    if self.remember:
                        self.authorized.append(parse_android_pubkey(data.rstrip(b"\0")))
                    state["authed"] = True
                    send(A_CNXN, 0x01000000, self.maxdata, b"device::ro.product.name=fake;")
                elif cmd == A_OPEN:
                    if not state["authed"]:
                        continue
                    dest = data.rstrip(b"\0")
                    mine = state["next_id"]
                    state["next_id"] += 1
                    send(A_OKAY, mine, a0)
                    if dest.startswith(b"shell:"):
                        self._shell(send, mine, a0, dest[6:])
                    elif dest.startswith(b"sync:"):
                        state["streams"][mine] = {"peer": a0, "buf": b"", "send": None}
                    else:
                        send(A_CLSE, mine, a0)
                elif cmd == A_WRTE:
                    stream = state["streams"].get(a1)
                    send(A_OKAY, a1, a0)
                    if stream is not None:
                        stream["buf"] += data
                        self._sync(send, a1, stream)
                elif cmd == A_CLSE:
                    if a1 in state["streams"]:
                        del state["streams"][a1]
                        send(A_CLSE, a1, a0)
        except (EOFError, OSError):
            pass
        finally:
            try:
                conn.close()
            except OSError:
                pass

    # -- shell -------------------------------------------------------------
    def _shell(self, send, mine: int, peer: int, command: bytes) -> None:
        text = command.decode("utf-8", "surrogateescape")
        self.commands.append(text)
        out = self.shell_hook(text) if self.shell_hook is not None else None
        if out is None:
            env = dict(os.environ, TIME_STYLE="long-iso", LC_ALL="C", TZ="UTC0")
            result = subprocess.run([b"/bin/sh", b"-c", self._map_cmd(command)],
                                    stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                    env=env, cwd=self.root)
            out = result.stdout.replace(self.root.encode(), b"")
        if self.crlf:
            out = out.replace(b"\n", b"\r\n")
        for start in range(0, len(out), self.maxdata):
            send(A_WRTE, mine, peer, out[start:start + self.maxdata])
        send(A_CLSE, mine, peer)

    # -- sync ----------------------------------------------------------------
    def _sync(self, send, mine: int, stream: dict) -> None:
        peer = stream["peer"]

        def reply(payload: bytes) -> None:
            for start in range(0, len(payload), self.maxdata):
                send(A_WRTE, mine, peer, payload[start:start + self.maxdata])

        while True:
            buf = stream["buf"]
            upload = stream["send"]
            if len(buf) < 8:
                return
            sid, length = struct.unpack_from("<4sI", buf)
            if upload is not None:
                if sid == b"DATA":
                    if len(buf) < 8 + length:
                        return
                    upload["fh"].write(buf[8:8 + length])
                    stream["buf"] = buf[8 + length:]
                    continue
                if sid == b"DONE":
                    stream["buf"] = buf[8:]
                    upload["fh"].close()
                    stream["send"] = None
                    if upload["fail"]:
                        msg = upload["fail"].encode()
                        reply(struct.pack("<4sI", b"FAIL", len(msg)) + msg)
                        continue
                    os.chmod(upload["local"], upload["mode"] & 0o7777)
                    os.utime(upload["local"], (length, length))
                    self.sync_ops.append(("SEND-DONE", upload["path"], upload["mode"], length))
                    reply(struct.pack("<4sI", b"OKAY", 0))
                    continue
                return
            if len(buf) < 8 + length:
                return
            arg = buf[8:8 + length]
            stream["buf"] = buf[8 + length:]
            path = arg.decode("utf-8", "surrogateescape")
            if sid == b"STAT":
                self.sync_ops.append(("STAT", path))
                try:
                    st = os.stat(self.local(path))
                    reply(struct.pack("<4s3I", b"STAT", st.st_mode, st.st_size & 0xFFFFFFFF,
                                      int(st.st_mtime)))
                except OSError:
                    reply(struct.pack("<4s3I", b"STAT", 0, 0, 0))
            elif sid == b"RECV":
                self.sync_ops.append(("RECV", path))
                local = os.fsencode(self.local(path))
                try:
                    if os.path.isdir(local):
                        raise IsADirectoryError(21, "Is a directory")
                    with open(local, "rb") as fh:
                        while True:
                            chunk = fh.read(64 * 1024)
                            if not chunk:
                                break
                            reply(struct.pack("<4sI", b"DATA", len(chunk)) + chunk)
                            if self.recv_delay:
                                time.sleep(self.recv_delay)
                    reply(struct.pack("<4sI", b"DONE", 0))
                except OSError as exc:
                    msg = f"open failed: {exc.strerror}".encode()
                    reply(struct.pack("<4sI", b"FAIL", len(msg)) + msg)
            elif sid == b"SEND":
                device_path, _, mode = path.rpartition(",")
                local = self.local(device_path)
                self.sync_ops.append(("SEND", device_path, int(mode)))
                try:
                    fh = open(os.fsencode(local), "wb")
                    fail = ""
                except OSError as exc:
                    fh, fail = open(os.devnull, "wb"), f"couldn't create file: {exc.strerror}"
                stream["send"] = {"fh": fh, "local": local, "path": device_path,
                                  "mode": int(mode), "fail": fail}
            else:  # QUIT or unknown
                return
