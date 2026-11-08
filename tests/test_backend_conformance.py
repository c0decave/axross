"""One conformance suite for every backend that runs without a service.

The review's main finding: the backend contract was only a convention.
Each protocol client had its own answer to "remove a path that is not
there", "rename onto itself", "a destination ending in /", "a name with a
trailing blank" - and a caller (the pane, the transfer engine, MCP,
scripting) that trusted one backend's answer lost data on another.

This suite runs one edge-case matrix (review3-proto/xcut/matrix.py)
against every backend tests/ can build in-process: LocalFS, RamFS,
SQLite, the S3 / Azure Blob fakes, WebDAV over axross' own server, SFTP
over tests/sftp_testkit.py, and the Telnet / RSH / SCP / ADB shells run
in the local /bin/sh. Expected answers come from each backend's declared
capabilities (core.backend_registry.BackendCapabilities): where a
backend legitimately differs, its caps say so (an object store's
``name_holds_file_and_folder``, ``rename_overwrites``, ``can_symlink`` /
``symlink_follows``, ``can_recursive_delete``). The only other entries are
KNOWN_GAPS: bugs found by this suite in modules round 3 did not change,
run as strict xfails so that a fix shows up.

FTP runs against a small threaded server over a folder defined here
(tests/ had only scripted ones); the shells run their commands in the
local /bin/sh in another zone than the client, so a listing that hands
the server's wall clock out as local time is caught.

Cases: not-found, already-exists, rename onto itself and onto an existing
file, rename of a folder into itself, remove of a non-empty folder, file
versus folder, trailing slash, leading and trailing blanks, control
characters, unicode, symlinks (where links are offered or a local tree
lies behind the backend), and naive versus aware modification times.
"""

from __future__ import annotations

import io
import os
import subprocess
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

import pytest

from core.backend_registry import BackendCapabilities
from core.server_ops import _known_backend_capabilities, server_side_move

#: The client's zone and the "server's" zone of the shell fakes: a
#: backend that hands out the server's wall clock as client-local time is
#: off by hours, not by the minute ls rounds to.
CLIENT_TZ = "Asia/Kolkata"
SERVER_TZ = "America/Los_Angeles"


@dataclass
class Target:
    name: str
    backend: object
    root: str
    #: The local folder behind the backend, when there is one (links are
    #: made there for backends that list links but cannot make them).
    local_dir: Path | None = None
    cleanup: list = field(default_factory=list)

    def J(self, *parts: str) -> str:
        return self.backend.join(self.root, *parts)

    @property
    def caps(self) -> BackendCapabilities:
        return _known_backend_capabilities(self.backend) or BackendCapabilities()


# -- makers --------------------------------------------------------------------


def _local(tmp_path):
    from core.local_fs import LocalFS

    root = tmp_path / "local"
    root.mkdir()
    return Target("local", LocalFS(), str(root), root)


def _ramfs(tmp_path):
    from core.ram_fs import RamFsSession

    s = RamFsSession(f"conformance-{time.monotonic_ns()}")
    return Target("ramfs", s, "/", cleanup=[s.disconnect])


def _sqlite(tmp_path):
    from core.sqlite_fs_client import SqliteFsSession

    try:
        s = SqliteFsSession(url=str(tmp_path / "fs.db"))
    except TypeError:
        s = SqliteFsSession(str(tmp_path / "fs.db"))
    return Target("sqlite", s, "/", cleanup=[getattr(s, "close", lambda: None)])


class _S3Store:
    """A stateful in-memory S3 bucket: the boto3 calls S3Session makes."""

    def __init__(self):
        self.objects: dict[str, tuple[bytes, datetime]] = {}

    def _err(self, code, op):
        from botocore.exceptions import ClientError

        return ClientError({"Error": {"Code": code}}, op)

    def list_objects_v2(self, Bucket, Prefix="", Delimiter=None, MaxKeys=1000, **kw):
        contents, prefixes = [], []
        for k in sorted(self.objects):
            if not k.startswith(Prefix):
                continue
            rest = k[len(Prefix):]
            if Delimiter and Delimiter in rest:
                p = Prefix + rest.split(Delimiter)[0] + Delimiter
                if {"Prefix": p} not in prefixes:
                    prefixes.append({"Prefix": p})
            else:
                data, when = self.objects[k]
                contents.append({"Key": k, "Size": len(data), "LastModified": when})
        contents = contents[:MaxKeys]
        out = {"Contents": contents, "KeyCount": len(contents) + len(prefixes)}
        if prefixes:
            out["CommonPrefixes"] = prefixes
        return out

    def get_paginator(self, name):
        store = self

        class _P:
            def paginate(self, **kw):
                yield store.list_objects_v2(**kw)

        return _P()

    def head_object(self, Bucket, Key):
        if Key not in self.objects:
            raise self._err("404", "HeadObject")
        data, when = self.objects[Key]
        return {"ContentLength": len(data), "LastModified": when}

    def get_object(self, Bucket, Key, **kw):
        if Key not in self.objects:
            raise self._err("NoSuchKey", "GetObject")
        return {"Body": io.BytesIO(self.objects[Key][0])}

    def _put(self, key, data):
        self.objects[key] = (bytes(data), datetime.now(timezone.utc))

    def put_object(self, Bucket, Key, Body=b"", **kw):
        self._put(Key, Body.read() if hasattr(Body, "read") else Body)

    def upload_fileobj(self, fileobj, bucket, key, **kw):
        self._put(key, fileobj.read())

    def delete_object(self, Bucket, Key):
        self.objects.pop(Key, None)

    def delete_objects(self, Bucket, Delete):
        for o in Delete["Objects"]:
            self.objects.pop(o["Key"], None)
        return {}

    def copy_object(self, Bucket, CopySource, Key, **kw):
        if CopySource["Key"] not in self.objects:
            raise self._err("NoSuchKey", "CopyObject")
        self._put(Key, self.objects[CopySource["Key"]][0])


def _s3(tmp_path):
    pytest.importorskip("botocore")
    from core.s3_client import S3Session

    s = object.__new__(S3Session)
    s._s3, s._bucket, s._anonymous = _S3Store(), "b", False
    return Target("s3", s, "/")


class _AzureStore:
    """A stateful in-memory Azure Blob container (flat namespace)."""

    def __init__(self):
        self.blobs: dict[str, tuple[bytes, datetime]] = {}

    def get_blob_client(self, name):
        return _AzureBlob(self, name)

    def delete_blob(self, name):
        _AzureBlob(self, name).delete_blob()

    def delete_blobs(self, *names):
        for name in names:
            self.delete_blob(name)

    def _props(self, name):
        data, when = self.blobs[name]
        return SimpleNamespace(name=name, size=len(data), last_modified=when, metadata={})

    def list_blobs(self, name_starts_with="", **kw):
        return _AzurePaged([self._props(n) for n in sorted(self.blobs)
                            if n.startswith(name_starts_with)])

    def walk_blobs(self, name_starts_with="", delimiter="/", **kw):
        out, seen = [], set()
        for n in sorted(self.blobs):
            if not n.startswith(name_starts_with):
                continue
            rest = n[len(name_starts_with):]
            if delimiter in rest:
                p = name_starts_with + rest.split(delimiter)[0] + delimiter
                if p not in seen:
                    seen.add(p)
                    out.append(SimpleNamespace(prefix=p))
            else:
                out.append(self._props(n))
        return _AzurePaged(out)


class _AzurePaged:
    def __init__(self, items):
        self.items = items

    def by_page(self):
        pages = SimpleNamespace(continuation_token=None)
        it = iter([self.items])
        pages.__iter__ = lambda: it
        return _AzurePages(self.items)

    def __iter__(self):
        return iter(self.items)


class _AzurePages:
    continuation_token = None

    def __init__(self, items):
        self._it = iter([items])

    def __iter__(self):
        return self

    def __next__(self):
        return next(self._it)


class _AzureBlob:
    def __init__(self, store, name):
        self.store, self.name, self.url = store, name, "mem://" + name

    def _missing(self):
        from azure.core.exceptions import ResourceNotFoundError

        return ResourceNotFoundError("BlobNotFound")

    def get_blob_properties(self):
        if self.name not in self.store.blobs:
            raise self._missing()
        props = self.store._props(self.name)
        props.copy = SimpleNamespace(status="success", status_description="")
        return props

    def upload_blob(self, data, overwrite=False, **kw):
        body = data.read() if hasattr(data, "read") else data
        self.store.blobs[self.name] = (bytes(body), datetime.now(timezone.utc))

    def download_blob(self, **kw):
        if self.name not in self.store.blobs:
            raise self._missing()
        data = self.store.blobs[self.name][0]
        return SimpleNamespace(size=len(data), chunks=lambda: iter([data]) if data else iter([]))

    def delete_blob(self, **kw):
        if self.name not in self.store.blobs:
            raise self._missing()
        del self.store.blobs[self.name]

    def start_copy_from_url(self, url, **kw):
        source = url[len("mem://"):]
        if source not in self.store.blobs:
            raise self._missing()
        self.store.blobs[self.name] = (self.store.blobs[source][0], datetime.now(timezone.utc))


def _azure_blob(tmp_path):
    pytest.importorskip("azure.core")
    pytest.importorskip("azure.storage.blob")
    from core.azure_client import AzureBlobSession

    s = object.__new__(AzureBlobSession)
    s._container = _AzureStore()
    return Target("azure_blob", s, "/")


def _webdav(tmp_path):
    pytest.importorskip("defusedxml")
    from core.local_fs import LocalFS
    from core.reverse_serve import serve_webdav
    from core.webdav_client import WebDavSession

    root = tmp_path / "dav"
    root.mkdir()
    srv = serve_webdav(LocalFS(), bind="127.0.0.1", port=0, root_path=str(root), auth_token=None)
    return Target("webdav", WebDavSession(srv.base_url), "/", root, cleanup=[srv.shutdown])


def _sftp(tmp_path):
    from paramiko.sftp import SFTP_OK

    from core.profiles import ConnectionProfile
    from core.ssh_client import SSHSession
    from tests import sftp_testkit
    from tests.sftp_testkit import SftpServer

    class _LinkSftp(sftp_testkit._Sftp):
        """tests/sftp_testkit.py's server with real LSTAT and SYMLINK."""

        def lstat(self, path):
            try:
                return sftp_testkit.SFTPAttributes.from_stat(os.lstat(self._real(path)))
            except OSError as exc:
                return self._err(exc)

        def symlink(self, target_path, path):
            target = self._real(target_path) if target_path.startswith("/") else target_path
            try:
                os.symlink(target, self._real(path))
            except OSError as exc:
                return self._err(exc)
            return SFTP_OK

    root = tmp_path / "sftp"
    root.mkdir()
    home = tmp_path / "home"
    (home / ".ssh").mkdir(parents=True)
    patch = mock.patch("pathlib.Path.home", return_value=home)
    patch.start()
    links = mock.patch.object(sftp_testkit, "_Sftp", _LinkSftp)
    links.start()
    patch_stop = patch.stop
    patch = SimpleNamespace(stop=lambda: (links.stop(), patch_stop()))
    server = SftpServer(str(root))
    s = SSHSession(ConnectionProfile(name="t", protocol="sftp", host="127.0.0.1",
                                     port=server.port, username="u"))
    try:
        s.connect(password="x", on_unknown_host=lambda _e: True)
    except Exception:
        patch.stop()
        server.close()
        raise
    return Target("sftp", s, "/", root, cleanup=[s.disconnect, server.close, patch.stop])


# The shell backends run their commands in the local /bin/sh, as in
# tests/test_remove_matrix.py, in the "server's" zone.
_SHELL_ENV = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "LC_ALL": "C.UTF-8",
              "TZ": SERVER_TZ}


def _sh(cmd: str) -> subprocess.CompletedProcess:
    return subprocess.run(["sh", "-c", cmd], capture_output=True, env=_SHELL_ENV, timeout=60)


class _TelnetShell:
    """telnet_client._ShellSession stand-in: one terminal stream (stderr
    joins stdout) and the exit status."""

    def execute(self, cmd, timeout=None):
        p = _sh(cmd)
        return (p.stdout + p.stderr).decode("utf-8", "replace"), p.returncode

    def execute_checked(self, cmd, timeout=None):
        from core.telnet_client import CommandFailed

        output, code = self.execute(cmd)
        if code != 0:
            raise CommandFailed(f"Command failed (exit {code}): {cmd[:80]}\n{output[:500]}")
        return output

    execute_streaming = execute


def _shell_root(tmp_path, name):
    root = tmp_path / name
    root.mkdir()
    return root


class _ShellRun:
    """One exec channel: stdin is collected, the command runs on the
    first read (the writers send all input, then read the status)."""

    def __init__(self, cmd):
        self.cmd, self.stdin, self.done = cmd, bytearray(), None

    def result(self):
        if self.done is None:
            self.done = subprocess.run(["sh", "-c", self.cmd], capture_output=True,
                                       env=_SHELL_ENV, timeout=60, input=bytes(self.stdin))
        return self.done

    def sendall(self, data):
        self.stdin += bytes(data)

    def shutdown_write(self):
        pass

    def recv_exit_status(self):
        return self.result().returncode


class _ShellStream:
    def __init__(self, run, which):
        self.run, self.which, self.channel, self._buf = run, which, run, None

    def read(self, n=-1):
        if self._buf is None:
            r = self.run.result()
            self._buf = io.BytesIO(r.stdout if self.which == "out" else r.stderr)
        return self._buf.read(n)


class _ShellClient:
    """paramiko.SSHClient stand-in for SCP: exec_command in the local sh."""

    def exec_command(self, cmd, timeout=None, **kw):
        run = _ShellRun(cmd)
        return _ShellStream(run, "in"), _ShellStream(run, "out"), _ShellStream(run, "err")


def _scp(tmp_path):
    from core.scp_client import SCPSession, _Capabilities

    s = object.__new__(SCPSession)
    s._client = _ShellClient()
    s._lock = threading.Lock()
    s._home_dir = "/"
    s._caps = _Capabilities(has_stat_gnu=True, has_chmod=True, has_readlink=True,
                            transfer_method="cat")
    root = _shell_root(tmp_path, "scp")
    return Target("scp", s, str(root), root)


def _telnet(tmp_path):
    from core.telnet_client import TelnetSession, _Capabilities

    s = object.__new__(TelnetSession)
    shell = _TelnetShell()
    s._ensure_connected = s._force_reconnect = lambda: shell
    s._caps = _Capabilities(has_base64=True, has_stat_gnu=True, has_chmod=True,
                            has_readlink=True, has_ls_escape=True, transfer_method="base64")
    root = _shell_root(tmp_path, "telnet")
    return Target("telnet", s, str(root), root)


def _rsh(tmp_path):
    from core.rsh_client import RshSession

    s = object.__new__(RshSession)
    s._host = "fake"

    def run_status(cmd, *, stdin=None, timeout=None):
        p = subprocess.run(["sh", "-c", cmd], capture_output=True, env=_SHELL_ENV, timeout=60,
                           input=stdin)
        return p.returncode, p.stdout, p.stderr

    s._run_status = run_status
    root = _shell_root(tmp_path, "rsh")
    return Target("rsh", s, str(root), root)


def _adb(tmp_path):
    from core.adb_client import AdbSession

    s = object.__new__(AdbSession)
    s._conn_lock = threading.Lock()
    s._label = "fake device"

    def copy(src, dst):
        with open(src, "rb") as fi, open(dst, "wb") as fo:
            fo.write(fi.read())

    s._device = SimpleNamespace(push=copy, pull=copy)

    def shell(cmd):
        # adb shell has one stream and no exit status; toybox prints ISO dates.
        p = _sh(cmd.replace("ls -la", "ls -la --time-style=long-iso", 1))
        return (p.stdout + p.stderr).decode("utf-8", "replace")

    s._shell = shell
    root = _shell_root(tmp_path, "adb")
    return Target("adb", s, str(root), root)


def _nfs(tmp_path):
    from core.nfs_client import NfsSession

    root = tmp_path / "nfs"
    root.mkdir()
    s = NfsSession.__new__(NfsSession)  # the kernel mount, pointed at a folder
    s._mount_point, s._mounted, s._host, s._export = str(root), True, "h", "/e"
    return Target("nfs", s, s.home(), root)


def _iscsi(tmp_path):
    from core.iscsi_client import IscsiSession

    root = tmp_path / "iscsi"
    root.mkdir()
    s = IscsiSession.__new__(IscsiSession)
    s._mount_point = str(root)
    return Target("iscsi", s, s.home(), root)


def _mtp(tmp_path):
    from core.mtp_client import MtpSession

    root = tmp_path / "mtp"
    root.mkdir()
    s = MtpSession.__new__(MtpSession)
    s._mount_dir, s._mounted, s._close_lock = str(root), False, threading.Lock()
    s._device_label, s._device_id, s._mounter = "Pixel", "1", "jmtpfs"
    return Target("mtp", s, s.home(), root)


def _nfs_user(tmp_path, version=3):
    import sys

    sys.path.insert(0, str(Path(__file__).resolve().parent))
    from fake_nfsd import FakeNfs4d, FakeNfsd

    from core.nfs_user_client import NfsUserSession

    root = tmp_path / "nfsd" / "export"
    root.mkdir(parents=True)
    if version == 4:
        srv = FakeNfs4d(str(root))
        s = NfsUserSession("127.0.0.1", "/export", port=srv.port, version=4, proxy_type="none")
    else:
        srv = FakeNfsd(str(root))
        s = NfsUserSession("127.0.0.1", "/export", port=srv.port, mount_port=srv.port,
                           proxy_type="none")
    return Target(f"nfs_user_v{version}", s, "/", root, cleanup=[s.close, srv.close])


class _FtpServer:
    """A small threaded FTP server over a local folder (RFC 959 + MLSD /
    MLST / SIZE / MDTM, RFC 3659), one thread per connection: FtpSession
    opens extra connections for transfers. tests/ has only scripted FTP
    servers (tests/ftp_fuzz_server.py) and ones without STOR or RNFR.

    It answers LIST / NLST as vsftpd, pure-ftpd and proftpd do: ``ls``
    of the argument, so a FILE's listing is that file, dot entries only
    with ``-a`` (vsftpd's force_dot_files=NO), and ``ls -l`` dates on
    the server's wall clock (SERVER_TZ). MLSD of a file is 501 (RFC 3659
    7.1). ``mlsd=False`` leaves MLST / MLSD out, as vsftpd does.

    ``dash_a``: "ls" takes ``-a`` as ls does; "refuse" answers 501 to an
    argument that starts with "-"; "literal" takes "-a x" for a path.
    ``pasv_host``: the address the 227 reply names. ``commands`` keeps
    every command line received."""

    def __init__(self, root: Path, *, mlsd: bool = True, dash_a: str = "ls",
                 pasv_host: str = "127,0,0,1"):
        import socket

        self.root = root
        self.mlsd = mlsd
        self.dash_a = dash_a
        self.pasv_host = pasv_host
        self.commands: list[str] = []
        self._sock = socket.create_server(("127.0.0.1", 0))
        self.port = self._sock.getsockname()[1]
        threading.Thread(target=self._accept, daemon=True).start()

    def close(self):
        self._sock.close()

    def _accept(self):
        while True:
            try:
                conn, _ = self._sock.accept()
            except OSError:
                return
            threading.Thread(target=self._serve, args=(conn,), daemon=True).start()

    def _real(self, cwd: str, arg: str) -> tuple[str, Path]:
        import posixpath

        path = posixpath.normpath(posixpath.join(cwd, arg or "."))
        path = "/" + path.lstrip("/")
        return path, self.root / path.lstrip("/")

    @staticmethod
    def _facts(p: Path) -> str:
        st = os.lstat(p)
        kind = "dir" if os.path.isdir(p) and not os.path.islink(p) else "file"
        when = datetime.fromtimestamp(st.st_mtime, timezone.utc).strftime("%Y%m%d%H%M%S")
        return f"type={kind};size={st.st_size};modify={when};"

    @staticmethod
    def _ls_line(p: Path, name: str) -> str:
        from zoneinfo import ZoneInfo

        st = os.lstat(p)
        kind = "l" if os.path.islink(p) else ("d" if os.path.isdir(p) else "-")
        when = datetime.fromtimestamp(st.st_mtime, ZoneInfo(SERVER_TZ))
        if kind == "l":
            name = f"{name} -> {os.readlink(p)}"
        return f"{kind}rw-r--r--   1 ftp ftp {st.st_size:>8} {when:%b %d %H:%M} {name}"

    def _serve(self, conn):
        import socket

        f = conn.makefile("rb")
        cwd, rename_from, pasv = "/", None, None

        def send(line):
            conn.sendall(line.encode("utf-8", "surrogateescape") + b"\r\n")

        def data_conn():
            nonlocal pasv
            c, _ = pasv.accept()
            pasv.close()
            pasv = None
            return c

        def no_data():
            nonlocal pasv
            if pasv:
                pasv.close()
                pasv = None

        send("220 conformance ftpd")
        while True:
            raw = f.readline()
            if not raw:
                break
            line = raw.rstrip(b"\r\n").decode("utf-8", "surrogateescape")
            verb, _, arg = line.partition(" ")
            verb = verb.upper()
            self.commands.append(line)
            try:
                if verb in ("USER",):
                    send("331 password")
                elif verb in ("PASS",):
                    send("230 in")
                elif verb == "FEAT":
                    send("211-Features")
                    feats = (" UTF8", " SIZE", " MDTM")
                    if self.mlsd:
                        feats = (" MLST type*;size*;modify*;", *feats)
                    for feat in feats:
                        send(feat)
                    send("211 End")
                elif verb in ("MLST", "MLSD") and not self.mlsd:
                    send("500 unknown command")
                    no_data()
                elif verb == "OPTS" and arg.upper().startswith("MLST") and not self.mlsd:
                    send("501 no")
                elif verb in ("OPTS", "TYPE", "NOOP", "MODE", "STRU"):
                    send("200 ok")
                elif verb == "PWD":
                    send(f'257 "{cwd}"')
                elif verb == "CWD":
                    path, real = self._real(cwd, arg)
                    if real.is_dir():
                        cwd = path
                        send("250 ok")
                    else:
                        send("550 not a folder")
                elif verb == "PASV":
                    pasv = socket.create_server(("127.0.0.1", 0))
                    port = pasv.getsockname()[1]
                    send(f"227 Entering Passive Mode ({self.pasv_host},{port >> 8},{port & 255})")
                elif verb == "MLST":
                    path, real = self._real(cwd, arg)
                    if not os.path.lexists(real):
                        send("550 not found")
                    else:
                        send("250-Listing")
                        send(f" {self._facts(real)} {path}")
                        send("250 End")
                elif verb == "MLSD":
                    path, real = self._real(cwd, arg)
                    if not os.path.lexists(real):
                        send("550 not found")
                        no_data()
                        continue
                    if not real.is_dir():
                        send("501 not a folder")
                        no_data()
                        continue
                    send("150 here")
                    c = data_conn()
                    for name in sorted(os.listdir(real)):
                        entry = self._facts(real / name) + " " + name
                        c.sendall(entry.encode("utf-8", "surrogateescape") + b"\r\n")
                    c.close()
                    send("226 done")
                elif verb in ("LIST", "NLST"):
                    if self.dash_a == "refuse" and arg.startswith("-"):
                        send("501 options not supported")
                        no_data()
                        continue
                    show_all = self.dash_a == "ls" and (arg == "-a" or arg.startswith("-a "))
                    if show_all:
                        arg = arg[2:].lstrip()
                    path, real = self._real(cwd, arg)
                    if not os.path.lexists(real):
                        send("550 not found")
                        no_data()
                        continue
                    if real.is_dir():
                        entries = [(real / n, n) for n in sorted(os.listdir(real))
                                   if show_all or not n.startswith(".")]
                        if show_all:
                            entries = [(real, "."), (real.parent, ".."), *entries]
                    else:
                        entries = [(real, arg)]  # ls prints the argument as given
                    send("150 here")
                    c = data_conn()
                    for p, name in entries:
                        entry = self._ls_line(p, name) if verb == "LIST" else name
                        c.sendall(entry.encode("utf-8", "surrogateescape") + b"\r\n")
                    c.close()
                    send("226 done")
                elif verb == "SIZE":
                    _, real = self._real(cwd, arg)
                    if real.is_file():
                        send(f"213 {real.stat().st_size}")
                    else:
                        send("550 no file")
                elif verb == "MDTM":
                    _, real = self._real(cwd, arg)
                    if real.is_file():
                        send("213 " + self._facts(real).split("modify=")[1].split(";")[0])
                    else:
                        send("550 no file")
                elif verb == "RETR":
                    _, real = self._real(cwd, arg)
                    if not real.is_file():
                        send("550 no file")
                        continue
                    send("150 sending")
                    c = data_conn()
                    c.sendall(real.read_bytes())
                    c.close()
                    send("226 done")
                elif verb in ("STOR", "APPE"):
                    _, real = self._real(cwd, arg)
                    if real.is_dir() or not real.parent.is_dir():
                        send("553 cannot store there")
                        continue
                    send("150 send it")
                    c = data_conn()
                    chunks = []
                    while True:
                        chunk = c.recv(65536)
                        if not chunk:
                            break
                        chunks.append(chunk)
                    c.close()
                    with open(real, "ab" if verb == "APPE" else "wb") as out:
                        out.write(b"".join(chunks))
                    send("226 stored")
                elif verb == "DELE":
                    _, real = self._real(cwd, arg)
                    if os.path.isdir(real) and not os.path.islink(real):
                        send("550 is a folder")
                    else:
                        os.unlink(real)
                        send("250 deleted")
                elif verb == "MKD":
                    path, real = self._real(cwd, arg)
                    os.mkdir(real)
                    send(f'257 "{path}" created')
                elif verb == "RMD":
                    _, real = self._real(cwd, arg)
                    os.rmdir(real)
                    send("250 removed")
                elif verb == "RNFR":
                    _, real = self._real(cwd, arg)
                    if os.path.lexists(real):
                        rename_from = real
                        send("350 ready")
                    else:
                        send("550 not found")
                elif verb == "RNTO":
                    _, real = self._real(cwd, arg)
                    if rename_from is None:
                        send("503 RNFR first")
                    else:
                        os.rename(rename_from, real)
                        rename_from = None
                        send("250 renamed")
                elif verb == "QUIT":
                    send("221 bye")
                    break
                else:
                    send("502 not implemented")
            except OSError as exc:
                send(f"550 {exc.strerror or exc}")
        conn.close()


def _ftp(tmp_path, *, mlsd: bool = True):
    from core.ftp_client import FtpSession

    root = tmp_path / "ftp"
    root.mkdir()
    srv = _FtpServer(root, mlsd=mlsd)
    s = FtpSession("127.0.0.1", srv.port, "u", "p")
    name = "ftp" if mlsd else "ftp_vsftpd"
    return Target(name, s, "/", root, cleanup=[s.close, srv.close])


def _smb(tmp_path):
    pytest.importorskip("smbprotocol")
    import sys

    sys.path.insert(0, str(Path(__file__).resolve().parent))
    from smb_fake_client import make_local_session

    from core import smb_client

    root = tmp_path / "smb"
    root.mkdir()
    s, fake = make_local_session(str(root))
    patch = mock.patch.object(smb_client, "smbclient", fake)
    patch.start()
    return Target("smb", s, "/", root, cleanup=[patch.stop])


MAKERS = {
    "smb": _smb,
    "ftp": _ftp,
    # vsftpd: no MLST / MLSD; names, types and dates come from NLST / LIST.
    "ftp_vsftpd": lambda tmp_path: _ftp(tmp_path, mlsd=False),
    "nfs": _nfs,
    "iscsi": _iscsi,
    "mtp": _mtp,
    "nfs_user_v3": _nfs_user,
    "nfs_user_v4": lambda tmp_path: _nfs_user(tmp_path, 4),
    "local": _local,
    "ramfs": _ramfs,
    "sqlite": _sqlite,
    "s3": _s3,
    "azure_blob": _azure_blob,
    "webdav": _webdav,
    "sftp": _sftp,
    "scp": _scp,
    "telnet": _telnet,
    "rsh": _rsh,
    "adb": _adb,
}


# -- cloud drives (section of the cloud fixes) ---------------------------------
#
# Google Drive, OneDrive, Dropbox and Azure Files over the in-memory fakes
# tests/fake_gdrive.py, fake_onedrive.py, fake_dropbox.py and
# fake_azure_files.py, which answer with the SDKs' own error types. Azure
# Blob is _azure_blob above. Their legitimate differences are in their caps
# (core.backend_registry), none is a known gap.


def _cloud_fakes():
    import sys

    here = str(Path(__file__).resolve().parent)
    if here not in sys.path:
        sys.path.insert(0, here)


def _gdrive(tmp_path):
    pytest.importorskip("googleapiclient")
    _cloud_fakes()
    import fake_gdrive

    return Target("gdrive", fake_gdrive.make_session(), "/")


def _onedrive(tmp_path):
    pytest.importorskip("requests")
    _cloud_fakes()
    import fake_onedrive

    return Target("onedrive", fake_onedrive.make_session(), "/")


def _dropbox(tmp_path):
    pytest.importorskip("dropbox")
    _cloud_fakes()
    import fake_dropbox

    return Target("dropbox", fake_dropbox.make_session(), "/")


def _azure_files(tmp_path):
    pytest.importorskip("azure.storage.fileshare")
    _cloud_fakes()
    import fake_azure_files

    return Target("azure_files", fake_azure_files.make_session(), "/")


MAKERS.update(gdrive=_gdrive, onedrive=_onedrive, dropbox=_dropbox, azure_files=_azure_files)


# -- known gaps ----------------------------------------------------------------

#: (test, backend) -> what the backend does wrong. These are bugs, not
#: legitimate differences (those are in the caps); each runs as a strict
#: xfail, so a fix shows up as XPASS and its line here must go. The 28
#: gaps of round 3 are fixed; these are what the cases added in the final
#: protocol review found in backends that review did not change.
KNOWN_GAPS: dict[tuple[str, str], str] = {
    **{
        ("test_a_file_with_a_trailing_slash_is_no_folder", name): (
            "stat('file/') answers with the file (the slash is normalized away)"
        )
        for name in ("iscsi", "nfs", "nfs_user_v3", "nfs_user_v4", "ramfs", "sqlite")
    },
    ("test_list_dir_of_a_file_is_not_a_directory", "iscsi"): (
        "list_dir of a file is a bare OSError, not NotADirectoryError"
    ),
    ("test_not_found_is_said_as_such_by_open_read_and_list_dir", "iscsi"): (
        "open_read / list_dir of a missing path is a bare OSError"
    ),
}


# -- fixtures and helpers ------------------------------------------------------


@pytest.fixture
def client_tz(monkeypatch):
    monkeypatch.setenv("TZ", CLIENT_TZ)
    time.tzset()
    yield
    monkeypatch.undo()
    time.tzset()


@pytest.fixture(params=sorted(MAKERS))
def t(request, tmp_path, client_tz):
    gap = KNOWN_GAPS.get((request.node.originalname, request.param))
    if gap:
        request.applymarker(pytest.mark.xfail(reason=gap, strict=True))
    target = MAKERS[request.param](tmp_path)
    try:
        b = target.backend
        b.mkdir(target.J("d"))
        b.mkdir(target.J("d", "sub"))
        _write(target, target.J("d", "f"), b"hello")
        _write(target, target.J("g"), b"other")
        yield target
    finally:
        for done in target.cleanup:
            try:
                done()
            except Exception:  # noqa: BLE001 - cleanup only
                pass


def _write(t: Target, path: str, data: bytes) -> None:
    with t.backend.open_write(path) as fh:
        fh.write(data)


def _read(t: Target, path: str) -> bytes:
    with t.backend.open_read(path) as fh:
        return fh.read()


def _names(t: Target, path: str | None = None) -> set[str]:
    return {i.name for i in t.backend.list_dir(path or t.root)} - {".", ".."}


def _seed_intact(t: Target) -> None:
    assert _read(t, t.J("d", "f")) == b"hello"
    assert _read(t, t.J("g")) == b"other"
    assert t.backend.is_dir(t.J("d", "sub"))


# -- not found -----------------------------------------------------------------


def test_not_found_is_said_as_such(t):
    b, nope = t.backend, t.J("nope")
    with pytest.raises(FileNotFoundError):
        b.stat(nope)
    assert b.exists(nope) is False
    assert b.is_dir(nope) is False
    with pytest.raises(OSError):
        b.open_read(nope)
    with pytest.raises(OSError):
        b.list_dir(nope)


def test_not_found_is_said_as_such_by_open_read_and_list_dir(t):
    """open_read / list_dir of a missing path is FileNotFoundError, not a
    bare OSError: the transfer engine, the pane and FUSE tell "not there"
    from "failed" by the class."""
    with pytest.raises(FileNotFoundError):
        t.backend.open_read(t.J("nope")).read()
    with pytest.raises(FileNotFoundError):
        t.backend.list_dir(t.J("nope"))


@pytest.mark.parametrize("recursive", [False, True])
def test_remove_of_a_missing_path_is_file_not_found(t, recursive):
    with pytest.raises(FileNotFoundError):
        t.backend.remove(t.J("nope"), recursive=recursive)
    _seed_intact(t)


def test_rename_of_a_missing_path_fails_and_creates_nothing(t):
    with pytest.raises(OSError):
        t.backend.rename(t.J("nope"), t.J("n2"))
    assert t.backend.exists(t.J("n2")) is False


# -- already exists ------------------------------------------------------------


def test_mkdir_of_an_existing_folder_keeps_its_content(t):
    try:
        t.backend.mkdir(t.J("d"))
    except FileExistsError:
        pass                                     # refusing is fine too
    _seed_intact(t)


def test_mkdir_over_a_file_is_file_exists_and_keeps_the_file(t):
    if getattr(t.caps, "name_holds_file_and_folder", False):
        pytest.skip(f"{t.name}: a file and a folder may share a name")
    with pytest.raises(FileExistsError):
        t.backend.mkdir(t.J("g"))
    _seed_intact(t)


def test_server_side_move_refuses_an_existing_destination(t):
    with pytest.raises(FileExistsError):
        server_side_move(t.backend, t.J("g"), t.J("d", "f"))
    _seed_intact(t)


# -- rename --------------------------------------------------------------------


def test_rename_onto_itself_keeps_the_file(t):
    try:
        t.backend.rename(t.J("d", "f"), t.J("d", "f"))
    except OSError:
        pass                                     # refusing is fine; losing it is not
    _seed_intact(t)


def test_rename_onto_an_existing_file_replaces_it_or_refuses(t):
    """rename_overwrites=True: rename(2) - the destination is replaced.
    False: no promise either way, but never a loss: either the source
    replaced the destination, or both are as they were."""
    b = t.backend
    try:
        b.rename(t.J("g"), t.J("d", "f"))
    except OSError:
        assert not t.caps.rename_overwrites, "rename_overwrites=True but the rename refused"
        _seed_intact(t)
        return
    assert _read(t, t.J("d", "f")) == b"other"
    assert b.exists(t.J("g")) is False


def test_rename_of_a_folder_into_itself_fails_and_keeps_it(t):
    with pytest.raises(OSError):
        t.backend.rename(t.J("d"), t.J("d", "sub", "d"))
    _seed_intact(t)


# -- remove --------------------------------------------------------------------


def test_remove_of_a_non_empty_folder_needs_recursive(t):
    b = t.backend
    with pytest.raises(OSError):
        b.remove(t.J("d"), recursive=False)
    _seed_intact(t)
    if t.caps.can_recursive_delete:
        b.remove(t.J("d"), recursive=True)
        assert b.exists(t.J("d")) is False
        assert _read(t, t.J("g")) == b"other"


# -- file versus folder --------------------------------------------------------


def test_file_and_folder_are_told_apart(t):
    b = t.backend
    assert b.is_dir(t.J("d")) is True
    assert b.is_dir(t.J("g")) is False
    assert b.stat(t.J("d")).is_dir is True
    st = b.stat(t.J("g"))
    assert st.is_dir is False and st.size == 5
    listed = {i.name: i.is_dir for i in b.list_dir(t.root)}
    assert listed.get("d") is True and listed.get("g") is False
    with pytest.raises(OSError):
        b.open_read(t.J("d")).read()
    with pytest.raises(OSError):
        b.list_dir(t.J("g"))


def test_list_dir_of_a_file_is_not_a_directory(t):
    """Not the file as its own child (what NLST / ls of a file answers)."""
    with pytest.raises(NotADirectoryError):
        t.backend.list_dir(t.J("g"))
    with pytest.raises(NotADirectoryError):
        t.backend.list_dir(t.J("d", "f"))


def test_a_file_cannot_be_written_over_a_folder(t):
    """Refused - unless the caps say a file and a folder can share the
    name (an object store): then the file comes beside the folder, and
    the folder keeps its content either way."""
    if getattr(t.caps, "name_holds_file_and_folder", False):
        _write(t, t.J("d"), b"x")
    else:
        with pytest.raises(OSError):
            _write(t, t.J("d"), b"x")
    _seed_intact(t)
    assert t.backend.is_dir(t.J("d"))


# -- trailing slash ------------------------------------------------------------


def test_trailing_slash_names_a_folder_only_when_there_is_one(t):
    b = t.backend
    assert b.stat(t.J("d") + "/").is_dir is True
    with pytest.raises(FileNotFoundError):
        b.stat(t.J("nothing") + "/")


def test_a_file_destination_ending_in_a_slash_is_refused(t):
    with pytest.raises(OSError):
        _write(t, t.J("t") + "/", b"data")
    assert "t" not in {i.name for i in t.backend.list_dir(t.root) if not i.is_dir}


def test_a_file_renamed_to_a_path_ending_in_a_slash_is_refused(t):
    """rename(2) of a file to "x/" is ENOTDIR; a backend that drops the
    slash made a FILE x."""
    with pytest.raises(OSError):
        t.backend.rename(t.J("g"), t.J("x") + "/")
    _seed_intact(t)
    assert "x" not in _names(t)


def test_a_file_with_a_trailing_slash_is_no_folder(t):
    """stat(2) of "file/" is ENOTDIR. A protocol that can only say "no
    such file" (SFTP maps ENOTDIR to SSH_FX_NO_SUCH_FILE) may; answering
    with the file may not."""
    if getattr(t.caps, "name_holds_file_and_folder", False):
        pytest.skip(f"{t.name}: 'g/' is a folder prefix of its own")
    with pytest.raises((NotADirectoryError, FileNotFoundError)):
        t.backend.stat(t.J("g") + "/")


# -- names ---------------------------------------------------------------------


@pytest.mark.parametrize("name", [" lead.txt", "trail.txt ", "  both  "],
                         ids=["leading", "trailing", "both"])
def test_blanks_at_either_end_of_a_name_are_kept(t, name):
    path = t.J(name)
    _write(t, path, b"blank")
    assert name in _names(t)
    assert _read(t, path) == b"blank"
    assert t.backend.stat(path).size == 5


@pytest.mark.parametrize("name", ["a\x01b", "tab\tname", "bell\x07"], ids=["SOH", "TAB", "BEL"])
def test_a_control_character_name_is_refused_or_kept_exactly(t, name):
    path = t.J(name)
    before = _names(t)
    try:
        _write(t, path, b"ctl")
    except OSError:
        assert _names(t) == before               # refused: nothing appeared
        return
    assert _names(t) - before == {name}          # kept: under exactly that name
    assert _read(t, path) == b"ctl"


@pytest.mark.parametrize("name", ["ü 名 €.txt", "éclair", "emoji-\U0001F600"],
                         ids=["mixed", "combining", "astral"])
def test_unicode_names_round_trip(t, name):
    path = t.J(name)
    _write(t, path, name.encode())
    assert name in _names(t)
    assert _read(t, path) == name.encode()


def test_dot_files_are_listed_and_removed_with_their_folder(t):
    """vsftpd and pure-ftpd leave dot entries out of a listing unless
    asked for them (``-a``): a folder copy left .htaccess behind and a
    recursive delete stopped at a folder that was not empty."""
    b = t.backend
    _write(t, t.J("d", ".htaccess"), b"deny")
    b.mkdir(t.J("d", ".git"))
    _write(t, t.J("d", ".git", "HEAD"), b"ref")
    assert {".htaccess", ".git"} <= _names(t, t.J("d"))
    assert _names(t, t.J("d", ".git")) == {"HEAD"}
    if t.caps.can_recursive_delete:
        b.remove(t.J("d"), recursive=True)
        assert b.exists(t.J("d")) is False
        assert _read(t, t.J("g")) == b"other"


# -- symlinks ------------------------------------------------------------------


def _make_link(t: Target, target: str, link: str) -> None:
    """A link made by the backend (can_symlink) or on the tree behind it
    (symlink_follows: the backend lists and follows links it cannot make)."""
    if not (t.caps.can_symlink or t.caps.symlink_follows):
        pytest.skip(f"{t.name}: no symbolic links in this protocol")
    if t.caps.can_symlink and hasattr(t.backend, "symlink"):
        try:
            t.backend.symlink(target, link)
            return
        except OSError:
            if t.local_dir is None:
                raise
    if t.local_dir is not None:
        rel = os.path.relpath(link, t.root) if os.path.isabs(link) else link.lstrip("/")
        os.symlink(target, t.local_dir / rel)
    else:
        pytest.skip(f"{t.name}: no symbolic links")


def test_a_dangling_link_exists_and_is_removed_as_the_link(t):
    link = t.J("dangling")
    _make_link(t, t.J("nowhere"), link)
    assert t.backend.exists(link) is True
    t.backend.remove(link)
    assert t.backend.exists(link) is False


def test_removing_a_link_to_a_folder_keeps_the_folder(t):
    link = t.J("to_d")
    _make_link(t, t.J("d"), link)
    t.backend.remove(link, recursive=False)
    assert t.backend.exists(link) is False
    _seed_intact(t)


# -- modification times --------------------------------------------------------


def _is_unknown(when: datetime) -> bool:
    return when.year <= 1970


def test_modification_times_are_the_clients_local_time(t):
    """FileItem.modified is naive local time (an aware value is converted
    by FileItem). A backend that hands the server's wall clock out as
    naive is off by the zone difference; stat and the listing agree."""
    now = datetime.now()
    st = t.backend.stat(t.J("g")).modified
    listing = {i.name: i.modified for i in t.backend.list_dir(t.root)}
    listed = listing["g"]
    # A folder's time too: without MLSD an FTP folder has only its LIST
    # date, which servers print on their own clock.
    for when in (st, listed, listing["d"]):
        assert when.tzinfo is None
        if not _is_unknown(when):
            assert abs(when - now) < timedelta(minutes=10), f"{when} vs now {now}"
    if not (_is_unknown(st) or _is_unknown(listed)):
        assert abs(st - listed) < timedelta(seconds=61)
