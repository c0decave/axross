"""A small FTP / explicit-FTPS server over a local folder, for end-to-end
tests of core.ftp_client without a container.

It answers as vsftpd / pure-ftpd do where the backend depends on it:
names are bytes on the wire (a latin-1 name is listed as stored), LIST is
``ls -l`` style with "name -> target" for links, MLSD / MLST give RFC 3659
facts, a missing path is 550, a refused one "550 Permission denied".
Explicit FTPS (AUTH TLS, PBSZ, PROT P) wraps the data connections with the
control connection's context; ``require_reuse`` refuses a data connection
that did not resume the control connection's TLS session (vsftpd's
require_ssl_reuse).

Knobs for the failure cases: ``delay`` (verb -> seconds before the reply),
``features`` (the FEAT lines), ``utf8`` (False refuses OPTS UTF8),
``drop_all()`` (the server hangs up every control connection, as after a
restart), ``max_conns`` (connections beyond it get "421 Too many").
"""

from __future__ import annotations

import datetime as _dt
import os
import socket
import ssl
import stat as _stat
import threading
import time

DEFAULT_FEATURES = ("MLST type*;size*;modify*;perm*;", "SIZE", "MDTM", "UTF8", "EPSV", "PASV",
                    "MFMT", "REST STREAM")


def self_signed_context(tmpdir: str, cn: str = "localhost") -> ssl.SSLContext:
    """A server context with a fresh self-signed certificate for *cn*."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    now = _dt.datetime.now(_dt.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name).issuer_name(name).public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - _dt.timedelta(days=1))
        .not_valid_after(now + _dt.timedelta(days=2))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(cn)]), critical=False)
        .sign(key, hashes.SHA256())
    )
    cert_path = os.path.join(tmpdir, "ftps-cert.pem")
    key_path = os.path.join(tmpdir, "ftps-key.pem")
    with open(cert_path, "wb") as fh:
        fh.write(cert.public_bytes(serialization.Encoding.PEM))
    with open(key_path, "wb") as fh:
        fh.write(key.private_bytes(serialization.Encoding.PEM,
                                   serialization.PrivateFormat.PKCS8,
                                   serialization.NoEncryption()))
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(cert_path, key_path)
    return ctx


class FtpFsServer:
    def __init__(self, root: str, *, user: str = "u", password: str = "p",
                 anonymous: bool = False, features=DEFAULT_FEATURES, utf8: bool = True,
                 tls_context: ssl.SSLContext | None = None, require_reuse: bool = False,
                 max_conns: int | None = None, delay: dict | None = None,
                 hash_cmds: bool = False, implicit: bool = False,
                 family: int = socket.AF_INET) -> None:
        self.root = os.fsencode(os.path.realpath(root))
        self.user, self.password, self.anonymous = user, password, anonymous
        self.features = tuple(features)
        self.utf8 = utf8
        self.tls_context = tls_context
        self.require_reuse = require_reuse
        self.max_conns = max_conns
        self.delay = dict(delay or {})
        self.hash_cmds = hash_cmds
        # Paths (e.g. b"/secret") answered "550 Permission denied", and
        # everything below them (as an unreadable entry is when the tests
        # run as root).
        self.denied: set[bytes] = set()
        # Implicit FTPS (port 990): TLS from the first byte, no AUTH TLS.
        self.implicit = implicit
        self.commands: list[str] = []
        self.logins = 0
        self._conns: set[socket.socket] = set()
        self._lock = threading.Lock()
        self.family = family
        self._sock = socket.socket(family, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind(("::1" if family == socket.AF_INET6 else "127.0.0.1", 0))
        self._sock.listen(32)
        self.host, self.port = self._sock.getsockname()[:2]
        self._closing = False
        threading.Thread(target=self._accept, daemon=True).start()

    # -- lifecycle ------------------------------------------------------
    def close(self) -> None:
        self._closing = True
        try:
            self._sock.close()
        except OSError:
            pass
        self.drop_all()

    def drop_all(self) -> None:
        """Hang up every open control connection (a server restart)."""
        with self._lock:
            conns, self._conns = list(self._conns), set()
        for c in conns:
            try:
                c.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            try:
                c.close()
            except OSError:
                pass

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()

    def _accept(self) -> None:
        while not self._closing:
            try:
                conn, _ = self._sock.accept()
            except OSError:
                return
            with self._lock:
                too_many = self.max_conns is not None and len(self._conns) >= self.max_conns
                if not too_many:
                    self._conns.add(conn)
            if too_many:
                try:
                    conn.sendall(b"421 Too many connections\r\n")
                finally:
                    conn.close()
                continue
            threading.Thread(target=self._serve, args=(conn,), daemon=True).start()

    # -- one control connection ------------------------------------------
    def _serve(self, conn: socket.socket) -> None:
        try:
            if self.implicit:
                conn = self.tls_context.wrap_socket(conn, server_side=True)
                with self._lock:
                    self._conns.add(conn)
        except (OSError, ssl.SSLError):
            conn.close()
            return
        state = _Conn(self, conn)
        try:
            state.run()
        except (OSError, ssl.SSLError, ValueError):
            pass
        finally:
            with self._lock:
                self._conns.discard(conn)
                self._conns.discard(state.ctrl)
            try:
                state.ctrl.close()
            except OSError:
                pass


class _Conn:
    def __init__(self, server: FtpFsServer, conn: socket.socket) -> None:
        self.srv = server
        self.ctrl = conn
        self.reader = conn.makefile("rb")
        self.cwd = b"/"
        self.logged_in = False
        self.user = None
        self.prot_p = False
        self.pasv: socket.socket | None = None
        self.port_addr: tuple[str, int] | None = None
        self.rnfr: bytes | None = None
        self.rest = 0

    def send(self, line: str | bytes) -> None:
        if isinstance(line, str):
            line = line.encode("utf-8", "surrogateescape")
        self.ctrl.sendall(line + b"\r\n")

    # paths -------------------------------------------------------------
    def vpath(self, arg: bytes) -> bytes:
        joined = arg if arg.startswith(b"/") else self.cwd.rstrip(b"/") + b"/" + arg
        parts: list[bytes] = []
        for part in joined.split(b"/"):
            if part in (b"", b"."):
                continue
            if part == b"..":
                if parts:
                    parts.pop()
                continue
            parts.append(part)
        return b"/" + b"/".join(parts)

    def real(self, arg: bytes) -> bytes:
        vpath = self.vpath(arg)
        if any(vpath == d or vpath.startswith(d + b"/") for d in self.srv.denied):
            raise PermissionError(vpath)
        return self.srv.root + vpath

    # data connection -----------------------------------------------------
    def open_data(self) -> socket.socket | None:
        if self.pasv is not None:
            ls, self.pasv = self.pasv, None
            ls.settimeout(10)
            try:
                dconn, _ = ls.accept()
            finally:
                ls.close()
        elif self.port_addr is not None:
            dconn = socket.create_connection(self.port_addr, timeout=10)
            self.port_addr = None
        else:
            return None
        if self.prot_p:
            dconn = self.srv.tls_context.wrap_socket(dconn, server_side=True)
            if self.srv.require_reuse and not dconn.session_reused:
                dconn.close()
                return "reuse"  # type: ignore[return-value]
        return dconn

    def with_data(self, produce) -> None:
        self.send("150 Opening data connection")
        dconn = self.open_data()
        if dconn == "reuse":
            self.send("425 TLS session resumption required")
            return
        if dconn is None:
            self.send("425 Use PASV or PORT first")
            return
        try:
            ok = produce(dconn)
        finally:
            try:
                if isinstance(dconn, ssl.SSLSocket):
                    try:
                        dconn.unwrap()
                    except (OSError, ssl.SSLError, ValueError):
                        pass
                dconn.close()
            except OSError:
                pass
        if ok is not False:
            self.send("226 Transfer complete")

    # listings -------------------------------------------------------------
    @staticmethod
    def _ls_line(path: bytes, name: bytes) -> bytes:
        st = os.lstat(path)
        mode = _stat.filemode(st.st_mode).encode()
        when = time.strftime("%b %d %H:%M", time.gmtime(st.st_mtime)).encode()
        line = b"%s 1 owner group %d %s %s" % (mode, st.st_size, when, name)
        if _stat.S_ISLNK(st.st_mode):
            line += b" -> " + os.readlink(path)
        return line

    @staticmethod
    def _facts(path: bytes) -> bytes:
        st = os.lstat(path)
        if _stat.S_ISLNK(st.st_mode):
            kind = b"OS.unix=symlink"
        elif _stat.S_ISDIR(st.st_mode):
            kind = b"dir"
        else:
            kind = b"file"
        mod = time.strftime("%Y%m%d%H%M%S", time.gmtime(st.st_mtime)).encode()
        return b"type=%s;size=%d;modify=%s;" % (kind, st.st_size, mod)

    def _entries(self, real: bytes, show_dot: bool) -> list[bytes]:
        names = sorted(os.listdir(real))
        return [n for n in names if show_dot or not n.startswith(b".")]

    def _split_opts(self, arg: bytes) -> tuple[bool, bytes]:
        if arg.startswith(b"-a"):
            rest = arg[2:].lstrip(b" ")
            return True, rest or b"."
        return False, arg or b"."

    # the loop ---------------------------------------------------------------
    def run(self) -> None:
        self.send("220 ftp-fs ready")
        while True:
            raw = self.reader.readline(8192)
            if not raw:
                return
            line = raw.rstrip(b"\r\n")
            verb, _, arg = line.partition(b" ")
            verb_s = verb.decode("ascii", "replace").upper()
            self.srv.commands.append(line.decode("utf-8", "replace"))
            wait = self.srv.delay.get(verb_s)
            if wait:
                time.sleep(wait)
            handler = getattr(self, "do_" + verb_s, None)
            if handler is None:
                self.send("502 Command not implemented")
                continue
            if not self.logged_in and verb_s not in ("USER", "PASS", "AUTH", "PBSZ", "PROT",
                                                    "FEAT", "QUIT", "NOOP", "OPTS", "SYST"):
                self.send("530 Please login with USER and PASS")
                continue
            try:
                if handler(arg) is False:
                    return
            except FileNotFoundError:
                self.send("550 No such file or directory")
            except NotADirectoryError:
                self.send("550 Not a directory")
            except PermissionError:
                self.send("550 Permission denied")
            except FileExistsError:
                self.send("550 File exists")
            except OSError as exc:
                self.send(f"550 {exc.strerror or exc}")

    # commands ---------------------------------------------------------------
    def do_AUTH(self, arg):
        if self.srv.tls_context is None:
            self.send("502 TLS not configured")
            return
        self.send("234 Proceed with negotiation")
        self.ctrl = self.srv.tls_context.wrap_socket(self.ctrl, server_side=True)
        with self.srv._lock:
            self.srv._conns.add(self.ctrl)
        self.reader = self.ctrl.makefile("rb")

    def do_PBSZ(self, arg):
        self.send("200 PBSZ=0")

    def do_PROT(self, arg):
        self.prot_p = arg.upper() == b"P"
        self.send("200 PROT ok")

    def do_USER(self, arg):
        self.user = arg.decode("utf-8", "replace")
        self.send("331 Password please")

    def do_PASS(self, arg):
        ok = (self.user == self.srv.user and arg.decode("utf-8", "replace") == self.srv.password)
        if self.srv.anonymous and self.user in ("anonymous", "ftp"):
            ok = True
        if ok:
            self.logged_in = True
            self.srv.logins += 1
            self.send("230 Login successful")
        else:
            self.send("530 Login incorrect")

    def do_SYST(self, arg):
        self.send("215 UNIX Type: L8")

    def do_FEAT(self, arg):
        self.send("211-Features:")
        for feat in self.srv.features:
            self.send(" " + feat)
        self.send("211 End")

    def do_OPTS(self, arg):
        up = arg.upper()
        if up.startswith(b"UTF8"):
            self.send("200 Always in UTF8 mode" if self.srv.utf8 else "501 no")
        elif up.startswith(b"MLST"):
            self.send("200 MLST OPTS ok")
        else:
            self.send("501 Option not understood")

    def do_NOOP(self, arg):
        self.send("200 NOOP ok")

    def do_QUIT(self, arg):
        self.send("221 Goodbye")
        return False

    def do_TYPE(self, arg):
        self.send("200 Type set")

    def do_PWD(self, arg):
        self.send(b'257 "' + self.cwd.replace(b'"', b'""') + b'" is the current directory')

    def do_CWD(self, arg):
        real = self.real(arg)
        if not os.path.isdir(real):
            raise FileNotFoundError(arg)
        if not os.access(real, os.X_OK):
            raise PermissionError(arg)
        self.cwd = self.vpath(arg)
        self.send("250 Directory changed")

    def do_CDUP(self, arg):
        return self.do_CWD(b"..")

    def _data_listener(self) -> socket.socket:
        ls = socket.socket(self.srv.family, socket.SOCK_STREAM)
        ls.bind(("::1" if self.srv.family == socket.AF_INET6 else "127.0.0.1", 0))
        return ls

    def do_PASV(self, arg):
        if self.srv.family == socket.AF_INET6:
            self.send("500 Use EPSV")
            return
        ls = self._data_listener()
        ls.listen(1)
        self.pasv = ls
        port = ls.getsockname()[1]
        self.send(f"227 Entering Passive Mode (127,0,0,1,{port >> 8},{port & 255})")

    def do_EPSV(self, arg):
        ls = self._data_listener()
        ls.listen(1)
        self.pasv = ls
        self.send(f"229 Entering Extended Passive Mode (|||{ls.getsockname()[1]}|)")

    def do_PORT(self, arg):
        nums = [int(x) for x in arg.split(b",")]
        self.port_addr = (".".join(map(str, nums[:4])), nums[4] * 256 + nums[5])
        self.send("200 PORT ok")

    def do_EPRT(self, arg):
        _, _af, host, port, _ = arg.decode().split(arg.decode()[0])
        self.port_addr = (host, int(port))
        self.send("200 EPRT ok")

    def do_LIST(self, arg):
        show_dot, target = self._split_opts(arg)
        real = self.real(target)
        if not os.path.lexists(real):
            raise FileNotFoundError(target)
        if os.path.isdir(real):
            if not os.access(real, os.R_OK):
                raise PermissionError(target)
            lines = [self._ls_line(os.path.join(real, n), n) for n in self._entries(real, show_dot)]
        else:
            lines = [self._ls_line(real, os.path.basename(real))]

        def produce(d):
            d.sendall(b"".join(ln + b"\r\n" for ln in lines))
        self.with_data(produce)

    def do_NLST(self, arg):
        show_dot, target = self._split_opts(arg)
        real = self.real(target)
        if not os.path.lexists(real):
            raise FileNotFoundError(target)
        if os.path.isdir(real):
            if not os.access(real, os.R_OK):
                raise PermissionError(target)
            names = self._entries(real, show_dot)
        else:
            names = [os.path.basename(real)]

        def produce(d):
            d.sendall(b"".join(n + b"\r\n" for n in names))
        self.with_data(produce)

    def do_MLSD(self, arg):
        if not any(f.startswith("MLST") for f in self.srv.features):
            self.send("500 Unknown command")
            return
        real = self.real(arg or b".")
        if not os.path.isdir(real):
            raise FileNotFoundError(arg)
        if not os.access(real, os.R_OK):
            raise PermissionError(arg)
        lines = [b"type=cdir; ."]
        for n in self._entries(real, True):
            lines.append(self._facts(os.path.join(real, n)) + b" " + n)

        def produce(d):
            d.sendall(b"".join(ln + b"\r\n" for ln in lines))
        self.with_data(produce)

    def do_MLST(self, arg):
        if not any(f.startswith("MLST") for f in self.srv.features):
            self.send("500 Unknown command")
            return
        real = self.real(arg or b".")
        if not os.path.lexists(real):
            raise FileNotFoundError(arg)
        self.send(b"250-Listing " + arg)
        self.send(b" " + self._facts(real) + b" " + self.vpath(arg))
        self.send("250 End")

    def do_SIZE(self, arg):
        real = self.real(arg)
        if not os.path.isfile(real):
            raise FileNotFoundError(arg)
        self.send(f"213 {os.path.getsize(real)}")

    def do_MDTM(self, arg):
        real = self.real(arg)
        if not os.path.exists(real):
            raise FileNotFoundError(arg)
        self.send("213 " + time.strftime("%Y%m%d%H%M%S", time.gmtime(os.path.getmtime(real))))

    def do_MFMT(self, arg):
        stamp, _, path = arg.partition(b" ")
        when = _dt.datetime.strptime(stamp.decode()[:14], "%Y%m%d%H%M%S").replace(
            tzinfo=_dt.timezone.utc).timestamp()
        os.utime(self.real(path), (when, when))
        self.send(b"213 Modify=" + stamp + b"; " + path)

    def do_REST(self, arg):
        self.rest = int(arg)
        self.send("350 Restart position accepted")

    def do_RETR(self, arg):
        real = self.real(arg)
        if not os.path.isfile(real):
            raise FileNotFoundError(arg)
        fh = open(real, "rb")  # noqa: SIM115 - closed in produce
        rest, self.rest = self.rest, 0

        def produce(d):
            with fh:
                fh.seek(rest)
                while chunk := fh.read(65536):
                    d.sendall(chunk)
        self.with_data(produce)

    def _store(self, arg, mode):
        real = self.real(arg)
        if os.path.isdir(real):
            raise IsADirectoryError(arg)
        fh = open(real, mode)  # noqa: SIM115 - closed in produce

        def produce(d):
            with fh:
                while chunk := d.recv(65536):
                    fh.write(chunk)
        self.with_data(produce)

    def do_STOR(self, arg):
        self._store(arg, "wb")

    def do_APPE(self, arg):
        self._store(arg, "ab")

    def do_DELE(self, arg):
        real = self.real(arg)
        if os.path.isdir(real) and not os.path.islink(real):
            raise IsADirectoryError(arg)
        os.unlink(real)
        self.send("250 Deleted")

    def do_MKD(self, arg):
        os.mkdir(self.real(arg))
        self.send(b'257 "' + self.vpath(arg) + b'" created')

    def do_RMD(self, arg):
        os.rmdir(self.real(arg))
        self.send("250 Removed")

    def do_RNFR(self, arg):
        real = self.real(arg)
        if not os.path.lexists(real):
            raise FileNotFoundError(arg)
        self.rnfr = real
        self.send("350 Ready for RNTO")

    def do_RNTO(self, arg):
        if self.rnfr is None:
            self.send("503 RNFR first")
            return
        os.rename(self.rnfr, self.real(arg))
        self.rnfr = None
        self.send("250 Renamed")

    def do_SITE(self, arg):
        parts = arg.split(b" ", 2)
        if len(parts) == 3 and parts[0].upper() == b"CHMOD":
            os.chmod(self.real(parts[2]), int(parts[1], 8))
            self.send("200 SITE CHMOD ok")
            return
        self.send("500 Unknown SITE command")

    def do_HASH(self, arg):
        if not self.srv.hash_cmds:
            self.send("502 Command not implemented")
            return
        import hashlib

        algo, _, arg = arg.partition(b" ")
        if algo.upper() != b"SHA-256":
            self.send("504 Algorithm not supported")
            return
        real = self.real(arg)
        with open(real, "rb") as fh:
            digest = hashlib.sha256(fh.read()).hexdigest()
        self.send(b"213 SHA-256 0-%d %s %s" % (os.path.getsize(real), digest.encode(), arg))
