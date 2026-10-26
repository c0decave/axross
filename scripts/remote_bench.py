"""Measure the remote backends and the transfer queue against a real server.

Usage: python scripts/remote_bench.py --url sftp://USER:PASS@HOST[:PORT]
                                      [--url2 URL] [--latency-ms 20]
                                      [--entries 2000] [--files 500] [--mb 100]
                                      [--only NAME,...] [--json OUT] [--tree DIR]
                                      [--parallel N]

The numbers the operator's "complete review of where we can still optimise
performance" asked for in the remote area, made repeatable. Remote cost is
round trips, so besides the time every scenario counts what went over the
wire: the backend calls (``*_calls``: list_dir, stat, open_write, ...), and
for SFTP the requests that waited for their answer (``*_sftp_sync``, one
round trip each), the pipelined ones (``*_sftp_async``) and the SSH channels
opened (``*_channels``, an exec such as sha256sum costs several round trips).

Scenarios, each on a fresh remote folder:

* ``list``: list_dir of a folder of ``--entries`` files,
* ``read``: open_read of a ``--mb`` MB file, read to the end,
* ``upload_big`` / ``download_big``: one ``--mb`` MB file through the
  transfer queue (TransferManager, as F5 queues it),
* ``upload_many`` / ``download_many``: a folder of ``--files`` 4 KiB files,
* ``download_selected``: those files selected one by one (F5 on a selection,
  not on their folder): the destination check, then the queue,
* ``relay_many`` / ``relay_big``: remote to remote (``--url2``, by default a
  second session to the same server), as between two remote panes,
* ``delete``: remove(recursive=True) of a folder of ``--files`` files,
* ``size``: core.tree_size over that folder (Calculate Size).

``--latency-ms`` puts a toxiproxy (``--toxiproxy``, the lab's 10.99.0.50)
in front of the server that delays each direction by half of it, so every
round trip costs that much more. Each copy is checked byte for byte.

Everything runs in a temporary HOME with Qt offscreen: no real settings,
known hosts or keyring are read or written. ``--tree`` imports axross from
another checkout (an old version extracted with ``git archive``) for an A/B;
the script checks that the modules really come from there. Compare minima
of alternating runs: the numbers move with the host's load.
"""

from __future__ import annotations

import argparse
import collections
import hashlib
import json
import os
import shutil
import sys
import tempfile
import threading
import time
import urllib.parse
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

SCENARIOS = (
    "list", "read", "upload_big", "download_big", "upload_many", "download_many",
    "download_selected", "relay_many", "relay_big", "delete", "size",
)

DEFAULT_PORTS = {"sftp": 22, "scp": 22, "ftp": 21, "ftps": 21, "smb": 445, "webdav": 80,
                 "s3": 9000}

#: The FileBackend calls that cost the server a request each.
COUNTED = (
    "list_dir", "stat", "is_dir", "exists", "mkdir", "remove", "rename", "open_read",
    "open_write", "chmod", "checksum", "set_modified", "copy", "readlink", "normalize",
    "disk_usage", "stat_many",
)


# -- toxiproxy ---------------------------------------------------------------------------------


class Toxiproxy:
    """One latency proxy on the lab's toxiproxy, removed by :meth:`close`."""

    def __init__(self, admin: str, name: str, upstream: str, listen_port: int, latency_ms: int):
        self.admin, self.name = admin, name
        self._call("DELETE", f"/proxies/{name}", ok_missing=True)
        self._call("POST", "/proxies", {"name": name, "listen": f"0.0.0.0:{listen_port}",
                                         "upstream": upstream, "enabled": True})
        half = latency_ms / 2
        for stream in ("upstream", "downstream"):
            self._call("POST", f"/proxies/{name}/toxics", {
                "name": f"lat_{stream}", "type": "latency", "stream": stream, "toxicity": 1.0,
                "attributes": {"latency": int(half), "jitter": 0}})

    def _call(self, method: str, path: str, body=None, ok_missing: bool = False) -> None:
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(self.admin + path, data=data, method=method,
                                     headers={"Content-Type": "application/json"})
        try:
            urllib.request.urlopen(req, timeout=5).read()
        except urllib.error.HTTPError as exc:
            if not (ok_missing and exc.code == 404):
                raise

    def close(self) -> None:
        self._call("DELETE", f"/proxies/{self.name}", ok_missing=True)


# -- counting ----------------------------------------------------------------------------------


class Counter:
    """Backend calls per name and SFTP requests, from every thread."""

    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.calls: collections.Counter = collections.Counter()
        self.seconds: collections.Counter = collections.Counter()
        self.sftp_sync = 0
        self.sftp_async = 0
        self.channels = 0
        #: Requests of the other protocols: smb, ftp_cmd, ftp_data, http.
        self.wire: collections.Counter = collections.Counter()

    def reset(self) -> None:
        with self.lock:
            self.calls.clear()
            self.seconds.clear()
            self.wire.clear()
            self.sftp_sync = self.sftp_async = self.channels = 0

    def bump(self, key: str) -> None:
        with self.lock:
            self.wire[key] += 1

    def snapshot(self) -> dict:
        with self.lock:
            return {"calls": sum(self.calls.values()), "by_call": dict(self.calls),
                    "ms_by_call": {k: round(v * 1000, 1) for k, v in self.seconds.items()},
                    "sftp_sync": self.sftp_sync, "sftp_async": self.sftp_async,
                    "channels": self.channels, "wire": dict(self.wire)}


def count_backend(backend, counter: Counter) -> None:
    """Count every :data:`COUNTED` call on *backend* (its type is kept)."""
    for name in COUNTED:
        method = getattr(backend, name, None)
        if not callable(method):
            continue

        def wrapper(*args, _m=method, _n=name, **kwargs):
            start = time.perf_counter()
            try:
                return _m(*args, **kwargs)
            finally:
                with counter.lock:
                    counter.calls[_n] += 1
                    counter.seconds[_n] += time.perf_counter() - start

        setattr(backend, name, wrapper)


def count_paramiko(counter: Counter) -> None:
    import paramiko
    from paramiko import sftp_client

    sync, async_ = sftp_client.SFTPClient._request, sftp_client.SFTPClient._async_request

    def request(self, *args, **kwargs):
        with counter.lock:
            counter.sftp_sync += 1
        counter_local.in_sync = True
        try:
            return sync(self, *args, **kwargs)
        finally:
            counter_local.in_sync = False

    def async_request(self, *args, **kwargs):
        if not getattr(counter_local, "in_sync", False):
            with counter.lock:
                counter.sftp_async += 1
        return async_(self, *args, **kwargs)

    open_session = paramiko.Transport.open_session

    def counted_open_session(self, *args, **kwargs):
        with counter.lock:
            counter.channels += 1
        return open_session(self, *args, **kwargs)

    counter_local = threading.local()
    sftp_client.SFTPClient._request = request
    sftp_client.SFTPClient._async_request = async_request
    paramiko.Transport.open_session = counted_open_session


def count_other_protocols(counter: Counter) -> None:
    """SMB messages sent, FTP commands and data connections, HTTP requests
    (requests and botocore both go through urllib3)."""

    def wrap(owner, name: str, key: str) -> None:
        original = getattr(owner, name)

        def counted(*args, **kwargs):
            counter.bump(key)
            return original(*args, **kwargs)

        setattr(owner, name, counted)

    import ftplib

    wrap(ftplib.FTP, "putcmd", "ftp_cmd")
    wrap(ftplib.FTP, "ntransfercmd", "ftp_data")
    try:
        from smbprotocol.connection import Connection

        wrap(Connection, "send", "smb")
        wrap(Connection, "send_compound", "smb_compound")
    except ImportError:
        pass
    try:
        from urllib3.connectionpool import HTTPConnectionPool

        wrap(HTTPConnectionPool, "urlopen", "http")
    except ImportError:
        pass


# -- backends ----------------------------------------------------------------------------------


def connect(url: str, label: str, home: str):
    """A connected backend for *url* (sftp://user:pass@host:port)."""
    parts = urllib.parse.urlsplit(url)
    if parts.scheme == "sftp":
        from core.profiles import ConnectionProfile
        from core.ssh_client import SSHSession

        profile = ConnectionProfile(name=label, protocol="sftp", host=parts.hostname,
                                    port=parts.port or 22, username=parts.username or "",
                                    auth_type="password")
        session = SSHSession(profile)
        session._known_hosts_path = Path(home) / f"known_hosts_{label}"
        session.connect(password=urllib.parse.unquote(parts.password or ""),
                        on_unknown_host=lambda _err: True)
        return session, session.home()
    if parts.scheme == "ramfs":
        from core.ram_fs import RamFsSession

        return RamFsSession(), "/"
    # Every other protocol as the connection manager builds it; profile
    # fields from the query (smb://u:p@host/?smb_share=x, webdav, s3, ...).
    from core.connection_manager import ConnectionManager
    from core.profiles import ConnectionProfile

    extra = dict(urllib.parse.parse_qsl(parts.query))
    for key in [k for k in extra if k.endswith("_url") or k.endswith("_endpoint")]:
        extra[key] = extra[key].replace("{host}", f"{parts.hostname}:{parts.port}")
    profile = ConnectionProfile(name=label, protocol=parts.scheme, host=parts.hostname or "",
                                port=parts.port or 0, username=parts.username or "", **extra)
    backend = ConnectionManager()._create_session(
        profile, urllib.parse.unquote(parts.password or ""), "", lambda _err: True)
    return backend, backend.home()


def via_proxy(url: str, args, name: str, offset: int):
    parts = urllib.parse.urlsplit(url)
    if not args.latency_ms or parts.scheme == "ramfs":
        return url, None
    port = parts.port or DEFAULT_PORTS.get(parts.scheme)
    if not port:
        raise SystemExit("--latency-ms needs an explicit port in the URL")
    listen = args.proxy_port + offset
    # The port in the name: two benches with their own --proxy-port share
    # the lab's toxiproxy without removing each other's proxy.
    proxy = Toxiproxy(f"http://{args.toxiproxy}:8474", f"{name}_{listen}",
                      f"{parts.hostname}:{port}", listen, args.latency_ms)
    netloc = parts.netloc.rsplit("@", 1)[0] + f"@{args.toxiproxy}:{listen}"
    return urllib.parse.urlunsplit(parts._replace(netloc=netloc)), proxy


# -- the bench ---------------------------------------------------------------------------------


def bench(args, home: str) -> dict:
    from PyQt6.QtCore import QEventLoop, QTimer
    from PyQt6.QtWidgets import QApplication

    app = QApplication.instance() or QApplication([])
    import core.transfer_worker as TW

    if not Path(TW.__file__).resolve().is_relative_to(Path(args.tree).resolve()):
        raise SystemExit(f"core.transfer_worker came from {TW.__file__}, not from {args.tree}")
    from core.local_fs import LocalFS
    from core.transfer_manager import TransferManager
    from core.transfer_worker import TransferDirection
    from core.tree_size import tree_size

    only = set(args.only.split(",")) if args.only else set(SCENARIOS)
    counter = Counter()
    count_paramiko(counter)
    count_other_protocols(counter)
    proxies = []
    url, proxy = via_proxy(args.url, args, "rbench_a", 0)
    proxies += [proxy] if proxy else []
    url2, proxy2 = via_proxy(args.url2 or args.url, args, "rbench_b", 1)
    proxies += [proxy2] if proxy2 else []
    if args.latency_ms and args.passive_ports:
        # FTP data connections: ftplib dials the PASV port on the control
        # connection's peer (the proxy), so each port gets a proxy too.
        low, _, high = args.passive_ports.partition("-")
        host = urllib.parse.urlsplit(args.url).hostname
        for port in range(int(low), int(high or low) + 1):
            proxies.append(Toxiproxy(f"http://{args.toxiproxy}:8474", f"rbench_p{port}",
                                     f"{host}:{port}", port, args.latency_ms))
    results: dict = {"latency_ms": args.latency_ms}
    remote, rhome = connect(url, "a", home)
    remote2, rhome2 = connect(url2, "b", home)
    # Setup and checks go over sessions without the latency link: only the
    # measured action pays it.
    setup = connect(args.url, "a_direct", home)[0] if proxy else remote
    setup2 = connect(args.url2 or args.url, "b_direct", home)[0] if proxy2 else remote2
    count_backend(remote, counter)
    count_backend(remote2, counter)
    local = LocalFS()
    work = Path(tempfile.mkdtemp(prefix="remote-bench-"))
    rroot = remote.join(rhome, f"rbench-{os.getpid()}")
    rroot2 = remote2.join(rhome2, f"rbench2-{os.getpid()}")
    setup.mkdir(rroot)
    if rroot2 != rroot:
        setup2.mkdir(rroot2)
    # Only when asked: an old --tree has no max_parallel and runs one job at a time.
    if args.parallel != 1:
        manager = TransferManager(max_parallel=args.parallel)
    else:
        manager = TransferManager()
    results["parallel"] = args.parallel

    def record(name: str, wall: float, cpu: float, gui: float, snap: dict) -> None:
        results[f"{name}_wall_ms"] = round(wall * 1000, 1)
        results[f"{name}_cpu_ms"] = round(cpu * 1000, 1)
        results[f"{name}_gui_cpu_ms"] = round(gui * 1000, 1)
        results[f"{name}_calls"] = snap["calls"]
        results[f"{name}_by_call"] = snap["by_call"]
        results[f"{name}_ms_by_call"] = snap["ms_by_call"]
        results[f"{name}_sftp_sync"] = snap["sftp_sync"]
        results[f"{name}_sftp_async"] = snap["sftp_async"]
        results[f"{name}_channels"] = snap["channels"]
        results[f"{name}_wire"] = snap["wire"]
        print(f"{name:14s} {wall * 1000:9.1f} ms  cpu {cpu * 1000:8.1f} ms  "
              f"calls {snap['calls']:5d}  sync {snap['sftp_sync']:5d}  "
              f"async {snap['sftp_async']:6d}  chan {snap['channels']:4d}  {snap['wire']}"
              f"\n    {snap['by_call']}"
              f"\n    ms {snap['ms_by_call']}",
              flush=True)

    def measure(name: str, action, done=lambda: True, timeout: float = 1800.0):
        counter.reset()
        cpu0, gui0, t0 = time.process_time(), time.thread_time(), time.perf_counter()
        value = action()
        deadline = t0 + timeout
        while not done() and time.perf_counter() < deadline:
            app.processEvents(QEventLoop.ProcessEventsFlag.AllEvents, 20)
            time.sleep(0.001)
        wall = time.perf_counter() - t0
        record(name, wall, time.process_time() - cpu0, time.thread_time() - gui0,
               counter.snapshot())
        return value

    def queue(name, src_backend, dst_backend, sources, dest, direction):
        state = {}

        def finished():
            state["done"] = True

        def start():
            plan = None
            if args.plan:
                # As F5 does: list the destination, every free name must
                # still be free when its job writes (if_exists="fail").
                from core.transfer_conflicts import ConflictPlan, scan_conflicts

                plan = ConflictPlan(dst_backend,
                                    scan_conflicts(src_backend, dst_backend, sources, dest))
            manager.transfer_files_in_background(
                src_backend, dst_backend, sources, dest, direction, conflict_plan=plan)

        manager.all_finished.connect(finished)
        try:
            measure(name, start, lambda: "done" in state)
        finally:
            manager.all_finished.disconnect(finished)
        failed = [j for j in manager.all_jobs() if j.status.name != "DONE"]
        results[f"{name}_failed"] = len(failed)
        if failed:
            print(f"  {len(failed)} failed: {failed[0].error_message}", flush=True)
        manager.clear_finished()

    def put(backend, path: str, data: bytes) -> None:
        with backend.open_write(path) as fh:
            fh.write(data)

    def get(backend, path: str) -> bytes:
        with backend.open_read(path) as fh:
            return fh.read()

    def digest_remote(backend, path: str) -> str:
        h = hashlib.sha256()
        with backend.open_read(path) as fh:
            for chunk in iter(lambda: fh.read(1 << 20), b""):
                h.update(chunk)
        return h.hexdigest()

    small = [bytes([i % 251]) * 4096 for i in range(args.files)]
    block = os.urandom(1 << 20)
    blob = work / "blob.bin"
    with blob.open("wb") as fh:
        for _ in range(args.mb):
            fh.write(block)
    blob_sha = hashlib.sha256(blob.read_bytes()).hexdigest()
    many = work / "many"
    many.mkdir()
    for i, data in enumerate(small):
        (many / f"f{i:05d}.bin").write_bytes(data)

    def remote_many(backend, folder: str) -> None:
        backend.mkdir(folder)
        for i, data in enumerate(small):
            put(backend, backend.join(folder, f"f{i:05d}.bin"), data)

    def same_many(backend, folder: str) -> bool:
        names = sorted(i.name for i in backend.list_dir(folder))
        if names != [f"f{i:05d}.bin" for i in range(args.files)]:
            return False
        return all(get(backend, backend.join(folder, n)) == small[i] for i, n in enumerate(names))

    try:
        if "list" in only:
            folder = remote.join(rroot, "listing")
            setup.mkdir(folder)
            for i in range(args.entries):
                put(setup, remote.join(folder, f"entry_{i:06d}.dat"), b"x" * (i % 97))
            items = measure("list", lambda: remote.list_dir(folder))
            results["list_entries_ok"] = int(len(items) == args.entries)
        if only & {"read", "download_big", "relay_big"}:
            rblob = remote.join(rroot, "blob.bin")
            with blob.open("rb") as src, setup.open_write(rblob) as dst:
                shutil.copyfileobj(src, dst, 1 << 20)
        if "read" in only:
            def read_all():
                h = hashlib.sha256()
                with remote.open_read(rblob) as fh:
                    for chunk in iter(lambda: fh.read(TW.CHUNK_SIZE), b""):
                        h.update(chunk)
                return h.hexdigest()

            got = measure("read", read_all)
            results["read_bytes_ok"] = int(got == blob_sha)
            results["read_mb_per_s"] = round(args.mb / (results["read_wall_ms"] / 1000), 2)
        if "upload_big" in only:
            dest = remote.join(rroot, "up_big")
            setup.mkdir(dest)
            queue("upload_big", local, remote, [str(blob)], dest, TransferDirection.UPLOAD)
            results["upload_big_bytes_ok"] = int(
                digest_remote(setup, remote.join(dest, "blob.bin")) == blob_sha)
            results["upload_big_mb_per_s"] = round(
                args.mb / (results["upload_big_wall_ms"] / 1000), 2)
        if "download_big" in only:
            dest = work / "down_big"
            dest.mkdir()
            queue("download_big", remote, local, [rblob], str(dest), TransferDirection.DOWNLOAD)
            got = dest / "blob.bin"
            results["download_big_bytes_ok"] = int(
                got.exists() and hashlib.sha256(got.read_bytes()).hexdigest() == blob_sha)
            results["download_big_mb_per_s"] = round(
                args.mb / (results["download_big_wall_ms"] / 1000), 2)
        if "upload_many" in only:
            dest = remote.join(rroot, "up_many")
            setup.mkdir(dest)
            queue("upload_many", local, remote, [str(many)], dest, TransferDirection.UPLOAD)
            results["upload_many_files_ok"] = int(same_many(setup, remote.join(dest, "many")))
        if only & {"download_many", "download_selected", "relay_many", "delete", "size"}:
            rmany = remote.join(rroot, "many")
            remote_many(setup, rmany)
        if "download_many" in only:
            dest = work / "down_many"
            dest.mkdir()
            queue("download_many", remote, local, [rmany], str(dest), TransferDirection.DOWNLOAD)
            results["download_many_files_ok"] = int(same_many(local, str(dest / "many")))
        if "download_selected" in only:
            # F5 on --files selected remote files (not their folder): the
            # destination check first, then the queue, as the main window.
            from core.transfer_conflicts import ConflictPlan, scan_conflicts

            dest = work / "down_sel"
            dest.mkdir()
            paths = [remote.join(rmany, f"f{i:05d}.bin") for i in range(args.files)]

            def check():
                return scan_conflicts(remote, local, paths, str(dest))

            plan = ConflictPlan(local, measure("download_selected_check", check))
            state = {}

            def finished():
                state["done"] = True

            manager.all_finished.connect(finished)
            try:
                measure("download_selected", lambda: manager.transfer_files_in_background(
                    remote, local, paths, str(dest), TransferDirection.DOWNLOAD,
                    conflict_plan=plan), lambda: "done" in state)
            finally:
                manager.all_finished.disconnect(finished)
            results["download_selected_failed"] = sum(
                j.status.name != "DONE" for j in manager.all_jobs())
            manager.clear_finished()
            got = sorted(p.name for p in dest.iterdir())
            results["download_selected_files_ok"] = int(
                got == [f"f{i:05d}.bin" for i in range(args.files)]
                and all((dest / n).read_bytes() == small[i] for i, n in enumerate(got)))
        if "relay_many" in only:
            dest = remote2.join(rroot2, "relay_many")
            setup2.mkdir(dest)
            queue("relay_many", remote, remote2, [rmany], dest, TransferDirection.RELAY)
            results["relay_many_files_ok"] = int(same_many(setup2, remote2.join(dest, "many")))
        if "relay_big" in only:
            dest = remote2.join(rroot2, "relay_big")
            setup2.mkdir(dest)
            queue("relay_big", remote, remote2, [rblob], dest, TransferDirection.RELAY)
            results["relay_big_bytes_ok"] = int(
                digest_remote(setup2, remote2.join(dest, "blob.bin")) == blob_sha)
            results["relay_big_mb_per_s"] = round(
                args.mb / (results["relay_big_wall_ms"] / 1000), 2)
        if "size" in only:
            size = measure("size", lambda: tree_size(remote, rmany))
            results["size_ok"] = int(size.files == args.files and size.bytes == 4096 * args.files)
        if "delete" in only:
            measure("delete", lambda: remote.remove(rmany, recursive=True))
            results["delete_ok"] = int(not setup.exists(rmany))
    finally:
        manager.shutdown()
        for backend, root in ((setup, rroot), (setup2, rroot2)):
            try:
                if backend.exists(root):
                    backend.remove(root, recursive=True)
            except Exception as exc:  # noqa: BLE001 - report, keep cleaning
                print(f"cleanup of {root} failed: {exc}", file=sys.stderr)
        for backend in {id(b): b for b in (remote, remote2, setup, setup2)}.values():
            close = getattr(backend, "disconnect", None) or getattr(backend, "close", None)
            if callable(close):
                close()
        for proxy in proxies:
            proxy.close()
        shutil.rmtree(work, ignore_errors=True)
        QTimer.singleShot(0, app.quit)
    return results


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--url", required=True, help="sftp://USER:PASS@HOST[:PORT] or ramfs://")
    parser.add_argument("--url2", help="the relay destination (default: a second --url session)")
    parser.add_argument("--latency-ms", type=int, default=0,
                        help="extra round-trip time through toxiproxy")
    parser.add_argument("--toxiproxy", default="10.99.0.50", help="toxiproxy host (admin :8474)")
    parser.add_argument("--proxy-port", type=int, default=12200, help="first proxy listen port")
    parser.add_argument("--passive-ports", help="FTP passive port range to proxy as well, "
                        "e.g. 30000-30010 (the lab's pure-ftpd)")
    parser.add_argument("--entries", type=int, default=2000, help="entries of the listed folder")
    parser.add_argument("--files", type=int, default=500, help="small files per folder")
    parser.add_argument("--mb", type=int, default=100, help="size of the big file")
    parser.add_argument("--plan", action="store_true",
                        help="queue as F5 does: destination check and a conflict plan first")
    parser.add_argument("--parallel", type=int, default=1,
                        help="transfer jobs that run at once (the Parallel transfers setting)")
    parser.add_argument("--only", help="comma-separated scenarios: " + ", ".join(SCENARIOS))
    parser.add_argument("--json", help="write the results to this file as well")
    parser.add_argument("--tree", default=str(ROOT), help="the axross checkout to measure")
    args = parser.parse_args(argv)
    home = tempfile.mkdtemp(prefix="remote-bench-home-")
    os.environ.update({
        "HOME": home, "XDG_CONFIG_HOME": f"{home}/.config", "XDG_DATA_HOME": f"{home}/.local",
        "XDG_CACHE_HOME": f"{home}/.cache", "XDG_STATE_HOME": f"{home}/.state",
        "PYTHON_KEYRING_BACKEND": "keyring.backends.null.Keyring",
    })
    os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
    sys.path.insert(0, str(Path(args.tree).resolve()))
    try:
        results = bench(args, home)
    finally:
        shutil.rmtree(home, ignore_errors=True)
    if args.json:
        Path(args.json).write_text(json.dumps(results, indent=1))
    return 0


if __name__ == "__main__":
    sys.exit(main())
