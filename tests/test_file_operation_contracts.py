from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path

from core.local_fs import LocalFS
from core.ram_fs import RamFsSession
from core.server_ops import server_side_copy, server_side_move


class FileOperationContractTests(unittest.TestCase):
    """Backend-level happy/sad/edge contracts for core file ops.

    These tests intentionally sit above individual protocol clients:
    UI, MCP, scripting and transfers all depend on these semantics.
    Protocol-specific Docker tests still need to prove that real
    services honour the same surface.
    """

    def test_happy_open_mkdir_copy_move_remove_on_localfs_and_ramfs(self) -> None:
        cases: list[tuple[str, object, str]] = []
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        cases.append(("localfs", LocalFS(), tmp.name))

        ram = RamFsSession("contract-happy")
        self.addCleanup(ram.disconnect)
        cases.append(("ramfs", ram, "/"))

        for label, backend, root in cases:
            with self.subTest(backend=label):
                base = backend.join(root, "contract-dir")
                source = backend.join(base, "source.txt")
                copied = backend.join(base, "copied.txt")
                moved = backend.join(base, "moved.txt")

                backend.mkdir(base)
                self.assertTrue(backend.is_dir(base))

                with backend.open_write(source) as fh:
                    fh.write(b"payload")
                with backend.open_read(source) as fh:
                    self.assertEqual(fh.read(), b"payload")

                server_side_copy(backend, source, copied)
                with backend.open_read(copied) as fh:
                    self.assertEqual(fh.read(), b"payload")
                self.assertTrue(backend.exists(source))

                server_side_move(backend, copied, moved)
                self.assertFalse(backend.exists(copied))
                with backend.open_read(moved) as fh:
                    self.assertEqual(fh.read(), b"payload")

                backend.remove(source)
                backend.remove(moved)
                backend.remove(base, recursive=False)
                self.assertFalse(backend.exists(base))

    def test_sad_native_copy_failure_does_not_materialise_partial_destination(self) -> None:
        class _PartialCopyLocal(LocalFS):
            def copy(self, src: str, dst: str) -> None:
                Path(dst).write_bytes(b"PARTIAL")
                raise OSError("disk full")

        with tempfile.TemporaryDirectory() as tmp:
            src = os.path.join(tmp, "source.bin")
            dst = os.path.join(tmp, "dest.bin")
            Path(src).write_bytes(b"full payload")

            with self.assertRaisesRegex(OSError, "disk full"):
                server_side_copy(_PartialCopyLocal(), src, dst)

            self.assertFalse(Path(dst).exists())
            leftovers = [
                p.name for p in Path(tmp).iterdir() if ".copy-" in p.name or ".replace-" in p.name
            ]
            self.assertEqual(leftovers, [])

    def test_sad_unsupported_native_copy_streams_without_temp_leftovers(self) -> None:
        class _NoNativeCopy(LocalFS):
            def copy(self, src: str, dst: str) -> None:
                raise OSError("no native copy available")

        with tempfile.TemporaryDirectory() as tmp:
            src = os.path.join(tmp, "source.bin")
            dst = os.path.join(tmp, "dest.bin")
            Path(src).write_bytes(b"fallback payload")

            server_side_copy(_NoNativeCopy(), src, dst)

            self.assertEqual(Path(dst).read_bytes(), b"fallback payload")
            leftovers = [
                p.name for p in Path(tmp).iterdir() if ".copy-" in p.name or ".replace-" in p.name
            ]
            self.assertEqual(leftovers, [])

    def test_sad_direct_stream_failure_restores_existing_destination(self) -> None:
        from core.server_ops import stream_copy_between_backends

        class _FailingRead:
            def __init__(self):
                self._sent = False

            def read(self, size=-1):
                if not self._sent:
                    self._sent = True
                    return b"partial"
                raise OSError("source broke")

            def close(self):
                pass

            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc, tb):
                self.close()

        class _Source:
            def open_read(self, path: str):
                return _FailingRead()

        class _DirectLocalNoTemp:
            def exists(self, path: str) -> bool:
                return os.path.exists(path)

            def is_dir(self, path: str) -> bool:
                return os.path.isdir(path)

            def remove(self, path: str, recursive: bool = False) -> None:
                os.remove(path)

            def open_read(self, path: str):
                return open(path, "rb")

            def open_write(self, path: str):
                return open(path, "wb")

        with tempfile.TemporaryDirectory() as tmp:
            dst = os.path.join(tmp, "target.bin")
            Path(dst).write_bytes(b"original")

            with self.assertRaisesRegex(OSError, "source broke"):
                stream_copy_between_backends(_Source(), "/source", _DirectLocalNoTemp(), dst)

            self.assertEqual(Path(dst).read_bytes(), b"original")

    def test_sad_direct_stream_failure_removes_new_partial_destination(self) -> None:
        from core.server_ops import stream_copy_between_backends

        class _FailingRead:
            def __init__(self):
                self._sent = False

            def read(self, size=-1):
                if not self._sent:
                    self._sent = True
                    return b"partial"
                raise OSError("source broke")

            def close(self):
                pass

            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc, tb):
                self.close()

        class _Source:
            def open_read(self, path: str):
                return _FailingRead()

        class _DirectLocalNoTemp:
            def exists(self, path: str) -> bool:
                return os.path.exists(path)

            def is_dir(self, path: str) -> bool:
                return os.path.isdir(path)

            def remove(self, path: str, recursive: bool = False) -> None:
                os.remove(path)

            def open_read(self, path: str):
                return open(path, "rb")

            def open_write(self, path: str):
                return open(path, "wb")

        with tempfile.TemporaryDirectory() as tmp:
            dst = os.path.join(tmp, "target.bin")

            with self.assertRaisesRegex(OSError, "source broke"):
                stream_copy_between_backends(_Source(), "/source", _DirectLocalNoTemp(), dst)

            self.assertFalse(Path(dst).exists())

    def test_sad_direct_stream_fails_closed_when_destination_probe_fails(self) -> None:
        from core.server_ops import stream_copy_between_backends

        class _Source:
            def open_read(self, path: str):
                raise AssertionError("copy must fail before reading source")

        class _Destination:
            def exists(self, path: str) -> bool:
                raise OSError("probe failed")

            def open_write(self, path: str):
                raise AssertionError("copy must fail before opening writer")

        with self.assertRaisesRegex(OSError, "without probing"):
            stream_copy_between_backends(
                _Source(),
                "/source",
                _Destination(),
                "/target",
            )

    def test_sad_no_overwrite_copy_fails_closed_when_destination_probe_fails(self) -> None:
        class _Backend:
            def exists(self, path: str) -> bool:
                raise OSError("probe failed")

            def copy(self, src: str, dst: str) -> None:
                raise AssertionError("copy must fail before native copy")

        with self.assertRaisesRegex(OSError, "existence check failed"):
            server_side_copy(_Backend(), "/source", "/target", overwrite=False)

    def test_edge_atomic_replace_on_no_overwrite_rename_backend(self) -> None:
        from core.atomic_io import atomic_write

        ram = RamFsSession("contract-edge")
        self.addCleanup(ram.disconnect)
        with ram.open_write("/target.txt") as fh:
            fh.write(b"old")

        atomic_write(ram, "/target.txt", b"new")

        with ram.open_read("/target.txt") as fh:
            self.assertEqual(fh.read(), b"new")
        leftovers = [
            item.name
            for item in ram.list_dir("/")
            if item.name.startswith(".tmp-") or ".replace-" in item.name
        ]
        self.assertEqual(leftovers, [])

    def test_edge_atomic_write_uses_dbfs_commit_writer_not_rename(self) -> None:
        from core.atomic_io import atomic_write
        from core.sqlite_fs_client import SqliteFsSession

        class _NoRenameSqlite(SqliteFsSession):
            def rename(self, src: str, dst: str) -> None:
                raise AssertionError("DB-FS atomic write must not rename")

        with tempfile.NamedTemporaryFile(suffix=".sqlite", delete=False) as handle:
            db_path = handle.name
        os.unlink(db_path)
        backend = _NoRenameSqlite(url=db_path)
        try:
            with backend.open_write("/target.txt") as fh:
                fh.write(b"old")

            atomic_write(backend, "/target.txt", b"new")

            self.assertEqual(backend.open_read("/target.txt").read(), b"new")
            leftovers = [
                item.name
                for item in backend.list_dir("/")
                if item.name.startswith(".tmp-") or ".replace-" in item.name
            ]
            self.assertEqual(leftovers, [])
        finally:
            backend.close()
            try:
                os.unlink(db_path)
            except OSError:
                pass

    def test_edge_move_fallback_undoes_destination_when_source_delete_fails(self) -> None:
        class _NoRenameRemoveSourceFails:
            name = "NoRenameFake"

            def __init__(self, source: str):
                self.source = source

            def exists(self, path: str) -> bool:
                return os.path.exists(path)

            def rename(self, src: str, dst: str) -> None:
                raise OSError("no rename support")

            def copy(self, src: str, dst: str) -> None:
                Path(dst).write_bytes(Path(src).read_bytes())

            def remove(self, path: str, recursive: bool = False) -> None:
                if path == self.source:
                    raise OSError("source still locked")
                os.remove(path)

        with tempfile.TemporaryDirectory() as tmp:
            src = os.path.join(tmp, "source.bin")
            dst = os.path.join(tmp, "dest.bin")
            Path(src).write_bytes(b"move payload")

            with self.assertRaisesRegex(OSError, "source still locked"):
                server_side_move(_NoRenameRemoveSourceFails(src), src, dst)

            self.assertEqual(Path(src).read_bytes(), b"move payload")
            self.assertFalse(Path(dst).exists())

    def test_edge_server_side_move_refuses_existing_destination(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            src = os.path.join(tmp, "source.bin")
            dst = os.path.join(tmp, "dest.bin")
            Path(src).write_bytes(b"source")
            Path(dst).write_bytes(b"dest")

            with self.assertRaisesRegex(FileExistsError, "already exists"):
                server_side_move(LocalFS(), src, dst)

            self.assertEqual(Path(src).read_bytes(), b"source")
            self.assertEqual(Path(dst).read_bytes(), b"dest")

    def test_edge_localfs_subclass_with_custom_rename_is_not_assumed_posix(self) -> None:
        from core.capability_contracts import contract_for_backend
        from core.transfer_manager import _should_use_temp_file

        class _NoRenameLocal(LocalFS):
            def rename(self, src: str, dst: str) -> None:
                raise OSError("no rename support")

        backend = _NoRenameLocal()
        contract = contract_for_backend(backend)
        self.assertFalse(contract.rename_atomic)
        self.assertFalse(_should_use_temp_file(backend))

    def test_edge_unknown_backend_does_not_get_temp_rename_by_default(self) -> None:
        from core.transfer_manager import _should_use_temp_file

        class _UnknownBackend:
            pass

        self.assertFalse(_should_use_temp_file(_UnknownBackend()))

    def test_edge_sqlite_fs_copy_and_rename_refuse_existing_destination(self) -> None:
        from core.sqlite_fs_client import SqliteFsSession

        with tempfile.NamedTemporaryFile(suffix=".sqlite", delete=False) as handle:
            db_path = handle.name
        os.unlink(db_path)
        backend = SqliteFsSession(url=db_path)
        try:
            with backend.open_write("/source.txt") as fh:
                fh.write(b"source")
            with backend.open_write("/target.txt") as fh:
                fh.write(b"target")

            with self.assertRaisesRegex(OSError, "already exists"):
                backend.copy("/source.txt", "/target.txt")
            with self.assertRaisesRegex(OSError, "already exists"):
                backend.rename("/source.txt", "/target.txt")

            self.assertEqual(backend.open_read("/source.txt").read(), b"source")
            self.assertEqual(backend.open_read("/target.txt").read(), b"target")
        finally:
            backend.close()
            try:
                os.unlink(db_path)
            except OSError:
                pass

    def test_edge_server_side_copy_overwrites_dbfs_via_guarded_stream(self) -> None:
        from core.sqlite_fs_client import SqliteFsSession

        with tempfile.NamedTemporaryFile(suffix=".sqlite", delete=False) as handle:
            db_path = handle.name
        os.unlink(db_path)
        backend = SqliteFsSession(url=db_path)
        try:
            with backend.open_write("/source.txt") as fh:
                fh.write(b"source")
            with backend.open_write("/target.txt") as fh:
                fh.write(b"target")

            server_side_copy(backend, "/source.txt", "/target.txt", overwrite=True)
            self.assertEqual(backend.open_read("/target.txt").read(), b"source")

            with backend.open_write("/target.txt") as fh:
                fh.write(b"target again")
            with self.assertRaisesRegex(FileExistsError, "already exists"):
                server_side_copy(
                    backend,
                    "/source.txt",
                    "/target.txt",
                    overwrite=False,
                )
            self.assertEqual(
                backend.open_read("/target.txt").read(),
                b"target again",
            )
        finally:
            backend.close()
            try:
                os.unlink(db_path)
            except OSError:
                pass

    def test_edge_dbfs_capabilities_do_not_claim_atomic_rename(self) -> None:
        from core.backend_registry import DBFS_CAPS
        from core.capability_contracts import CapabilityContract
        from core.server_ops import _supports_temp_destination
        from core.sqlite_fs_client import SqliteFsSession
        from core.transfer_manager import _should_use_temp_file

        contract = CapabilityContract.from_caps(DBFS_CAPS)
        self.assertFalse(contract.rename_atomic)

        with tempfile.NamedTemporaryFile(suffix=".sqlite", delete=False) as handle:
            db_path = handle.name
        os.unlink(db_path)
        backend = SqliteFsSession(url=db_path)
        try:
            self.assertFalse(_should_use_temp_file(backend))
            self.assertFalse(_supports_temp_destination(backend))
        finally:
            backend.close()
            try:
                os.unlink(db_path)
            except OSError:
                pass

    def test_edge_registry_autoloads_for_low_level_capability_lookup(self) -> None:
        from core import atomic_io, backend_registry

        saved_registry = dict(backend_registry._registry)
        try:
            backend_registry._registry.clear()
            self.assertIsNotNone(backend_registry.get("sftp"))

            backend_registry._registry.clear()
            registered = {info.protocol_id for info in backend_registry.all_backends()}
            self.assertIn("s3", registered)

            backend_registry._registry.clear()
            s3_backend = type("S3Session", (), {})()
            self.assertTrue(atomic_io._is_native_atomic(s3_backend))
        finally:
            backend_registry._registry.clear()
            backend_registry._registry.update(saved_registry)
