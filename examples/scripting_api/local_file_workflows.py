"""Local and in-memory examples for the core axross scripting verbs."""

from __future__ import annotations

import os
import tempfile
import time
import zipfile
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator

COVERS = (
    "localfs",
    "ramfs",
    "copy",
    "move",
    "remove",
    "trash",
    "checksum",
    "read_bytes",
    "write_bytes",
    "read_text",
    "write_text",
    "hash_bytes",
    "hash_file",
    "encrypt",
    "decrypt",
    "extract_archive",
    "is_archive",
    "find_files",
    "grep",
    "GrepHit",
    "diff_files",
    "magic_type",
    "text_encoding",
    "entropy",
    "archive_inspect",
    "ArchiveEntry",
    "diagnose",
    "preview_delete",
    "preview_transfer",
    "recovery_scan",
    "recent_operations",
    "security_mode",
    "where_was_i",
    "health_pulse",
    "summarize",
    "explain",
    "compare_file",
    "inspect_targets",
    "federated_search",
    "resumable_copy",
    "snapshot_now",
    "start_trail",
    "stop_trail",
    "list_trails",
    "list_snapshots",
    "diff_snapshots",
    "dashboard",
)


@contextmanager
def _isolated_state(root: Path) -> Iterator[None]:
    """Keep history/trail state under the example temp directory."""
    from core import trail, visit_history

    old_trail_config = trail.CONFIG_DIR
    old_trail_db = trail.DB_FILE
    old_history_file = visit_history.HISTORY_FILE
    state = root / ".axross-state"
    trail.CONFIG_DIR = state
    trail.DB_FILE = state / "trail.db"
    visit_history.HISTORY_FILE = state / "visit_history.json"
    try:
        yield
    finally:
        try:
            trail.stop_all_trails()
        except Exception:
            pass
        trail.CONFIG_DIR = old_trail_config
        trail.DB_FILE = old_trail_db
        visit_history.HISTORY_FILE = old_history_file


def _wait_for_snapshot(axross, trail_name: str, *, minimum: int = 1) -> None:
    deadline = time.monotonic() + 3.0
    while time.monotonic() < deadline:
        if len(axross.list_snapshots(trail_name)) >= minimum:
            return
        time.sleep(0.05)
    raise AssertionError(f"trail {trail_name!r} did not record {minimum} snapshot(s)")


def run(base_dir: str | os.PathLike[str] | None = None) -> dict:
    """Run the local-safe examples and return a compact result dict."""
    import axross
    from core.profiles import ConnectionProfile

    tmp_ctx = None
    if base_dir is None:
        tmp_ctx = tempfile.TemporaryDirectory()
        root = Path(tmp_ctx.name)
    else:
        root = Path(base_dir)
        root.mkdir(parents=True, exist_ok=True)

    try:
        with _isolated_state(root):
            local = axross.localfs()
            ram = axross.ramfs(max_bytes=4 * 1024 * 1024)
            peer = axross.ramfs(max_bytes=4 * 1024 * 1024)

            # Attach profile metadata so visit-history examples have
            # something meaningful to show.
            ram._axross_profile = ConnectionProfile(  # type: ignore[attr-defined]
                name="example-ramfs",
                protocol="ramfs",
                host="example-host",
                username="operator",
            )
            ram._axross_profile_key = "example-ramfs-session"  # type: ignore[attr-defined]

            local_root = root / "local"
            local_root.mkdir()
            source = local_root / "source.txt"
            other = local_root / "other.txt"
            archive = local_root / "bundle.zip"
            extract_to = local_root / "extract"

            axross.write_text(local, str(source), "alpha\nsecret=42\n")
            axross.write_text(local, str(other), "alpha\nsecret=43\n")
            assert axross.read_text(local, str(source)) == "alpha\nsecret=42\n"
            assert axross.read_bytes(local, str(source)).startswith(b"alpha")
            assert axross.checksum(local, str(source)).startswith("sha256:")
            assert len(axross.hash_file(local, str(source))) == 64
            assert len(axross.hash_bytes(b"example")) == 64

            copied = axross.copy(local, str(source), ram, "/copied.txt")
            assert copied == source.stat().st_size
            axross.move(ram, "/copied.txt", ram, "/moved.txt")
            assert axross.read_text(ram, "/moved.txt") == "alpha\nsecret=42\n"

            axross.write_bytes(ram, "/data.bin", b"\x00\x01\x02", overwrite=False)
            encrypted = axross.encrypt(ram, "/moved.txt", "correct horse", overwrite=True)
            assert encrypted == "/moved.txt.axenc"
            assert axross.decrypt(ram, encrypted, "correct horse") == b"alpha\nsecret=42\n"

            axross.write_text(peer, "/moved.txt", "alpha\nsecret=99\n")
            compare = axross.compare_file([ram, peer], "/moved.txt")
            inspected = axross.inspect_targets([(ram, "/moved.txt"), (peer, "/moved.txt")])
            found = axross.federated_search(
                [ram, peer],
                name="*.txt",
                contains="secret",
                roots=["/"],
                max_depth=2,
            )
            assert found.hits
            assert compare.probes
            assert inspected.targets

            resume_manifest = root / "resume.json"
            resumed = axross.resumable_copy(
                ram,
                "/moved.txt",
                peer,
                "/resumed.txt",
                segment_size=64 * 1024,
                manifest_path=resume_manifest,
                overwrite=True,
            )
            assert resumed.bytes_transferred >= 0

            delete_preview = axross.preview_delete(ram, ["/moved.txt"])
            transfer_preview = axross.preview_transfer(ram, peer, ["/moved.txt"], "/")
            assert "item" in delete_preview
            assert "item" in transfer_preview

            axross.write_text(ram, "/delete-me.txt", "bye")
            axross.remove(ram, "/delete-me.txt", confirm=True)
            axross.write_text(ram, "/trash-me.txt", "recoverable")
            trash_id = axross.trash(ram, "/trash-me.txt", root="/", confirm=True)
            assert trash_id

            with zipfile.ZipFile(archive, "w") as zf:
                zf.writestr("inside.txt", "hello from zip\n")
            assert axross.is_archive(str(archive))
            entries = axross.archive_inspect(str(archive))
            assert entries and entries[0].name == "inside.txt"
            axross.extract_archive(str(archive), str(extract_to))
            assert (extract_to / "inside.txt").is_file()

            matches = list(axross.find_files(local, str(local_root), pattern="*.txt"))
            grep_hits = list(axross.grep(local, str(source), "secret"))
            diff = axross.diff_files(local, str(source), local, str(other))
            assert matches
            assert grep_hits and grep_hits[0].line_no == 2
            assert "-secret=42" in diff or "+secret=43" in diff

            optional: dict[str, str] = {}
            try:
                optional["magic_type"] = axross.magic_type(b"PK\x03\x04demo")
            except OSError as exc:
                optional["magic_type"] = f"skipped: {exc}"
            try:
                optional["text_encoding"] = str(axross.text_encoding(b"plain text"))
            except OSError as exc:
                optional["text_encoding"] = f"skipped: {exc}"
            optional["entropy"] = f"{axross.entropy(b'aaaaabbbbbccccc'):.2f}"

            summary = axross.summarize(ram, "/")
            explanation = axross.explain(ram, "/")
            diagnostics = axross.diagnose(ram, root="/", write_test=True)
            recovery = axross.recovery_scan(ram, "/")
            history = axross.where_was_i("example-host")
            health = axross.health_pulse()
            assert summary.render()
            assert explanation.render()
            assert diagnostics
            assert recovery
            assert history is not None
            assert isinstance(health, list)

            previous_mode = axross.security_mode()
            try:
                assert axross.security_mode("normal") == "normal"
            finally:
                axross.security_mode(previous_mode)

            trail_name = "example-local-trail"
            snap_a = axross.snapshot_now(ram, "/", name=trail_name)
            axross.write_text(ram, "/new.txt", "new file")
            snap_b = axross.snapshot_now(ram, "/", name=trail_name)
            snapshots = axross.list_snapshots(trail_name)
            trail_diff = axross.diff_snapshots(snap_a.snapshot_id, snap_b.snapshot_id)
            assert snapshots
            assert "/new.txt" in trail_diff.added
            assert any(t["name"] == trail_name for t in axross.list_trails())

            bg_name = axross.start_trail(ram, "/", name="example-background-trail")
            _wait_for_snapshot(axross, bg_name)
            assert axross.stop_trail(bg_name) is True

            dashboard_json = axross.dashboard(
                fmt="json",
                with_capacity=True,
                backends=[ram],
            )
            assert "captured_at" in dashboard_json

            return {
                "copied": copied,
                "grep_hits": len(grep_hits),
                "search_hits": len(found.hits),
                "trail_snapshots": len(snapshots),
                "recent_operations": len(axross.recent_operations(limit=5)),
                "optional": optional,
            }
    finally:
        if tmp_ctx is not None:
            tmp_ctx.cleanup()


if __name__ == "__main__":
    print(run())
