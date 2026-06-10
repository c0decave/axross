"""Profile, bookmark, saved-script and runtime-doc examples."""

from __future__ import annotations

import contextlib
import io
import os
import tempfile
from pathlib import Path
from typing import Iterator

COVERS = (
    "__version__",
    "open",
    "list_backends",
    "available_backends",
    "list_profiles",
    "get_profile",
    "save_profile",
    "delete_profile",
    "list_bookmarks",
    "add_bookmark",
    "remove_bookmark",
    "script_dir",
    "list_scripts",
    "save_script",
    "load_script",
    "delete_script",
    "run_script",
    "docs",
    "help",
    "message",
    "confirm",
    "toast",
)


@contextlib.contextmanager
def _isolated_config(root: Path) -> Iterator[None]:
    """Redirect profile/bookmark/script storage to ``root``."""
    from core import bookmarks, profiles

    old_home = os.environ.get("HOME")
    old_profile_config = profiles.CONFIG_DIR
    old_profiles_file = profiles.PROFILES_FILE
    old_bookmark_config = bookmarks.CONFIG_DIR
    old_bookmarks_file = bookmarks.BOOKMARKS_FILE

    config = root / ".config" / "axross"
    os.environ["HOME"] = str(root)
    profiles.CONFIG_DIR = config
    profiles.PROFILES_FILE = config / "profiles.json"
    bookmarks.CONFIG_DIR = config
    bookmarks.BOOKMARKS_FILE = config / "bookmarks.json"
    try:
        yield
    finally:
        if old_home is None:
            os.environ.pop("HOME", None)
        else:
            os.environ["HOME"] = old_home
        profiles.CONFIG_DIR = old_profile_config
        profiles.PROFILES_FILE = old_profiles_file
        bookmarks.CONFIG_DIR = old_bookmark_config
        bookmarks.BOOKMARKS_FILE = old_bookmarks_file


def interactive_prompt_example() -> None:
    """Pattern for interactive scripts; intentionally not run in tests."""
    import axross

    if axross.confirm("Start the operator-approved action?"):
        axross.toast("Action started", level="info")
        axross.message("Action completed", title="axross example")


def run(base_dir: str | os.PathLike[str] | None = None) -> dict:
    """Run storage and documentation examples without touching user config."""
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
        with _isolated_config(root):
            assert axross.__version__
            all_backends = axross.list_backends()
            available = axross.available_backends()
            assert "ramfs" in all_backends

            profile = ConnectionProfile(
                name="Example RamFS",
                protocol="ramfs",
                host="",
                username="",
            )
            axross.save_profile(profile)
            assert "Example RamFS" in axross.list_profiles()
            assert axross.get_profile("Example RamFS").protocol == "ramfs"

            opened = axross.open("Example RamFS")
            try:
                axross.write_text(opened, "/from-profile.txt", "opened by name")
                assert axross.read_text(opened, "/from-profile.txt") == "opened by name"
            finally:
                close = getattr(opened, "close", None) or getattr(opened, "disconnect", None)
                if close:
                    close()

            axross.add_bookmark(
                "Example Home",
                "/",
                backend_name="RAM:example",
                profile_name="Example RamFS",
            )
            bookmarks = axross.list_bookmarks()
            assert len(bookmarks) == 1
            axross.remove_bookmark(0)
            assert axross.list_bookmarks() == []

            saved_path = axross.save_script(
                "hash_demo",
                "result = axross.hash_bytes(b'example')\n",
            )
            assert Path(saved_path).is_file()
            assert "hash_demo" in axross.list_scripts()
            assert "hash_bytes" in axross.load_script("hash_demo")
            namespace = axross.run_script("hash_demo")
            assert len(namespace["result"]) == 64
            axross.delete_script("hash_demo")
            assert "hash_demo" not in axross.list_scripts()

            docs_text = axross.docs("copy")
            full_docs = axross.docs()
            assert docs_text.startswith("### `axross.copy")
            assert "axross.open" in full_docs

            help_buffer = io.StringIO()
            with contextlib.redirect_stdout(help_buffer):
                axross.help()
            assert "Axross scripting cheat-sheet" in help_buffer.getvalue()

            axross.delete_profile("Example RamFS")
            assert axross.get_profile("Example RamFS") is None

            return {
                "backends": len(all_backends),
                "available_backends": len(available),
                "script_dir": axross.script_dir(),
                "docs_chars": len(full_docs),
            }
    finally:
        if tmp_ctx is not None:
            tmp_ctx.cleanup()


if __name__ == "__main__":
    print(run())
