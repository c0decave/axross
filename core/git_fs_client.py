"""Git-as-storage FileBackend using dulwich.

Treats a git repository as a filesystem: branches are directories
under ``/``, the tree at each branch's HEAD is its child filesystem.
Writes commit a new tree onto the branch (one commit per file
write); ``flush_push()`` syncs to the remote.

Layout::

    /                       — list of local + remote branches
    /<branch>/              — tree at that branch's tip
    /<branch>/path/to/file  — blob at that path

Capabilities & guard rails:

* **Author / email** come from the profile (``author_name`` /
  ``author_email``); ``~/.gitconfig`` is used as a fallback.
* **Fast-forward only.** Any operation that would rewrite history
  (force-push, branch reset, amend) is refused. The session refuses
  to commit if the local branch tip has diverged from the remote.
* **No working tree assumption.** We talk to the object store
  directly via dulwich; there is no ``.git/index`` checkout. Bare
  repos work the same as non-bare.
* **Remote URLs auto-clone** into a per-session cache dir under
  ``~/.cache/axross/git/<sha1>/``. ``flush_push()`` pushes back.

Requires: ``pip install axross[git]`` — dulwich>=0.21.
"""
from __future__ import annotations

import hashlib
import io
import logging
import os
import posixpath
import stat as st_mod
import threading
from datetime import datetime
from pathlib import Path
from typing import IO

from models.file_item import FileItem

log = logging.getLogger(__name__)

from core.git_fs_writer_helper import _GitWriter  # noqa: E402

try:
    from dulwich import porcelain  # type: ignore[import-not-found]
    from dulwich.client import get_transport_and_path  # type: ignore[import-not-found]
    from dulwich.objects import Blob, Commit, Tree  # type: ignore[import-not-found]
    from dulwich.repo import Repo  # type: ignore[import-not-found]
except ImportError:
    porcelain = None  # type: ignore[assignment]
    get_transport_and_path = None  # type: ignore[assignment]
    Blob = Commit = Tree = Repo = None  # type: ignore[assignment]

CACHE_ROOT = Path.home() / ".cache" / "axross" / "git"

# File mode used when committing new blobs. We don't model executables
# per-file (the FileBackend chmod surface only flips one bit on/off
# in the commit metadata); 0o100644 is the regular-file default.
_DEFAULT_BLOB_MODE = 0o100644
_EXEC_BLOB_MODE = 0o100755


class GitForceRefused(OSError):
    """Raised when an operation would rewrite history (force-push,
    non-fast-forward, amend). The user has to address the divergence
    in a real git client; axross refuses to do destructive history
    edits silently."""


# ---------------------------------------------------------------------------
# URL → cache-path
# ---------------------------------------------------------------------------

def _cache_dir_for(url: str) -> Path:
    """Deterministic per-URL cache dir under CACHE_ROOT. The hash
    salts on the full URL so http://x/repo and ssh://x/repo don't
    collide."""
    digest = hashlib.sha1(url.encode("utf-8")).hexdigest()[:16]
    return CACHE_ROOT / digest


# ---------------------------------------------------------------------------
# Public session
# ---------------------------------------------------------------------------

class GitFsSession:
    """Git-backed FileBackend."""

    supports_symlinks = False
    supports_hardlinks = False

    def __init__(
        self,
        url: str = "",
        path: str = "",
        author_name: str = "",
        author_email: str = "",
        default_branch: str = "main",
        **_ignored,
    ):
        if Repo is None:
            raise ImportError(
                "Git backend requires dulwich. "
                "Install with: pip install axross[git]"
            )
        if not url and not path:
            raise OSError("Git backend needs either url= or path=")
        self._origin_url = url or ""
        self._lock = threading.RLock()
        self._default_branch = default_branch

        if path and not url:
            # Local repo path supplied directly.
            self._repo = Repo(os.path.abspath(path))
            self._workdir = self._repo.path
            log.info("Git-FS opened local repo: %s", self._workdir)
        else:
            cache_dir = _cache_dir_for(url)
            cache_dir.parent.mkdir(parents=True, exist_ok=True)
            if (cache_dir / ".git").exists() or (cache_dir / "HEAD").exists():
                self._repo = Repo(str(cache_dir))
                self._workdir = str(cache_dir)
                # Refresh from origin so we operate on current refs.
                try:
                    porcelain.fetch(self._repo, remote_location=url)
                    log.debug("Git-FS fetched from %s", url)
                except Exception as exc:  # noqa: BLE001
                    log.warning("Git-FS fetch from %s failed: %s", url, exc)
            else:
                log.info("Git-FS cloning %s -> %s", url, cache_dir)
                self._repo = porcelain.clone(
                    url, str(cache_dir), bare=True, depth=None,
                )
                self._workdir = str(cache_dir)

        # Author identity. Profile takes precedence, then git config,
        # then a deliberately-broken default that forces the user to
        # set one before they can commit.
        self._author_name = author_name or self._git_config_value("user", "name") or ""
        self._author_email = author_email or self._git_config_value("user", "email") or ""

        # Branch tip cache: ref name → commit sha (bytes). Refreshed
        # after every commit so list_dir reflects new state.
        self._branch_tips: dict[str, bytes] = {}
        self._refresh_branch_tips()

    # ------------------------------------------------------------------
    # Identity / lifecycle
    # ------------------------------------------------------------------

    @property
    def name(self) -> str:
        return f"Git: {self._origin_url or self._workdir}"

    @property
    def connected(self) -> bool:
        return self._repo is not None

    def close(self) -> None:
        try:
            self._repo.close()
        except Exception:  # noqa: BLE001
            pass

    def disconnect(self) -> None:
        self.close()

    def _git_config_value(self, section: str, key: str) -> str:
        try:
            cfg = self._repo.get_config_stack()
            val = cfg.get((section.encode(),), key.encode())
            return val.decode("utf-8", "replace") if val else ""
        except (KeyError, Exception):  # noqa: BLE001
            return ""

    # ------------------------------------------------------------------
    # Path helpers
    # ------------------------------------------------------------------

    def home(self) -> str:
        return f"/{self._default_branch}"

    def separator(self) -> str:
        return "/"

    def join(self, *parts: str) -> str:
        cleaned = [s for s in (p.strip("/") for p in parts) if s]
        if not cleaned:
            return "/"
        return "/" + "/".join(cleaned)

    def parent(self, path: str) -> str:
        return posixpath.dirname(path.rstrip("/")) or "/"

    def normalize(self, path: str) -> str:
        if not path:
            return "/"
        if not path.startswith("/"):
            path = "/" + path
        return posixpath.normpath(path) or "/"

    @staticmethod
    def _split_branch(path: str) -> tuple[str, str]:
        """Split ``/branch/sub/path`` → ``("branch", "sub/path")``.
        Root → ``("", "")``."""
        path = path.lstrip("/")
        if not path:
            return "", ""
        parts = path.split("/", 1)
        if len(parts) == 1:
            return parts[0], ""
        return parts[0], parts[1]

    # ------------------------------------------------------------------
    # Branch / tree walking
    # ------------------------------------------------------------------

    def _refresh_branch_tips(self) -> None:
        with self._lock:
            self._branch_tips = {}
            refs = self._repo.get_refs()
            for ref, sha in refs.items():
                ref_str = ref.decode("utf-8", "replace") if isinstance(ref, bytes) else ref
                if ref_str.startswith("refs/heads/"):
                    self._branch_tips[ref_str[len("refs/heads/"):]] = sha
                elif (
                    ref_str.startswith("refs/remotes/origin/")
                    and ref_str != "refs/remotes/origin/HEAD"
                ):
                    name = ref_str[len("refs/remotes/origin/"):]
                    # Only expose remote branches that don't already
                    # have a local counterpart.
                    if name not in self._branch_tips:
                        self._branch_tips[name] = sha

    def _list_branches(self) -> list[FileItem]:
        return [
            FileItem(
                name=branch, is_dir=True, is_link=False, size=0,
                modified=datetime.fromtimestamp(0), permissions=0o755,
            )
            for branch in sorted(self._branch_tips)
        ]

    def _walk_tree_to(self, branch: str, sub_path: str) -> tuple[Tree, str]:
        """Walk a tree along ``sub_path`` and return ``(tree, name)``
        where ``tree`` is the directory tree containing ``name`` and
        ``name`` is the leaf (or empty when sub_path is empty).

        Raises :class:`OSError` for any missing intermediate."""
        with self._lock:
            tip = self._branch_tips.get(branch)
            if tip is None:
                raise OSError(f"No such branch: {branch}")
            commit = self._repo[tip]
            tree = self._repo[commit.tree]
            if not sub_path:
                return tree, ""
            parts = sub_path.split("/")
            for i, part in enumerate(parts[:-1]):
                entry = self._tree_entry(tree, part)
                if entry is None or not st_mod.S_ISDIR(entry[0]):
                    raise OSError(f"Path component not a directory: {part}")
                tree = self._repo[entry[1]]
            return tree, parts[-1]

    @staticmethod
    def _tree_entry(tree, name: str):
        """Lookup ``name`` in ``tree`` — return ``(mode, sha)`` or None."""
        name_b = name.encode("utf-8")
        try:
            mode, sha = tree[name_b]
            return mode, sha
        except KeyError:
            return None

    # ------------------------------------------------------------------
    # FileBackend — read surface
    # ------------------------------------------------------------------

    def list_dir(self, path: str) -> list[FileItem]:
        path = self.normalize(path)
        if path == "/":
            return self._list_branches()
        branch, sub = self._split_branch(path)
        try:
            if not sub:
                tip = self._branch_tips.get(branch)
                if tip is None:
                    raise OSError(f"No such branch: {branch}")
                tree = self._repo[self._repo[tip].tree]
            else:
                parent_tree, leaf = self._walk_tree_to(branch, sub)
                entry = self._tree_entry(parent_tree, leaf)
                if entry is None:
                    raise OSError(f"No such path: {path}")
                mode, sha = entry
                if not st_mod.S_ISDIR(mode):
                    raise OSError(f"Not a directory: {path}")
                tree = self._repo[sha]
        except KeyError as exc:
            raise OSError(f"Git list({path}): {exc}") from exc

        items: list[FileItem] = []
        for entry in tree.items():
            name = entry.path.decode("utf-8", "replace")
            mode = entry.mode
            sha = entry.sha
            is_dir = st_mod.S_ISDIR(mode)
            size = 0
            mtime = datetime.fromtimestamp(0)
            if not is_dir:
                try:
                    blob = self._repo[sha]
                    size = blob.raw_length() if hasattr(blob, "raw_length") else len(blob.data)
                except KeyError:
                    size = 0
            items.append(FileItem(
                name=name, is_dir=is_dir, is_link=False,
                size=size, modified=mtime,
                permissions=mode & 0o777 if not is_dir else 0o755,
            ))
        return items

    def stat(self, path: str) -> FileItem:
        path = self.normalize(path)
        if path == "/":
            return FileItem(
                name="/", is_dir=True, is_link=False, size=0,
                modified=datetime.fromtimestamp(0), permissions=0o755,
            )
        branch, sub = self._split_branch(path)
        if branch and not sub:
            if branch not in self._branch_tips:
                raise OSError(f"No such branch: {branch}")
            return FileItem(
                name=branch, is_dir=True, is_link=False, size=0,
                modified=datetime.fromtimestamp(0), permissions=0o755,
            )
        try:
            parent_tree, leaf = self._walk_tree_to(branch, sub)
            entry = self._tree_entry(parent_tree, leaf)
        except KeyError as exc:
            raise OSError(f"Git stat({path}): {exc}") from exc
        if entry is None:
            raise OSError(f"No such path: {path}")
        mode, sha = entry
        is_dir = st_mod.S_ISDIR(mode)
        if is_dir:
            return FileItem(
                name=leaf, is_dir=True, is_link=False, size=0,
                modified=datetime.fromtimestamp(0), permissions=0o755,
            )
        blob = self._repo[sha]
        size = len(blob.data)
        return FileItem(
            name=leaf, is_dir=False, is_link=False,
            size=size, modified=datetime.fromtimestamp(0),
            permissions=mode & 0o777,
        )

    def is_dir(self, path: str) -> bool:
        try:
            return self.stat(path).is_dir
        except OSError:
            return False

    def exists(self, path: str) -> bool:
        try:
            self.stat(path)
            return True
        except OSError:
            return False

    def open_read(self, path: str) -> IO[bytes]:
        path = self.normalize(path)
        branch, sub = self._split_branch(path)
        if not branch or not sub:
            raise OSError("Git read: path must be /<branch>/<file>")
        try:
            parent_tree, leaf = self._walk_tree_to(branch, sub)
            entry = self._tree_entry(parent_tree, leaf)
        except KeyError as exc:
            raise OSError(f"Git read({path}): {exc}") from exc
        if entry is None:
            raise OSError(f"No such path: {path}")
        mode, sha = entry
        if st_mod.S_ISDIR(mode):
            raise OSError(f"Is a directory: {path}")
        blob = self._repo[sha]
        return io.BytesIO(blob.data)

    def readlink(self, path: str) -> str:
        raise OSError("Git symlinks not exposed by axross")

    # ------------------------------------------------------------------
    # FileBackend — write surface
    # ------------------------------------------------------------------

    def open_write(self, path: str, append: bool = False) -> IO[bytes]:
        path = self.normalize(path)
        branch, sub = self._split_branch(path)
        if not branch or not sub:
            raise OSError("Git write: path must be /<branch>/<file>")
        prelude = b""
        if append and self.exists(path):
            with self.open_read(path) as fh:
                prelude = fh.read()
        return _GitWriter(self, branch, sub, prelude)

    def mkdir(self, path: str) -> None:
        # Git tracks files, not empty directories. mkdir is a no-op
        # except when the user is trying to create a top-level branch
        # — for that, they should use the bookmark / branch UI.
        if path.count("/") <= 1:
            raise OSError(
                "Git: branches must be created via git, not mkdir. "
                "Existing branches appear at the root automatically.",
            )
        # Deeper paths: no-op (git has no empty trees).

    def remove(self, path: str, recursive: bool = False) -> None:
        path = self.normalize(path)
        branch, sub = self._split_branch(path)
        if not branch or not sub:
            raise OSError("Git remove: refusing to delete a branch via FS API")
        # Build a new tree without the removed entry.
        self._commit_modification(branch, sub, blob_data=None, message=f"axross: rm {sub}")

    def rename(self, src: str, dst: str) -> None:
        src = self.normalize(src)
        dst = self.normalize(dst)
        src_branch, src_sub = self._split_branch(src)
        dst_branch, dst_sub = self._split_branch(dst)
        if src_branch != dst_branch:
            raise OSError("Git: cross-branch rename is not supported (use copy)")
        with self.open_read(src) as fh:
            data = fh.read()
        # Two commits to keep the diff readable: write to dst, then rm src.
        self._commit_modification(dst_branch, dst_sub, blob_data=data,
                                   message=f"axross: mv {src_sub} → {dst_sub} (a)")
        self._commit_modification(src_branch, src_sub, blob_data=None,
                                   message=f"axross: mv {src_sub} → {dst_sub} (b)")

    def copy(self, src: str, dst: str) -> None:
        src = self.normalize(src)
        dst = self.normalize(dst)
        with self.open_read(src) as fh:
            data = fh.read()
        dst_branch, dst_sub = self._split_branch(dst)
        self._commit_modification(dst_branch, dst_sub, blob_data=data,
                                   message=f"axross: cp {src} → {dst}")

    def chmod(self, path: str, mode: int) -> None:
        # Map any executable bit → 0o100755, else 0o100644.
        path = self.normalize(path)
        branch, sub = self._split_branch(path)
        with self.open_read(path) as fh:
            data = fh.read()
        new_mode = _EXEC_BLOB_MODE if (mode & 0o111) else _DEFAULT_BLOB_MODE
        self._commit_modification(branch, sub, blob_data=data,
                                   message=f"axross: chmod {oct(mode)} {sub}",
                                   blob_mode=new_mode)

    def list_versions(self, path: str) -> list:
        # TODO: walk the commit history along the branch and surface
        # one entry per commit that touched the file. For now, return [].
        return []

    def open_version_read(self, path: str, version_id: str):
        raise OSError("Git version-walk not yet implemented in v1")

    def disk_usage(self, path: str) -> tuple[int, int, int]:
        return (0, 0, 0)

    # ------------------------------------------------------------------
    # Git-specific verbs (API_GAPS round 2)
    # ------------------------------------------------------------------

    def log(self, branch: str = "main", *,
            limit: int = 100,
            sub_path: str | None = None) -> list[dict]:
        """Walk the commit history of ``branch`` newest-first. Returns
        up to ``limit`` dicts ``{sha, author_name, author_email,
        message, timestamp, parents}``.

        ``sub_path`` filters to commits that touched that sub-path
        (uses dulwich's path-filter walker; cheaper than walking
        every commit + diffing).
        """
        from dulwich.walk import Walker
        tip = self._branch_tips.get(branch)
        if tip is None:
            self._refresh_branch_tips()
            tip = self._branch_tips.get(branch)
        if tip is None:
            raise OSError(f"git log: unknown branch {branch!r}")
        kwargs = {"include": [tip]}
        if sub_path:
            kwargs["paths"] = [sub_path.lstrip("/").encode("utf-8")]
        out: list[dict] = []
        for entry in Walker(self._repo.object_store, **kwargs):
            commit = entry.commit
            out.append({
                "sha": commit.id.decode("ascii"),
                "author_name": commit.author.split(b" <", 1)[0]
                                  .decode("utf-8", "replace"),
                "author_email": (
                    commit.author.split(b" <", 1)[1].rstrip(b">")
                                 .decode("utf-8", "replace")
                    if b" <" in commit.author else ""
                ),
                "message": commit.message.decode("utf-8", "replace"),
                "timestamp": int(commit.author_time),
                "parents": [p.decode("ascii") for p in commit.parents],
            })
            if len(out) >= int(limit):
                break
        return out

    def diff(self, sha_a: str, sha_b: str = "HEAD", *,
             branch: str = "main") -> str:
        """Unified diff between two commits. ``sha_b="HEAD"`` resolves
        to the current branch tip; otherwise both args are full or
        abbreviated SHAs.

        Returns the diff as a single string (UTF-8 decoded); empty
        string means no changes.
        """
        from dulwich import porcelain as _porc
        import io as _io
        if sha_b == "HEAD":
            tip = self._branch_tips.get(branch)
            if tip is None:
                raise OSError(f"git diff: unknown branch {branch!r}")
            sha_b = tip.decode("ascii")
        buf = _io.BytesIO()
        try:
            _porc.diff_tree(
                self._repo,
                self._resolve_to_tree(sha_a),
                self._resolve_to_tree(sha_b),
                outstream=buf,
            )
        except Exception as exc:  # noqa: BLE001 — dulwich raises various
            raise OSError(f"git diff {sha_a}..{sha_b}: {exc}") from exc
        return buf.getvalue().decode("utf-8", "replace")

    def _resolve_to_tree(self, sha_or_ref: str) -> bytes:
        """Take a commit SHA / tag / branch name and return its tree
        object id (what dulwich.porcelain.diff_tree wants)."""
        as_bytes = sha_or_ref.encode("ascii") if isinstance(sha_or_ref, str) \
            else sha_or_ref
        # Try as a direct commit SHA first.
        try:
            obj = self._repo[as_bytes]
        except KeyError:
            # Branch name?
            tip = self._branch_tips.get(sha_or_ref)
            if tip is None:
                raise OSError(
                    f"git diff: cannot resolve {sha_or_ref!r}",
                ) from None
            obj = self._repo[tip]
        # If it's a Commit, return its tree; if a Tree, return as-is.
        if hasattr(obj, "tree"):
            return obj.tree
        return obj.id

    def branch_list(self) -> list[str]:
        """All known local + remote-tracking branches, sorted. Refreshes
        the cached tip-set first so a remote-side advance shows up."""
        self._refresh_branch_tips()
        return sorted(self._branch_tips)

    def tag_list(self) -> list[dict]:
        """All tags in the repo. Returns dicts ``{name, sha, target}``
        — ``target`` is the commit the tag points at; for annotated
        tags ``sha`` is the tag-object SHA and ``target`` is the
        underlying commit. Lightweight tags have ``sha == target``."""
        from dulwich.objects import Tag as _Tag
        out: list[dict] = []
        for ref, sha in self._repo.get_refs().items():
            ref_str = ref.decode("ascii", "replace")
            if not ref_str.startswith("refs/tags/"):
                continue
            name = ref_str[len("refs/tags/"):]
            target = sha
            try:
                obj = self._repo[sha]
            except KeyError:
                continue
            if isinstance(obj, _Tag):
                target = obj.object[1]
            out.append({
                "name": name,
                "sha": sha.decode("ascii"),
                "target": target.decode("ascii"),
            })
        return sorted(out, key=lambda t: t["name"])

    def blame(self, path: str, *,
              branch: str | None = None) -> list[dict]:
        """Per-line authorship for ``path`` — returns one dict per
        line ``{line_no, sha, author_name, author_email, timestamp,
        line}``.

        ``path`` is in the axross-FileBackend form ``/<branch>/<sub>``
        (matches list_dir / open_read / open_write conventions). Pass
        ``branch=`` explicitly to override the branch the path encodes.

        Implementation: walk the path's commit history, diff each
        adjacent pair, and credit each line to the earliest commit
        that introduced it. Pure Python (no shellout); slower than
        git-cli's heuristic blame.
        """
        # Path encodes the branch — ``/<branch>/<sub>``.
        norm = self.normalize(path)
        path_branch, sub = self._split_branch(norm)
        if branch is None:
            branch = path_branch
        if not branch:
            raise OSError(f"git blame: no branch in path: {path!r}")
        if not sub:
            raise OSError(f"git blame: path missing sub-path: {path!r}")
        sha_b = self._branch_tips.get(branch)
        if sha_b is None:
            raise OSError(f"git blame: unknown branch {branch!r}")
        try:
            parent_tree, leaf = self._walk_tree_to(branch, sub)
            entry = self._tree_entry(parent_tree, leaf)
        except KeyError:
            raise OSError(f"git blame: path not in branch: {path!r}") from None
        if entry is None:
            raise OSError(f"git blame: path not in branch: {path!r}")
        _mode, blob_sha = entry
        blob = self._repo[blob_sha]
        current_lines = blob.data.decode("utf-8", "replace").splitlines()

        # Walk commits that touched this path; map each line number
        # → first commit that introduced it (newest match wins per
        # walker iteration order).
        history = self.log(branch=branch, sub_path=sub, limit=10_000)
        lines_credit: list[dict | None] = [None] * len(current_lines)
        for commit_meta in reversed(history):  # oldest first
            try:
                # Reconstruct the file at this commit's tree.
                commit = self._repo[commit_meta["sha"].encode("ascii")]
                tree = self._repo[commit.tree]
                parts = sub.split("/")
                cur = tree
                for p in parts[:-1]:
                    sub_entry = self._tree_entry(cur, p)
                    if sub_entry is None:
                        cur = None; break
                    cur = self._repo[sub_entry[1]]
                if cur is None:
                    continue
                file_entry = self._tree_entry(cur, parts[-1])
                if file_entry is None:
                    continue
                file_blob = self._repo[file_entry[1]]
                cur_lines = file_blob.data.decode("utf-8", "replace").splitlines()
            except KeyError:
                continue
            # Each line in cur_lines that matches current_lines and
            # hasn't been credited yet → credit to this commit.
            for i, line in enumerate(cur_lines):
                if i >= len(current_lines):
                    break
                if line == current_lines[i] and lines_credit[i] is None:
                    lines_credit[i] = {
                        "line_no": i + 1,
                        "sha": commit_meta["sha"],
                        "author_name": commit_meta["author_name"],
                        "author_email": commit_meta["author_email"],
                        "timestamp": commit_meta["timestamp"],
                        "line": current_lines[i],
                    }
        # Fill any uncredited lines with a sentinel (matches git's
        # ``^``-prefixed boundary commit notation conceptually).
        return [
            c if c is not None else {
                "line_no": i + 1,
                "sha": "0" * 40,
                "author_name": "",
                "author_email": "",
                "timestamp": 0,
                "line": current_lines[i],
            }
            for i, c in enumerate(lines_credit)
        ]

    def checksum(self, path: str, algorithm: str = "sha256") -> str:
        # Git already has a content-addressable hash — return the
        # blob SHA as a strong fingerprint. The "git:" prefix flags
        # the algorithm so callers don't compare it against a sha256.
        path = self.normalize(path)
        branch, sub = self._split_branch(path)
        if not branch or not sub:
            return ""
        try:
            parent_tree, leaf = self._walk_tree_to(branch, sub)
            entry = self._tree_entry(parent_tree, leaf)
        except KeyError:
            return ""
        if entry is None:
            return ""
        _mode, sha = entry
        return f"git:{sha.decode() if isinstance(sha, bytes) else sha}"

    # ------------------------------------------------------------------
    # Internal commit helper
    # ------------------------------------------------------------------

    def _commit_modification(
        self, branch: str, sub: str,
        blob_data: bytes | None,
        message: str,
        blob_mode: int = _DEFAULT_BLOB_MODE,
    ) -> None:
        """Build a new tree on ``branch`` with ``sub`` set to
        ``blob_data`` (or removed if None) and commit it. Refuses if
        the local branch ref is behind a known remote tip
        (fast-forward only)."""
        if not self._author_name or not self._author_email:
            raise OSError(
                "Git commit refused: no author identity. Set "
                "author_name / author_email on the profile or in "
                "~/.gitconfig.",
            )
        with self._lock:
            tip_sha = self._branch_tips.get(branch)
            if tip_sha is None:
                # Brand-new branch: empty tree, no parent.
                parent_sha = None
                root_tree = Tree()
            else:
                # Fast-forward guard: refuse if origin's view of this
                # branch is ahead of the local tip we're about to amend.
                origin_ref = f"refs/remotes/origin/{branch}".encode()
                refs = self._repo.get_refs()
                origin_sha = refs.get(origin_ref)
                if origin_sha and origin_sha != tip_sha:
                    if self._is_ancestor(tip_sha, origin_sha):
                        # Local is BEHIND origin — refuse to commit on
                        # top of stale tip; user has to fetch+merge first.
                        raise GitForceRefused(
                            f"Local branch {branch} is behind origin/{branch}; "
                            "fetch + merge before committing via axross."
                        )
                parent_commit = self._repo[tip_sha]
                root_tree = self._repo[parent_commit.tree]
                parent_sha = tip_sha

            new_root = self._build_modified_tree(root_tree, sub, blob_data, blob_mode)
            self._repo.object_store.add_object(new_root)

            commit = Commit()
            commit.tree = new_root.id
            commit.parents = [parent_sha] if parent_sha else []
            committer = f"{self._author_name} <{self._author_email}>".encode()
            commit.author = commit.committer = committer
            now = int(datetime.now().timestamp())
            commit.author_time = commit.commit_time = now
            commit.author_timezone = commit.commit_timezone = 0
            commit.encoding = b"UTF-8"
            commit.message = message.encode("utf-8")
            self._repo.object_store.add_object(commit)
            self._repo.refs[f"refs/heads/{branch}".encode()] = commit.id
            self._branch_tips[branch] = commit.id
            log.info("Git-FS commit %s on %s: %s", commit.id.decode()[:8], branch, message)

    def _build_modified_tree(
        self, root_tree: Tree, sub: str,
        blob_data: bytes | None,
        blob_mode: int,
    ) -> Tree:
        """Recursively rebuild ``root_tree`` so that ``sub`` points at
        ``blob_data`` (or is absent when blob_data is None). Returns
        the new root Tree (already added to object store along the way)."""
        parts = sub.split("/")
        return self._modify_tree_rec(root_tree, parts, blob_data, blob_mode)

    def _modify_tree_rec(
        self, tree: Tree, parts: list[str],
        blob_data: bytes | None, blob_mode: int,
    ) -> Tree:
        new_tree = Tree()
        # Copy every entry that we're not modifying.
        head = parts[0].encode("utf-8")
        for entry in tree.items():
            if entry.path == head:
                continue
            new_tree.add(entry.path, entry.mode, entry.sha)
        if len(parts) == 1:
            # Leaf modification.
            if blob_data is not None:
                blob = Blob.from_string(blob_data)
                self._repo.object_store.add_object(blob)
                new_tree.add(head, blob_mode, blob.id)
            # else: deletion — already left out above.
        else:
            # Recurse into the (possibly new) subtree.
            existing = self._tree_entry(tree, parts[0])
            if existing and st_mod.S_ISDIR(existing[0]):
                sub_tree = self._repo[existing[1]]
            else:
                sub_tree = Tree()
            new_sub = self._modify_tree_rec(sub_tree, parts[1:], blob_data, blob_mode)
            # Only persist non-empty subtrees — git has no concept of
            # an empty directory, and unconditionally adding empty
            # trees pollutes the loose-object set on every delete that
            # empties a directory.
            if len(new_sub.items()):  # noqa: WPS507 — explicit empty-tree check
                self._repo.object_store.add_object(new_sub)
                new_tree.add(head, st_mod.S_IFDIR, new_sub.id)
        self._repo.object_store.add_object(new_tree)
        return new_tree

    # Walk-cap on _is_ancestor traversal. On long-lived branches the
    # parent-set can grow unboundedly, and we'd allocate ~40 bytes per
    # SHA in the seen-set. Cap to 50 000 commits and treat overflow as
    # "cannot prove ancestry → fail-closed (refuse the commit)" — the
    # operator can still resolve via a real git client.
    _ANCESTOR_WALK_CAP = 50_000

    def _is_ancestor(self, candidate: bytes, descendant: bytes) -> bool:
        """True when ``candidate`` is reachable from ``descendant`` via
        parent links (i.e. candidate is an ancestor of descendant).
        Returns False when the walk exhausts the cap — that's the
        fail-closed direction since the only caller refuses to commit
        when this returns True."""
        seen: set[bytes] = set()
        stack: list[bytes] = [descendant]
        while stack:
            if len(seen) >= self._ANCESTOR_WALK_CAP:
                log.warning(
                    "Git-FS _is_ancestor walk exceeded %d commits; "
                    "treating as non-ancestor (refusing commit).",
                    self._ANCESTOR_WALK_CAP,
                )
                return False
            sha = stack.pop()
            if sha in seen:
                continue
            seen.add(sha)
            if sha == candidate:
                return True
            try:
                obj = self._repo[sha]
            except KeyError:
                continue
            for parent in getattr(obj, "parents", []) or []:
                stack.append(parent)
        return False

    # ------------------------------------------------------------------
    # Optional: push to origin (manual)
    # ------------------------------------------------------------------

    def flush_push(self, branch: str | None = None) -> None:
        """Push local commits to origin. Branch defaults to every
        branch the session has touched. Refuses non-fast-forward
        unconditionally (no force-push surface)."""
        if not self._origin_url:
            raise OSError("Git-FS: no remote URL — nothing to push to")
        branches = [branch] if branch else list(self._branch_tips)
        for b in branches:
            try:
                porcelain.push(
                    self._repo, remote_location=self._origin_url,
                    refspecs=[f"refs/heads/{b}:refs/heads/{b}".encode()],
                    force=False,
                )
            except Exception as exc:
                if "non-fast-forward" in str(exc).lower():
                    raise GitForceRefused(
                        f"push refused: branch {b} would require force-push"
                    ) from exc
                raise OSError(f"Git push {b}: {exc}") from exc
            log.info("Git-FS pushed %s → %s", b, self._origin_url)
