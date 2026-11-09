"""Git-as-storage FileBackend using dulwich.

Treats a git repository as a filesystem: branches are directories
under ``/``, the tree at each branch's HEAD is its child filesystem.
Writes commit a new tree onto the branch (one commit per file
write).

Layout::

    /                       — list of local + remote branches
    /<branch>/              — tree at that branch's tip
    /<branch>/path/to/file  — blob at that path

Capabilities & guard rails:

* **Author / email** come from the profile (``author_name`` /
  ``author_email``); ``~/.gitconfig`` is used as a fallback.
* **Fast-forward only.** axross never rewrites history on a remote
  (no force-push, branch reset of a pushed branch, amend). The
  session refuses to commit if the local branch tip has diverged from
  the remote.
* **No working tree assumption.** We talk to the object store
  directly via dulwich; there is no ``.git/index`` checkout. Bare
  repos work the same as non-bare.
* **Remote URLs auto-clone** into a per-URL cache dir under
  ``~/.cache/axross/git/<sha256[:16]>/``.

URL sessions and the remote (the cache is a mirror, not a fork):

* **Opening fetches.** Each local branch then follows ``origin``:
  behind → fast-forwarded; rewritten upstream (a force-push) while
  every local commit of it was already on origin → reset to origin's
  new tip (logged); deleted upstream with nothing unpushed → deleted
  here too. A branch with commits that never reached origin keeps
  them (nothing is thrown away): ahead of origin they are pushed with
  the next write; diverged from origin (upstream force-pushed over
  them) the branch is read-only here until it is merged in a real git
  client (:class:`GitForceRefused`).
* **Every write is pushed** (``auto_push=True``, the default): the
  commit goes to origin straight away, fast-forward only. When the
  push fails (network, rejected) the commit stays in the cache, the
  write raises :class:`GitPushFailed` naming the commit, and the next
  write - or ``flush_push()`` / ``axross.git_push`` - pushes it along.
  A script that wants one push for many writes passes
  ``auto_push=False`` and calls ``flush_push()`` itself. A branch that
  is checked out in a local non-bare origin is not written (git
  refuses such a push; dulwich would move the ref under the work tree).
* **Offline:** when origin cannot be reached at open, the session
  opens the cached copy *read-only* (``offline`` is the reason; every
  write raises ``EROFS``) and says so - a WARNING in the log and
  :meth:`GitFsSession.status_note` in the pane's status line, as is
  a count of commits not pushed yet.

Requires: ``pip install axross[git]`` — dulwich>=0.21.
"""

from __future__ import annotations

import contextlib
import errno
import functools
import hashlib
import io
import logging
import os
import posixpath
import re
import shlex
import stat as st_mod
import threading
import zlib
from datetime import datetime
from pathlib import Path
from typing import IO
from urllib.parse import urlsplit, urlunsplit

from core.append_helpers import read_existing_for_append
from core.backend import SessionLifecycle
from core.redaction import redact_url
from models.file_item import FileItem

log = logging.getLogger(__name__)


@contextlib.contextmanager
def _as_oserror(operation: str, path: str):
    """Normalise dulwich/zlib failures into the documented OSError.

    Loose git objects are zlib streams, so this is the one backend where
    a decompression failure is reachable. ``zlib.error`` is NOT an
    OSError — its MRO is ``error -> Exception`` — so it escaped the
    contract every other backend keeps (docs/SCRIPTING_REFERENCE.md:18).
    Concretely, ``ui/text_editor._save_file`` wraps the save in
    ``except OSError``, so a corrupt object gave the user a raw
    traceback reading "Error -3 while decompressing data: incorrect
    header check" instead of the Save Error dialog that exists for it.

    OSError subclasses pass through untouched: re-wrapping them would
    bury errno and the original message. KeyboardInterrupt and
    SystemExit are deliberately not caught — a user pressing Ctrl+C is
    not a corrupt repository.
    """
    try:
        yield
    except OSError:
        raise
    except (KeyboardInterrupt, SystemExit):
        raise
    except Exception as exc:  # noqa: BLE001 — dulwich raises its own tree
        raise OSError(
            f"Git {operation} failed for {path}: the repository object could "
            f"not be decoded and may be corrupt ({type(exc).__name__}: {exc})"
        ) from exc


# A loose object's header ("blob 1234\0") is far shorter than this.
_LOOSE_HEADER_MAX = 64


def _loose_header_is_complete(raw: bytes) -> bool:
    """Whether a zlib-framed loose object decompresses to a header
    ending in NUL within its first ``_LOOSE_HEADER_MAX`` bytes. A
    stream that is not zlib at all counts as complete: dulwich reads it
    as a new-style object or rejects it with its own error."""
    try:
        head = zlib.decompressobj().decompress(raw, _LOOSE_HEADER_MAX)
    except zlib.error:
        return True  # dulwich raises zlib.error itself; _as_oserror maps it
    return b"\0" in head


def _guard_loose_objects(repo) -> None:
    """Refuse a truncated loose object instead of hanging on it.

    dulwich (1.2.6) parses a loose object's header in
    ShaFile._parse_legacy_object_header (dulwich/objects.py) by reading
    more of the file until the decompressed header holds a NUL - after
    _parse_file already read the whole file, so a zlib stream that ends
    before the NUL (an object cut short by a crash or a full disk, or
    sent so by a remote) loops forever on empty reads, hanging every
    call that touches it (found by tests/test_fuzz_git.py). The check
    runs before dulwich's loader; the store keeps working as before for
    every intact object.
    """
    store = getattr(repo, "object_store", None)
    loader = getattr(store, "_get_loose_object", None)
    shafile_path = getattr(store, "_get_shafile_path", None)
    if loader is None or shafile_path is None:
        return

    def guarded(sha):
        try:
            with open(shafile_path(sha), "rb") as fh:
                raw = fh.read(4096)
        except OSError:
            return loader(sha)  # missing: dulwich answers None
        if raw and (raw[0] & 0x8F) == 0x08 and not _loose_header_is_complete(raw):
            raise OSError(
                errno.EIO,
                f"Git object {sha!r} is truncated: its header never ends (a corrupt loose object)",
            )
        return loader(sha)

    store._get_loose_object = guarded


def _object_errors_as_oserror(method):
    """``_as_oserror`` around a whole backend method.

    It guarded only the commit path, but every read decodes objects too:
    a corrupt (or hostile, as fetched from a remote) commit, tree or blob
    made list_dir / stat / open_read raise dulwich's
    ObjectFormatException or zlib.error to callers that handle OSError
    (found by tests/test_fuzz_git.py)."""

    @functools.wraps(method)
    def wrapper(self, *args, **kwargs):
        path = args[0] if args and isinstance(args[0], str) else ""
        with _as_oserror(method.__name__, path):
            return method(self, *args, **kwargs)

    return wrapper


from core.git_fs_writer_helper import _GitWriter  # noqa: E402

#: The most versions list_versions returns: a file of a long history
#: would otherwise load every blob of it.
MAX_VERSIONS = 200
#: A commit id: SHA-1 (40) or SHA-256 (64) hex.
_SHA = re.compile(r"[0-9a-f]{40}|[0-9a-f]{64}")


def _is_gitlink(mode: int) -> bool:
    return (mode & 0o170000) == _GITLINK_MODE


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
# A submodule entry: the sha names a commit of ANOTHER repository, which
# this object store usually does not hold.
_GITLINK_MODE = 0o160000
_EXEC_BLOB_MODE = 0o100755


class GitForceRefused(OSError):
    """Raised when an operation would rewrite history (force-push,
    non-fast-forward, amend). The user has to address the divergence
    in a real git client; axross refuses to do destructive history
    edits silently."""


class GitPushFailed(OSError):
    """A write was committed into the session's cache but could not be
    pushed to origin (unreachable, rejected). The commit is kept and is
    pushed with the next write or ``flush_push()``."""


class GitBranchMoved(OSError):
    """Raised when a write finds the branch moved since the session read
    it (or while it committed): committing on the old tip would drop the
    commits made in between, so axross refuses instead."""


def _ref_or_none(refs, name: bytes):
    """The sha *name* points at in *refs*, None when there is no such ref."""
    try:
        return refs[name]
    except KeyError:
        return None


def _short_sha(sha: bytes | None) -> str:
    """The first 8 hex digits of *sha*, "none" for a missing ref."""
    if not sha:
        return "none"
    return (sha.decode("ascii", "replace") if isinstance(sha, bytes) else str(sha))[:8]


def _checked_out_in(repo) -> set[str]:
    """Branches a work tree of *repo* has checked out: the HEAD of a
    non-bare repo and the HEAD of every linked worktree."""
    control = repo.controldir()
    heads = [] if repo.bare else [os.path.join(control, "HEAD")]
    linked = os.path.join(control, "worktrees")
    if os.path.isdir(linked):
        heads += [os.path.join(linked, name, "HEAD") for name in sorted(os.listdir(linked))]
    branches: set[str] = set()
    for head in heads:
        try:
            with open(head, "rb") as fh:
                text = fh.read(4096).strip()
        except OSError:
            continue
        if text.startswith(b"ref: refs/heads/"):
            branches.add(text[len(b"ref: refs/heads/") :].decode("utf-8", "replace"))
    return branches


# ---------------------------------------------------------------------------
# URL → cache-path
# ---------------------------------------------------------------------------


def _cache_dir_for(url: str) -> Path:
    """Deterministic per-URL cache dir under CACHE_ROOT. The hash
    salts on the full URL so http://x/repo and ssh://x/repo don't
    collide."""
    digest = hashlib.sha256(url.encode("utf-8")).hexdigest()[:16]
    return CACHE_ROOT / digest


# ---------------------------------------------------------------------------
# Public session
# ---------------------------------------------------------------------------


_SCP_LIKE_RE = re.compile(r"^(?:(?P<user>[^@/:]+)@)?(?P<host>[^:/@]+):(?P<path>.*)$")


def _proxied_transport(url: str, proxy_cfg) -> tuple[str, dict, list]:
    """Route a remote through *proxy_cfg*.

    Returns ``(connect_url, transport_kwargs, tunnels)``:

    * http(s): a urllib3 proxy manager (SOCKS or HTTP CONNECT); the URL is
      untouched so TLS verifies the real host.
    * ssh / scp-style: a loopback tunnel; ssh dials it but keeps the real
      host's identity via ``HostKeyAlias``.
    * git://: a loopback tunnel.
    * local paths / file://: nothing to proxy.
    """
    from core import proxy as proxy_mod

    if "://" not in url:
        match = _SCP_LIKE_RE.match(url)
        if not match or url.startswith(("/", ".")) or len(match.group("host")) == 1:
            return url, {}, []  # plain local path
        path = match.group("path")
        user = f"{match.group('user')}@" if match.group("user") else ""
        tail = path if path.startswith("/") else f"/~/{path}"
        url = f"ssh://{user}{match.group('host')}{tail}"
    parts = urlsplit(url)
    scheme = parts.scheme.lower()
    if scheme in ("http", "https"):
        return url, {"pool_manager": proxy_mod.build_urllib3_proxy_manager(proxy_cfg)}, []
    if scheme not in ("ssh", "git", "git+ssh", "ssh+git"):
        return url, {}, []
    host = parts.hostname or ""
    if not host or host.startswith("-"):
        raise OSError(f"Git remote host {host!r} is not acceptable")
    port = parts.port or (9418 if scheme == "git" else 22)
    tunnel = proxy_mod.LocalTunnel(proxy_cfg, host, port).start()
    userinfo = parts.netloc.rpartition("@")[0]
    netloc = f"{userinfo + '@' if userinfo else ''}{tunnel.host}:{tunnel.port}"
    connect_url = urlunsplit((parts.scheme, netloc, parts.path, parts.query, parts.fragment))
    kwargs: dict = {}
    if scheme != "git":
        kwargs["ssh_command"] = f"ssh -o HostKeyAlias={shlex.quote(host)}"
    return connect_url, kwargs, [tunnel]


def _dulwich_url(url: str) -> str:
    """*url* as dulwich understands it.

    open_url sends every git+ scheme here. dulwich knows git+ssh, but
    reads git+https:// as an SSH URL with an empty host; the "git+" of
    git+http(s) only picks this backend and goes.
    """
    scheme, sep, rest = url.partition("://")
    if sep and scheme.lower() in ("git+https", "git+http"):
        return f"{scheme[4:].lower()}://{rest}"
    return url


class GitFsSession(SessionLifecycle):
    """Git-backed FileBackend."""

    supports_symlinks = False
    supports_hardlinks = False
    _MAX_APPEND_EXISTING_SIZE = 256 * 1024 * 1024

    def __init__(
        self,
        url: str = "",
        path: str = "",
        author_name: str = "",
        author_email: str = "",
        default_branch: str = "",
        auto_push: bool = True,
        **_ignored,
    ):
        self._tunnels: list = []
        # Why origin could not be reached when the session opened ("" =
        # it could): the cache is shown read-only then.
        self.offline = ""
        self._auto_push = bool(auto_push)
        self._status_note = ""
        self._transport_kwargs: dict = {}
        url = _dulwich_url(url) if url else url
        self._connect_url = url or ""
        if Repo is None:
            raise ImportError("Git backend requires dulwich. Install with: pip install axross[git]")
        if not url and not path:
            raise OSError("Git backend needs either url= or path=")
        self._origin_url = url or ""
        self._display_origin_url = redact_url(self._origin_url) if self._origin_url else ""
        self._lock = threading.RLock()
        self._default_branch = default_branch

        if path and not url:
            # Local repo path supplied directly.
            self._repo = Repo(os.path.abspath(path))
            _guard_loose_objects(self._repo)
            self._workdir = self._repo.path
            log.info("Git-FS opened local repo: %s", self._workdir)
        else:
            cache_dir = _cache_dir_for(url)
            cache_dir.parent.mkdir(parents=True, exist_ok=True)
            from core.proxy import proxy_config_from_kwargs

            proxy_cfg = proxy_config_from_kwargs(_ignored)
            if proxy_cfg is not None:
                self._connect_url, self._transport_kwargs, self._tunnels = _proxied_transport(
                    url, proxy_cfg
                )
            try:
                if (cache_dir / ".git").exists() or (cache_dir / "HEAD").exists():
                    self._repo = Repo(str(cache_dir))
                    _guard_loose_objects(self._repo)
                    self._workdir = str(cache_dir)
                    # Refresh from origin so we operate on current refs.
                    try:
                        self._fetch_origin()
                        log.debug("Git-FS fetched from %s", self._display_origin_url)
                    except Exception as exc:  # noqa: BLE001
                        # The cache is all there is: shown, but read-only -
                        # a commit here could neither be pushed nor checked
                        # against what origin has now.
                        self.offline = str(exc) or type(exc).__name__
                        log.warning(
                            "Git-FS: origin %s is unreachable (%s); showing the cached "
                            "copy from the last fetch, read-only",
                            self._display_origin_url,
                            self.offline,
                        )
                else:
                    log.info("Git-FS cloning %s -> %s", self._display_origin_url, cache_dir)
                    self._repo = porcelain.clone(
                        self._connect_url,
                        str(cache_dir),
                        bare=True,
                        depth=None,
                        **self._transport_kwargs,
                    )
                    _guard_loose_objects(self._repo)
                    self._workdir = str(cache_dir)
            except BaseException:
                self._close_tunnels()
                raise

        # Author identity. Profile takes precedence, then git config,
        # then a deliberately-broken default that forces the user to
        # set one before they can commit.
        self._author_name = author_name or self._git_config_value("user", "name") or ""
        self._author_email = author_email or self._git_config_value("user", "email") or ""

        # Branch tip cache: ref name → commit sha (bytes). Refreshed
        # after every commit so list_dir reflects new state.
        self._branch_tips: dict[str, bytes] = {}
        self._refresh_branch_tips()
        self._refresh_status_note()

    # ------------------------------------------------------------------
    # Identity / lifecycle
    # ------------------------------------------------------------------

    @property
    def name(self) -> str:
        display_origin = getattr(self, "_display_origin_url", "")
        if not display_origin and getattr(self, "_origin_url", ""):
            display_origin = redact_url(self._origin_url)
        return f"Git: {display_origin or self._workdir}"

    @property
    def connected(self) -> bool:
        return self._repo is not None

    def close(self) -> None:
        if self._repo is not None:
            display_origin = getattr(self, "_display_origin_url", "")
            log.info("Git-FS closing: %s", display_origin or self._workdir)
        try:
            self._repo.close()
        except Exception:  # noqa: BLE001
            pass
        self._close_tunnels()

    def disconnect(self) -> None:
        self.close()

    def _close_tunnels(self) -> None:
        for tunnel in self._tunnels:
            tunnel.close()
        self._tunnels = []

    def _fetch_origin(self) -> None:
        """Fetch from origin, honouring the profile proxy when set, and
        bring the cache's refs up to the remote's.

        ``porcelain.fetch(remote_location=<URL>)`` updated no ref: given a
        URL, not the remote's name, dulwich has no remote to file the
        refs under. The objects arrived, the refs stayed at clone time,
        and a session showed - and committed on top of - the clone-time
        content for ever. The refs are set here: see
        :meth:`_update_from_remote_refs`."""
        client, path = get_transport_and_path(
            self._connect_url,
            config=self._repo.get_config_stack(),
            **self._transport_kwargs,
        )
        result = client.fetch(path.encode() if isinstance(path, str) else path, self._repo)
        self._update_from_remote_refs(getattr(result, "refs", None) or {})

    _REMOTE_PREFIX = b"refs/remotes/origin/"

    def _update_from_remote_refs(self, remote_refs: dict) -> None:
        """File a fetch's answer under ``refs/remotes/origin/*``, and move
        each local branch that has nothing of its own along with it.

        * ``refs/remotes/origin/<b>`` = the remote's ``refs/heads/<b>``.
        * ``refs/heads/<b>`` is fast-forwarded when it is an ancestor of
          the remote's tip: no commit made here is lost.
        * origin rewrote the branch (a force-push) and every commit of
          the local branch was on origin before (the local tip is the
          remote-tracking tip of the last fetch or push, or behind it):
          the local branch follows origin's new tip - nothing of ours is
          dropped, and the session no longer shows (and refuses writes
          to) content upstream has replaced.
        * a branch with commits of its own (not pushed yet) keeps them:
          ahead of origin they are pushed with the next write; diverged,
          _commit_modification refuses to build on it until it is merged.
        * a branch origin deleted goes here too when nothing of it is
          unpushed; its remote-tracking ref goes in every case.
        * a tag the cache does not have yet is added; one it has stays.
        Refs whose objects the fetch did not bring are skipped."""
        refs = self._repo.refs
        store = self._repo.object_store
        upstream: dict[bytes, bytes] = {}
        remote_branches: set[bytes] = set()
        for ref, sha in remote_refs.items():
            if not isinstance(ref, bytes) or not sha or ref.endswith(b"^{}"):
                continue
            if ref.startswith(b"refs/heads/"):
                remote_branches.add(ref[len(b"refs/heads/") :])
            if sha not in store:
                continue
            if ref.startswith(b"refs/heads/"):
                upstream[ref[len(b"refs/heads/") :]] = sha
            elif ref.startswith(b"refs/tags/") and ref not in refs:
                refs[ref] = sha
        for name, sha in upstream.items():
            shown = name.decode("utf-8", "replace")
            previous = _ref_or_none(refs, self._REMOTE_PREFIX + name)
            refs[self._REMOTE_PREFIX + name] = sha
            local_ref = b"refs/heads/" + name
            local = _ref_or_none(refs, local_ref)
            if local is None or local == sha:
                continue
            if self._is_ancestor(local, sha):
                refs.set_if_equals(local_ref, local, sha)
                log.debug("Git-FS: %s fast-forwarded to %s", shown, _short_sha(sha))
            elif self._is_ancestor(sha, local):
                log.info("Git-FS: %s has commits not pushed to origin yet", shown)
            elif previous is not None and (local == previous or self._is_ancestor(local, previous)):
                refs.set_if_equals(local_ref, local, sha)
                log.warning(
                    "Git-FS: origin rewrote branch %s (a force-push: %s -> %s); nothing of "
                    "it was unpushed here, so it follows origin",
                    shown, _short_sha(previous), _short_sha(sha),
                )
            else:
                log.warning(
                    "Git-FS: local branch %s has commits origin does not have and origin "
                    "has diverged from it (%s vs %s); it is kept as it is here and is "
                    "read-only until it is merged in a git client",
                    shown, _short_sha(local), _short_sha(sha),
                )
        if remote_branches:
            for ref in list(refs.keys(base=self._REMOTE_PREFIX)):
                if ref == b"HEAD" or ref in remote_branches:
                    continue
                previous = _ref_or_none(refs, self._REMOTE_PREFIX + ref)
                del refs[self._REMOTE_PREFIX + ref]
                local = _ref_or_none(refs, b"refs/heads/" + ref)
                if local is None or previous is None:
                    continue
                shown = ref.decode("utf-8", "replace")
                if local == previous or self._is_ancestor(local, previous):
                    refs.remove_if_equals(b"refs/heads/" + ref, local)
                    log.warning("Git-FS: origin deleted branch %s; it goes here too", shown)
                else:
                    log.warning(
                        "Git-FS: origin deleted branch %s, which has commits not pushed; "
                        "it is kept here", shown,
                    )

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
        """The branch a pane opens on: the one named, if the repository has
        it; else the repository's HEAD branch, "main", or the first branch;
        "/" for a repository without branches."""
        tips = self._branch_tips
        candidates = [self._default_branch, self._head_branch(), "main"]
        for name in candidates:
            if name and name in tips:
                return f"/{name}"
        return f"/{sorted(tips)[0]}" if tips else "/"

    def _head_branch(self) -> str:
        try:
            target = self._repo.refs.get_symrefs().get(b"HEAD", b"")
        except Exception:  # noqa: BLE001 - a repository without a symbolic HEAD
            return ""
        prefix = b"refs/heads/"
        return target[len(prefix) :].decode("utf-8", "replace") if target.startswith(prefix) else ""

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

    def _split_branch(self, path: str) -> tuple[str, str]:
        """Split ``/branch/sub/path`` → ``("branch", "sub/path")``.
        Root → ``("", "")``.

        Branch names may contain ``/`` (``feature/x``), so the longest
        known branch that matches whole leading components wins. A path
        that names no known branch splits at its first component, which
        is how a write creates a new branch."""
        path = path.strip("/")
        if not path:
            return "", ""
        best = ""
        for branch in self._branch_tips:
            if len(branch) > len(best) and (path == branch or path.startswith(branch + "/")):
                best = branch
        if best:
            return best, path[len(best) + 1 :]
        parts = path.split("/", 1)
        if len(parts) == 1:
            return parts[0], ""
        return parts[0], parts[1]

    def _namespace_children(self, prefix: str) -> list[str]:
        """Next name components of the branches below ``prefix``
        (``""`` for the root): ``feature/x`` makes ``feature`` a
        directory at ``/`` and ``x`` one at ``/feature``."""
        lead = prefix.strip("/")
        lead = lead + "/" if lead else ""
        return sorted(
            {b[len(lead) :].split("/", 1)[0] for b in self._branch_tips if b.startswith(lead)}
        )

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
                    self._branch_tips[ref_str[len("refs/heads/") :]] = sha
                elif (
                    ref_str.startswith("refs/remotes/origin/")
                    and ref_str != "refs/remotes/origin/HEAD"
                ):
                    name = ref_str[len("refs/remotes/origin/") :]
                    # Only expose remote branches that don't already
                    # have a local counterpart.
                    if name not in self._branch_tips:
                        self._branch_tips[name] = sha

    def _list_branches(self, prefix: str = "") -> list[FileItem]:
        return [
            FileItem(
                name=name,
                is_dir=True,
                is_link=False,
                size=0,
                modified=datetime.fromtimestamp(0),
                permissions=0o755,
            )
            for name in self._namespace_children(prefix)
        ]

    def _walk_tree_to(self, branch: str, sub_path: str) -> tuple[Tree, str]:
        """Walk a tree along ``sub_path`` and return ``(tree, name)``
        where ``tree`` is the directory tree containing ``name`` and
        ``name`` is the leaf (or empty when sub_path is empty).

        Raises :class:`FileNotFoundError` for a missing branch or
        intermediate (or a file in its place)."""
        with self._lock:
            tip = self._branch_tips.get(branch)
            if tip is None:
                raise FileNotFoundError(errno.ENOENT, f"No such branch: {branch}")
            commit = self._repo[tip]
            tree = self._repo[commit.tree]
            if not sub_path:
                return tree, ""
            parts = sub_path.split("/")
            for i, part in enumerate(parts[:-1]):
                entry = self._tree_entry(tree, part)
                if entry is None or not st_mod.S_ISDIR(entry[0]):
                    raise FileNotFoundError(
                        errno.ENOENT, f"Path component not a directory: {part}"
                    )
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

    @_object_errors_as_oserror
    def list_dir(self, path: str) -> list[FileItem]:
        path = self.normalize(path)
        if path == "/":
            return self._list_branches()
        branch, sub = self._split_branch(path)
        if branch not in self._branch_tips and self._namespace_children(path):
            return self._list_branches(path)
        try:
            if not sub:
                tip = self._branch_tips.get(branch)
                if tip is None:
                    raise FileNotFoundError(errno.ENOENT, f"No such branch: {branch}", path)
                tree = self._repo[self._repo[tip].tree]
            else:
                parent_tree, leaf = self._walk_tree_to(branch, sub)
                entry = self._tree_entry(parent_tree, leaf)
                if entry is None:
                    raise FileNotFoundError(errno.ENOENT, "No such path", path)
                mode, sha = entry
                if not st_mod.S_ISDIR(mode):
                    raise NotADirectoryError(errno.ENOTDIR, "Not a directory", path)
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
            items.append(
                FileItem(
                    name=name,
                    is_dir=is_dir,
                    is_link=False,
                    size=size,
                    modified=mtime,
                    permissions=mode & 0o777 if not is_dir else 0o755,
                )
            )
        return items

    @_object_errors_as_oserror
    def stat(self, path: str) -> FileItem:
        item = self._stat(self.normalize(path))
        if path.endswith("/") and path.strip("/") and not item.is_dir:
            # stat(2) of "file/": not the file.
            raise NotADirectoryError(errno.ENOTDIR, "Not a directory", path)
        return item

    def _stat(self, path: str) -> FileItem:
        if path == "/":
            return FileItem(
                name="/",
                is_dir=True,
                is_link=False,
                size=0,
                modified=datetime.fromtimestamp(0),
                permissions=0o755,
            )
        branch, sub = self._split_branch(path)
        if branch not in self._branch_tips and self._namespace_children(path):
            return FileItem(
                name=posixpath.basename(path),
                is_dir=True,
                is_link=False,
                size=0,
                modified=datetime.fromtimestamp(0),
                permissions=0o755,
            )
        if branch and not sub:
            if branch not in self._branch_tips:
                raise FileNotFoundError(errno.ENOENT, f"No such branch: {branch}")
            return FileItem(
                name=posixpath.basename(branch),
                is_dir=True,
                is_link=False,
                size=0,
                modified=datetime.fromtimestamp(0),
                permissions=0o755,
            )
        try:
            parent_tree, leaf = self._walk_tree_to(branch, sub)
            entry = self._tree_entry(parent_tree, leaf)
        except KeyError as exc:
            raise OSError(f"Git stat({path}): {exc}") from exc
        if entry is None:
            raise FileNotFoundError(errno.ENOENT, f"No such path: {path}")
        mode, sha = entry
        is_dir = st_mod.S_ISDIR(mode)
        if is_dir:
            return FileItem(
                name=leaf,
                is_dir=True,
                is_link=False,
                size=0,
                modified=datetime.fromtimestamp(0),
                permissions=0o755,
            )
        if _is_gitlink(mode):
            # Submodule: the commit lives in another repository.
            return FileItem(
                name=leaf,
                is_dir=False,
                is_link=False,
                size=0,
                modified=datetime.fromtimestamp(0),
                permissions=0o555,
            )
        blob = self._repo[sha]
        size = len(blob.data)
        return FileItem(
            name=leaf,
            is_dir=False,
            is_link=False,
            size=size,
            modified=datetime.fromtimestamp(0),
            permissions=mode & 0o777,
        )

    def is_dir(self, path: str) -> bool:
        """False only for "not found"; an object the repository lacks or
        cannot read is an OSError."""
        try:
            return self.stat(path).is_dir
        except FileNotFoundError:
            return False

    def exists(self, path: str) -> bool:
        """False only for "not found"; any other failure is an OSError -
        server_side_copy(overwrite=False) takes False as its go-ahead."""
        try:
            self.stat(path)
        except FileNotFoundError:
            return False
        return True

    @_object_errors_as_oserror
    def open_read(self, path: str) -> IO[bytes]:
        path = self.normalize(path)
        branch, sub = self._split_branch(path)
        if not branch or not sub:
            if self.exists(path):
                raise IsADirectoryError(errno.EISDIR, "Is a directory", path)
            raise FileNotFoundError(errno.ENOENT, "No such branch", path)
        try:
            parent_tree, leaf = self._walk_tree_to(branch, sub)
            entry = self._tree_entry(parent_tree, leaf)
        except KeyError as exc:
            raise OSError(f"Git read({path}): {exc}") from exc
        if entry is None:
            raise FileNotFoundError(errno.ENOENT, "No such path", path)
        mode, sha = entry
        if st_mod.S_ISDIR(mode):
            raise IsADirectoryError(errno.EISDIR, "Is a directory", path)
        if _is_gitlink(mode):
            raise OSError(f"Git read: {path} is a submodule, not a file")
        blob = self._repo[sha]
        # dulwich hands back whatever a cut-short zlib stream yielded
        # ("hel" for "hello\n") without an error; check() recomputes the
        # object's id from its content and raises ChecksumMismatch.
        blob.check()
        return io.BytesIO(blob.data)

    @_object_errors_as_oserror
    def readlink(self, path: str) -> str:
        raise OSError("Git symlinks not exposed by axross")

    # ------------------------------------------------------------------
    # FileBackend — write surface
    # ------------------------------------------------------------------

    @_object_errors_as_oserror
    def open_write(self, path: str, append: bool = False) -> IO[bytes]:
        if path.endswith("/"):
            # normalize() drops the slash: "t/" would become a FILE t.
            raise IsADirectoryError(errno.EISDIR, "A file name cannot end in '/'", path)
        path = self.normalize(path)
        branch, sub = self._split_branch(path)
        if not branch or not sub:
            raise OSError("Git write: path must be /<branch>/<file>")
        prelude = b""
        if append:
            cap = self._MAX_APPEND_EXISTING_SIZE
            prelude = read_existing_for_append(
                open_read=self.open_read,
                stat=self.stat,
                path=path,
                cap=cap,
                label="Git",
                logger=log,
            )
            if len(prelude) > cap:
                raise OSError(f"Git append: existing file exceeds {cap // (1024 * 1024)} MiB cap")
        return _GitWriter(self, branch, sub, prelude)

    @_object_errors_as_oserror
    def mkdir(self, path: str) -> None:
        # Git tracks files, not empty directories. mkdir is a no-op
        # except when the user is trying to create a top-level branch
        # — for that, they should use the bookmark / branch UI.
        if self.normalize(path).count("/") <= 1:
            if self.exists(path):
                raise FileExistsError(errno.EEXIST, "The branch exists", path)
            raise OSError(
                errno.EPERM,
                "Git: branches must be created via git, not mkdir. "
                "Existing branches appear at the root automatically.",
            )
        # Deeper paths: no-op (git has no empty trees) - unless a file
        # already has the name.
        try:
            item = self.stat(path)
        except FileNotFoundError:
            return
        if not item.is_dir:
            raise FileExistsError(errno.EEXIST, "A file has this name", path)

    @_object_errors_as_oserror
    def remove(self, path: str, recursive: bool = False) -> None:
        path = self.normalize(path)
        branch, sub = self._split_branch(path)
        if not branch or not sub:
            raise OSError("Git remove: refusing to delete a branch via FS API")
        item = self.stat(path)  # FileNotFoundError when the path is absent
        if item.is_dir and not recursive:
            # A git tree is never empty, so a directory always has children.
            raise OSError(errno.ENOTEMPTY, f"Git remove: directory not empty: {path}")
        # Build a new tree without the removed entry.
        self._commit_modification(branch, sub, blob_data=None, message=f"axross: rm {sub}")

    @_object_errors_as_oserror
    def rename(self, src: str, dst: str) -> None:
        if dst.endswith("/") and not self.is_dir(src):
            # rename(2) of a file to "x/" is ENOTDIR; normalize() would
            # drop the slash and make a FILE x.
            raise NotADirectoryError(errno.ENOTDIR, "Not a directory", dst)
        src = self.normalize(src)
        dst = self.normalize(dst)
        src_branch, src_sub = self._split_branch(src)
        dst_branch, dst_sub = self._split_branch(dst)
        if src_branch != dst_branch:
            raise OSError("Git: cross-branch rename is not supported (use copy)")
        # The rename is two commits, "write dst" then "remove src": onto
        # itself the second removed the file, and onto an existing file
        # the first replaced it without a word (DbFsBackend refuses both).
        if dst == src:
            raise OSError(errno.EINVAL, f"Git rename: source and destination are the same: {src}")
        if self.exists(dst):
            raise FileExistsError(errno.EEXIST, f"Git rename: destination already exists: {dst}")
        with self.open_read(src) as fh:
            data = fh.read()
        mode = self._file_mode(src_branch, src_sub)
        # Two commits to keep the diff readable: write to dst, then rm src.
        self._commit_modification(
            dst_branch,
            dst_sub,
            blob_data=data,
            message=f"axross: mv {src_sub} → {dst_sub} (a)",
            blob_mode=mode,
            push=False,
        )
        self._commit_modification(
            src_branch, src_sub, blob_data=None, message=f"axross: mv {src_sub} → {dst_sub} (b)"
        )

    @_object_errors_as_oserror
    def copy(self, src: str, dst: str) -> None:
        src = self.normalize(src)
        dst = self.normalize(dst)
        with self.open_read(src) as fh:
            data = fh.read()
        src_branch, src_sub = self._split_branch(src)
        dst_branch, dst_sub = self._split_branch(dst)
        self._commit_modification(
            dst_branch,
            dst_sub,
            blob_data=data,
            message=f"axross: cp {src} → {dst}",
            blob_mode=self._file_mode(src_branch, src_sub),
        )

    @_object_errors_as_oserror
    def chmod(self, path: str, mode: int) -> None:
        # Map any executable bit → 0o100755, else 0o100644.
        path = self.normalize(path)
        branch, sub = self._split_branch(path)
        with self.open_read(path) as fh:
            data = fh.read()
        new_mode = _EXEC_BLOB_MODE if (mode & 0o111) else _DEFAULT_BLOB_MODE
        self._commit_modification(
            branch,
            sub,
            blob_data=data,
            message=f"axross: chmod {oct(mode)} {sub}",
            blob_mode=new_mode,
        )

    def _entry_at(self, tree_sha: bytes, sub: str):
        """``(mode, sha)`` of *sub* in the tree *tree_sha*, or None."""
        tree = self._repo[tree_sha]
        parts = sub.split("/")
        for part in parts[:-1]:
            entry = self._tree_entry(tree, part)
            if entry is None or not st_mod.S_ISDIR(entry[0]):
                return None
            tree = self._repo[entry[1]]
        return self._tree_entry(tree, parts[-1])

    def _version_tip(self, path: str) -> tuple[str, bytes]:
        """``(sub path, branch tip)`` of a versioned path."""
        branch, sub = self._split_branch(self.normalize(path))
        with self._lock:
            tip = self._branch_tips.get(branch) if branch else None
        if branch and tip is None:
            self._refresh_branch_tips()
            with self._lock:
                tip = self._branch_tips.get(branch)
        if tip is None:
            raise FileNotFoundError(errno.ENOENT, f"No such branch: {branch or path}")
        return sub, tip

    @_object_errors_as_oserror
    def list_versions(self, path: str) -> list:
        """One version per commit of the branch that changed the file,
        newest first (at most :data:`MAX_VERSIONS`); the id is the commit
        sha. A deleted file keeps its history; a folder has none."""
        from datetime import timezone

        from dulwich.walk import Walker

        from models.file_version import FileVersion

        sub, tip = self._version_tip(path)
        if not sub:
            return []
        current = self._entry_at(self._repo[tip].tree, sub)
        if current is not None and (st_mod.S_ISDIR(current[0]) or _is_gitlink(current[0])):
            return []
        out = []
        for walked in Walker(self._repo.object_store, include=[tip], paths=[sub.encode("utf-8")]):
            commit = walked.commit
            entry = self._entry_at(commit.tree, sub)
            if entry is None or st_mod.S_ISDIR(entry[0]) or _is_gitlink(entry[0]):
                continue  # the commit that deleted it, or a folder of that name then
            sha = commit.id.decode("ascii")
            subject = commit.message.decode("utf-8", "replace").strip().splitlines()
            out.append(FileVersion(
                version_id=sha,
                modified=datetime.fromtimestamp(int(commit.commit_time), timezone.utc),
                size=len(self._repo[entry[1]].data),
                is_current=not out and current is not None and entry[1] == current[1],
                label=f"{sha[:10]} {subject[0][:72] if subject else ''}".rstrip(),
            ))
            if len(out) >= MAX_VERSIONS:
                break
        return out

    @_object_errors_as_oserror
    def open_version_read(self, path: str, version_id: str):
        """The file as the commit *version_id* had it. Only commits in
        the branch's history count: another branch's commit is read
        through that branch's path."""
        from dulwich.objects import Commit

        text = str(version_id or "").strip().lower()
        if not _SHA.fullmatch(text):
            raise OSError(f"Git version of {path}: {version_id!r} is not a commit sha")
        sub, tip = self._version_tip(path)
        if not sub:
            raise IsADirectoryError(f"Is a directory: {path}")
        sha = text.encode("ascii")
        try:
            commit = self._repo[sha]
        except KeyError:
            raise FileNotFoundError(f"Git version of {path}: no commit {text}") from None
        if not isinstance(commit, Commit):
            raise OSError(f"Git version of {path}: {text} is not a commit")
        if not self._is_ancestor(sha, tip):
            raise OSError(f"Git version of {path}: {text} is not in the history of its branch")
        entry = self._entry_at(commit.tree, sub)
        if entry is None:
            raise FileNotFoundError(f"Git version of {path}: not in commit {text}")
        if st_mod.S_ISDIR(entry[0]):
            raise IsADirectoryError(f"Is a directory: {path}")
        if _is_gitlink(entry[0]):
            raise OSError(f"Git read: {path} is a submodule, not a file")
        blob = self._repo[entry[1]]
        blob.check()
        return io.BytesIO(blob.data)

    def disk_usage(self, path: str) -> tuple[int, int, int]:
        return (0, 0, 0)

    # ------------------------------------------------------------------
    # Git-specific verbs (API_GAPS round 2)
    # ------------------------------------------------------------------

    @_object_errors_as_oserror
    def log(
        self, branch: str = "main", *, limit: int = 100, sub_path: str | None = None
    ) -> list[dict]:
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
            out.append(
                {
                    "sha": commit.id.decode("ascii"),
                    "author_name": commit.author.split(b" <", 1)[0].decode("utf-8", "replace"),
                    "author_email": (
                        commit.author.split(b" <", 1)[1].rstrip(b">").decode("utf-8", "replace")
                        if b" <" in commit.author
                        else ""
                    ),
                    "message": commit.message.decode("utf-8", "replace"),
                    "timestamp": int(commit.author_time),
                    "parents": [p.decode("ascii") for p in commit.parents],
                }
            )
            if len(out) >= int(limit):
                break
        return out

    @_object_errors_as_oserror
    def diff(self, sha_a: str, sha_b: str = "HEAD", *, branch: str = "main") -> str:
        """Unified diff between two commits. ``sha_b="HEAD"`` resolves
        to the current branch tip; otherwise both args are full or
        abbreviated SHAs.

        Returns the diff as a single string (UTF-8 decoded); empty
        string means no changes.
        """
        import io as _io

        from dulwich import porcelain as _porc

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
        as_bytes = sha_or_ref.encode("ascii") if isinstance(sha_or_ref, str) else sha_or_ref
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

    @_object_errors_as_oserror
    def branch_list(self) -> list[str]:
        """All known local + remote-tracking branches, sorted. Refreshes
        the cached tip-set first so a remote-side advance shows up."""
        self._refresh_branch_tips()
        return sorted(self._branch_tips)

    @_object_errors_as_oserror
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
            name = ref_str[len("refs/tags/") :]
            target = sha
            try:
                obj = self._repo[sha]
            except KeyError:
                continue
            if isinstance(obj, _Tag):
                target = obj.object[1]
            out.append(
                {
                    "name": name,
                    "sha": sha.decode("ascii"),
                    "target": target.decode("ascii"),
                }
            )
        return sorted(out, key=lambda t: t["name"])

    @_object_errors_as_oserror
    def blame(self, path: str, *, branch: str | None = None) -> list[dict]:
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
                        cur = None
                        break
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
            c
            if c is not None
            else {
                "line_no": i + 1,
                "sha": "0" * 40,
                "author_name": "",
                "author_email": "",
                "timestamp": 0,
                "line": current_lines[i],
            }
            for i, c in enumerate(lines_credit)
        ]

    @_object_errors_as_oserror
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
        self,
        branch: str,
        sub: str,
        blob_data: bytes | None,
        message: str,
        blob_mode: int | None = None,
        push: bool = True,
    ) -> None:
        """Build a new tree on ``branch`` with ``sub`` set to
        ``blob_data`` (or removed if None) and commit it. Refuses if
        the local branch ref is behind a known remote tip
        (fast-forward only), or if a work tree has the branch checked
        out. ``blob_mode`` None keeps the mode of the file it replaces
        (100644 for a new file). In a URL session with ``auto_push``
        the commit is pushed to origin unless *push* is False (the
        first half of a two-commit change)."""
        if not self._author_name or not self._author_email:
            raise OSError(
                "Git commit refused: no author identity. Set "
                "author_name / author_email on the profile or in "
                "~/.gitconfig.",
            )
        if self.offline:
            raise OSError(
                errno.EROFS,
                f"Git: origin {self._display_origin_url} could not be reached when the "
                f"session opened ({self.offline}); the cached copy is shown read-only. "
                f"Reconnect when the remote is reachable.",
            )
        if self._pushes() and branch in self._origin_checked_out_branches():
            raise OSError(
                errno.EBUSY,
                f"Git: branch {branch} is checked out in the origin repository "
                f"{self._display_origin_url}; a push to it would leave that work tree "
                f"behind (git refuses such a push), so axross does not commit to it. "
                f"Write to another branch or use a bare origin.",
            )
        with self._lock, _as_oserror("write", f"/{branch}/{sub}"):
            if branch in self._checked_out_branches():
                # Moving the ref would leave that work tree's index and
                # files at the old commit: git status shows the change
                # reverted and the next git commit undoes it.
                raise OSError(
                    errno.EBUSY,
                    f"Git: branch {branch} is checked out in a work tree; axross does "
                    "not commit to it (git refuses such a push too). Write to another "
                    "branch or a bare clone.",
                )
            # The tip the session read (and the caller decided on) may
            # be stale: someone may have committed or pushed to the
            # branch since. Building on it would drop that work from
            # the branch, so the ref is read again here and the commit
            # refused when it moved.
            ref_name = f"refs/heads/{branch}".encode()
            current_refs = self._repo.get_refs()
            local_sha = current_refs.get(ref_name)
            tip_now = (
                local_sha
                if local_sha is not None
                else current_refs.get(f"refs/remotes/origin/{branch}".encode())
            )
            seen_sha = self._branch_tips.get(branch)
            if tip_now != seen_sha:
                # Show the branch as it is now; the change is not made.
                self._refresh_branch_tips()
                raise GitBranchMoved(
                    errno.ESTALE,
                    f"Git: branch {branch} moved since axross read it "
                    f"({_short_sha(seen_sha)} -> {_short_sha(tip_now)}): someone "
                    f"committed or pushed to it. axross did not commit, so that work "
                    f"is kept; refresh the folder and repeat the change.",
                )
            tip_sha = tip_now
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
                    if not self._is_ancestor(origin_sha, tip_sha):
                        # Only a local tip that already contains origin
                        # may grow. Behind, diverged, or an ancestry walk
                        # that hit its cap: refuse rather than commit on
                        # top of history the push would have to rewrite.
                        raise GitForceRefused(
                            f"Local branch {branch} is behind or has diverged from "
                            f"origin/{branch}; fetch + merge before committing via axross."
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
            # Compare-and-swap: a commit landing between the read above
            # and here (another process, a push) is not overwritten.
            if local_sha is None:
                moved_ok = self._repo.refs.add_if_new(ref_name, commit.id)
            else:
                moved_ok = self._repo.refs.set_if_equals(ref_name, local_sha, commit.id)
            if not moved_ok:
                self._refresh_branch_tips()
                raise GitBranchMoved(
                    errno.ESTALE,
                    f"Git: branch {branch} moved while axross committed to it: someone "
                    f"committed or pushed at the same time. axross did not move the "
                    f"branch, so that work is kept; refresh the folder and repeat the "
                    f"change.",
                )
            self._branch_tips[branch] = commit.id
            log.info("Git-FS commit %s on %s: %s", commit.id.decode()[:8], branch, message)
        if push and self._pushes():
            try:
                self._push_branch(branch)
            except OSError as exc:
                self._refresh_status_note()
                raise GitPushFailed(
                    errno.EIO,
                    f"Git: the change was committed ({_short_sha(commit.id)} on {branch}) "
                    f"in the local cache but not pushed to {self._display_origin_url}: "
                    f"{exc}. It is pushed with the next write to the branch.",
                ) from exc
        self._refresh_status_note()

    def _checked_out_branches(self) -> set[str]:
        """Branches a work tree of this repo has checked out: the HEAD of
        a non-bare repo and the HEAD of every linked worktree."""
        return _checked_out_in(self._repo)

    def _pushes(self) -> bool:
        """Whether a commit is pushed to origin straight away."""
        return bool(self._origin_url) and self._auto_push

    def _origin_checked_out_branches(self) -> set[str]:
        """Branches checked out in origin when origin is a local non-bare
        repository (``file://`` or a path); empty for any other remote."""
        url = self._origin_url
        if url.startswith("file://"):
            local = urlsplit(url).path
        elif "://" not in url and url.startswith(("/", ".")):
            local = url
        else:
            return set()
        try:
            origin = Repo(local)
        except Exception:  # noqa: BLE001 - not a repository (yet): the push says why
            return set()
        try:
            return _checked_out_in(origin)
        finally:
            origin.close()

    # ------------------------------------------------------------------
    # Sync state with origin
    # ------------------------------------------------------------------

    #: The most commits counted per branch for "not pushed".
    _UNPUSHED_COUNT_CAP = 1000

    def unpushed_commits(self) -> dict[str, int]:
        """``{branch: n}`` of local branches with *n* commits origin does
        not have (as of the last fetch or push); empty for a session
        without a remote."""
        if not self._origin_url:
            return {}
        out: dict[str, int] = {}
        with self._lock:
            refs = self._repo.get_refs()
            for ref, sha in refs.items():
                if not ref.startswith(b"refs/heads/"):
                    continue
                name = ref[len(b"refs/heads/") :]
                origin = refs.get(self._REMOTE_PREFIX + name)
                if origin == sha:
                    continue
                walker = self._repo.get_walker(
                    include=[sha],
                    exclude=[origin] if origin else None,
                    max_entries=self._UNPUSHED_COUNT_CAP,
                )
                count = sum(1 for _entry in walker)
                if count:
                    out[name.decode("utf-8", "replace")] = count
        return out

    def _refresh_status_note(self) -> None:
        from core.i18n import tr

        note = ""
        try:
            if self.offline:
                note = tr("offline: cached copy, read-only")
            else:
                pending = self.unpushed_commits()
                if pending:
                    note = tr("not pushed to origin: {branches}").format(
                        branches=", ".join(f"{b} ({n})" for b, n in sorted(pending.items()))
                    )
        except Exception as exc:  # noqa: BLE001 - a status line never breaks a write
            log.debug("Git-FS status note: %s", exc)
        self._status_note = note

    def status_note(self) -> str:
        """One line for the pane's status bar: offline (the cached copy,
        read-only) or the branches with commits not pushed yet; "" when
        the session is in step with origin."""
        return self._status_note

    def _file_mode(self, branch: str, sub: str) -> int:
        """The commit mode of the file ``sub`` on ``branch``: 100755 for
        an executable, else 100644."""
        tree, name = self._walk_tree_to(branch, sub)
        entry = self._tree_entry(tree, name)
        return _EXEC_BLOB_MODE if entry and entry[0] == _EXEC_BLOB_MODE else _DEFAULT_BLOB_MODE

    def _build_modified_tree(
        self,
        root_tree: Tree,
        sub: str,
        blob_data: bytes | None,
        blob_mode: int | None,
    ) -> Tree:
        """Recursively rebuild ``root_tree`` so that ``sub`` points at
        ``blob_data`` (or is absent when blob_data is None). Returns
        the new root Tree (already added to object store along the way)."""
        parts = sub.split("/")
        return self._modify_tree_rec(root_tree, parts, blob_data, blob_mode)

    def _modify_tree_rec(
        self,
        tree: Tree,
        parts: list[str],
        blob_data: bytes | None,
        blob_mode: int | None,
    ) -> Tree:
        new_tree = Tree()
        # Copy every entry that we're not modifying.
        head = parts[0].encode("utf-8")
        for entry in tree.items():
            if entry.path == head:
                continue
            new_tree.add(entry.path, entry.mode, entry.sha)
        existing = self._tree_entry(tree, parts[0])
        if len(parts) == 1:
            # Leaf modification.
            if blob_data is not None:
                if existing and st_mod.S_ISDIR(existing[0]):
                    # Writing a blob here would drop the whole subtree.
                    raise IsADirectoryError(errno.EISDIR, f"Is a directory: {parts[0]}")
                if blob_mode is None:
                    # A save keeps the file's mode: an executable stays one.
                    keep = existing is not None and existing[0] == _EXEC_BLOB_MODE
                    blob_mode = _EXEC_BLOB_MODE if keep else _DEFAULT_BLOB_MODE
                blob = Blob.from_string(blob_data)
                self._repo.object_store.add_object(blob)
                new_tree.add(head, blob_mode, blob.id)
            # else: deletion — already left out above.
        else:
            # Recurse into the (possibly new) subtree.
            if existing is None:
                sub_tree = Tree()
            elif st_mod.S_ISDIR(existing[0]):
                sub_tree = self._repo[existing[1]]
            else:
                # A file or submodule: replacing it with a directory
                # would silently drop it from the commit.
                raise NotADirectoryError(errno.ENOTDIR, f"Not a directory: {parts[0]}")
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
        """Push local commits to origin. Branch defaults to every local
        branch of the session. Refuses non-fast-forward
        unconditionally (no force-push surface)."""
        if not self._origin_url:
            raise OSError("Git-FS: no remote URL — nothing to push to")
        if branch:
            branches = [branch]
        else:
            branches = [
                b for b in list(self._branch_tips)
                if _ref_or_none(self._repo.refs, f"refs/heads/{b}".encode()) is not None
            ]
        try:
            for b in branches:
                self._push_branch(b)
        finally:
            self._refresh_status_note()

    def _push_branch(self, b: str) -> None:
        """Push local branch *b* to origin (fast-forward only) and move
        ``refs/remotes/origin/<b>`` to what was pushed."""
        if b in self._origin_checked_out_branches():
            raise OSError(
                errno.EBUSY,
                f"Git push {b}: the branch is checked out in the origin repository; "
                f"git refuses such a push",
            )
        ref = f"refs/heads/{b}".encode()
        pushed = _ref_or_none(self._repo.refs, ref)
        out = io.BytesIO()
        try:
            porcelain.push(
                self._repo,
                remote_location=self._connect_url,
                refspecs=[ref + b":" + ref],
                force=False,
                outstream=out,
                errstream=out,
                **self._transport_kwargs,
            )
        except Exception as exc:
            text = f"{exc} {out.getvalue().decode('utf-8', 'replace')}".lower()
            if "non-fast-forward" in text or "diverged" in text:
                raise GitForceRefused(
                    f"push refused: branch {b} would require force-push"
                ) from exc
            raise OSError(f"Git push {b}: {exc}") from exc
        if isinstance(pushed, bytes):
            self._repo.refs[self._REMOTE_PREFIX + b.encode()] = pushed
        display_origin = getattr(self, "_display_origin_url", "") or redact_url(
            self._origin_url
        )
        log.info("Git-FS pushed %s → %s", b, display_origin)
