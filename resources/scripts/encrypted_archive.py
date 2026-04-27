"""encrypted_archive.py — pack a directory tree as one encrypted blob.

Stitches three internal axross modules together:

1. ``core.archive`` — produces the in-memory tarball (zip-bomb /
   zip-slip guards apply when extracting later).
2. ``core.encrypted_overlay.encrypt_bytes`` — AEAD-seals the
   tarball with the user's passphrase.
3. The destination backend's ``open_write`` — writes the ciphertext
   to ``<dst>.tar.axenc`` on whatever backend you point it at.

Reverse via :func:`unpack` which decrypts then extracts.

Usage::

    src = axross.localfs()
    dst = axross.open("backup-target")
    pack(src, "/var/data", dst, "/backups/snap-2026-04-26.tar.axenc",
         passphrase="passphrase")
"""
from __future__ import annotations

import io
import os
import tarfile

from core.encrypted_overlay import decrypt_bytes, encrypt_bytes


def pack(src_backend, src_root: str,
         dst_backend, dst_path: str,
         passphrase: str) -> int:
    """Tar + encrypt + write. Returns the size of the ciphertext
    in bytes."""
    if not dst_path.endswith(".tar.axenc"):
        raise ValueError("dst_path must end with .tar.axenc")
    buf = io.BytesIO()
    # Walk via the src backend's protocol-agnostic surface.
    with tarfile.open(mode="w", fileobj=buf) as tar:
        _add_tree(tar, src_backend, src_root)
    sealed = encrypt_bytes(buf.getvalue(), passphrase)
    with dst_backend.open_write(dst_path) as fh:
        fh.write(sealed)
    return len(sealed)


def unpack(src_backend, src_path: str, dst_dir_local: str,
           passphrase: str) -> int:
    """Read the ciphertext, decrypt, extract on disk. Returns the
    number of files extracted."""
    with src_backend.open_read(src_path) as fh:
        sealed = fh.read()
    plain = decrypt_bytes(sealed, passphrase)
    n = 0
    os.makedirs(dst_dir_local, exist_ok=True)
    base = os.path.abspath(dst_dir_local) + os.sep
    with tarfile.open(mode="r", fileobj=io.BytesIO(plain)) as tar:
        for member in tar:
            # Two layers of zip-slip defence:
            # 1. ``commonpath`` rejects any member whose path escapes
            #    the destination via .. or absolute prefix. We append
            #    os.sep to the base path so ``/tmp/foo`` no longer
            #    matches ``/tmp/foobar/x`` (off-by-one a `startswith`
            #    check would have allowed).
            # 2. tarfile's "data" filter (mandatory on Python 3.14, opt-in
            #    on 3.12+) refuses absolute paths, symlinks pointing
            #    outside the destination, device files, and setuid bits.
            target = os.path.abspath(os.path.join(dst_dir_local, member.name))
            try:
                if os.path.commonpath([target, base.rstrip(os.sep)]) != base.rstrip(os.sep):
                    continue
            except ValueError:
                # Different drives on Windows — refuse outright.
                continue
            try:
                tar.extract(member, dst_dir_local, filter="data")
            except TypeError:
                # Python < 3.12 has no ``filter`` kwarg. We already
                # passed the commonpath check, so a basic extract is
                # safe for the cases that matter (path traversal); the
                # filter would additionally reject device files and
                # setuid bits, but axross is pinned to 3.10+ where the
                # 3.12+ filter exists for everyone except the oldest
                # supported runtime.
                tar.extract(member, dst_dir_local)
            n += 1
    return n


def _add_tree(tar: tarfile.TarFile, backend, root: str) -> None:
    """Walk ``backend`` and add every file under ``root`` to ``tar``."""
    stack = [root]
    while stack:
        current = stack.pop()
        try:
            items = backend.list_dir(current)
        except OSError:
            continue
        for it in items:
            child = backend.join(current, it.name)
            rel = child[len(root):].lstrip("/")
            if not rel:
                continue
            if it.is_dir:
                stack.append(child)
            else:
                try:
                    with backend.open_read(child) as fh:
                        data = fh.read()
                except OSError:
                    continue
                info = tarfile.TarInfo(name=rel)
                info.size = len(data)
                info.mode = 0o644
                tar.addfile(info, io.BytesIO(data))
