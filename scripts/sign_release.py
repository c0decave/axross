#!/usr/bin/env python3
"""Sign a release's SHA256SUMS: ``sign_release.py <key.pem> <SHA256SUMS>``.

Writes ``SHA256SUMS.sig`` next to ``SHA256SUMS``: the raw 64-byte Ed25519
signature of the exact bytes of ``SHA256SUMS`` (nothing is normalised). The
one-file binaries refuse an update whose ``SHA256SUMS`` carries no valid
signature by a key pinned in ``core.self_update.TRUSTED_KEYS``
(docs/PACKAGING.md, "Self-update: what a release must carry").

* The key is a PEM private Ed25519 key (PKCS#8, as ``openssl genpkey
  -algorithm ed25519`` writes it). An encrypted key asks for its
  passphrase. A key file that is not a regular file, or that group or
  others can read, is refused.
* No key material is ever printed - only the derived PUBLIC key, so the
  release manager can see which key signed.
* A key whose public half is not pinned in this tree is refused (the
  installed binaries would refuse the release); ``--allow-unpinned``
  signs anyway (a key rotation, a test key).
* The signature is verified with the derived public key, through the same
  check the updater runs, before anything is written; the file is written
  atomically.
* A ``SHA256SUMS`` the updater would refuse (larger than its bound, or
  without one checksum line) is not signed.

Exit status: 0 written, 1 refused, 2 usage.
"""

from __future__ import annotations

import argparse
import base64
import getpass
import os
import stat
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from cryptography.exceptions import UnsupportedAlgorithm  # noqa: E402
from cryptography.hazmat.primitives import serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: E402

from core import self_update as SU  # noqa: E402

#: A PEM private key is a few hundred bytes; anything far larger is not one.
MAX_KEY_BYTES = 16 << 10


class Refused(Exception):
    """Signing is refused; the text says why (never key material)."""


def read_key_file(path: Path) -> bytes:
    """The bytes of *path*, refused when it is not a regular file of its
    own or when group or others can read it (checked on the open file)."""
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    try:
        fd = os.open(path, flags)
    except OSError as exc:
        if os.path.islink(path):
            raise Refused(f"{path} is a symbolic link; the key must be a regular file") from None
        raise Refused(f"cannot open the key file {path}: {exc.strerror}") from None
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            raise Refused(f"{path} is not a regular file; the key must be a regular file")
        if os.name == "posix" and info.st_mode & (stat.S_IRWXG | stat.S_IRWXO):
            raise Refused(f"{path} is readable by group or others (mode "
                          f"{stat.S_IMODE(info.st_mode):04o}); chmod 600 it first")
        with os.fdopen(fd, "rb", closefd=False) as fh:
            data = fh.read(MAX_KEY_BYTES + 1)
    finally:
        os.close(fd)
    if len(data) > MAX_KEY_BYTES:
        raise Refused(f"{path} is larger than {MAX_KEY_BYTES} bytes; not a PEM private key")
    return data


def load_private_key(pem: bytes) -> Ed25519PrivateKey:
    """The Ed25519 key of *pem*; an encrypted one asks for its passphrase.
    Errors never quote the file."""
    try:
        try:
            key = serialization.load_pem_private_key(pem, password=None)
        except TypeError:  # encrypted: a passphrase is needed
            passphrase = getpass.getpass("Passphrase of the release key: ")
            key = serialization.load_pem_private_key(pem, password=passphrase.encode("utf-8"))
    except (ValueError, TypeError, UnsupportedAlgorithm):
        raise Refused("cannot read the private key (not a PEM private key, or a wrong "
                      "passphrase)") from None
    if not isinstance(key, Ed25519PrivateKey):
        raise Refused("the private key is not an Ed25519 key")
    return key


def public_key_b64(key: Ed25519PrivateKey) -> str:
    raw = key.public_key().public_bytes(serialization.Encoding.Raw,
                                        serialization.PublicFormat.Raw)
    return base64.b64encode(raw).decode("ascii")


def read_sums(path: Path) -> bytes:
    try:
        with open(path, "rb") as fh:
            data = fh.read(SU.MAX_SUMS_BYTES + 1)
    except OSError as exc:
        raise Refused(f"cannot read {path}: {exc.strerror}") from None
    if len(data) > SU.MAX_SUMS_BYTES:
        raise Refused(f"{path} is larger than {SU.MAX_SUMS_BYTES} bytes; the updater refuses "
                      f"a {SU.SUMS_NAME} that large")
    if not SU.parse_sums(data.decode("utf-8", errors="replace")):
        raise Refused(f"{path} has no checksum line ({SU.SUMS_NAME} as sha256sum writes it)")
    return data


def sign(private_key: Ed25519PrivateKey, data: bytes) -> bytes:
    return private_key.sign(data)


def write_atomically(path: Path, data: bytes) -> None:
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.", suffix=".part")
    try:
        with os.fdopen(fd, "wb") as out:
            out.write(data)
            out.flush()
            os.fsync(out.fileno())
        os.chmod(tmp, 0o644)
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def sign_release(key_path: Path, sums_path: Path, *, allow_unpinned: bool = False) -> Path:
    """Sign *sums_path* with the key in *key_path*; returns the .sig path."""
    key = load_private_key(read_key_file(key_path))
    public = public_key_b64(key)
    pinned = public in SU.TRUSTED_KEYS
    if not pinned and not allow_unpinned:
        raise Refused(f"the public key {public} is not pinned in core/self_update.py "
                      "TRUSTED_KEYS: installed binaries would refuse this release "
                      "(--allow-unpinned signs anyway)")
    data = read_sums(sums_path)
    signature = sign(key, data)
    try:
        SU.verify_signature(data, signature, keys=(public,))
    except SU.SignatureError as exc:
        raise Refused(f"the new signature does not verify, nothing written: {exc}") from None
    target = sums_path.with_name(SU.SIG_NAME)
    try:
        write_atomically(target, signature)
    except OSError as exc:
        raise Refused(f"cannot write {target}: {exc.strerror}") from None
    print(f"{target}: signed {len(data)} bytes of {sums_path.name}")
    print(f"public key: {public} ({'pinned' if pinned else 'NOT pinned'} in TRUSTED_KEYS)")
    return target


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        description="Write SHA256SUMS.sig (raw Ed25519 signature) next to SHA256SUMS.")
    parser.add_argument("key", type=Path, help="PEM private Ed25519 key (mode 600)")
    parser.add_argument("sums", type=Path, help="the release's SHA256SUMS")
    parser.add_argument("--allow-unpinned", action="store_true",
                        help="sign with a key that core/self_update.py does not pin")
    args = parser.parse_args(argv)
    try:
        sign_release(args.key, args.sums, allow_unpinned=args.allow_unpinned)
    except Refused as exc:
        print(f"sign_release: refused: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
