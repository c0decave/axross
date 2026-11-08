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
  signs anyway (a test key).
* A pinned key that the binaries in use do not pin (not in
  :data:`FIELD_KEYS`) is refused as well: it is the next key of a rotation,
  and no installed binary could update to a release signed with it.
  ``--allow-new-key`` signs anyway, with a warning - only once a release
  signed with a field key, and pinning the new one, has binaries in the
  field (docs/PACKAGING.md, "Key rotation"); then move the key into
  :data:`FIELD_KEYS`.
* The signature is verified with the derived public key, through the same
  check the updater runs, before anything is written; the file is written
  atomically.
* A ``SHA256SUMS`` the updater would refuse (larger than its bound, or
  without one checksum line) is not signed.
* ``--packs-issue N`` numbers the release's pack manifest: the line
  ``# axross-packs-issue N`` goes right after the ``# axross-release`` line
  (signed with it). The first publication may leave it out (issue 0); each
  re-issue of the manifest under the same version takes the next number -
  core.packs refuses an issue lower than the one installed, and another
  manifest under the installed number. Binaries before it ignore the line.

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

from core import packs as P  # noqa: E402
from core import self_update as SU  # noqa: E402

#: A PEM private key is a few hundred bytes; anything far larger is not one.
MAX_KEY_BYTES = 16 << 10

#: The release keys that the oldest installed binaries which must still
#: update pin (their own core/self_update.py TRUSTED_KEYS) - a subset of
#: TRUSTED_KEYS. A release must be signed with one of these, or those
#: binaries refuse it. Today: the binaries of 0.14.53 to 0.14.136 pin only
#: the first key, and 0.15.176 shipped no binaries, so no binary in the
#: field carries the second one yet. The second key joins this tuple once
#: a release signed with the first key and pinning both has binaries out
#: (docs/PACKAGING.md, "Key rotation"); the first one leaves it only when
#: no supported binary pins it alone any more.
FIELD_KEYS: tuple[str, ...] = (
    "rJX0yymA5/Mbw24qIpuLNaLqC/FbvugEREz1p0pSz68=",  # pinned by every binary of 0.14.53 on
)


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


def with_packs_issue(data: bytes, issue: int) -> bytes:
    """*data* (SHA256SUMS) with the line ``# axross-packs-issue <issue>``
    right after its release line; one that names another issue is Refused."""
    text = data.decode("utf-8", errors="replace")
    lines = text.splitlines(keepends=True)
    present = [line for line in lines if line.startswith(P.PACKS_ISSUE_PREFIX)]
    if present:
        try:
            named = P.packs_issue_of_sums(text)
        except P.PackError as exc:
            raise Refused(str(exc)) from None
        if named != issue:
            raise Refused(f"{SU.SUMS_NAME} names packs issue {named}, not {issue}")
        return data
    at = next((i + 1 for i, line in enumerate(lines) if line.startswith(SU.RELEASE_LINE_PREFIX)), 0)
    if at and not lines[at - 1].endswith("\n"):
        lines[at - 1] += "\n"
    lines.insert(at, f"{P.PACKS_ISSUE_PREFIX}{issue}\n")
    return "".join(lines).encode("utf-8")


def sign_release(key_path: Path, sums_path: Path, *, allow_unpinned: bool = False,
                 version: str | None = None, packs_issue: int | None = None,
                 allow_new_key: bool = False) -> Path:
    """Sign *sums_path* with the key in *key_path*; returns the .sig path."""
    key = load_private_key(read_key_file(key_path))
    public = public_key_b64(key)
    pinned = public in SU.TRUSTED_KEYS
    if not pinned and not allow_unpinned:
        raise Refused(f"the public key {public} is not pinned in core/self_update.py "
                      "TRUSTED_KEYS: installed binaries would refuse this release "
                      "(--allow-unpinned signs anyway)")
    in_field = public in FIELD_KEYS
    if pinned and not in_field and not allow_new_key:
        raise Refused(f"the public key {public} is pinned in this tree but not by the binaries "
                      "in use (FIELD_KEYS in scripts/sign_release.py): every installed binary "
                      "would refuse this release. Sign with a field key; --allow-new-key signs "
                      "anyway, once a release signed with a field key and pinning this one has "
                      "binaries in the field (docs/PACKAGING.md, \"Key rotation\")")
    data = read_sums(sums_path)
    text = data.decode("utf-8", errors="replace")
    named = SU.release_of_sums(text)
    if version is not None and named is None:
        data = f"{SU.RELEASE_LINE_PREFIX}{version}\n".encode() + data
        named = version
    if named is None:
        raise Refused(f"{sums_path} names no release version (a first line "
                      f"'{SU.RELEASE_LINE_PREFIX}X.Y.Z', which --version adds): the updater "
                      "refuses a release without it")
    if version is not None and named != version:
        raise Refused(f"{sums_path} is for {named}, not {version}")
    if packs_issue is not None:
        if packs_issue < 0 or packs_issue > 999_999_999:
            raise Refused(f"--packs-issue {packs_issue}: a number from 0 to 999999999")
        data = with_packs_issue(data, packs_issue)
    else:
        try:
            P.packs_issue_of_sums(data.decode("utf-8", errors="replace"))
        except P.PackError as exc:
            raise Refused(str(exc)) from None
    signature = sign(key, data)
    try:
        SU.verify_signature(data, signature, keys=(public,))
    except SU.SignatureError as exc:
        raise Refused(f"the new signature does not verify, nothing written: {exc}") from None
    target = sums_path.with_name(SU.SIG_NAME)
    try:
        if data != read_sums(sums_path):
            write_atomically(sums_path, data)  # with the release line it is signed with
        write_atomically(target, signature)
    except OSError as exc:
        raise Refused(f"cannot write {target}: {exc.strerror}") from None
    print(f"{target}: signed {len(data)} bytes of {sums_path.name}")
    print(f"public key: {public} ({'pinned' if pinned else 'NOT pinned'} in TRUSTED_KEYS)")
    if not in_field:
        print(f"sign_release: WARNING: {public} is not a key the binaries in use pin "
              "(FIELD_KEYS): installed binaries of the releases before will refuse this "
              "release", file=sys.stderr)
    return target


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        description="Write SHA256SUMS.sig (raw Ed25519 signature) next to SHA256SUMS.")
    parser.add_argument("key", type=Path, help="PEM private Ed25519 key (mode 600)")
    parser.add_argument("sums", type=Path, help="the release's SHA256SUMS")
    parser.add_argument("--allow-unpinned", action="store_true",
                        help="sign with a key that core/self_update.py does not pin")
    parser.add_argument("--allow-new-key", action="store_true",
                        help="sign with a pinned key that the binaries in use do not pin "
                             "(not in FIELD_KEYS): only once a release signed with a field key "
                             "and pinning this one has binaries in the field")
    parser.add_argument("--version", default=None,
                        help="the release's version: added as the first line of SHA256SUMS "
                             "when it has none (the updater requires it)")
    parser.add_argument("--packs-issue", type=int, default=None, metavar="N",
                        help="number of the pack manifest's issue: the line "
                             f"'{P.PACKS_ISSUE_PREFIX}N' after the release line (raise it by one "
                             "for each re-issue of the manifest under the same version)")
    args = parser.parse_args(argv)
    try:
        sign_release(args.key, args.sums, allow_unpinned=args.allow_unpinned, version=args.version,
                     packs_issue=args.packs_issue, allow_new_key=args.allow_new_key)
    except Refused as exc:
        print(f"sign_release: refused: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
