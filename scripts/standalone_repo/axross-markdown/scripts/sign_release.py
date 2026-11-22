#!/usr/bin/env python3
"""Sign an axross-markdown release's SHA256SUMS on the maintainer's machine.

CI builds a release as a draft (.github/workflows/release.yml); the updater
(src/axross_markdown/_ax/core/markdown_update.py) takes no release without
``SHA256SUMS.sig``: the raw 64-byte Ed25519 signature of the exact bytes of
``SHA256SUMS``, made with a key whose public half the updater pins
(TRUSTED_KEYS). The private key never goes to CI or into a repository.

    sign_release.py pubkey  --key KEY             the public half (to pin)
    sign_release.py sign    SHA256SUMS --key KEY  writes SHA256SUMS.sig
    sign_release.py release vX.Y.Z --key KEY [--publish]
        the draft's SHA256SUMS downloaded, every file of the draft checked
        against it, signed, SHA256SUMS.sig uploaded; --publish then makes the
        draft the latest release

A key whose public half is not pinned in the updater is refused (a release
signed with it would be refused by every installed program); so is a key
file others may read. Needs Python 3.11+, the ``cryptography`` package and,
for ``release``, the GitHub CLI (``gh``) logged in with write access to the
repository.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
UPDATER = ROOT / "src" / "axross_markdown" / "_ax" / "core" / "markdown_update.py"
REPO = "c0decave/axross-markdown"
SUMS = "SHA256SUMS"
SIG = "SHA256SUMS.sig"
_LINE = re.compile(r"([0-9a-f]{64}) [ *]([A-Za-z0-9][A-Za-z0-9._-]{0,199})")


def _crypto():
    try:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import (
            Ed25519PrivateKey,
            Ed25519PublicKey,
        )
    except ImportError:
        sys.exit("sign_release.py needs the Python package cryptography (pip install cryptography)")
    return serialization, Ed25519PrivateKey, Ed25519PublicKey


def load_key(path: Path):
    serialization, private_type, _ = _crypto()
    st = path.stat()
    if os.name == "posix" and st.st_mode & 0o077:
        sys.exit(f"{path}: others may read the release key (chmod 600 it)")
    key = serialization.load_pem_private_key(path.read_bytes(), password=None)
    if not isinstance(key, private_type):
        sys.exit(f"{path} is not an Ed25519 private key")
    return key


def public_raw(key) -> bytes:
    serialization, _, _ = _crypto()
    return key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def pinned_keys(source: Path = UPDATER) -> list[bytes]:
    """The keys the updater pins (TRUSTED_KEYS' base64 strings)."""
    text = source.read_text(encoding="utf-8")
    found = re.search(r"^TRUSTED_KEYS\b[^=\n]*=\s*\((.*?)\n\)", text, re.MULTILINE | re.DOTALL)
    if found is None:
        sys.exit(f"{source}: no TRUSTED_KEYS")
    keys = []
    for value in re.findall(r'^\s*"([A-Za-z0-9+/]{43}=)"', found.group(1), re.MULTILINE):
        raw = base64.b64decode(value, validate=True)
        if len(raw) == 32:
            keys.append(raw)
    return keys


def sign(sums: bytes, key, trusted: list[bytes]) -> bytes:
    """The signature of *sums*, checked against the key's public half and refused when that is not one of
    *trusted* - or when a line of *sums* is not '<sha256>  <name>' (the updater refuses those)."""
    _, _, public_type = _crypto()
    raw = public_raw(key)
    if raw not in trusted:
        sys.exit("this key's public half is not pinned in the updater (TRUSTED_KEYS): "
                 f"{base64.b64encode(raw).decode()}")
    for line in sums.decode("utf-8").splitlines():
        if line.strip() and not _LINE.fullmatch(line):
            sys.exit(f"{SUMS}: a line that is not '<sha256>  <name>': {line[:80]!r}")
    signature = key.sign(sums)
    public_type.from_public_bytes(raw).verify(signature, sums)
    assert len(signature) == 64
    return signature


def gh(*args: str, capture: bool = False) -> str:
    out = subprocess.run(["gh", *args], check=True, text=True, stdout=subprocess.PIPE if capture else None)
    return out.stdout if capture else ""


def release(tag: str, key, trusted: list[bytes], repo: str, publish: bool, verify_files: bool) -> None:
    if not re.fullmatch(r"v[0-9]{1,6}\.[0-9]{1,6}\.[0-9]{1,6}", tag):
        sys.exit(f"{tag!r} is no vX.Y.Z tag")
    version = tag[1:]
    with tempfile.TemporaryDirectory(prefix="axross-markdown-sign-") as tmp:
        folder = Path(tmp)
        gh("release", "download", tag, "--repo", repo, "--pattern", SUMS, "--dir", tmp)
        sums = (folder / SUMS).read_bytes()
        listed = {}
        for line in sums.decode("utf-8").splitlines():
            match = _LINE.fullmatch(line)
            if match:
                listed[match.group(2)] = match.group(1)
        names = gh("release", "view", tag, "--repo", repo, "--json", "assets", "--jq", ".assets[].name",
                   capture=True).split()
        files = [n for n in names if n not in (SUMS, SIG)]
        missing = [n for n in files if n not in listed]
        if missing:
            sys.exit(f"files of the release without an entry in {SUMS}: {missing}")
        updater = [n for n in files if n.startswith((f"axross-markdown-{version}-", f"axross-mdcat-{version}-"))]
        if not updater:
            sys.exit(f"the release has none of the files the updater fetches (axross-markdown-{version}-…)")
        if verify_files:
            for name in files:
                gh("release", "download", tag, "--repo", repo, "--pattern", name, "--dir", tmp, "--clobber")
                digest = hashlib.sha256((folder / name).read_bytes()).hexdigest()
                if digest != listed[name]:
                    sys.exit(f"{name}: its SHA-256 is not the one in {SUMS}")
                (folder / name).unlink()
                print(f"ok  {name}")
        (folder / SIG).write_bytes(sign(sums, key, trusted))
        gh("release", "upload", tag, str(folder / SIG), "--repo", repo, "--clobber")
        print(f"{SIG} uploaded to {repo} {tag}")
    if publish:
        gh("release", "edit", tag, "--repo", repo, "--draft=false", "--latest")
        print(f"{tag} published")


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    sub = parser.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("pubkey")
    p.add_argument("--key", type=Path, required=True)
    p = sub.add_parser("sign")
    p.add_argument("sums", type=Path)
    p.add_argument("--key", type=Path, required=True)
    p.add_argument("--out", type=Path)
    p.add_argument("--pinned-from", type=Path, default=UPDATER,
                   help="the file whose TRUSTED_KEYS are pinned (default: the updater of this tree)")
    p = sub.add_parser("release")
    p.add_argument("tag")
    p.add_argument("--key", type=Path, required=True)
    p.add_argument("--repo", default=REPO)
    p.add_argument("--publish", action="store_true")
    p.add_argument("--no-verify-files", action="store_true",
                   help="sign without downloading every file to check its SHA-256")
    p.add_argument("--pinned-from", type=Path, default=UPDATER)
    args = parser.parse_args(argv)
    key = load_key(args.key)
    if args.cmd == "pubkey":
        print("base64:", base64.b64encode(public_raw(key)).decode())
        return 0
    if args.cmd == "sign":
        signature = sign(args.sums.read_bytes(), key, pinned_keys(args.pinned_from))
        out = args.out or args.sums.with_name(SIG)
        out.write_bytes(signature)
        print(f"{out} written")
        return 0
    release(args.tag, key, pinned_keys(args.pinned_from), args.repo, args.publish, not args.no_verify_files)
    return 0


if __name__ == "__main__":
    sys.exit(main())
