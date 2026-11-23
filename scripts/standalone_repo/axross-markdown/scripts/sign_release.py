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
        the draft's SHA256SUMS downloaded and checked as the updater checks
        it; every file of the draft downloaded, its SHA-256 checked against
        it and its provenance against GitHub's attestation (gh attestation
        verify: made by .github/workflows/release.yml of this repository for
        this tag on GitHub's runners - the workflow attests every asset); the
        files the updater fetches all there; then signed, SHA256SUMS.sig
        uploaded; --publish then makes the draft the latest release

A key whose public half is not pinned in the updater is refused (a release
signed with it would be refused by every installed program); so is a key
file others may read. The key may be encrypted (PKCS#8 PEM, e.g. ``openssl
pkcs8 -topk8 -v2 aes-256-cbc``): its passphrase is asked for, or read from
AXROSS_MARKDOWN_KEY_PASSPHRASE. A SHA256SUMS the updater would refuse (a line
not '<sha256>  <name>', a name twice, a path) is not signed. Needs Python
3.11+, the ``cryptography`` package and, for ``release``, the GitHub CLI
(``gh``, with ``gh attestation``) logged in with write access to the
repository.
"""

from __future__ import annotations

import argparse
import base64
import getpass
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
#: The workflow whose attestations a release's files must carry (actions/attest-build-provenance).
WORKFLOW = ".github/workflows/release.yml"
#: Where an encrypted key's passphrase may come from instead of the prompt (a script's run).
PASSPHRASE_ENV = "AXROSS_MARKDOWN_KEY_PASSPHRASE"
# (the updater's own limits and name rule: core/markdown_update.py MAX_SUMS_BYTES, MAX_SUMS_LINES, _NAME)
MAX_SUMS_BYTES = 64 << 10
MAX_SUMS_LINES = 500
_LINE = re.compile(r"([0-9a-f]{64}) [ *]([A-Za-z0-9][A-Za-z0-9._-]{0,199})")


def updater_files(version: str) -> list[str]:
    """The files of release *version* the updater fetches (core/markdown_update.py asset_name): every one
    must be in the release and in its SHA256SUMS - a missing one leaves its installs without the update."""
    return [f"axross-markdown-{version}-linux-x86_64", f"axross-markdown-{version}-x86_64.AppImage",
            f"axross-markdown-{version}-macos-arm64", f"axross-markdown-{version}-windows-x64.exe",
            f"axross-mdcat-{version}-windows-x64.exe"]


def parse_sums(sums: bytes) -> dict[str, str]:
    """{name: sha256} of *sums* - or the script stops where the updater (core/markdown_update.py parse_sums,
    signed_sums) would refuse the file: more than 64 KiB or 500 lines, no UTF-8, a line that is not
    '<sha256>  <name>' (a name with a path, '..', a leading dot), a name twice."""
    if len(sums) > MAX_SUMS_BYTES:
        sys.exit(f"{SUMS} has {len(sums)} bytes, the updater takes at most {MAX_SUMS_BYTES}")
    try:
        text = sums.decode("utf-8")
    except UnicodeDecodeError:
        sys.exit(f"{SUMS} is no UTF-8 text")
    listed: dict[str, str] = {}
    for number, line in enumerate(text.splitlines()):
        if number >= MAX_SUMS_LINES:
            sys.exit(f"{SUMS} has more than {MAX_SUMS_LINES} lines, the updater takes at most {MAX_SUMS_LINES}")
        if not line.strip():
            continue
        match = _LINE.fullmatch(line)
        if match is None or "/" in line or "\\" in line or ".." in match.group(2):
            sys.exit(f"{SUMS}: a line that is not '<sha256>  <name>': {line[:80]!r}")
        name = match.group(2)
        if name in listed:
            sys.exit(f"{SUMS} names {name} twice (the updater refuses it)")
        listed[name] = match.group(1)
    return listed


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


def passphrase(path: Path, environ=None, ask=None) -> bytes:
    """The passphrase of the encrypted key *path*: AXROSS_MARKDOWN_KEY_PASSPHRASE, else asked (no echo)."""
    environ = os.environ if environ is None else environ
    value = environ.get(PASSPHRASE_ENV)
    if value is None:
        value = (ask or getpass.getpass)(f"passphrase of {path}: ")
    if not value:
        sys.exit(f"{path} is encrypted: no passphrase given")
    return value.encode("utf-8")


def load_key(path: Path, environ=None, ask=None):
    serialization, private_type, _ = _crypto()
    st = path.stat()
    if os.name == "posix" and st.st_mode & 0o077:
        sys.exit(f"{path}: others may read the release key (chmod 600 it)")
    data = path.read_bytes()
    try:
        key = serialization.load_pem_private_key(data, password=None)
    except TypeError:  # (encrypted: "Password was not given but private key is encrypted")
        try:
            key = serialization.load_pem_private_key(data, password=passphrase(path, environ, ask))
        except ValueError:
            sys.exit(f"{path}: the passphrase does not open the key")
    except ValueError as exc:
        sys.exit(f"{path} is no PEM private key: {exc}")
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
    *trusted* - or when the updater would refuse *sums* (parse_sums)."""
    _, _, public_type = _crypto()
    raw = public_raw(key)
    if raw not in trusted:
        sys.exit("this key's public half is not pinned in the updater (TRUSTED_KEYS): "
                 f"{base64.b64encode(raw).decode()}")
    parse_sums(sums)
    signature = key.sign(sums)
    public_type.from_public_bytes(raw).verify(signature, sums)
    assert len(signature) == 64
    return signature


def gh(*args: str, capture: bool = False) -> str:
    out = subprocess.run(["gh", *args], check=True, text=True, stdout=subprocess.PIPE if capture else None)
    return out.stdout if capture else ""


def attested(path: Path, tag: str, repo: str) -> None:
    """Stop unless GitHub holds an attestation of *path* (its SHA-256) made by WORKFLOW of *repo* for *tag*
    on GitHub's own runners: a file put into the draft by hand, or built anywhere else, is never signed."""
    try:
        gh("attestation", "verify", str(path), "--repo", repo, "--signer-workflow", f"{repo}/{WORKFLOW}",
           "--source-ref", f"refs/tags/{tag}", "--deny-self-hosted-runners", capture=True)
    except subprocess.CalledProcessError:
        sys.exit(f"{path.name}: no attestation by {repo}/{WORKFLOW} for {tag} - not signed "
                 f"(gh attestation verify {path.name} --repo {repo} says why)")


def release(tag: str, key, trusted: list[bytes], repo: str, publish: bool) -> None:
    if not re.fullmatch(r"v[0-9]{1,6}\.[0-9]{1,6}\.[0-9]{1,6}", tag):
        sys.exit(f"{tag!r} is no vX.Y.Z tag")
    version = tag[1:]
    with tempfile.TemporaryDirectory(prefix="axross-markdown-sign-") as tmp:
        folder = Path(tmp)
        gh("release", "download", tag, "--repo", repo, "--pattern", SUMS, "--dir", tmp)
        sums = (folder / SUMS).read_bytes()
        listed = parse_sums(sums)
        names = gh("release", "view", tag, "--repo", repo, "--json", "assets", "--jq", ".assets[].name",
                   capture=True).split()
        if len(set(names)) != len(names):
            sys.exit(f"the release names a file twice: {sorted(n for n in set(names) if names.count(n) > 1)}")
        files = [n for n in names if n not in (SUMS, SIG)]
        missing = [n for n in files if n not in listed]
        if missing:
            sys.exit(f"files of the release without an entry in {SUMS}: {missing}")
        absent = [n for n in listed if n not in files]
        if absent:
            sys.exit(f"{SUMS} names files the release does not have: {absent}")
        lacking = [n for n in updater_files(version) if n not in files]
        if lacking:
            sys.exit(f"the release lacks files the updater fetches: {lacking}")
        attested(folder / SUMS, tag, repo)
        print(f"ok  {SUMS} (attested)")
        for name in files:
            gh("release", "download", tag, "--repo", repo, "--pattern", name, "--dir", tmp, "--clobber")
            digest = hashlib.sha256((folder / name).read_bytes()).hexdigest()
            if digest != listed[name]:
                sys.exit(f"{name}: its SHA-256 is not the one in {SUMS}")
            attested(folder / name, tag, repo)
            (folder / name).unlink()
            print(f"ok  {name} (SHA-256, attested)")
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
    release(args.tag, key, pinned_keys(args.pinned_from), args.repo, args.publish)
    return 0


if __name__ == "__main__":
    sys.exit(main())
