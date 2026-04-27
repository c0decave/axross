"""ramfs_pipeline.py — chain transforms through a RAM workspace.

Demonstrates RamFS as scratch space for a multi-step pipeline that
must keep plaintext off disk:

1. Pull an encrypted blob from a remote backend.
2. Decrypt straight into RamFS.
3. Run the bytes through any transform you care about (the example
   does sha256 + length).
4. Re-encrypt with a NEW passphrase and push to a different
   destination — without ever writing the cleartext to a disk file.

Same idea as ``ramfs_decrypt.py`` but with the re-encrypt leg added,
which is the OPSEC-relevant pattern when you're rotating
passphrases across backends.

Usage::

    src = axross.open("vault-old")
    dst = axross.open("vault-new")
    rotate_passphrase(
        src, "/secrets/customer-a.axenc", "old-passphrase",
        dst, "/secrets/customer-a.axenc", "new-passphrase",
    )
"""
from __future__ import annotations

import hashlib

from core.encrypted_overlay import decrypt_bytes, encrypt_bytes
from core.ram_fs import RamFsSession


def rotate_passphrase(src_backend, src_path: str, old_passphrase: str,
                      dst_backend, dst_path: str, new_passphrase: str) -> dict:
    """Decrypt + re-encrypt + push. Returns ``{sha256, length}``."""
    with src_backend.open_read(src_path) as fh:
        sealed_old = fh.read()
    plaintext = decrypt_bytes(sealed_old, old_passphrase)

    # Stage in RamFS so a debugger snapshot / oom-kill core dump
    # doesn't expose the cleartext via /tmp.
    ram = RamFsSession()
    try:
        ram.mkdir("/staging")
        with ram.open_write("/staging/blob") as wf:
            wf.write(plaintext)
        # Read back from RAM (proves the staging step).
        with ram.open_read("/staging/blob") as rf:
            staged = rf.read()
    finally:
        ram.close()

    sealed_new = encrypt_bytes(staged, new_passphrase)
    with dst_backend.open_write(dst_path) as fh:
        fh.write(sealed_new)
    return {
        "sha256": hashlib.sha256(staged).hexdigest(),
        "length": len(staged),
    }
