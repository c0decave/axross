"""ramfs_decrypt.py — decrypt an .axenc file straight into RAM.

Pulls an encrypted blob from BACKEND, decrypts it with PASSPHRASE,
and stages the plaintext in a RamFS session so the bytes never
touch disk. Returns the RamFS session and the path it wrote — the
caller can then ``axross.read_bytes(ram, path)`` or hand the session
to a viewer dialog.

Usage::

    src = axross.open("backup-target")
    ram, path = decrypt_to_ram(src, "/secrets/db.axenc", "passphrase")
    print(axross.read_text(ram, path)[:200])
"""
from __future__ import annotations


def decrypt_to_ram(backend, enc_path: str, passphrase: str) -> tuple:
    plaintext = axross.decrypt(backend, enc_path, passphrase)
    ram = axross.ramfs()
    ram.mkdir("/decrypted")
    name = enc_path.rsplit("/", 1)[-1]
    if name.endswith(".axenc"):
        name = name[:-len(".axenc")]
    target = f"/decrypted/{name or 'plaintext.bin'}"
    axross.write_bytes(ram, target, plaintext)
    return ram, target
