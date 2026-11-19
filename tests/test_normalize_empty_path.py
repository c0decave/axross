"""normalize("") is the root, not "." (review round 2).

``posixpath.normpath("")`` is ``"."``, so ``normpath(path) or "/"`` never
fell back to the root: an empty path (an empty field of a script, an
MCP call, a bookmark) became "." - the key "." on S3 and Azure, the
remote shell's working folder on SCP, Telnet and rsync.
"""

from __future__ import annotations

import importlib
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

BACKENDS = [
    ("core.scp_client", "SCPSession"),
    ("core.azure_client", "AzureBlobSession"),
    ("core.azure_client", "AzureFilesSession"),
    ("core.dropbox_client", "DropboxSession"),
    ("core.ftp_client", "FtpSession"),
    ("core.rsync_client", "RsyncSession"),
    ("core.s3_client", "S3Session"),
    ("core.webdav_client", "WebDavSession"),
    ("core.telnet_client", "TelnetSession"),
]


@pytest.mark.parametrize("module, cls", BACKENDS, ids=[c for _m, c in BACKENDS])
def test_sad_empty_path_is_the_root(module, cls) -> None:
    session = object.__new__(getattr(importlib.import_module(module), cls))
    assert session.normalize("") == "/"
    assert session.normalize("/a/../b") == "/b"
