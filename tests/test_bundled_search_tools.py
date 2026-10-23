"""ripgrep and fd in the axross-full Linux bundle (punch-list item 52).

Operator: *„wir sollten uU tools wie ripgrep und find-fd einbauen, also
binary static compiled da sie ebenfalls bereits hoch optimiert sind."*

The builder image fetches the static musl releases with pinned SHA-256
sums (Dockerfile.build), the spec puts them into ``bin/`` of the full
bundle with their licence files, and core.file_search.find_tool prefers
``bin/`` of a frozen build. These tests hold the pieces together; the
last one runs against a built binary when there is one.
"""

from __future__ import annotations

import os
import re
import subprocess
import sys
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

DOCKERFILE = (REPO_ROOT / "Dockerfile.build").read_text(encoding="utf-8")
SPEC = (REPO_ROOT / "build" / "axross.spec").read_text(encoding="utf-8")
LICENSES = (REPO_ROOT / "THIRD_PARTY_LICENSES.md").read_text(encoding="utf-8")
TOOLS = {"RG": "ripgrep", "FD": "fd"}


def arg(name: str) -> str:
    match = re.search(rf"^ARG {name}=(\S+)$", DOCKERFILE, re.MULTILINE)
    return match.group(1) if match else ""


class PinnedDownloadTests(unittest.TestCase):
    def test_happy_versions_and_checksums_are_pinned(self) -> None:
        for key in TOOLS:
            self.assertRegex(arg(f"{key}_VERSION"), r"^\d+\.\d+\.\d+$", key)
            self.assertRegex(arg(f"{key}_SHA256"), r"^[0-9a-f]{64}$", key)

    def test_happy_every_download_is_checked_before_use(self) -> None:
        # Each fetched archive goes through sha256sum -c before tar sees it.
        for key in TOOLS:
            fetch = re.search(rf"curl [^\n]*-o (\S+) [^\n]*\$\{{{key}_VERSION\}}", DOCKERFILE)
            self.assertIsNotNone(fetch, f"no pinned download for {key}")
            archive = fetch.group(1)
            check = DOCKERFILE.find(f'"${{{key}_SHA256}}  {archive}" | sha256sum -c')
            untar = DOCKERFILE.find(f"tar --no-same-owner -xzf {archive}")
            self.assertGreater(check, fetch.start(), key)
            self.assertGreater(untar, check, f"{key} is unpacked before its checksum is checked")

    def test_sad_only_https_github_releases(self) -> None:
        for url in re.findall(r"https?://\S+", DOCKERFILE):
            if "ripgrep" in url or "/fd/" in url:
                self.assertTrue(url.startswith("https://github.com/"), url)
                self.assertIn("/releases/download/", url)
                self.assertIn("x86_64-unknown-linux-musl", url)

    def test_edge_the_licence_file_lists_the_pinned_versions(self) -> None:
        """A version typed twice ages: the licence table must name the one
        the Dockerfile pins."""
        for key, project in TOOLS.items():
            self.assertIn(f"| {project} {arg(key + '_VERSION')} |", LICENSES, project)


class SpecTests(unittest.TestCase):
    def test_happy_the_full_bundle_takes_rg_and_fd_into_bin(self) -> None:
        self.assertIn("AXROSS_BUNDLE_BIN", SPEC)
        self.assertRegex(SPEC, r'for _tool in \("rg", "fd"\)')
        self.assertIn('(_path, "bin")', SPEC)
        self.assertIn("binaries=bundle_binaries", SPEC)
        self.assertIn("ENV AXROSS_BUNDLE_BIN=/opt/axross-bin", DOCKERFILE)

    def test_sad_slim_stays_without_them(self) -> None:
        """The collection sits inside the full-only block: slim never reads it."""
        lines = SPEC.splitlines()
        at = next(i for i, line in enumerate(lines) if "AXROSS_BUNDLE_BIN" in line)
        self.assertTrue(lines[at].startswith("    "), lines[at])
        opener = next(line for line in reversed(lines[:at])
                      if line and not line.startswith((" ", "#")))
        self.assertEqual(opener, 'if FLAVOR == "full":')

    def test_edge_the_licences_travel_with_the_binaries(self) -> None:
        self.assertIn('"licenses/search-tools"', SPEC)
        for name in ("ripgrep-LICENSE-MIT", "fd-LICENSE-MIT"):
            self.assertIn(name, DOCKERFILE)


class FindToolTests(unittest.TestCase):
    def test_happy_a_frozen_build_prefers_its_own_bin(self) -> None:
        import tempfile

        from core import file_search as FS

        with tempfile.TemporaryDirectory() as bundle:
            os.mkdir(os.path.join(bundle, "bin"))
            rg = os.path.join(bundle, "bin", "rg")
            with open(rg, "w") as fh:
                fh.write("#!/bin/sh\n")
            os.chmod(rg, 0o755)
            old = (getattr(sys, "frozen", None), getattr(sys, "_MEIPASS", None))
            sys.frozen, sys._MEIPASS = True, bundle
            try:
                self.assertEqual(FS.find_tool("rg"), rg)
                os.chmod(rg, 0o644)  # not executable: falls back to PATH
                self.assertNotEqual(FS.find_tool("rg"), rg)
            finally:
                if old[0] is None:
                    del sys.frozen
                else:
                    sys.frozen = old[0]
                if old[1] is None:
                    del sys._MEIPASS
                else:
                    sys._MEIPASS = old[1]


class BuiltBinaryTests(unittest.TestCase):
    def test_e2e_the_built_full_binary_finds_its_bundled_tools(self) -> None:
        binary = REPO_ROOT / "dist" / "axross-full"
        if not binary.exists():
            self.skipTest("no dist/axross-full built")
        script = ("from core.file_search import find_tool\n"
                  "print('RG', find_tool('rg'))\nprint('FD', find_tool('fd'))\n")
        result = subprocess.run([str(binary), "--script", "-"], input=script, text=True,
                                capture_output=True, timeout=180,
                                env={**os.environ, "QT_QPA_PLATFORM": "offscreen",
                                     "PATH": "/usr/bin:/bin"})
        out = result.stdout + result.stderr
        self.assertRegex(out, r"RG \S*/bin/rg", out)
        self.assertRegex(out, r"FD \S*/bin/fd", out)
