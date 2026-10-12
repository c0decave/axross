"""The sdist must not carry operator-only documents.

``recursive-include docs *.md`` picks up every Markdown file in the work
tree, tracked or not, so internal notes (handoff, plans, the open-findings
security report) have to be excluded explicitly.
"""
from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
PRIVATE = (
    "docs/HANDOFF.md",
    "docs/BACKLOG.md",
    "docs/plans/2026-roadmap.md",
    "docs/SECURITY-REVIEW-2026-10.md",
)
PUBLIC = ("docs/USAGE.md", "docs/PROXY_SUPPORT.md")


def _sdist_docs() -> set[str]:
    from setuptools._distutils.filelist import FileList

    with tempfile.TemporaryDirectory() as tmp:
        for rel in (*PRIVATE, *PUBLIC):
            path = Path(tmp, rel)
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("x")
        cwd = os.getcwd()
        os.chdir(tmp)
        try:
            files = FileList()
            files.findall()
            for line in (REPO_ROOT / "MANIFEST.in").read_text().splitlines():
                line = line.strip()
                if line.startswith(("recursive-include docs", "prune docs", "exclude docs")):
                    files.process_template_line(line)
            return {f.replace(os.sep, "/") for f in files.files}
        finally:
            os.chdir(cwd)


class SdistManifestTest(unittest.TestCase):
    def test_public_docs_are_included(self) -> None:
        included = _sdist_docs()
        for rel in PUBLIC:
            self.assertIn(rel, included)

    def test_operator_only_docs_are_excluded(self) -> None:
        included = _sdist_docs()
        for rel in PRIVATE:
            self.assertNotIn(rel, included)

    def test_mirror_excludes_the_security_report(self) -> None:
        script = REPO_ROOT / "scripts" / "export-public.py"
        if not script.exists():
            self.skipTest("export tooling is not part of the public tree")
        text = script.read_text()
        self.assertIn('"docs/SECURITY-REVIEW-2026-10.md"', text)


if __name__ == "__main__":
    unittest.main()
