"""The sdist must not carry operator-only documents.

``recursive-include docs *.md`` picks up every Markdown file in the work
tree, tracked or not, so internal notes (handoff, plans, the open-findings
security report) have to be excluded explicitly.

setuptools also adds every ``tests/test*.py`` by default
(``_distutils/command/sdist.py``), so a private test file reached every
sdist up to 0.7.6. ``BuiltSdistTest`` builds the real sdist and holds it
against the mirror's own exclude list.
"""
from __future__ import annotations

import importlib.util
import os
import subprocess
import sys
import tarfile
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
EXPORT_SCRIPT = REPO_ROOT / "scripts" / "export-public.py"
SCRUB_RULES = REPO_ROOT / "scripts" / "_scrub_rules.py"
IDENTITY_RULES = {"operator-email", "operator-handle"}
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


def _load(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _private_members(members: list[str], prefixes: tuple[str, ...]) -> list[str]:
    """Members (``<name>-<version>/<path>``) the public mirror would drop.

    Same matching as ``export-public.py``: exact path or prefix.
    """
    rels = (m.split("/", 1)[1] for m in members if "/" in m)
    return sorted(r for r in rels if any(r == p or r.startswith(p) for p in prefixes))


@unittest.skipUnless(EXPORT_SCRIPT.exists(), "export tooling is not part of the public tree")
class BuiltSdistTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.prefixes = _load(EXPORT_SCRIPT, "export_public").MIRROR_EXCLUDE_PREFIXES
        tmp = tempfile.TemporaryDirectory()
        cls.addClassCleanup(tmp.cleanup)
        subprocess.run(
            [sys.executable, "-m", "build", "--sdist", "--no-isolation", "--outdir", tmp.name, str(REPO_ROOT)],
            check=True,
            capture_output=True,
        )
        (sdist,) = Path(tmp.name).glob("*.tar.gz")
        with tarfile.open(sdist) as tar:
            cls.members = tar.getnames()
            cls.texts = {
                m.name: tar.extractfile(m).read().decode("utf-8", "replace")
                for m in tar.getmembers()
                if m.isfile() and m.size < 4_000_000
            }

    def test_happy_no_mirror_excluded_file_is_in_the_sdist(self) -> None:
        self.assertEqual(_private_members(self.members, self.prefixes), [])

    def test_happy_public_tests_are_still_shipped(self) -> None:
        rels = {m.split("/", 1)[1] for m in self.members if "/" in m}
        self.assertIn("tests/test_sdist_manifest.py", rels)
        self.assertIn("tests/test_packaging.py", rels)

    @unittest.skipUnless(SCRUB_RULES.exists(), "scrub rules are not part of the public tree")
    def test_sad_no_operator_identity_in_any_sdist_file(self) -> None:
        find_leaks = _load(SCRUB_RULES, "scrub_rules").find_leaks
        hits = {
            name: found
            for name, text in self.texts.items()
            if (found := IDENTITY_RULES & set(find_leaks(text, include_paths=False)))
        }
        self.assertEqual(hits, {})

    def test_sad_the_checker_reports_private_members(self) -> None:
        members = [
            "axross-1.0/tests/test_scrub_rules.py",
            "axross-1.0/docs/plans/x.md",
            "axross-1.0/core/ram_fs.py",
            "axross-1.0/",
        ]
        self.assertEqual(
            _private_members(members, ("tests/test_scrub_rules.py", "docs/plans/")),
            ["docs/plans/x.md", "tests/test_scrub_rules.py"],
        )

    def test_edge_every_private_test_path_is_excluded_even_when_untracked(self) -> None:
        """Each ``tests/`` entry of the mirror list, present as a file, stays out.

        The real build only sees files that exist here; this covers the
        others, through the same defaults + MANIFEST.in processing.
        """
        from setuptools._distutils.filelist import FileList

        private = [p + "x.py" if p.endswith("_") else p for p in self.prefixes if p.startswith("tests/")]
        public = ["tests/test_packaging.py", "tests/test_peers.py"]
        self.assertTrue(private)
        with tempfile.TemporaryDirectory() as tmp:
            for rel in (*private, *public):
                Path(tmp, rel).parent.mkdir(parents=True, exist_ok=True)
                Path(tmp, rel).write_text("x")
            cwd = os.getcwd()
            os.chdir(tmp)
            try:
                files = FileList()
                files.findall()
                files.process_template_line("include tests/test*.py")  # setuptools default
                for line in (REPO_ROOT / "MANIFEST.in").read_text().splitlines():
                    if line.strip().startswith(("exclude", "prune", "global-exclude", "recursive-exclude")):
                        files.process_template_line(line.strip())
                included = {f.replace(os.sep, "/") for f in files.files}
            finally:
                os.chdir(cwd)
        self.assertEqual(sorted(set(private) & included), [])
        self.assertEqual(sorted(set(public) & included), sorted(public))

    def test_edge_the_checker_matches_like_the_mirror_export(self) -> None:
        members = ["a-1/tests/test_peer_x.py", "a-1/tests/test_peers.py", "a-1/tests/test_pe.py"]
        self.assertEqual(_private_members(members, ("tests/test_peer_",)), ["tests/test_peer_x.py"])
        self.assertEqual(_private_members([], self.prefixes), [])


if __name__ == "__main__":
    unittest.main()
