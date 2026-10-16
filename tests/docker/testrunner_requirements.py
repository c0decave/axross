"""Print the lab test runner's pip requirements, derived from pyproject.toml.

Used by Dockerfile.testrunner at image build time (stdlib only - nothing
is installed yet). Every base dependency and every optional extra is
included so no live test skips for a missing import, except packages that
are not published on PyPI: installing those either fails the build or,
once a stranger registers the name, installs the stranger's package.

Usage: python testrunner_requirements.py path/to/pyproject.toml
"""

from __future__ import annotations

import re
import sys
import tomllib

#: Project names axross depends on that are not on PyPI. The same set gates
#: the public mirror (UNPUBLISHED_DEPENDENCIES in scripts/export-public.py);
#: tests/test_testrunner_requirements.py holds the two equal.
UNPUBLISHED_DEPENDENCIES: frozenset[str] = frozenset()

_NAME = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)")


def project_name(requirement: str) -> str:
    """The PEP 503 normalised project name of a requirement string."""
    match = _NAME.match(requirement)
    if match is None:
        raise ValueError(f"not a requirement: {requirement!r}")
    return re.sub(r"[-_.]+", "-", match.group(1)).lower()


def requirements(meta: dict, unpublished=UNPUBLISHED_DEPENDENCIES) -> list[str]:
    """Base dependencies first, then every extra's, first-seen order, no
    duplicates, without the *unpublished* projects."""
    reqs = list(meta.get("dependencies", []))
    for deps in meta.get("optional-dependencies", {}).values():
        reqs.extend(deps)
    return [r for r in dict.fromkeys(reqs) if project_name(r) not in unpublished]


def main(argv: list[str]) -> int:
    if len(argv) != 1:
        print(__doc__.strip().splitlines()[-1], file=sys.stderr)
        return 2
    with open(argv[0], "rb") as fh:
        meta = tomllib.load(fh)["project"]
    for req in requirements(meta):
        print(req)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
