"""The axross-headless-mcp export carries a Dockerfile at its root.

Directories build the server from the repository: Glama ("use my existing
Dockerfile"), the Docker MCP Catalog (source.commit + Dockerfile). The
repository had none, so each listing needed its own hand-made build spec.
The Dockerfile installs the exported package itself (the same commit, no
version pin to keep in step), runs it as an unprivileged user, read-only by
default, confined to /data."""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(ROOT))


def test_happy_the_export_has_a_dockerfile_that_installs_itself(tmp_path):
    import export_standalone as EXP

    out = EXP.export("mcp", tmp_path / "mcp")
    text = (out / "Dockerfile").read_text(encoding="utf-8")
    lines = [l.strip() for l in text.splitlines() if l.strip() and not l.lstrip().startswith("#")]
    assert lines[:2] == ["ARG PYTHON_IMAGE=python:3.12-slim", "FROM ${PYTHON_IMAGE}"]
    assert "COPY . /src" in lines
    assert any(l.startswith("RUN pip install --no-cache-dir /src") for l in lines)
    assert "USER mcp" in lines
    assert 'ENTRYPOINT ["axross-headless-mcp"]' in lines
    assert 'CMD ["--mcp-root", "/data"]' in lines
    assert "--mcp-write" not in text.split("CMD", 1)[1]  # read-only unless asked
    assert 'LABEL io.modelcontextprotocol.server.name="io.github.c0decave/axross-headless-mcp"' in lines
    # Nothing of axross's own build (the repo has no main.py or ui/).
    assert "main.py" not in text and "PyQt" not in text
