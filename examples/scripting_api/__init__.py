"""Runnable examples for the public ``axross.*`` scripting API.

Each module exposes:

* ``COVERS``: public API names demonstrated by that module.
* ``run(...)``: an executable smoke example used by the test suite.
"""

from __future__ import annotations

from importlib import import_module
from typing import Iterable

MODULES = (
    "local_file_workflows",
    "script_store",
    "network_diagnostics",
    "credential_testing",
    "protocol_recipes",
    "docker_protocol_smoke",
)


def coverage() -> dict[str, list[str]]:
    """Return ``axross`` API name -> example module names."""
    out: dict[str, list[str]] = {}
    for module_name in MODULES:
        module = import_module(f"{__name__}.{module_name}")
        for api_name in getattr(module, "COVERS", ()):
            out.setdefault(str(api_name), []).append(module_name)
    return out


def missing(public_names: Iterable[str]) -> list[str]:
    """Return public API names that have no example coverage."""
    covered = coverage()
    return sorted(name for name in public_names if name not in covered)
