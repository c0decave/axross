"""Every public scripting function is fully annotated, and the annotations
name real types.

A machine reading ``axross.api_schema()`` or ``help(axross.copy)`` learns
the argument types from the signature; 63 of the 109 public functions
had a parameter or the return without a hint (``backend`` everywhere,
``open()`` returning nothing said).
"""

from __future__ import annotations

import ast
import builtins
import inspect
import typing

import pytest

from core import scripting as axross


def _public_functions() -> list[tuple[str, object]]:
    return [
        (name, getattr(axross, name))
        for name in axross.__all__
        if inspect.isfunction(getattr(axross, name))
    ]


def _type_checking_namespace(module) -> dict:
    """Run the ``if TYPE_CHECKING:`` imports of ``module`` for real, so the
    hints resolve against exactly what the module declares - a typo or a
    renamed class fails here."""
    tree = ast.parse(inspect.getsource(module))
    namespace: dict = {}
    for node in tree.body:
        if isinstance(node, ast.If) and getattr(node.test, "id", "") in {
            "TYPE_CHECKING",
            "_TYPE_CHECKING",
        }:
            code = compile(ast.Module(body=node.body, type_ignores=[]), module.__file__, "exec")
            builtins.exec(code, namespace)  # imports only (see the ast filter above)
    return namespace


_IDS = {"ids": lambda v: v if isinstance(v, str) else ""}


@pytest.mark.parametrize("name,fn", _public_functions(), **_IDS)
def test_happy_every_parameter_and_the_return_are_annotated(name, fn) -> None:
    sig = inspect.signature(fn)
    missing = [p.name for p in sig.parameters.values() if p.annotation is inspect.Parameter.empty]
    assert missing == [], f"axross.{name}: parameters without a type hint: {missing}"
    assert sig.return_annotation is not inspect.Signature.empty, f"axross.{name}: no return hint"


@pytest.mark.parametrize("name,fn", _public_functions(), **_IDS)
def test_sad_every_annotation_names_a_real_type(name, fn) -> None:
    module = inspect.getmodule(fn)
    namespace = {**vars(module), **_type_checking_namespace(module)}
    typing.get_type_hints(fn, globalns=namespace)


def test_edge_backend_parameters_are_file_backends() -> None:
    for name, fn in _public_functions():
        for param in inspect.signature(fn).parameters.values():
            if param.name in {"backend", "src_backend", "dst_backend", "source_backend",
                              "dest_backend", "b1", "b2"}:
                assert "FileBackend" in str(param.annotation), (name, param.name)
