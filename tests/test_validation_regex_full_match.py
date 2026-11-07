"""A check of a whole value is a full match: no regex in core/, ui/,
resources/, scripts/ or main.py that ends in ``$`` is used with
``re.match`` / ``re.search`` - however ``re`` is imported, however the
pattern is built.

``$`` matches at the very end *and* before a newline at the end, so
``re.match(r"^[A-Za-z0-9._/-]+$", "file\\n")`` accepts a name with a
trailing newline - which then reached a PJL command line, a TFTP request,
an MTP device id, a podman argument or an rsh command. ``fullmatch`` (or
``\\Z``) does not. The finds were fixed one place at a time; this test
keeps new ones out.

A pattern that ends in ``\\s*$`` swallows the newline itself, and one
compiled with re.MULTILINE means each line on purpose: both are fine.
Anything else has to be in :data:`ALLOWED` with the reason.
"""

from __future__ import annotations

import ast
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

#: ``(file, pattern name or the pattern itself)`` -> why ``$`` is right there.
ALLOWED: dict[tuple[str, str], str] = {
    # Parsers of one line a server or tool printed, already split into
    # lines: they read fields out, nothing they accept is passed on as is.
    ("core/ftp_client.py", "_UNIX_LIST_LINE"): "one line of a LIST answer",
    ("core/rsh_client.py", "_LS_RE"): "one line of ls output",
    ("core/telnet_client.py", "_LS_LINE_RE"): "one line of ls output",
    ("core/rsync_client.py", "_MODULE_RE"): "one line of the module list",
    ("core/rsync_client.py", "_LIST_RE"): "one line of a listing, split at LF already",
    ("resources/extensions/forensic_tools.py", "_FLS"): "one line of fls output",
    ("resources/extensions/virtualbox.py", '^"?([^"=]+)"?="?(.*?)"?$'):
        "one stripped line of showvminfo --machinereadable",
    ("scripts/extension_matrix.py", "_LOADED"): "one line of axross' log",
    ("core/system_info.py", "head"): "one line of /proc/asound/cards",
    ("core/mcp_discover.py", "_ITEM"): "one line of a README",
    ("core/wmi_client.py", "_DMTF_RE"): "a WMI date read into numbers",
    ("core/mcp_detect.py", "^(.*?)(?:==|@(?=[0-9]))(.*)$"): "splits name==version",
    ("core/third_party.py", "_SO"): "a bundled library's file name, for its family",
    ("core/third_party.py", "^(.+)-[^-]+\\.dist-info$"): "a bundled folder's name",
    ("core/s3_client.py", "^(.+)\\.s3(?:[.-]([a-z0-9-]+))?\\.amazonaws\\.com$"):
        "reads the bucket out of a host name; the bucket is validated after",
    # A prompt at the end of what the device sent so far: $ means "the
    # end", a newline after the prompt is the device's.
    ("core/telnet_cisco.py", "_PROMPT_RE"): "prompt at the end of the buffer",
    ("core/telnet_cisco.py", "_PRIV_PROMPT_RE"): "prompt at the end of the buffer",
    # Matching more is the safe side here: a fullmatch would let a
    # trailing newline through unmasked or unproxied.
    ("core/mcp_detect.py", "_SECRET_NAME"): "flags a secret's name; more is safer",
    ("core/mcp_detect.py", "_SECRET_OPTION"): "masks --token=…; a fullmatch would not "
                                               "mask a value ending in a newline",
    ("core/git_fs_client.py", "_SCP_LIKE_RE"): "host:path rebuilt into ssh:// from the "
                                               "groups (the newline is dropped); a "
                                               "fullmatch would skip the proxy",
    # Suffix tests on one word (is "-ings" its ending), nothing validated.
    ("core/voice_text.py", "ings?$"): "a word's ending",
    ("core/voice_text.py", "lings?$"): "a word's ending",
    ("core/voice_text.py", "[^aeiouy]rings?$"): "a word's ending",
    ("core/voice_text.py", "(?:[^aeiou]|[eao])ys?$"): "a word's ending",
}


def _ends_in_dollar(pattern: str) -> bool:
    if not pattern.endswith("$") or pattern.endswith("\\$"):
        return False
    return not re.search(r"\\s[*+]\$$", pattern)


def _inline_multiline(pattern: str) -> bool:
    """``(?m)`` / ``(?im)`` at the start: MULTILINE inside the pattern."""
    return bool(re.match(r"\(\?[aiLmsux]*m[aiLmsux]*\)", pattern))


#: A part of a pattern that is not a constant (an f-string field, a name).
HOLE = "{…}"


class _Finder:
    """The names the re module and its functions go by in one source."""

    FUNCS = ("compile", "match", "search", "fullmatch")

    def __init__(self, tree: ast.AST) -> None:
        self.modules = {"re"}            # import re / import re as _re
        self.functions: dict[str, str] = {}  # from re import match as m -> {"m": "match"}
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.name == "re":
                        self.modules.add(alias.asname or "re")
            elif isinstance(node, ast.ImportFrom) and node.module == "re":
                for alias in node.names:
                    if alias.name in self.FUNCS:
                        self.functions[alias.asname or alias.name] = alias.name
        self.constants: dict[str, str] = {}

    def re_function(self, func: ast.expr) -> str | None:
        """``match`` for ``re.match`` / ``_re.match`` / an imported ``match``."""
        if (isinstance(func, ast.Attribute) and func.attr in self.FUNCS
                and isinstance(func.value, ast.Name) and func.value.id in self.modules):
            return func.attr
        if isinstance(func, ast.Name):
            return self.functions.get(func.id)
        return None

    def pattern(self, node: ast.expr, partial: bool = False) -> str | None:
        """The pattern *node* builds, a non-constant part as :data:`HOLE`;
        None when its end is not known (HOLE when *partial*: a part of a
        concatenation that has a known end)."""
        known = self._pattern(node, partial)
        return HOLE if known is None and partial else known

    def _pattern(self, node: ast.expr, partial: bool) -> str | None:
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            return node.value
        if isinstance(node, ast.Name) and node.id in self.constants:
            return self.constants[node.id]
        if isinstance(node, ast.JoinedStr):  # f"^{name}$"
            return "".join(v.value if isinstance(v, ast.Constant) else HOLE
                           for v in node.values)
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):  # "^" + x + "$"
            right = self.pattern(node.right, partial)
            if right is None:
                return None
            return self.pattern(node.left, partial=True) + right
        if (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                and node.func.attr == "format"):  # "^{}$".format(x)
            return self.pattern(node.func.value)
        return None

    def multiline(self, call: ast.Call, pattern: str) -> bool:
        flags = list(call.args[1:]) + [k.value for k in call.keywords]
        return _inline_multiline(pattern) or any(
            re.search(r"MULTILINE|\.M\b", ast.unparse(a)) for a in flags)


def finds(source: str) -> list[tuple[int, str]]:
    """``(line, name or pattern)`` of each regex in *source* that ends in
    ``$`` and is used with match/search - through ``re`` or an alias of it
    (``import re as _re``, ``from re import match``), compiled into a name
    or used at once (``re.compile(p).match(v)``), the pattern a constant,
    a name for one, an f-string, a concatenation or a ``.format``."""
    tree = ast.parse(source)
    finder = _Finder(tree)
    assigns = [n for n in ast.walk(tree)
               if isinstance(n, (ast.Assign, ast.AnnAssign)) and n.value is not None]

    def names_of(node) -> list[str]:
        targets = node.targets if isinstance(node, ast.Assign) else [node.target]
        return [t.id if isinstance(t, ast.Name) else t.attr for t in targets
                if isinstance(t, (ast.Name, ast.Attribute))]

    for _round in range(2):  # a constant built from another constant
        for node in assigns:
            pattern = finder.pattern(node.value)
            if pattern is not None and not isinstance(node.value, ast.Call):
                for name in names_of(node):
                    finder.constants[name] = pattern

    def dollar_compile(node: ast.expr) -> str | None:
        """The pattern of ``re.compile(p, …)`` when p ends in $ (no MULTILINE)."""
        if (isinstance(node, ast.Call) and finder.re_function(node.func) == "compile"
                and node.args and (pattern := finder.pattern(node.args[0])) is not None
                and _ends_in_dollar(pattern) and not finder.multiline(node, pattern)):
            return pattern
        return None

    compiled: dict[str, str] = {}  # name -> pattern
    for node in assigns:
        if (pattern := dollar_compile(node.value)) is not None:
            for name in names_of(node):
                compiled[name] = pattern
    out = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        if finder.re_function(func) in ("match", "search") and node.args:
            pattern = finder.pattern(node.args[0])
            if (pattern is not None and _ends_in_dollar(pattern)
                    and not finder.multiline(node, pattern)):
                out.append((node.lineno, pattern))
        elif isinstance(func, ast.Attribute) and func.attr in ("match", "search"):
            owner = func.value
            if (pattern := dollar_compile(owner)) is not None:  # re.compile(p).match(v)
                out.append((node.lineno, pattern))
                continue
            name = owner.id if isinstance(owner, ast.Name) else (
                owner.attr if isinstance(owner, ast.Attribute) else None)
            if name in compiled:
                out.append((node.lineno, name))
    return out


#: Where axross' code is: every regex there is checked.
FOLDERS = ("core", "ui", "resources", "scripts")


def _sources():
    for folder in FOLDERS:
        yield from sorted((ROOT / folder).rglob("*.py"))
    yield ROOT / "main.py"


def test_sad_no_dollar_ended_regex_is_used_with_match_or_search():
    found = []
    for path in _sources():
        rel = path.relative_to(ROOT).as_posix()
        for line, what in finds(path.read_text(encoding="utf-8")):
            if (rel, what) not in ALLOWED:
                found.append(f"{rel}:{line} {what}")
    assert not found, ("use fullmatch (or \\Z) - $ also matches before a trailing "
                       "newline:\n" + "\n".join(found))


def test_happy_the_finder_sees_each_form():
    source = '''
import re
_A = re.compile(r"^[a-z]+$")
_B = re.compile(r"^x\\s*$")
_C = re.compile(r"^x$", re.MULTILINE)
_D = r"^[0-9]+$"
_A.match(v); _B.match(v); _C.search(v); _A.fullmatch(v)
re.match(r"^[a-z]+$", v); re.match(_D, v); re.fullmatch(r"^[a-z]+$", v); re.match(r"a\\$", v)
'''
    assert sorted(finds(source)) == [(7, "_A"), (8, "^[0-9]+$"), (8, "^[a-z]+$")]


def test_happy_the_finder_sees_aliases_inline_compiles_and_built_patterns():
    """``import re as _re``, ``from re import match``, ``re.compile(p).match``
    and patterns built from f-strings, ``+`` and ``.format`` - forms the
    first version of this test did not see."""
    source = '''
import re as _re
from re import match as m, search
_E = _re.compile(r"^[a-z]+$")
_F = _re.compile(r"^x$", _re.M)
_G = _re.compile(r"(?m)^x$")
_E.match(v); _F.match(v); _G.match(v)
_re.match(r"^[0-9]+$", v); m(r"^a$", v); search(r"b$", v); _re.compile(r"^c$").match(v)
_re.compile(r"^d$").fullmatch(v)
_re.match(f"^{name}$", v); _re.match("^" + name + "$", v); _re.match("^{}$".format(name), v)
_H = rf"^{name}x$"
_re.search(_H, v); _re.match(f"^{name}", v)
'''
    assert sorted(finds(source)) == [
        (7, "_E"), (8, "^[0-9]+$"), (8, "^a$"), (8, "^c$"), (8, "b$"),
        (10, "^{}$"), (10, "^" + HOLE + "$"), (10, "^" + HOLE + "$"), (12, "^" + HOLE + "x$")]


def test_sad_names_with_a_trailing_newline_are_not_what_they_look_like():
    """The finds of the wider check: a file name ending in a newline is not
    a duplicity volume, a licence file or a Python extension."""
    import importlib.util
    import sys

    sys.path.insert(0, str(ROOT / "scripts"))
    try:
        import bundle_licenses
        import native_inventory
    finally:
        sys.path.remove(str(ROOT / "scripts"))
    spec = importlib.util.spec_from_file_location(
        "backup_repos_regex_check", ROOT / "resources" / "extensions" / "backup_repos.py")
    backup_repos = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = backup_repos  # its dataclasses look it up
    spec.loader.exec_module(backup_repos)
    volume = "duplicity-full.20240101T000000Z.vol1.difftar.gpg"
    assert backup_repos._DUP.match(volume) and not backup_repos._DUP.match(volume + "\n")
    assert bundle_licenses.LICENCE_NAME.match("LICENSE.txt")
    assert not bundle_licenses.LICENCE_NAME.match("LICENSE\n")
    assert native_inventory._EXTENSION.search("x.cpython-311-x86_64-linux-gnu.so")
    assert not native_inventory._EXTENSION.search("x.abi3.so\n")
    assert native_inventory._SONAME.search("libz.so.1.3")
    assert not native_inventory._SONAME.search("libz.so.1\n")


def test_sad_validators_refuse_a_trailing_newline():
    """What slipped through before: each is refused now."""
    import pytest

    from core import mcp_catalog, pjl_client, rsh_client

    with pytest.raises(OSError):
        rsh_client._validate_path("/tmp/x\n")  # a newline ends the rsh command line
    assert rsh_client._validate_path("/tmp/x") == "/tmp/x"
    for ref in ("alpine:3.20\n", "alpine@sha256:" + "a" * 64 + "\n", "alpine\n"):
        with pytest.raises(ValueError):
            mcp_catalog.split_image(ref)
    assert mcp_catalog.split_image("alpine:3.20")[1] == "3.20"
    for check in (pjl_client._PATH_RE, pjl_client._VOLUME_RE):
        assert check.fullmatch("0\n") is None
