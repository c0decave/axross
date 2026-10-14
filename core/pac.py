"""Proxy auto-config (PAC) evaluation with a restricted interpreter.

A PAC file is JavaScript, usually fetched from the network. Running it in
a real JS engine would put a script engine in the process for code that
is not ours; instead this module parses and evaluates the *small* subset
real PAC files use:

* ``function`` declarations, ``var``, ``if`` / ``else``, ``for``,
  ``while``, ``return``, blocks, ``//`` and ``/* */`` comments
* strings, numbers, booleans, ``null``, array literals, ``a[i]``
* ``! - && || ?: == != === !== < > <= >= + - * / %``, ``=`` and ``+=``,
  ``++`` / ``--``
* the PAC helper functions (``dnsDomainIs``, ``shExpMatch``,
  ``isInNet``, ``isPlainHostName``, ``localHostOrDomainIs``,
  ``dnsDomainLevels``, ``dnsResolve``, ``isResolvable``, ``myIpAddress``,
  ``weekdayRange``, ``dateRange``, ``timeRange``) and the string methods
  ``substring``, ``indexOf``, ``lastIndexOf``, ``toLowerCase``,
  ``toUpperCase``, ``charAt``, ``split``, ``replace`` (string pattern),
  ``startsWith``, ``endsWith`` and ``length``

There is no object model, no ``eval``, no I/O besides the DNS lookups the
PAC helpers themselves are defined to do, and a step limit stops runaway
loops. Anything outside the subset raises :class:`PacError`; callers
treat that as *no answer* and **fail closed** (never "connect direct").
"""

from __future__ import annotations

import fnmatch
import ipaddress
import re
import socket
import time
from collections.abc import Callable
from dataclasses import dataclass

MAX_STEPS = 200_000
MAX_DEPTH = 40
MAX_STRING = 1 << 16
MAX_SOURCE = 1 << 20


class PacError(Exception):
    """The PAC script is invalid, unsupported, or failed while running."""


@dataclass(frozen=True)
class PacDirective:
    """One entry of a PAC result: ``DIRECT`` or a proxy of some kind."""

    kind: str  # "direct" | "http" | "https" | "socks4" | "socks5"
    host: str = ""
    port: int = 0


# ---------------------------------------------------------------------------
# Result strings
# ---------------------------------------------------------------------------
_KIND_BY_WORD = {
    "PROXY": "http",
    "HTTP": "http",
    "HTTPS": "https",
    "SOCKS": "socks4",
    "SOCKS4": "socks4",
    "SOCKS5": "socks5",
}


def parse_result(text: object) -> list[PacDirective]:
    """Parse ``"PROXY a:80; SOCKS5 b:1080; DIRECT"``."""
    if not isinstance(text, str):
        raise PacError(f"FindProxyForURL returned {type(text).__name__}, expected a string")
    out: list[PacDirective] = []
    for part in text.split(";"):
        part = part.strip()
        if not part:
            continue
        word, _, rest = part.partition(" ")
        word = word.upper()
        if word == "DIRECT":
            out.append(PacDirective("direct"))
            continue
        kind = _KIND_BY_WORD.get(word)
        if kind is None:
            raise PacError(f"unknown PAC directive {word!r}")
        hostport = rest.strip()
        host, sep, port_s = hostport.rpartition(":")
        if not sep or not host or not port_s.isdigit() or not (1 <= int(port_s) <= 65535):
            raise PacError(f"malformed PAC proxy {hostport!r} (expected host:port)")
        out.append(PacDirective(kind, host.strip("[]"), int(port_s)))
    if not out:
        raise PacError("FindProxyForURL returned an empty result")
    return out


# ---------------------------------------------------------------------------
# Tokenizer
# ---------------------------------------------------------------------------
_KEYWORDS = {
    "function",
    "var",
    "let",
    "const",
    "if",
    "else",
    "return",
    "for",
    "while",
    "true",
    "false",
    "null",
    "undefined",
    "typeof",
    "new",
}
_TOKEN_RE = re.compile(
    r"""
    (?P<ws>\s+)
  | (?P<line_comment>//[^\n]*)
  | (?P<block_comment>/\*.*?\*/)
  | (?P<number>\d+\.?\d*|\.\d+)
  | (?P<string>"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*')
  | (?P<ident>[A-Za-z_$][A-Za-z0-9_$]*)
  | (?P<op>===|!==|==|!=|<=|>=|&&|\|\||\+\+|--|\+=|-=|[-+*/%<>=!?:;,.(){}\[\]])
    """,
    re.VERBOSE | re.DOTALL,
)


@dataclass
class _Tok:
    kind: str  # num str id kw op eof
    value: object
    pos: int


def _tokenize(src: str) -> list[_Tok]:
    if len(src) > MAX_SOURCE:
        raise PacError("PAC script too large")
    toks: list[_Tok] = []
    i = 0
    n = len(src)
    while i < n:
        m = _TOKEN_RE.match(src, i)
        if m is None:
            raise PacError(f"unsupported syntax at offset {i}: {src[i : i + 20]!r}")
        i = m.end()
        kind = m.lastgroup
        text = m.group()
        if kind in ("ws", "line_comment", "block_comment"):
            continue
        if kind == "number":
            toks.append(_Tok("num", float(text), m.start()))
        elif kind == "string":
            toks.append(_Tok("str", _unescape(text[1:-1]), m.start()))
        elif kind == "ident":
            toks.append(_Tok("kw" if text in _KEYWORDS else "id", text, m.start()))
        else:
            toks.append(_Tok("op", text, m.start()))
    toks.append(_Tok("eof", None, n))
    return toks


_ESCAPES = {"n": "\n", "t": "\t", "r": "\r", "\\": "\\", "'": "'", '"': '"', "0": "\0"}


def _unescape(s: str) -> str:
    if "\\" not in s:
        return s
    out = []
    i = 0
    while i < len(s):
        c = s[i]
        if c == "\\" and i + 1 < len(s):
            nxt = s[i + 1]
            if (
                nxt == "x"
                and i + 3 < len(s) + 0
                and re.fullmatch(r"[0-9a-fA-F]{2}", s[i + 2 : i + 4])
            ):
                out.append(chr(int(s[i + 2 : i + 4], 16)))
                i += 4
                continue
            out.append(_ESCAPES.get(nxt, nxt))
            i += 2
            continue
        out.append(c)
        i += 1
    return "".join(out)


# ---------------------------------------------------------------------------
# Parser -> tuples
# ---------------------------------------------------------------------------
class _Parser:
    def __init__(self, toks: list[_Tok]) -> None:
        self.toks = toks
        self.i = 0

    # helpers
    def peek(self) -> _Tok:
        return self.toks[self.i]

    def next(self) -> _Tok:
        t = self.toks[self.i]
        self.i += 1
        return t

    def is_op(self, value: str) -> bool:
        t = self.peek()
        return t.kind == "op" and t.value == value

    def is_kw(self, value: str) -> bool:
        t = self.peek()
        return t.kind == "kw" and t.value == value

    def eat_op(self, value: str) -> None:
        t = self.next()
        if t.kind != "op" or t.value != value:
            raise PacError(f"expected {value!r} at offset {t.pos}")

    def accept_op(self, value: str) -> bool:
        if self.is_op(value):
            self.i += 1
            return True
        return False

    # program
    def program(self) -> list:
        body = []
        while self.peek().kind != "eof":
            body.append(self.statement())
        return body

    def statement(self):
        t = self.peek()
        if t.kind == "op" and t.value == "{":
            return self.block()
        if t.kind == "op" and t.value == ";":
            self.i += 1
            return ("empty",)
        if t.kind == "kw":
            if t.value == "function":
                return self.function_decl()
            if t.value in ("var", "let", "const"):
                self.i += 1
                decls = []
                while True:
                    name = self.next()
                    if name.kind != "id":
                        raise PacError(f"bad variable name at offset {name.pos}")
                    init = None
                    if self.accept_op("="):
                        init = self.expression()
                    decls.append((name.value, init))
                    if not self.accept_op(","):
                        break
                self.end_statement()
                return ("var", decls)
            if t.value == "if":
                self.i += 1
                self.eat_op("(")
                cond = self.expression()
                self.eat_op(")")
                then = self.statement()
                other = None
                if self.is_kw("else"):
                    self.i += 1
                    other = self.statement()
                return ("if", cond, then, other)
            if t.value == "return":
                self.i += 1
                value = None
                if not (self.is_op(";") or self.is_op("}") or self.peek().kind == "eof"):
                    value = self.expression()
                self.end_statement()
                return ("return", value)
            if t.value == "while":
                self.i += 1
                self.eat_op("(")
                cond = self.expression()
                self.eat_op(")")
                return ("while", cond, self.statement())
            if t.value == "for":
                self.i += 1
                self.eat_op("(")
                init = None
                if not self.is_op(";"):
                    if self.peek().kind == "kw" and self.peek().value in ("var", "let", "const"):
                        self.i += 1
                        name = self.next().value
                        self.eat_op("=")
                        init = ("var", [(name, self.expression())])
                    else:
                        init = ("expr", self.expression())
                self.eat_op(";")
                cond = None if self.is_op(";") else self.expression()
                self.eat_op(";")
                step = None if self.is_op(")") else self.expression()
                self.eat_op(")")
                return ("for", init, cond, step, self.statement())
        expr = self.expression()
        self.end_statement()
        return ("expr", expr)

    def end_statement(self) -> None:
        if not self.accept_op(";"):
            t = self.peek()
            if t.kind != "eof" and not (t.kind == "op" and t.value == "}"):
                raise PacError(f"expected ';' at offset {t.pos}")

    def block(self):
        self.eat_op("{")
        body = []
        while not self.is_op("}"):
            if self.peek().kind == "eof":
                raise PacError("unterminated block")
            body.append(self.statement())
        self.eat_op("}")
        return ("block", body)

    def function_decl(self):
        self.i += 1
        name = self.next()
        if name.kind != "id":
            raise PacError("function declarations must be named")
        self.eat_op("(")
        params = []
        while not self.is_op(")"):
            p = self.next()
            if p.kind != "id":
                raise PacError(f"bad parameter at offset {p.pos}")
            params.append(p.value)
            if not self.accept_op(","):
                break
        self.eat_op(")")
        return ("function", name.value, params, self.block())

    # expressions (precedence climbing)
    def expression(self):
        return self.assignment()

    def assignment(self):
        left = self.ternary()
        t = self.peek()
        if t.kind == "op" and t.value in ("=", "+=", "-="):
            if left[0] not in ("id", "index"):
                raise PacError("invalid assignment target")
            self.i += 1
            return ("assign", t.value, left, self.assignment())
        return left

    def ternary(self):
        cond = self.binary(0)
        if self.accept_op("?"):
            a = self.assignment()
            self.eat_op(":")
            b = self.assignment()
            return ("cond", cond, a, b)
        return cond

    _LEVELS = [
        ("||",),
        ("&&",),
        ("==", "!=", "===", "!=="),
        ("<", ">", "<=", ">="),
        ("+", "-"),
        ("*", "/", "%"),
    ]

    def binary(self, level: int):
        if level >= len(self._LEVELS):
            return self.unary()
        left = self.binary(level + 1)
        while True:
            t = self.peek()
            if t.kind == "op" and t.value in self._LEVELS[level]:
                self.i += 1
                right = self.binary(level + 1)
                left = ("bin", t.value, left, right)
            else:
                return left

    def unary(self):
        t = self.peek()
        if t.kind == "op" and t.value in ("!", "-", "+"):
            self.i += 1
            return ("un", t.value, self.unary())
        if t.kind == "kw" and t.value == "typeof":
            self.i += 1
            return ("typeof", self.unary())
        if t.kind == "op" and t.value in ("++", "--"):
            self.i += 1
            target = self.unary()
            if target[0] != "id":
                raise PacError("invalid increment target")
            return ("assign", "+=" if t.value == "++" else "-=", target, ("num", 1.0))
        return self.postfix()

    def postfix(self):
        expr = self.primary()
        while True:
            if self.accept_op("."):
                name = self.next()
                if name.kind not in ("id", "kw"):
                    raise PacError(f"bad property name at offset {name.pos}")
                if self.is_op("("):
                    args = self.arguments()
                    expr = ("method", expr, name.value, args)
                else:
                    expr = ("prop", expr, name.value)
            elif self.is_op("("):
                if expr[0] != "id":
                    raise PacError("only named functions can be called")
                expr = ("call", expr[1], self.arguments())
            elif self.accept_op("["):
                idx = self.expression()
                self.eat_op("]")
                expr = ("index", expr, idx)
            elif self.peek().kind == "op" and self.peek().value in ("++", "--"):
                op = self.next().value
                if expr[0] != "id":
                    raise PacError("invalid increment target")
                expr = ("assign", "+=" if op == "++" else "-=", expr, ("num", 1.0))
            else:
                return expr

    def arguments(self) -> list:
        self.eat_op("(")
        args = []
        while not self.is_op(")"):
            args.append(self.assignment())
            if not self.accept_op(","):
                break
        self.eat_op(")")
        return args

    def primary(self):
        t = self.next()
        if t.kind == "num":
            return ("num", t.value)
        if t.kind == "str":
            return ("str", t.value)
        if t.kind == "id":
            return ("id", t.value)
        if t.kind == "kw":
            if t.value in ("true", "false"):
                return ("bool", t.value == "true")
            if t.value in ("null", "undefined"):
                return ("null",)
            raise PacError(f"unsupported keyword {t.value!r} at offset {t.pos}")
        if t.kind == "op":
            if t.value == "(":
                e = self.expression()
                self.eat_op(")")
                return e
            if t.value == "[":
                items = []
                while not self.is_op("]"):
                    items.append(self.assignment())
                    if not self.accept_op(","):
                        break
                self.eat_op("]")
                return ("array", items)
        raise PacError(f"unexpected token at offset {t.pos}")


# ---------------------------------------------------------------------------
# Evaluator
# ---------------------------------------------------------------------------
class _Return(Exception):
    def __init__(self, value) -> None:
        self.value = value


def _truthy(v) -> bool:
    if v is None:
        return False
    if isinstance(v, bool):
        return v
    if isinstance(v, float):
        return v != 0.0 and v == v
    if isinstance(v, str):
        return v != ""
    return True


def _num(v) -> float:
    if isinstance(v, bool):
        return 1.0 if v else 0.0
    if isinstance(v, float):
        return v
    if v is None:
        return 0.0
    if isinstance(v, str):
        try:
            return float(v) if v.strip() else 0.0
        except ValueError:
            return float("nan")
    raise PacError("cannot convert value to a number")


def _str(v) -> str:
    if v is None:
        return "null"
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, float):
        return str(int(v)) if v == int(v) and abs(v) < 1e15 else str(v)
    if isinstance(v, str):
        return v
    if isinstance(v, list):
        return _join(v, ",")
    raise PacError("cannot convert value to a string")


def _cap(s: str) -> str:
    """Every string a script builds goes through here: growth by doubling
    (``s += s``, ``s.replace(x, s)``) reaches gigabytes in thirty steps."""
    if len(s) > MAX_STRING:
        raise PacError("string too long")
    return s


def _join(items: list, sep: str) -> str:
    """``Array.join`` that stops before, not after, building an oversized string."""
    parts: list[str] = []
    total = 0
    for x in items:
        part = _str(x)
        total += len(part) + (len(sep) if parts else 0)
        if total > MAX_STRING:
            raise PacError("string too long")
        parts.append(part)
    return sep.join(parts)


def _int(v) -> int:
    """Integer value of a JS number; NaN / infinity are a script error."""
    n = _num(v)
    if n != n or n in (float("inf"), float("-inf")):
        raise PacError("expected an integer, got a non-finite number")
    return int(n)


def _loose_eq(a, b) -> bool:
    if a is None or b is None:
        return a is None and b is None
    if isinstance(a, str) and isinstance(b, str):
        return a == b
    if isinstance(a, list) or isinstance(b, list):
        return a is b
    return _num(a) == _num(b)


def _strict_eq(a, b) -> bool:
    if type(a) is not type(b):
        return False
    if isinstance(a, list):
        return a is b
    return a == b


class _Frame(dict):
    pass


class _Interpreter:
    def __init__(self, functions: dict, builtins: dict) -> None:
        self.functions = functions
        self.builtins = builtins
        self.steps = 0
        self.depth = 0
        self.globals: dict = {}

    def tick(self) -> None:
        self.steps += 1
        if self.steps > MAX_STEPS:
            raise PacError("PAC script exceeded the step limit")

    # statements
    def run_block(self, body: list, env: dict) -> None:
        for st in body:
            self.exec(st, env)

    def exec(self, st, env: dict) -> None:
        self.tick()
        kind = st[0]
        if kind == "expr":
            self.eval(st[1], env)
        elif kind == "var":
            for name, init in st[1]:
                env[name] = self.eval(init, env) if init is not None else None
        elif kind == "if":
            if _truthy(self.eval(st[1], env)):
                self.exec(st[2], env)
            elif st[3] is not None:
                self.exec(st[3], env)
        elif kind == "block":
            self.run_block(st[1], env)
        elif kind == "return":
            raise _Return(self.eval(st[1], env) if st[1] is not None else None)
        elif kind == "while":
            while _truthy(self.eval(st[1], env)):
                self.tick()
                self.exec(st[2], env)
        elif kind == "for":
            _k, init, cond, step, body = st
            if init is not None:
                self.exec(init, env)
            while cond is None or _truthy(self.eval(cond, env)):
                self.tick()
                self.exec(body, env)
                if step is not None:
                    self.eval(step, env)
        elif kind in ("empty", "function"):
            pass
        else:  # pragma: no cover - parser cannot produce others
            raise PacError(f"unsupported statement {kind}")

    # expressions
    def eval(self, e, env: dict):
        self.tick()
        kind = e[0]
        if kind == "num" or kind == "str" or kind == "bool":
            return e[1]
        if kind == "null":
            return None
        if kind == "id":
            name = e[1]
            if name in env:
                return env[name]
            if name == "undefined":
                return None
            raise PacError(f"undefined variable {name!r}")
        if kind == "array":
            return [self.eval(x, env) for x in e[1]]
        if kind == "un":
            v = self.eval(e[2], env)
            if e[1] == "!":
                return not _truthy(v)
            if e[1] == "-":
                return -_num(v)
            return _num(v)
        if kind == "typeof":
            try:
                v = self.eval(e[1], env)
            except PacError:
                return "undefined"
            if v is None:
                return "object"
            return {bool: "boolean", float: "number", str: "string", list: "object"}[type(v)]
        if kind == "cond":
            return self.eval(e[2] if _truthy(self.eval(e[1], env)) else e[3], env)
        if kind == "bin":
            return self.binop(e, env)
        if kind == "assign":
            return self.assign(e, env)
        if kind == "index":
            base = self.eval(e[1], env)
            idx = self.eval(e[2], env)
            if isinstance(base, list):
                i = _int(idx)
                return base[i] if 0 <= i < len(base) else None
            if isinstance(base, str):
                i = _int(idx)
                return base[i] if 0 <= i < len(base) else None
            raise PacError("cannot index this value")
        if kind == "prop":
            base = self.eval(e[1], env)
            if e[2] == "length" and isinstance(base, (str, list)):
                return float(len(base))
            raise PacError(f"unsupported property {e[2]!r}")
        if kind == "method":
            return self.method(self.eval(e[1], env), e[2], [self.eval(a, env) for a in e[3]])
        if kind == "call":
            return self.call(e[1], [self.eval(a, env) for a in e[2]])
        raise PacError(f"unsupported expression {kind}")  # pragma: no cover

    def binop(self, e, env: dict):
        op = e[1]
        if op == "&&":
            left = self.eval(e[2], env)
            return self.eval(e[3], env) if _truthy(left) else left
        if op == "||":
            left = self.eval(e[2], env)
            return left if _truthy(left) else self.eval(e[3], env)
        a = self.eval(e[2], env)
        b = self.eval(e[3], env)
        if op == "+":
            if (
                isinstance(a, str)
                or isinstance(b, str)
                or isinstance(a, list)
                or isinstance(b, list)
            ):
                return _cap(_str(a) + _str(b))
            return _num(a) + _num(b)
        if op in ("-", "*", "/", "%"):
            x, y = _num(a), _num(b)
            if op == "-":
                return x - y
            if op == "*":
                return x * y
            if y == 0:
                return float("nan")
            return x / y if op == "/" else x % y
        if op == "==":
            return _loose_eq(a, b)
        if op == "!=":
            return not _loose_eq(a, b)
        if op == "===":
            return _strict_eq(a, b)
        if op == "!==":
            return not _strict_eq(a, b)
        if isinstance(a, str) and isinstance(b, str):
            x, y = a, b
        else:
            x, y = _num(a), _num(b)
        return {"<": x < y, ">": x > y, "<=": x <= y, ">=": x >= y}[op]

    def assign(self, e, env: dict):
        op, target, value_expr = e[1], e[2], e[3]
        value = self.eval(value_expr, env)
        if target[0] == "id":
            name = target[1]
            if op != "=":
                cur = env.get(name)
                value = (
                    _cap(_str(cur) + _str(value))
                    if op == "+=" and (isinstance(cur, str) or isinstance(value, str))
                    else (_num(cur) + _num(value) if op == "+=" else _num(cur) - _num(value))
                )
            env[name] = value
            return value
        base = self.eval(target[1], env)
        idx = _int(self.eval(target[2], env))
        if not isinstance(base, list) or not (0 <= idx < 4096):
            raise PacError("invalid array assignment")
        while len(base) <= idx:
            base.append(None)
        base[idx] = value
        return value

    # calls
    def call(self, name: str, args: list):
        if name in self.functions:
            return self.invoke(self.functions[name], args)
        fn = self.builtins.get(name)
        if fn is None:
            raise PacError(f"unknown function {name!r}")
        try:
            return fn(*args)
        except PacError:
            raise
        except (TypeError, ValueError) as exc:
            raise PacError(f"bad arguments to {name}(): {exc}") from exc

    def invoke(self, fn, args: list):
        params, body = fn
        self.depth += 1
        if self.depth > MAX_DEPTH:
            raise PacError("PAC recursion too deep")
        env = dict(self.globals)
        env.update(zip(params, args + [None] * max(0, len(params) - len(args)), strict=False))
        try:
            self.run_block(body, env)
            return None
        except _Return as r:
            return r.value
        finally:
            self.depth -= 1

    def method(self, base, name: str, args: list):
        if isinstance(base, str):
            s = base
            if name == "substring" or name == "slice":
                a = _int(args[0]) if args else 0
                b = _int(args[1]) if len(args) > 1 else len(s)
                if name == "substring":
                    a, b = max(0, min(a, len(s))), max(0, min(b, len(s)))
                    if a > b:
                        a, b = b, a
                return s[a:b]
            if name == "indexOf":
                start = _int(args[1]) if len(args) > 1 else 0
                return float(s.find(_str(args[0]), max(0, start)))
            if name == "lastIndexOf":
                return float(s.rfind(_str(args[0])))
            if name == "toLowerCase":
                return s.lower()
            if name == "toUpperCase":
                return s.upper()
            if name == "charAt":
                i = _int(args[0]) if args else 0
                return s[i] if 0 <= i < len(s) else ""
            if name == "split":
                return s.split(_str(args[0])) if args and _str(args[0]) else list(s)
            if name == "replace":
                return _cap(s.replace(_str(args[0]), _str(args[1]), 1))
            if name == "startsWith":
                return s.startswith(_str(args[0]))
            if name == "endsWith":
                return s.endswith(_str(args[0]))
            if name == "trim":
                return s.strip()
        elif isinstance(base, list):
            if name == "join":
                return _join(base, _str(args[0]) if args else ",")
            if name == "indexOf":
                for i, x in enumerate(base):
                    if _strict_eq(x, args[0]):
                        return float(i)
                return -1.0
        raise PacError(f"unsupported method {name!r}")


# ---------------------------------------------------------------------------
# PAC helper functions
# ---------------------------------------------------------------------------
def _dns_resolve_default(host: str) -> str | None:
    try:
        return socket.gethostbyname(host)
    except OSError:
        return None


def _my_ip_default() -> str:
    # Address of the interface that would reach the internet; no packets sent.
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("192.0.2.1", 9))
        return s.getsockname()[0]
    except OSError:
        return "127.0.0.1"
    finally:
        s.close()


def _make_builtins(
    resolver: Callable[[str], str | None],
    my_ip: Callable[[], str],
    now: Callable[[], time.struct_time],
) -> dict:
    def isPlainHostName(host):
        return "." not in _str(host)

    def dnsDomainIs(host, domain):
        host, domain = _str(host).lower(), _str(domain).lower()
        return host.endswith(domain) if domain else False

    def localHostOrDomainIs(host, hostdom):
        host, hostdom = _str(host).lower(), _str(hostdom).lower()
        return host == hostdom or (("." not in host) and hostdom.startswith(host + "."))

    def isResolvable(host):
        return resolver(_str(host)) is not None

    def isInNet(host, pattern, mask):
        ip = _str(host)
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            resolved = resolver(ip)
            if resolved is None:
                return False
            ip = resolved
        try:
            net = ipaddress.ip_network(f"{_str(pattern)}/{_str(mask)}", strict=False)
            return ipaddress.ip_address(ip) in net
        except ValueError:
            return False

    def dnsResolve(host):
        return resolver(_str(host))

    def convert_addr(ipaddr):
        try:
            return float(int(ipaddress.IPv4Address(_str(ipaddr))))
        except ValueError:
            return None

    def dnsDomainLevels(host):
        return float(_str(host).count("."))

    def shExpMatch(s, pattern):
        # Case-insensitive glob; "?" and "*" like the Netscape spec.
        return fnmatch.fnmatchcase(_str(s).lower(), _str(pattern).lower())

    days = ["MON", "TUE", "WED", "THU", "FRI", "SAT", "SUN"]

    def weekdayRange(wd1, wd2=None, gmt=None):
        t = time.gmtime() if (gmt == "GMT" or wd2 == "GMT") else now()
        today = t.tm_wday
        a = days.index(_str(wd1).upper())
        b = a if wd2 in (None, "GMT") else days.index(_str(wd2).upper())
        return a <= today <= b if a <= b else (today >= a or today <= b)

    months = ["JAN", "FEB", "MAR", "APR", "MAY", "JUN", "JUL", "AUG", "SEP", "OCT", "NOV", "DEC"]

    def dateRange(*args):
        t = now()
        args = [a for a in args if a != "GMT"]
        if len(args) == 1:
            a = args[0]
            if isinstance(a, str) and a.upper() in months:
                return t.tm_mon - 1 == months.index(a.upper())
            return t.tm_mday == _int(a) if _num(a) < 32 else t.tm_year == _int(a)
        if len(args) == 2 and all(isinstance(a, str) and a.upper() in months for a in args):
            lo, hi = months.index(args[0].upper()), months.index(args[1].upper())
            m = t.tm_mon - 1
            return lo <= m <= hi if lo <= hi else (m >= lo or m <= hi)
        if len(args) == 2:
            return _int(args[0]) <= t.tm_mday <= _int(args[1])
        return True

    def timeRange(*args):
        t = now()
        args = [a for a in args if a != "GMT"]
        h = t.tm_hour
        if len(args) == 1:
            return h == _int(args[0])
        if len(args) == 2:
            lo, hi = _int(args[0]), _int(args[1])
            return lo <= h <= hi if lo <= hi else (h >= lo or h <= hi)
        secs = h * 3600 + t.tm_min * 60 + t.tm_sec
        if len(args) == 4:
            lo = _int(args[0]) * 3600 + _int(args[1]) * 60
            hi = _int(args[2]) * 3600 + _int(args[3]) * 60
        elif len(args) == 6:
            lo = _int(args[0]) * 3600 + _int(args[1]) * 60 + _int(args[2])
            hi = _int(args[3]) * 3600 + _int(args[4]) * 60 + _int(args[5])
        else:
            return True
        return lo <= secs <= hi if lo <= hi else (secs >= lo or secs <= hi)

    return {
        "isPlainHostName": isPlainHostName,
        "dnsDomainIs": dnsDomainIs,
        "localHostOrDomainIs": localHostOrDomainIs,
        "isResolvable": isResolvable,
        "isInNet": isInNet,
        "dnsResolve": dnsResolve,
        "convert_addr": convert_addr,
        "dnsDomainLevels": dnsDomainLevels,
        "shExpMatch": shExpMatch,
        "weekdayRange": weekdayRange,
        "dateRange": dateRange,
        "timeRange": timeRange,
        "myIpAddress": my_ip,
        "alert": lambda *_a: None,
    }


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------
class PacScript:
    """A parsed PAC file ready to answer ``find(url, host)``."""

    def __init__(
        self,
        source: str,
        *,
        resolver: Callable[[str], str | None] | None = None,
        my_ip: Callable[[], str] | None = None,
        now: Callable[[], time.struct_time] | None = None,
    ) -> None:
        try:
            program = _Parser(_tokenize(source)).program()
        except RecursionError as exc:
            raise PacError("PAC script nests too deeply") from exc
        except IndexError as exc:  # the parser ran past the last token
            raise PacError("PAC script ends unexpectedly") from exc
        self._functions: dict[str, tuple[list[str], list]] = {}
        self._globals_init: list = []
        for st in program:
            if st[0] == "function":
                self._functions[st[1]] = (st[2], st[3][1])
            else:
                self._globals_init.append(st)
        if "FindProxyForURL" not in self._functions:
            raise PacError("PAC script does not define FindProxyForURL(url, host)")
        self._builtins = _make_builtins(
            resolver or _dns_resolve_default, my_ip or _my_ip_default, now or time.localtime
        )

    def find(self, url: str, host: str) -> list[PacDirective]:
        interp = _Interpreter(self._functions, self._builtins)
        genv: dict = {}
        interp.globals = genv
        try:
            interp.run_block(self._globals_init, genv)
            result = interp.invoke(self._functions["FindProxyForURL"], [url, host])
        except _Return:  # top-level return: treat as no answer
            raise PacError("unexpected return at top level") from None
        except RecursionError as exc:
            raise PacError("PAC script nests too deeply") from exc
        except (
            ValueError,
            OverflowError,
            IndexError,
            KeyError,
            TypeError,
            ZeroDivisionError,
            MemoryError,
        ) as exc:
            # Whatever the script provoked, it is "no answer", never a crash.
            raise PacError(f"PAC script failed: {exc}") from exc
        return parse_result(result)


def load_pac(source: str, **kw) -> PacScript:
    """Parse PAC *source*; raises :class:`PacError` when unusable."""
    return PacScript(source, **kw)
