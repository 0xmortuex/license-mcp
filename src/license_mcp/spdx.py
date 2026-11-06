"""A small SPDX license-expression parser.

Grammar (SPDX spec, Annex D), with the usual precedence WITH > AND > OR:

    expression := or
    or         := and ("OR" and)*
    and        := with ("AND" with)*
    with       := atom ("WITH" exception-id)?
    atom       := "(" expression ")" | license-id["+"] | ["DocumentRef-x:"]"LicenseRef-x"

Operators are accepted in any case ("mit or apache-2.0" shows up in the wild) and
rendered in upper case. This module only parses and renders; deciding what an id
*means* lives in normalize.py and licenses.py.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass

from .errors import SpdxError

MAX_LENGTH = 2000
MAX_DEPTH = 40

_TOKEN = re.compile(r"\s*(\(|\)|[A-Za-z0-9][A-Za-z0-9.:_+-]*)")


@dataclass(frozen=True)
class Term:
    """One license id, optionally with a trailing '+' and a WITH exception."""

    id: str
    plus: bool = False
    exception: str | None = None

    @property
    def is_ref(self) -> bool:
        return self.id.startswith("LicenseRef-") or ":LicenseRef-" in self.id

    def __str__(self) -> str:
        s = self.id + ("+" if self.plus else "")
        return f"{s} WITH {self.exception}" if self.exception else s


@dataclass(frozen=True)
class Compound:
    op: str  # "AND" or "OR"
    items: tuple[Node, ...]

    def __str__(self) -> str:
        return render(self)


Node = Term | Compound


def _tokenize(text: str) -> list[str]:
    tokens: list[str] = []
    pos = 0
    text = text.rstrip()
    while pos < len(text):
        m = _TOKEN.match(text, pos)
        if m is None:
            raise SpdxError(
                f"unexpected character {text[pos:].lstrip()[:1]!r} at position {pos} in {text[:80]!r}"
            )
        tokens.append(m.group(1))
        pos = m.end()
    return tokens


class _Parser:
    def __init__(self, tokens: list[str], source: str) -> None:
        self.tokens = tokens
        self.i = 0
        self.source = source

    def peek(self) -> str | None:
        return self.tokens[self.i] if self.i < len(self.tokens) else None

    def peek_op(self) -> str | None:
        t = self.peek()
        return t.upper() if t is not None and t.upper() in ("AND", "OR", "WITH") else None

    def fail(self, why: str) -> SpdxError:
        return SpdxError(f"{why} in SPDX expression {self.source[:120]!r}")

    def parse_or(self, depth: int) -> Node:
        if depth > MAX_DEPTH:
            raise self.fail("expression is nested too deeply")
        items = [self.parse_and(depth)]
        while self.peek_op() == "OR":
            self.i += 1
            items.append(self.parse_and(depth))
        return items[0] if len(items) == 1 else _make("OR", items)

    def parse_and(self, depth: int) -> Node:
        items = [self.parse_with(depth)]
        while self.peek_op() == "AND":
            self.i += 1
            items.append(self.parse_with(depth))
        return items[0] if len(items) == 1 else _make("AND", items)

    def parse_with(self, depth: int) -> Node:
        atom = self.parse_atom(depth)
        if self.peek_op() == "WITH":
            if not isinstance(atom, Term):
                raise self.fail("WITH must follow a single license id, not a parenthesised group")
            self.i += 1
            exc = self.peek()
            if exc is None or exc in ("(", ")") or self.peek_op() is not None:
                raise self.fail("WITH needs an exception id after it")
            self.i += 1
            if exc.endswith("+"):
                raise self.fail("an exception id cannot end with '+'")
            return Term(atom.id, atom.plus, exc)
        return atom

    def parse_atom(self, depth: int) -> Node:
        t = self.peek()
        if t is None:
            raise self.fail("expression ends where a license id was expected")
        if t == "(":
            self.i += 1
            inner = self.parse_or(depth + 1)
            if self.peek() != ")":
                raise self.fail("missing closing ')'")
            self.i += 1
            return inner
        if t == ")" or self.peek_op() is not None:
            raise self.fail(f"unexpected {t!r} where a license id was expected")
        self.i += 1
        plus = t.endswith("+")
        ident = t[:-1] if plus else t
        if not ident or "+" in ident:
            raise self.fail(f"malformed license id {t!r}")
        if ":" in ident and not re.fullmatch(r"DocumentRef-[A-Za-z0-9.-]+:LicenseRef-[A-Za-z0-9.-]+", ident):
            raise self.fail(f"malformed license id {t!r}")
        if ident.startswith("LicenseRef-") and plus:
            raise self.fail("a LicenseRef cannot carry '+'")
        return Term(ident, plus)


def _make(op: str, items: list[Node]) -> Compound:
    flat: list[Node] = []
    for it in items:
        if isinstance(it, Compound) and it.op == op:
            flat.extend(it.items)
        else:
            flat.append(it)
    return Compound(op, tuple(flat))


def parse(text: str) -> Node:
    """Parse an SPDX expression. Raises SpdxError with a position/context message."""
    if not isinstance(text, str) or not text.strip():
        raise SpdxError("empty SPDX expression")
    if len(text) > MAX_LENGTH:
        raise SpdxError(f"SPDX expression is {len(text)} characters long; the limit is {MAX_LENGTH}")
    p = _Parser(_tokenize(text.strip()), text.strip())
    node = p.parse_or(0)
    if p.peek() is not None:
        raise p.fail(f"unexpected {p.peek()!r} after the end of the expression (missing AND/OR?)")
    return node


def render(node: Node, _parent: str | None = None) -> str:
    """Canonical text: upper-case operators, parentheses only where precedence needs them."""
    if isinstance(node, Term):
        return str(node)
    inner = f" {node.op} ".join(render(c, node.op) for c in node.items)
    return f"({inner})" if _parent == "AND" and node.op == "OR" else inner


def terms(node: Node) -> list[Term]:
    if isinstance(node, Term):
        return [node]
    out: list[Term] = []
    for c in node.items:
        out.extend(terms(c))
    return out


def map_terms(node: Node, fn: Callable[[Term], Node]) -> Node:
    """Rebuild the tree with every term replaced by fn(term)."""
    if isinstance(node, Term):
        return fn(node)
    items = [map_terms(c, fn) for c in node.items]
    return _make(node.op, items)
