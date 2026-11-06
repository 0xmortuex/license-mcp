"""SPDX parser table tests: valid expressions (render), invalid expressions (errors), structure."""

from __future__ import annotations

import pytest

from license_mcp import spdx
from license_mcp.errors import SpdxError
from license_mcp.spdx import Compound, Term

# input -> canonical rendering
VALID = [
    ("MIT", "MIT"),
    ("Apache-2.0", "Apache-2.0"),
    ("GPL-2.0-only", "GPL-2.0-only"),
    ("GPL-2.0+", "GPL-2.0+"),
    ("BSD-3-Clause", "BSD-3-Clause"),
    ("MIT OR Apache-2.0", "MIT OR Apache-2.0"),
    ("mit or apache-2.0", "mit OR apache-2.0"),
    ("MIT AND BSD-3-Clause", "MIT AND BSD-3-Clause"),
    ("MIT and BSD-3-Clause", "MIT AND BSD-3-Clause"),
    ("(MIT)", "MIT"),
    ("((MIT))", "MIT"),
    ("(MIT OR Apache-2.0)", "MIT OR Apache-2.0"),
    ("MIT OR Apache-2.0 OR BSD-2-Clause", "MIT OR Apache-2.0 OR BSD-2-Clause"),
    ("MIT AND Apache-2.0 AND ISC", "MIT AND Apache-2.0 AND ISC"),
    ("MIT OR (Apache-2.0 AND ISC)", "MIT OR Apache-2.0 AND ISC"),
    ("(MIT OR Apache-2.0) AND ISC", "(MIT OR Apache-2.0) AND ISC"),
    ("MIT AND (Apache-2.0 OR ISC)", "MIT AND (Apache-2.0 OR ISC)"),
    ("MIT OR Apache-2.0 AND ISC", "MIT OR Apache-2.0 AND ISC"),
    ("(MIT AND Apache-2.0) OR ISC", "MIT AND Apache-2.0 OR ISC"),
    ("((MIT OR ISC) AND (Apache-2.0 OR Zlib))", "(MIT OR ISC) AND (Apache-2.0 OR Zlib)"),
    ("GPL-2.0-only WITH Classpath-exception-2.0", "GPL-2.0-only WITH Classpath-exception-2.0"),
    ("GPL-2.0+ WITH GCC-exception-3.1", "GPL-2.0+ WITH GCC-exception-3.1"),
    ("Apache-2.0 WITH LLVM-exception", "Apache-2.0 WITH LLVM-exception"),
    ("MIT OR GPL-2.0-only WITH Classpath-exception-2.0", "MIT OR GPL-2.0-only WITH Classpath-exception-2.0"),
    ("(GPL-2.0-only WITH Classpath-exception-2.0) AND MIT", "GPL-2.0-only WITH Classpath-exception-2.0 AND MIT"),
    ("gpl-3.0-only with gcc-exception-3.1", "gpl-3.0-only WITH gcc-exception-3.1"),
    ("LicenseRef-Proprietary", "LicenseRef-Proprietary"),
    ("LicenseRef-my.custom-1", "LicenseRef-my.custom-1"),
    ("DocumentRef-spdx-tool-1.2:LicenseRef-MIT-Style-2", "DocumentRef-spdx-tool-1.2:LicenseRef-MIT-Style-2"),
    ("MIT OR LicenseRef-Custom", "MIT OR LicenseRef-Custom"),
    ("LicenseRef-A AND LicenseRef-B", "LicenseRef-A AND LicenseRef-B"),
    ("Apache-2.0+", "Apache-2.0+"),
    ("LGPL-2.1-or-later", "LGPL-2.1-or-later"),
    ("AGPL-3.0-or-later OR GPL-3.0-or-later", "AGPL-3.0-or-later OR GPL-3.0-or-later"),
    ("CC-BY-4.0", "CC-BY-4.0"),
    ("0BSD", "0BSD"),
    ("MIT   OR\tApache-2.0", "MIT OR Apache-2.0"),
    ("  MIT  ", "MIT"),
    ("MIT OR\nApache-2.0", "MIT OR Apache-2.0"),
    ("(((((MIT)))))", "MIT"),
    ("A-1 OR B-2 OR C-3 OR D-4 OR E-5", "A-1 OR B-2 OR C-3 OR D-4 OR E-5"),
    ("MIT OR (Apache-2.0 OR ISC)", "MIT OR Apache-2.0 OR ISC"),
    ("MIT AND (Apache-2.0 AND ISC)", "MIT AND Apache-2.0 AND ISC"),
    ("Foo.Bar-1.0", "Foo.Bar-1.0"),
    ("OR-Tools-1.0", "OR-Tools-1.0"),
]

INVALID = [
    ("", "empty"),
    ("   ", "empty"),
    ("MIT OR", "ends where"),
    ("OR MIT", "unexpected 'OR'"),
    ("MIT AND", "ends where"),
    ("AND", "unexpected 'AND'"),
    ("(MIT", "closing"),
    ("MIT)", "unexpected ')'"),
    ("()", "unexpected ')'"),
    ("MIT OR OR Apache-2.0", "unexpected 'OR'"),
    ("MIT Apache-2.0", "missing AND/OR"),
    ("MIT WITH", "needs an exception"),
    ("WITH Classpath-exception-2.0", "unexpected 'WITH'"),
    ("(MIT OR ISC) WITH Classpath-exception-2.0", "single license id"),
    ("MIT WITH AND", "needs an exception"),
    ("MIT WITH Foo+", "cannot end with '+'"),
    ("MIT/Apache-2.0", "unexpected character"),
    ("MIT, Apache-2.0", "unexpected character"),
    ("MIT;ISC", "unexpected character"),
    ("MIT &", "unexpected character"),
    ("LicenseRef-x+", "cannot carry"),
    ("A+B", "malformed"),
    ("DocumentRef-x:Foo", "malformed"),
    ("MIT OR (Apache-2.0", "closing"),
    ("MIT $", "unexpected character"),
    ("-MIT", "unexpected character"),
    ("+", "unexpected character"),
    ("MIT\x00", "unexpected character"),
    ("(" * 100 + "MIT" + ")" * 100, "nested too deeply"),
    ("MIT " + "OR MIT " * 2000, "limit"),
]


@pytest.mark.parametrize(("text", "rendered"), VALID)
def test_valid_expressions_parse_and_render(text: str, rendered: str) -> None:
    node = spdx.parse(text)
    assert spdx.render(node) == rendered
    # rendering is a fixed point: parsing the output gives the same tree
    assert spdx.parse(rendered) == node


@pytest.mark.parametrize(("text", "fragment"), INVALID)
def test_invalid_expressions_raise_with_a_reason(text: str, fragment: str) -> None:
    with pytest.raises(SpdxError) as exc:
        spdx.parse(text)
    assert fragment in str(exc.value)


def test_precedence_with_binds_tighter_than_and_tighter_than_or() -> None:
    node = spdx.parse("A-1 OR B-1 AND C-1 WITH E-1")
    assert isinstance(node, Compound) and node.op == "OR"
    left, right = node.items
    assert left == Term("A-1")
    assert isinstance(right, Compound) and right.op == "AND"
    assert right.items == (Term("B-1"), Term("C-1", exception="E-1"))


def test_parentheses_override_precedence() -> None:
    node = spdx.parse("(A-1 OR B-1) AND C-1")
    assert isinstance(node, Compound) and node.op == "AND"
    assert isinstance(node.items[0], Compound) and node.items[0].op == "OR"


def test_same_operator_chains_are_flattened() -> None:
    node = spdx.parse("A-1 OR (B-1 OR (C-1 OR D-1))")
    assert isinstance(node, Compound) and len(node.items) == 4


def test_terms_and_plus_and_ref_flags() -> None:
    node = spdx.parse("GPL-2.0+ OR LicenseRef-x AND MIT WITH Foo-1.0")
    ts = spdx.terms(node)
    assert [t.id for t in ts] == ["GPL-2.0", "LicenseRef-x", "MIT"]
    assert ts[0].plus and not ts[1].plus
    assert ts[1].is_ref and not ts[0].is_ref
    assert ts[2].exception == "Foo-1.0"


def test_map_terms_rebuilds_tree() -> None:
    node = spdx.parse("MIT OR (ISC AND Zlib)")
    out = spdx.map_terms(node, lambda t: Term(t.id.lower()))
    assert spdx.render(out) == "mit OR isc AND zlib"


def test_hostile_inputs_fail_cleanly() -> None:
    with pytest.raises(SpdxError):
        spdx.parse("(" * 100000)
    with pytest.raises(SpdxError):
        spdx.parse("A" * 5_000_000)
    with pytest.raises(SpdxError):
        spdx.parse(None)  # type: ignore[arg-type]
