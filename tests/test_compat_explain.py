"""Compatibility table, explain_license, and the tool wrappers around them."""

from __future__ import annotations

import pytest

from license_mcp import compat, licenses
from license_mcp import explain as ex
from license_mcp.errors import LicenseError
from license_mcp.server import compatibility, explain_license

C, K, X, U = compat.COMPATIBLE, compat.CONDITIONAL, compat.INCOMPATIBLE, compat.UNKNOWN

# (project, dependency, verdict, rule)
TABLE = [
    ("MIT", "MIT", C, "R2"),
    ("MIT", "Apache-2.0", C, "R1"),
    ("MIT", "BSD-3-Clause", C, "R2"),
    ("proprietary", "MIT", C, "R2"),
    ("proprietary", "Apache-2.0", C, "R1"),
    ("proprietary", "CC0-1.0", C, "R2"),
    ("GPL-2.0-only", "Apache-2.0", X, "R1"),
    ("GPL-2.0-or-later", "Apache-2.0", K, "R1"),
    ("GPL-3.0-only", "Apache-2.0", C, "R1"),
    ("LGPL-2.1-only", "Apache-2.0", X, "R1"),
    ("AGPL-3.0-only", "Apache-2.0", C, "R1"),
    ("GPL-3.0-only", "MIT", C, "R2"),
    ("GPL-2.0-only", "BSD-4-Clause", X, "R2"),
    ("MIT", "BSD-4-Clause", C, "R2"),
    ("GPL-3.0-only", "OpenSSL", X, "R2"),
    ("MIT", "GPL-3.0-only", X, "R7"),
    ("Apache-2.0", "GPL-3.0-only", X, "R7"),
    ("proprietary", "GPL-2.0-only", X, "R7"),
    ("GPL-3.0-only", "GPL-3.0-only", C, "R7"),
    ("GPL-3.0-or-later", "GPL-3.0-only", C, "R7"),
    ("AGPL-3.0-only", "GPL-3.0-only", C, "R7"),
    ("GPL-2.0-only", "GPL-2.0-only", C, "R7"),
    ("GPL-3.0-only", "GPL-2.0-only", X, "R7"),
    ("GPL-2.0-or-later", "GPL-2.0-only", K, "R7"),
    ("GPL-3.0-only", "GPL-2.0-or-later", C, "R7"),
    ("GPL-2.0-only", "GPL-2.0-or-later", C, "R7"),
    ("GPL-2.0-only", "GPL-3.0-only", X, "R7"),
    ("GPL-2.0-or-later", "GPL-3.0-or-later", K, "R7"),
    ("LGPL-3.0-only", "GPL-3.0-only", X, "R7"),
    ("MIT", "GPL-2.0-only WITH Classpath-exception-2.0", K, "R7"),
    ("proprietary", "GPL-2.0-only WITH Classpath-exception-2.0", K, "R7"),
    ("GPL-3.0-only", "GPL-2.0-only WITH Classpath-exception-2.0", X, "R7"),
    ("GPL-2.0-only", "GPL-2.0-only WITH Classpath-exception-2.0", C, "R7"),
    ("MIT", "MPL-2.0", K, "R3"),
    ("GPL-3.0-only", "MPL-2.0", C, "R3"),
    ("MPL-2.0", "MPL-2.0", C, "R3"),
    ("proprietary", "LGPL-2.1-or-later", K, "R4"),
    ("MIT", "LGPL-3.0-only", K, "R4"),
    ("GPL-3.0-only", "LGPL-3.0-only", C, "R4"),
    ("GPL-2.0-only", "LGPL-3.0-only", X, "R4"),
    ("GPL-2.0-or-later", "LGPL-3.0-or-later", K, "R4"),
    ("GPL-3.0-only", "LGPL-2.1-only", C, "R4"),
    ("GPL-2.0-only", "LGPL-2.1-only", C, "R4"),
    ("GPL-3.0-only", "EPL-2.0", K, "R5"),
    ("GPL-3.0-only", "EPL-1.0", X, "R5"),
    ("GPL-3.0-only", "CDDL-1.0", X, "R5"),
    ("MIT", "EPL-2.0", K, "R5"),
    ("EPL-2.0", "EPL-2.0", C, "R5"),
    ("GPL-3.0-only", "CC-BY-SA-4.0", C, "R6"),
    ("MIT", "CC-BY-SA-4.0", K, "R6"),
    ("AGPL-3.0-only", "AGPL-3.0-only", C, "R8"),
    ("GPL-3.0-only", "AGPL-3.0-only", K, "R8"),
    ("MIT", "AGPL-3.0-only", X, "R8"),
    ("proprietary", "AGPL-3.0-or-later", X, "R8"),
    ("proprietary", "SSPL-1.0", K, "R9"),
    ("MIT", "SSPL-1.0", X, "R9"),
    ("MIT", "BUSL-1.1", X, "R9"),
    ("proprietary", "Elastic-2.0", K, "R9"),
    ("MIT", "CC-BY-NC-4.0", X, "R10"),
    ("proprietary", "CC-BY-NC-SA-4.0", X, "R10"),
    ("CC-BY-NC-4.0", "CC-BY-NC-4.0", K, "R10"),
    ("MIT", "JSON", K, "R11"),
    ("MIT", "CC-BY-ND-4.0", K, "R11"),
    ("MIT", "LicenseRef-Proprietary", U, "R0"),
    ("MIT", "Foo-1.0", U, "R0"),
    ("Foo-1.0", "MIT", U, "R0"),
    ("MIT", "EUPL-1.2", U, "R12"),
    # expressions: dependency OR picks the best option, AND the worst; project OR must satisfy all options
    ("MIT", "MIT OR GPL-3.0-only", C, "R2"),
    ("MIT", "GPL-3.0-only OR AGPL-3.0-only", X, "R7"),
    ("MIT", "MIT AND GPL-3.0-only", X, "R7"),
    ("MIT", "MIT AND Apache-2.0", C, "R2"),
    ("MIT OR GPL-3.0-only", "Apache-2.0", C, "R1"),
    ("MIT OR GPL-2.0-only", "Apache-2.0", X, "R1"),
    ("Apache-2.0 OR MIT", "GPL-3.0-only", X, "R7"),
    # messy spellings go through normalisation
    ("GPLv3", "Apache 2", C, "R1"),
    ("GPL-2.0", "Apache-2.0", X, "R1"),
]


@pytest.mark.parametrize(("proj", "dep", "verdict", "rule"), TABLE)
def test_compatibility_table(proj: str, dep: str, verdict: str, rule: str) -> None:
    p = compat.parse_side(proj, "project")
    d = compat.parse_side(dep, "dep")
    assert p.node is not None and d.node is not None
    res = compat.evaluate(p.node, d.node)
    assert (res.verdict, res.rule) == (verdict, rule), res.reason
    assert res.reason


def test_table_size() -> None:
    assert len(TABLE) >= 70


def test_agpl_network_note_is_attached() -> None:
    out = compatibility("proprietary", "AGPL-3.0-only")
    assert "INCOMPATIBLE" in out and "network" in out and "not legal advice" in out
    assert "network" in compatibility("GPL-3.0-only", "AGPL-3.0-only")
    assert "network clause" not in compatibility("MIT", "Apache-2.0").split("Direction:")[0]


def test_compatibility_tool_output_cites_the_rule_and_direction() -> None:
    out = compatibility("MIT", "Apache-2.0")
    assert out.startswith("Dependency Apache-2.0 into a project licensed MIT: COMPATIBLE")
    assert "Rule R1" in out and "Direction:" in out
    out2 = compatibility("GPL-2.0-only", "Apache-2.0")
    assert "INCOMPATIBLE" in out2 and "GPLv3" in out2
    assert "several licenses" in compatibility("MIT OR Apache-2.0", "MIT")


def test_compatibility_rejects_nonsense_with_advice() -> None:
    with pytest.raises(LicenseError, match="cannot interpret project_license"):
        compatibility("banana", "MIT")
    with pytest.raises(LicenseError, match="cannot interpret dependency_license"):
        compatibility("MIT", "")


# ---------------------------------------------------------------- explain


def test_every_table_entry_is_explainable_and_consistent() -> None:
    assert len(licenses.TABLE) >= 40
    for lid, info in licenses.TABLE.items():
        assert info.id == lid and info.summary and info.category
        out = explain_license(lid)
        assert info.name in out and "category:" in out and "guidance" in out


def test_explain_variants() -> None:
    assert "Read 'Apache 2' as SPDX: Apache-2.0" in explain_license("Apache 2")
    out = explain_license("GPL-2.0")
    assert "GPL-2.0-only" in out and "strong-copyleft" in out
    out = explain_license("MIT OR Apache-2.0")
    assert "compound expression" in out and "MIT License" in out and "Apache License 2.0" in out
    out = explain_license("GPL-2.0-only WITH Classpath-exception-2.0")
    assert "weak copyleft" in out and "Classpath" in out
    assert "patent" in explain_license("Apache-2.0").lower()
    assert "network" in explain_license("AGPL-3.0-only").lower()


def test_explain_unknown_ids_do_not_guess() -> None:
    out = explain_license("Foo-1.0")
    assert "not in the built-in table" in out and "will not guess" in out
    out = explain_license("GPL-1.0-only")
    assert "strong-copyleft" in out  # by family
    assert "Cannot interpret" in ex.explain("total nonsense here")


def test_deprecated_and_case_handling_in_table() -> None:
    assert licenses.canonical_case("apache-2.0") == "Apache-2.0"
    assert licenses.category_of("GPL-3.0-only", "Classpath-exception-2.0") == licenses.WEAK
    assert licenses.category_of("Apache-2.0", "LLVM-exception") == licenses.PERMISSIVE
    assert licenses.category_of("Nope-1.0") is None
