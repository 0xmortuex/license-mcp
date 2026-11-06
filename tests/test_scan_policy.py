"""End-to-end on real files: fake (but structurally real) venvs, node_modules and cargo registries."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from license_mcp import installed as inst
from license_mcp import policy as pol
from license_mcp import report
from license_mcp import scan as scanner
from license_mcp.errors import LicenseError
from license_mcp.sandbox import Sandbox

from .conftest import (
    MIT_TEXT,
    add_crate,
    add_dist,
    add_node_pkg,
    can_symlink,
    copy_fixture,
    site_packages,
    write,
)

UV_LOCK = """version = 1
requires-python = ">=3.10"

[[package]]
name = "demo"
version = "0.1.0"
source = { virtual = "." }
dependencies = [{ name = "alpha" }, { name = "beta" }, { name = "delta" }, { name = "epsilon" }]

[[package]]
name = "alpha"
version = "1.0.0"
source = { registry = "https://pypi.org/simple" }
dependencies = [{ name = "gamma" }]

[[package]]
name = "beta"
version = "2.0.0"
source = { registry = "https://pypi.org/simple" }

[[package]]
name = "gamma"
version = "3.0.0"
source = { registry = "https://pypi.org/simple" }

[[package]]
name = "delta"
version = "4.0.0"
source = { registry = "https://pypi.org/simple" }

[[package]]
name = "epsilon"
version = "5.0.0"
source = { registry = "https://pypi.org/simple" }

[[package]]
name = "zeta"
version = "1.0.0"
source = { registry = "https://pypi.org/simple" }

[[package]]
name = "eta"
version = "1.0.0"
source = { registry = "https://pypi.org/simple" }
"""


def python_project(tmp: Path, posix: bool = False) -> Path:
    proj = tmp / "proj"
    write(proj / "uv.lock", UV_LOCK)
    sp = site_packages(proj / ".venv", posix=posix)
    add_dist(sp, "alpha", "1.0.0", expression="MIT",
             files={"LICENSE": MIT_TEXT, "NOTICE": "alpha notice\n"})
    add_dist(sp, "beta", "2.0.0", license_field="BSD")
    add_dist(sp, "gamma", "3.0.0", classifiers=("License :: OSI Approved :: GNU General Public License v3 (GPLv3)",),
             pep639={"COPYING": "Copyright (C) 2007 Free Software Foundation, Inc.\n"})
    add_dist(sp, "delta", "4.0.0", expression="MIT OR GPL-3.0-only")
    add_dist(sp, "epsilon", "5.0.0")  # installed but says nothing
    add_dist(sp, "zeta", "2.0.0", expression="MIT")  # installed version differs from the locked 1.0.0
    add_dist(sp, "eta", "1.0.0", license_field="Permission is hereby granted, free of charge, to any person\n"
             "obtaining a copy of this software ...", classifiers=("License :: OSI Approved :: Apache Software License",))
    return proj


@pytest.mark.parametrize("posix", [False, True])
def test_python_installed_metadata_is_the_source(tmp_path: Path, posix: bool) -> None:
    proj = python_project(tmp_path, posix)
    s = scanner.scan(str(proj), Sandbox([str(tmp_path)]))
    by = {p.pkg.name: p for p in s.pkgs}
    assert by["alpha"].normalized.expression == "MIT"
    assert by["alpha"].source == "installed metadata (License-Expression)"
    assert by["beta"].normalized.expression == "BSD-3-Clause" and by["beta"].normalized.approximate
    assert by["beta"].source == "installed metadata (License field)"
    assert by["gamma"].normalized.expression == "GPL-3.0-only"
    assert by["gamma"].source == "installed metadata (license classifier)"
    assert by["delta"].normalized.expression == "MIT OR GPL-3.0-only"
    # installed but silent -> UNKNOWN with the reason; never guessed
    assert by["epsilon"].normalized.unknown and by["epsilon"].source == "none"
    # version mismatch: the installed copy is NOT used, and the note says why
    assert by["zeta"].normalized.unknown
    assert any("differs from locked" in n for n in by["zeta"].notes)
    # pasted license text in the License field -> falls through to the classifier
    assert by["eta"].normalized.expression == "Apache-2.0"
    assert by["eta"].source == "installed metadata (license classifier)"
    assert [p.pkg.direct for p in s.pkgs if p.pkg.name in ("alpha", "gamma")] == [True, False]
    assert {os.path.basename(f) for f in by["alpha"].files} == {"LICENSE", "NOTICE"}
    assert {os.path.basename(f) for f in by["gamma"].files} == {"COPYING"}  # PEP 639 licenses/ directory


def test_explicit_python_argument_selects_the_venv(tmp_path: Path) -> None:
    proj = tmp_path / "proj"
    write(proj / "uv.lock", UV_LOCK)
    other = tmp_path / "elsewhere" / "myenv"
    sp = site_packages(other)
    add_dist(sp, "alpha", "1.0.0", expression="ISC")
    (other / "Scripts").mkdir(parents=True)
    (other / "Scripts" / "python.exe").write_text("", encoding="utf-8")
    sb = Sandbox([str(tmp_path)])
    for given in (other, other / "Scripts" / "python.exe", sp):
        s = scanner.scan(str(proj), sb, python=str(given))
        assert {p.pkg.name: p.normalized.expression for p in s.pkgs}["alpha"] == "ISC"
    with pytest.raises(LicenseError, match="found no site-packages"):
        scanner.scan(str(proj), sb, python=str(tmp_path / "proj"))


def test_no_venv_gives_unknown_and_an_explanatory_note(tmp_path: Path) -> None:
    proj = tmp_path / "proj"
    write(proj / "uv.lock", UV_LOCK)
    s = scanner.scan(str(proj), Sandbox([str(tmp_path)]))
    assert all(p.normalized.unknown for p in s.pkgs)
    assert any("no virtualenv found" in n for n in s.notes)


def test_default_policy_verdicts(tmp_path: Path) -> None:
    proj = python_project(tmp_path)
    s = scanner.scan(str(proj), Sandbox([str(tmp_path)]))
    p = pol.load_policy(str(proj), None, None, None)
    v = {x.pkg.pkg.name: x for x in pol.evaluate_scan(s, p)}
    assert v["alpha"].verdict == pol.OK
    assert v["gamma"].verdict == pol.VIOLATION and "strong copyleft" in v["gamma"].reasons[0]
    assert v["beta"].verdict == pol.REVIEW and "ambiguous" in v["beta"].reasons[0]
    assert v["delta"].verdict == pol.OK and v["delta"].chosen == "MIT"
    assert v["epsilon"].verdict == pol.REVIEW and "no license found" in v["epsilon"].reasons[0]
    assert v["eta"].verdict == pol.REVIEW  # Apache Software License classifier is ambiguous


def test_allow_list_makes_everything_else_a_violation(tmp_path: Path) -> None:
    proj = python_project(tmp_path)
    s = scanner.scan(str(proj), Sandbox([str(tmp_path)]))
    p = pol.load_policy(str(proj), ["MIT", "Apache-2.0"], None, None)
    v = {x.pkg.pkg.name: x for x in pol.evaluate_scan(s, p)}
    assert v["alpha"].verdict == pol.OK
    assert v["delta"].verdict == pol.OK and v["delta"].chosen == "MIT"
    assert v["gamma"].verdict == pol.VIOLATION and "not on the allow list" in v["gamma"].reasons[0]
    assert v["beta"].verdict == pol.VIOLATION  # BSD-3-Clause is not on this list


def test_deny_beats_allow_and_deny_by_category(tmp_path: Path) -> None:
    proj = python_project(tmp_path)
    s = scanner.scan(str(proj), Sandbox([str(tmp_path)]))
    p = pol.load_policy(str(proj), ["MIT"], ["MIT"], None)
    assert {x.pkg.pkg.name: x.verdict for x in pol.evaluate_scan(s, p)}["alpha"] == pol.VIOLATION
    p2 = pol.load_policy(str(proj), None, ["strong-copyleft", "BSD-*"], None)
    v = {x.pkg.pkg.name: x for x in pol.evaluate_scan(s, p2)}
    assert v["gamma"].verdict == pol.VIOLATION and "denied" in v["gamma"].reasons[0]
    assert v["beta"].verdict == pol.VIOLATION
    # deny MIT: dual-licensed 'MIT OR GPL-3.0-only' has no acceptable option left
    p3 = pol.load_policy(str(proj), None, ["MIT"], None)
    assert {x.pkg.pkg.name: x.verdict for x in pol.evaluate_scan(s, p3)}["delta"] == pol.VIOLATION


def test_project_license_uses_the_compatibility_table(tmp_path: Path) -> None:
    proj = python_project(tmp_path)
    s = scanner.scan(str(proj), Sandbox([str(tmp_path)]))
    v = {x.pkg.pkg.name: x for x in pol.evaluate_scan(s, pol.load_policy(str(proj), None, None, "GPL-3.0-only"))}
    assert v["gamma"].verdict == pol.OK  # GPL-3.0 into a GPL-3.0 project
    v2 = {x.pkg.pkg.name: x for x in pol.evaluate_scan(s, pol.load_policy(str(proj), None, None, "MIT"))}
    assert v2["gamma"].verdict == pol.VIOLATION and "incompatible" in v2["gamma"].reasons[0]


def test_policy_file_exceptions_and_argument_override(tmp_path: Path) -> None:
    proj = python_project(tmp_path)
    write(proj / ".license-policy.toml",
          'allow = ["MIT"]\ndeny = []\nproject_license = "MIT"\n\n[exceptions]\n'
          'epsilon = "vendor confirmed MIT by email"\n"gamma@3.0.0" = "separate process, reviewed"\n')
    s = scanner.scan(str(proj), Sandbox([str(tmp_path)]))
    p = pol.load_policy(str(proj), None, None, None)
    assert p.origin == pol.POLICY_FILE
    v = {x.pkg.pkg.name: x for x in pol.evaluate_scan(s, p)}
    assert v["epsilon"].verdict == pol.OK and v["epsilon"].excepted == "vendor confirmed MIT by email"
    assert "otherwise needs review" in v["epsilon"].reasons[1]
    assert v["gamma"].verdict == pol.OK and v["gamma"].excepted
    assert v["beta"].verdict == pol.VIOLATION
    # arguments override the file key by key
    p2 = pol.load_policy(str(proj), ["MIT", "BSD-3-Clause"], None, None)
    assert "overridden by arguments: allow" in p2.origin
    assert {x.pkg.pkg.name: x.verdict for x in pol.evaluate_scan(s, p2)}["beta"] == pol.REVIEW  # approx spelling


def test_policy_file_errors(tmp_path: Path) -> None:
    write(tmp_path / ".license-policy.toml", 'alow = ["MIT"]\n')
    with pytest.raises(LicenseError, match="unknown key"):
        pol.load_policy(str(tmp_path), None, None, None)
    write(tmp_path / ".license-policy.toml", 'allow = ["Not A License At All"]\n')
    with pytest.raises(LicenseError, match="not a recognisable license"):
        pol.load_policy(str(tmp_path), None, None, None)
    write(tmp_path / ".license-policy.toml", "allow = [")
    with pytest.raises(LicenseError, match="cannot read"):
        pol.load_policy(str(tmp_path), None, None, None)
    write(tmp_path / ".license-policy.toml", "allow = 3\n")
    with pytest.raises(LicenseError, match="list of strings"):
        pol.load_policy(str(tmp_path), None, None, None)
    with pytest.raises(LicenseError, match="project_license"):
        pol.load_policy(str(tmp_path / "nowhere"), None, None, "Banana")


def test_reports_render_and_carry_the_footer(tmp_path: Path) -> None:
    proj = python_project(tmp_path)
    sb = Sandbox([str(tmp_path)])
    s = scanner.scan(str(proj), sb)
    inv = report.inventory(s, None, 15)
    assert "MIT  -  1 package(s)" in inv
    assert "UNKNOWN (2)" in inv and "epsilon@5.0.0" in inv and "zeta@1.0.0" in inv
    assert "Dual/multi-licensed" in inv and "delta@4.0.0: MIT OR GPL-3.0-only  ->  MIT" in inv
    assert "Ambiguous spellings" in inv and "not legal advice" in inv
    assert "License sources: installed metadata" in inv
    p = pol.load_policy(str(proj), None, None, None)
    rep = report.policy_report(s, p, pol.evaluate_scan(s, p), False, 50)
    assert "RESULT: FAIL - 1 violation(s)" in rep and "gamma@3.0.0" in rep and "[source: installed metadata" in rep
    assert "not legal advice" in rep
    notices = report.notices(s, sb)
    assert "### alpha 1.0.0" in notices and "Copyright (c) 2021 Jane Doe" in notices
    assert "UNKNOWN LICENSE - resolve before shipping" in notices
    files = report.license_files(s)
    assert "alpha@1.0.0: LICENSE, NOTICE" in files and "NOTICE file" in files
    assert "zeta@1.0.0" not in files.split("have no installed copy")[0].split("installed but ship no")[0]


def test_allow_list_changes_the_dual_license_choice(tmp_path: Path) -> None:
    proj = python_project(tmp_path)
    s = scanner.scan(str(proj), Sandbox([str(tmp_path)]))
    inv = report.inventory(s, ["GPL-3.0-only"], 15)
    assert "delta@4.0.0: MIT OR GPL-3.0-only  ->  GPL-3.0-only" in inv


# ---------------------------------------------------------------- node


def node_project(tmp: Path) -> Path:
    proj = copy_fixture("npm3", tmp / "web")
    add_node_pkg(proj, "ms", "2.1.3", "Apache-2.0", {"LICENSE": MIT_TEXT})  # differs from the lockfile's MIT
    add_node_pkg(proj, "semver", "9.9.9", "ISC")  # wrong version installed
    return proj


def test_node_installed_beats_lockfile_and_mismatch_falls_back(tmp_path: Path) -> None:
    proj = node_project(tmp_path)
    s = scanner.scan(str(proj), Sandbox([str(tmp_path)]))
    by = {p.pkg.name: p for p in s.pkgs}
    assert by["ms"].normalized.expression == "Apache-2.0" and by["ms"].source.startswith("installed node_modules")
    assert by["debug"].normalized.expression == "MIT" and by["debug"].source == "lockfile (package-lock.json)"
    assert by["semver"].normalized.expression == "ISC" and by["semver"].source.startswith("lockfile")
    assert any("differs from locked" in n for n in by["semver"].notes)
    assert [os.path.basename(f) for f in by["ms"].files] == ["LICENSE"]
    assert by["debug"].pkg.direct is True and by["ms"].pkg.direct is False


def test_node_nested_install_path_from_lockfile(tmp_path: Path) -> None:
    proj = tmp_path / "web"
    write(proj / "package-lock.json", """{"lockfileVersion": 3, "packages": {
      "": {"dependencies": {"a": "1"}},
      "node_modules/a": {"version": "1.0.0"},
      "node_modules/a/node_modules/b": {"version": "2.0.0"}}}""")
    add_node_pkg(proj, "a", "1.0.0", "MIT")
    add_node_pkg(proj, "b", "2.0.0", {"type": "BSD-2-Clause"}, at="node_modules/a/node_modules/b")
    s = scanner.scan(str(proj), Sandbox([str(tmp_path)]))
    assert {p.pkg.name: p.normalized.expression for p in s.pkgs} == {"a": "MIT", "b": "BSD-2-Clause"}


def test_pnpm_store_layout(tmp_path: Path) -> None:
    proj = copy_fixture("pnpm9", tmp_path / "web")
    add_node_pkg(proj, "ms", "2.1.3", "MIT", at="node_modules/.pnpm/ms@2.1.3/node_modules/ms")
    s = scanner.scan(str(proj), Sandbox([str(tmp_path)]))
    by = {p.pkg.name: p for p in s.pkgs}
    assert by["ms"].normalized.expression == "MIT" and by["ms"].source.startswith("installed node_modules")
    assert by["debug"].normalized.unknown


# ---------------------------------------------------------------- rust and go


def test_cargo_registry_and_go(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    home = tmp_path / "cargohome"
    monkeypatch.setenv("CARGO_HOME", str(home))
    add_crate(home, "chrono", "0.4.19", "MIT/Apache-2.0", {"LICENSE-MIT": MIT_TEXT, "LICENSE-APACHE": "x"})
    add_crate(home, "smallvec", "0.6.9", None)
    proj = copy_fixture("cargo", tmp_path / "rs")
    s = scanner.scan(str(proj), Sandbox([str(tmp_path / "rs")]))
    by = {p.pkg.name: p for p in s.pkgs}
    assert by["chrono"].normalized.expression == "MIT OR Apache-2.0"
    assert by["chrono"].source == "cargo registry Cargo.toml"
    assert {os.path.basename(f) for f in by["chrono"].files} == {"LICENSE-MIT", "LICENSE-APACHE"}
    assert by["smallvec"].normalized.unknown and any("no `license` key" in n for n in by["smallvec"].notes)
    assert by["libc"].normalized.unknown
    go = scanner.scan(str(copy_fixture("go", tmp_path / "go")), Sandbox([str(tmp_path / "go")]))
    assert all(p.normalized.unknown for p in go.pkgs)
    assert any("Go modules" in n for n in go.notes)


# ---------------------------------------------------------------- sandbox and hostile inputs


def test_sandbox_blocks_paths_outside(tmp_path: Path) -> None:
    allowed = tmp_path / "allowed"
    allowed.mkdir()
    outside = tmp_path / "outside"
    write(outside / "uv.lock", UV_LOCK)
    write(allowed / "uv.lock", UV_LOCK)
    sb = Sandbox([str(allowed)])
    for bad in (str(outside), str(allowed / ".." / "outside"), "..", "../outside"):
        with pytest.raises(LicenseError, match="outside the allowed"):
            scanner.scan(bad, sb)
    with pytest.raises(LicenseError, match="NUL"):
        scanner.scan("x\x00y", sb)
    with pytest.raises(LicenseError, match="outside the allowed"):
        scanner.scan(str(allowed), sb, python=str(outside))


def test_relative_paths_resolve_against_the_first_allowed_dir(tmp_path: Path) -> None:
    write(tmp_path / "proj" / "uv.lock", UV_LOCK)
    s = scanner.scan("proj", Sandbox([str(tmp_path)]))
    assert len(s.pkgs) == 7


@pytest.mark.skipif(os.name == "nt", reason="symlink creation needs privileges on Windows runners")
def test_symlinked_metadata_pointing_outside_is_not_read(tmp_path: Path) -> None:
    if not can_symlink(tmp_path):
        pytest.skip("cannot create symlinks here")
    proj = tmp_path / "proj"
    write(proj / "uv.lock", UV_LOCK)
    sp = site_packages(proj / ".venv")
    secret = tmp_path / "outside" / "alpha-1.0.0.dist-info"
    write(secret / "METADATA", "Name: alpha\nVersion: 1.0.0\nLicense-Expression: GPL-3.0-only\n")
    os.symlink(secret, sp / "alpha-1.0.0.dist-info", target_is_directory=True)
    s = scanner.scan(str(proj), Sandbox([str(proj)]))
    a = next(p for p in s.pkgs if p.pkg.name == "alpha")
    assert a.normalized.unknown and any("outside the allowed" in n for n in a.notes)


def test_huge_metadata_is_capped(tmp_path: Path) -> None:
    proj = tmp_path / "proj"
    write(proj / "uv.lock", UV_LOCK)
    sp = site_packages(proj / ".venv")
    di = add_dist(sp, "alpha", "1.0.0", expression="MIT")
    with open(di / "METADATA", "a", encoding="utf-8") as fh:
        fh.write("x" * (3 * inst.MAX_META_BYTES))
    s = scanner.scan(str(proj), Sandbox([str(tmp_path)]))
    assert {p.pkg.name: p.normalized.expression for p in s.pkgs}["alpha"] == "MIT"


def test_malformed_dist_info_does_not_crash(tmp_path: Path) -> None:
    proj = tmp_path / "proj"
    write(proj / "uv.lock", UV_LOCK)
    sp = site_packages(proj / ".venv")
    d = sp / "alpha-1.0.0.dist-info"
    d.mkdir()
    (d / "METADATA").write_bytes(b"\xff\xfe\x00\x01 binary \x00 garbage\nLicense: \xc3(\n")
    s = scanner.scan(str(proj), Sandbox([str(tmp_path)]))
    assert next(p for p in s.pkgs if p.pkg.name == "alpha").normalized.unknown


def test_copyright_extraction_skips_templates_and_boilerplate(tmp_path: Path) -> None:
    f = tmp_path / "LICENSE"
    write(f, "Copyright [yyyy] [name of copyright owner]\nCopyright notice above\n"
             "Copyright (c) 2019-2024 Real Person <r@example.com>\n(c) 2020 Other Org\n"
             "Copyright holders may not be liable\n© 2021 Unicode Person\n")
    out = inst.extract_copyright([str(f)], Sandbox([str(tmp_path)]))
    assert out == ["Copyright (c) 2019-2024 Real Person <r@example.com>", "(c) 2020 Other Org",
                   "© 2021 Unicode Person"]
