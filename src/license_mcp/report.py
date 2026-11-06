"""Text rendering for the tools. Every report ends with the same honest-limits footer."""

from __future__ import annotations

import os
from collections import Counter, defaultdict

from . import installed as inst
from . import licenses as L
from . import policy as pol_mod
from . import spdx
from .sandbox import Sandbox
from .scan import PkgLicense, Scan
from .spdx import Compound

FOOTER = (
    "Limits: this is guidance, not legal advice. License data comes from package metadata, which can differ from "
    "the license file actually shipped (or be out of date). UNKNOWN means no usable license data was found, not "
    "that a package is unlicensed. Dual-licence choices and 'ok' verdicts assume you comply with each license's "
    "conditions (notices, source offers). Every package's source is shown so you can judge how far to trust it."
)


def _tag(p: PkgLicense) -> str:
    return "direct" if p.pkg.direct else ("transitive" if p.pkg.direct is False else "?")


def _names(items: list[PkgLicense], limit: int, show_tag: bool = True) -> str:
    shown = [f"{p.label}" + (f" ({_tag(p)})" if show_tag and p.pkg.direct else "") for p in items[:limit]]
    more = len(items) - len(shown)
    return ", ".join(shown) + (f", ... and {more} more" if more > 0 else "")


def _header(scan: Scan) -> list[str]:
    lines = [f"Project: {scan.root}"]
    base = scan.root if os.path.isdir(scan.root) else os.path.dirname(scan.root)

    def rel(path: str) -> str:
        try:
            return os.path.relpath(path, base)
        except ValueError:
            return path

    lines.append("Lockfiles: " + "; ".join(
        f"{rel(lk.path)} ({lk.ecosystem}, {len(lk.packages)} packages)" for lk in scan.lockfiles))
    total = len(scan.pkgs)
    if scan.direct_known:
        d = sum(1 for p in scan.pkgs if p.pkg.direct)
        known = sum(1 for p in scan.pkgs if p.pkg.direct is not None)
        lines.append(f"Packages: {total} ({d} direct, {known - d} transitive"
                     + (f", {total - known} unknown" if total - known else "") + ")")
    else:
        lines.append(f"Packages: {total} (direct vs transitive could not be determined)")
    src = Counter(p.source.split(" (")[0].split(":")[0] if p.source != "none" else "none" for p in scan.pkgs)
    lines.append("License sources: " + ", ".join(f"{k} {v}" for k, v in sorted(src.items(), key=lambda kv: -kv[1])))
    if scan.sites:
        lines.append("Python environments read: " + "; ".join(scan.sites))
    return lines


def inventory(scan: Scan, allow: list[str] | None, list_limit: int) -> str:
    policy = pol_mod.Policy(allow=pol_mod._clean_specs(allow, "allow") if allow else [])
    groups: dict[str, list[PkgLicense]] = defaultdict(list)
    for p in scan.pkgs:
        groups[p.normalized.display()].append(p)
    out = ["License inventory", *_header(scan), ""]
    known_groups = sorted(((k, v) for k, v in groups.items() if k != "UNKNOWN"), key=lambda kv: (-len(kv[1]), kv[0]))
    out.append(f"By license ({len(known_groups)} distinct):")
    for expr, items in known_groups:
        node = items[0].normalized.node
        assert node is not None
        cats = sorted({L.category_of(t.id, t.exception) or "unclassified" for t in spdx.terms(node)})
        d = sum(1 for p in items if p.pkg.direct)
        split = f"{d} direct, {len(items) - d} transitive" if scan.direct_known else "direct/transitive unknown"
        out.append(f"  {expr}  -  {len(items)} package(s) ({split})  [{', '.join(cats)}]")
        out.append(f"      {_names(items, list_limit)}")
    duals = [p for p in scan.pkgs if p.normalized.node is not None and isinstance(p.normalized.node, Compound)
             and p.normalized.node.op == "OR"]
    if duals:
        out += ["", f"Dual/multi-licensed packages ({len(duals)}) - the OR choice"
                + (" (using your allow list)" if policy.allow else " (preferring the least restrictive option)") + ":"]
        for p in duals[:max(list_limit, 10)]:
            assert p.normalized.node is not None
            ev = pol_mod.eval_node(p.normalized.node, policy)
            out.append(f"  {p.label}: {p.normalized.expression}  ->  {ev.chosen}")
        if len(duals) > max(list_limit, 10):
            out.append(f"  ... and {len(duals) - max(list_limit, 10)} more")
    unknown = groups.get("UNKNOWN", [])
    if unknown:
        out += ["", f"UNKNOWN ({len(unknown)}) - no usable license data; not guessed:"]
        for p in unknown[:max(list_limit, 25)]:
            why = "; ".join(p.normalized.notes[:1] + p.notes[:2]) or "no license information found"
            out.append(f"  {p.label} ({_tag(p)}): {why}")
        if len(unknown) > max(list_limit, 25):
            out.append(f"  ... and {len(unknown) - max(list_limit, 25)} more")
    fuzzy = [p for p in scan.pkgs if p.normalized.approximate]
    if fuzzy:
        out += ["", f"Ambiguous spellings read as a most-likely license ({len(fuzzy)}) - please confirm:"]
        for p in fuzzy[:15]:
            out.append(f"  {p.label}: {p.normalized.raw!r} -> {p.normalized.expression}")
    if scan.notes:
        out += ["", "Notes:"] + [f"  - {n}" for n in scan.notes]
    out += ["", FOOTER]
    return "\n".join(out)


def policy_report(scan: Scan, pol: pol_mod.Policy, verdicts: list[pol_mod.Verdict], show_ok: bool, limit: int) -> str:
    bad = [v for v in verdicts if v.verdict == pol_mod.VIOLATION]
    rev = [v for v in verdicts if v.verdict == pol_mod.REVIEW]
    ok = [v for v in verdicts if v.verdict == pol_mod.OK]
    result = "FAIL" if bad else ("REVIEW" if rev else "PASS")
    out = ["License policy check", *_header(scan), f"Policy: {pol.describe()}", ""]
    out.append(f"RESULT: {result} - {len(bad)} violation(s), {len(rev)} need review, {len(ok)} ok")
    for title, items in (("VIOLATIONS", bad), ("NEEDS REVIEW", rev)):
        if not items:
            continue
        out += ["", f"{title} ({len(items)}):"]
        for v in items[:limit]:
            lic = v.pkg.normalized.display()
            out.append(f"  {v.pkg.label} ({_tag(v.pkg)})  license: {lic}  [source: {v.pkg.source}]")
            for r in v.reasons:
                out.append(f"      - {r}")
        if len(items) > limit:
            out.append(f"  ... and {len(items) - limit} more (raise `limit` to see them)")
    if ok:
        out += ["", f"OK ({len(ok)}):"]
        if show_ok:
            for v in ok[:limit]:
                extra = f"  [exception: {v.excepted}]" if v.excepted else ""
                out.append(f"  {v.pkg.label}  {v.pkg.normalized.display()}  [source: {v.pkg.source}]{extra}")
            if len(ok) > limit:
                out.append(f"  ... and {len(ok) - limit} more")
        else:
            out.append("  (pass show_ok=true to list them)")
    attr = sum(1 for v in verdicts if v.attribution and v.verdict == pol_mod.OK)
    if attr:
        out += ["", f"Attribution: {attr} ok package(s) require you to keep their copyright/license notice when you "
                    "distribute; run generate_notices for a starting THIRD-PARTY-NOTICES.md."]
    if scan.notes:
        out += ["", "Notes:"] + [f"  - {n}" for n in scan.notes]
    out += ["", FOOTER]
    return "\n".join(out)


def notices(scan: Scan, sandbox: Sandbox) -> str:
    out = ["# Third-Party Notices", "",
           "This project includes third-party packages under the licenses listed below. "
           "Generated from lockfile and package metadata; verify against each package's own license file "
           "before publishing.", ""]
    sections: dict[str, list[PkgLicense]] = defaultdict(list)
    for p in scan.pkgs:
        sections[p.normalized.display()].append(p)
    for lic in sorted(sections, key=lambda k: (k == "UNKNOWN", k)):
        items = sections[lic]
        out.append(f"## {lic}" if lic != "UNKNOWN" else "## UNKNOWN LICENSE - resolve before shipping")
        out.append("")
        info = L.info(lic)
        if info:
            out.append(f"_{info.name}: {info.summary}_")
            out.append("")
        for p in items:
            out.append(f"### {p.pkg.name} {p.pkg.version}")
            out.append(f"- License: {lic}")
            out.append(f"- Ecosystem: {p.pkg.ecosystem}")
            out.append(f"- License source: {p.source}")
            cr = inst.extract_copyright(p.files, sandbox)
            if cr:
                out.append("- Copyright:")
                out += [f"  - {c}" for c in cr]
            else:
                out.append("- Copyright: not found in package metadata or license files")
            if p.files:
                out.append("- License files: " + ", ".join(sorted({os.path.basename(f) for f in p.files})))
            if p.normalized.approximate:
                out.append(f"- Note: license text {p.normalized.raw!r} was ambiguous; confirm {lic}")
            out.append("")
    out.append("---")
    out.append(FOOTER)
    return "\n".join(out)


def license_files(scan: Scan) -> str:
    with_files = [p for p in scan.pkgs if p.files]
    installed_no_files = [p for p in scan.pkgs if not p.files and p.installed_path]
    not_installed = [p for p in scan.pkgs if not p.installed_path]
    out = ["License files shipped by installed dependencies", *_header(scan), ""]
    out.append(f"{len(with_files)} package(s) ship a LICENSE/NOTICE/COPYING file in their installed copy:")
    for p in with_files:
        names = ", ".join(sorted({os.path.basename(f) for f in p.files}))
        has_notice = any(os.path.basename(f).lower().startswith("notice") for f in p.files)
        out.append(f"  {p.label}: {names}" + ("   <-- has a NOTICE file: reproduce it when distributing" if has_notice else ""))
    if installed_no_files:
        out += ["", f"{len(installed_no_files)} package(s) are installed but ship no license file "
                f"(you may need to fetch the license text from upstream):"]
        out += [f"  {p.label} ({p.normalized.display()})" for p in installed_no_files[:60]]
    if not_installed:
        out += ["", f"{len(not_installed)} package(s) have no installed copy that could be inspected "
                "(not in the venv / node_modules / cargo registry), so their files are unknown:"]
        out += [f"  {p.label}" for p in not_installed[:40]]
        if len(not_installed) > 40:
            out.append(f"  ... and {len(not_installed) - 40} more")
    if scan.notes:
        out += ["", "Notes:"] + [f"  - {n}" for n in scan.notes]
    out += ["", FOOTER]
    return "\n".join(out)
