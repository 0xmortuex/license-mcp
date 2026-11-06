"""The policy engine: a verdict (ok / needs review / violation) per package, with reasons."""

from __future__ import annotations

import fnmatch
import os
import sys
from dataclasses import dataclass, field
from typing import Any

from . import compat
from . import licenses as L
from . import spdx
from .errors import LicenseError
from .normalize import normalize
from .scan import PkgLicense, Scan
from .spdx import Node, Term

if sys.version_info >= (3, 11):
    import tomllib
else:  # pragma: no cover
    import tomli as tomllib

OK = "ok"
REVIEW = "needs review"
VIOLATION = "violation"
_RANK = {OK: 0, REVIEW: 1, VIOLATION: 2}
POLICY_FILE = ".license-policy.toml"
CATEGORIES = {
    L.PUBLIC_DOMAIN, L.PERMISSIVE, L.WEAK, L.STRONG, L.NETWORK, L.SOURCE_AVAILABLE, L.NONCOMMERCIAL,
    L.RESTRICTED, L.PROPRIETARY,
}

LINKING_NOTE = (
    "weak copyleft: fine to use unmodified as a separate library (dynamic linking, or shipping the "
    "library untouched). If you modify it, or statically link/bundle it, the library's own terms (share "
    "changes, allow replacement) apply"
)


@dataclass
class Policy:
    allow: list[str] = field(default_factory=list)
    deny: list[str] = field(default_factory=list)
    project_license: str | None = None
    exceptions: dict[str, str] = field(default_factory=dict)
    origin: str = "built-in defaults"
    _project: Node | None = None

    def describe(self) -> str:
        bits = []
        if self.allow:
            bits.append("allow=" + ", ".join(self.allow))
        if self.deny:
            bits.append("deny=" + ", ".join(self.deny))
        if self.project_license:
            bits.append(f"project_license={self.project_license}")
        if self.exceptions:
            bits.append(f"{len(self.exceptions)} exception(s)")
        return (" ".join(bits) if bits else "no allow/deny/project_license (default rules)") + f"  [{self.origin}]"


def _clean_specs(values: Any, what: str) -> list[str]:
    if values is None:
        return []
    if isinstance(values, str):
        values = [values]
    if not isinstance(values, list) or not all(isinstance(v, str) for v in values):
        raise LicenseError(f"{what} must be a list of strings (SPDX ids, wildcards like 'BSD-*', or categories)")
    out: list[str] = []
    for v in values:
        v = v.strip()
        if not v:
            continue
        if v in CATEGORIES or "*" in v or "?" in v:
            out.append(v)
            continue
        n = normalize(v)
        if n.unknown or n.node is None:
            raise LicenseError(
                f"{what} entry {v!r} is not a recognisable license. Use SPDX ids such as 'MIT' or 'GPL-3.0-only', "
                f"wildcards such as 'BSD-*', or a category ({', '.join(sorted(CATEGORIES))})."
            )
        out.append(spdx.render(n.node))
    return out


def load_policy(
    directory: str,
    allow: list[str] | None,
    deny: list[str] | None,
    project_license: str | None,
) -> Policy:
    """Policy from .license-policy.toml in `directory` (if present), with explicit arguments overriding it."""
    pol = Policy()
    file_path = os.path.join(directory, POLICY_FILE)
    from_file = False
    if os.path.isfile(file_path):
        try:
            if os.path.getsize(file_path) > 256 * 1024:
                raise LicenseError(f"{file_path} is larger than 256 KiB")
            with open(file_path, "rb") as fh:
                data = tomllib.loads(fh.read().decode("utf-8"))
        except (OSError, UnicodeDecodeError, tomllib.TOMLDecodeError) as e:
            raise LicenseError(f"cannot read {file_path}: {e}") from e
        known = {"allow", "deny", "project_license", "exceptions"}
        extra = set(data) - known
        if extra:
            raise LicenseError(
                f"{file_path}: unknown key(s) {', '.join(sorted(extra))}. Allowed keys: {', '.join(sorted(known))}."
            )
        pol.allow = _clean_specs(data.get("allow"), f"{POLICY_FILE} 'allow'")
        pol.deny = _clean_specs(data.get("deny"), f"{POLICY_FILE} 'deny'")
        pl = data.get("project_license")
        if pl is not None and not isinstance(pl, str):
            raise LicenseError(f"{file_path}: project_license must be a string")
        pol.project_license = pl
        exc = data.get("exceptions") or {}
        if not isinstance(exc, dict) or not all(isinstance(k, str) and isinstance(v, str) for k, v in exc.items()):
            raise LicenseError(f"{file_path}: [exceptions] must map package names to reason strings")
        pol.exceptions = {k.lower(): v for k, v in exc.items()}
        from_file = True
    overrides = []
    if allow is not None:
        pol.allow = _clean_specs(allow, "allow")
        overrides.append("allow")
    if deny is not None:
        pol.deny = _clean_specs(deny, "deny")
        overrides.append("deny")
    if project_license is not None:
        pol.project_license = project_license
        overrides.append("project_license")
    if pol.project_license:
        n = compat.parse_side(pol.project_license, "project_license")
        pol._project = n.node
        pol.project_license = n.expression
    if from_file and overrides:
        pol.origin = f"{POLICY_FILE}, overridden by arguments: {', '.join(overrides)}"
    elif from_file:
        pol.origin = POLICY_FILE
    elif overrides:
        pol.origin = "arguments"
    return pol


def _matches(t: Term, specs: list[str]) -> str | None:
    cat = L.category_of(t.id, t.exception)
    for s in specs:
        if s in CATEGORIES:
            if cat == s:
                return s
        elif "*" in s or "?" in s:
            if fnmatch.fnmatchcase(t.id, s) or fnmatch.fnmatchcase(str(t), s):
                return s
        elif s == str(t) or s == t.id:
            return s
    return None


@dataclass
class Eval:
    verdict: str
    reasons: list[str]
    chosen: str  # expression text actually relied on


def _eval_term(t: Term, pol: Policy) -> Eval:
    name = str(t)
    cat = L.category_of(t.id, t.exception)
    m = _matches(t, pol.deny)
    if m:
        return Eval(VIOLATION, [f"{name} is denied by policy (matches deny entry {m!r})"], name)
    m = _matches(t, pol.allow)
    if m:
        return Eval(OK, [f"{name} is on the allow list (entry {m!r})"], name)
    if pol.allow:
        if cat is None:
            return Eval(REVIEW, [f"{name} is not in the built-in license table and not on the allow list"], name)
        return Eval(VIOLATION, [f"{name} ({cat}) is not on the allow list"], name)
    if pol._project is not None:
        res = compat.evaluate(pol._project, t)
        v = {compat.COMPATIBLE: OK, compat.CONDITIONAL: REVIEW, compat.INCOMPATIBLE: VIOLATION,
             compat.UNKNOWN: REVIEW}[res.verdict]
        why = f"{name} into a {pol.project_license} project is {res.verdict} [{res.rule}]: {res.reason}"
        return Eval(v, [why, *res.notes] if v != OK else [why], name)
    if cat in (L.PERMISSIVE, L.PUBLIC_DOMAIN):
        return Eval(OK, [f"{name} is {cat}"], name)
    if cat == L.WEAK:
        return Eval(REVIEW, [f"{name}: {LINKING_NOTE}"], name)
    if cat == L.STRONG:
        return Eval(VIOLATION, [
            f"{name} is strong copyleft: distributing a product that includes it generally requires releasing the "
            "whole combined work under the GPL. Pass project_license (e.g. 'GPL-3.0-only') if your project is itself GPL"
        ], name)
    if cat == L.NETWORK:
        return Eval(VIOLATION, [
            f"{name} is network copyleft: it extends GPL-style source obligations to users who only interact "
            "with the software over a network. Pass project_license='AGPL-3.0-only' if that is acceptable"
        ], name)
    if cat == L.SOURCE_AVAILABLE:
        return Eval(VIOLATION, [f"{name} is source-available, not open source: its terms restrict commercial/service use"], name)
    if cat == L.NONCOMMERCIAL:
        return Eval(VIOLATION, [f"{name} forbids commercial use"], name)
    if cat == L.RESTRICTED:
        return Eval(REVIEW, [f"{name} has a field-of-use or no-derivatives restriction"], name)
    if cat == L.PROPRIETARY:
        return Eval(REVIEW, [f"{name} is proprietary / no open-source license granted: check your agreement with the vendor"], name)
    return Eval(REVIEW, [f"{name} is not in the built-in license table (unclassified); read its terms"], name)


def eval_node(node: Node, pol: Policy) -> Eval:
    if isinstance(node, Term):
        return _eval_term(node, pol)
    parts = [eval_node(c, pol) for c in node.items]
    if node.op == "OR":
        best = min(parts, key=lambda e: _RANK[e.verdict])
        if len(parts) > 1:
            return Eval(best.verdict, [f"dual-licensed ({spdx.render(node)}): chose {best.chosen}"] + best.reasons,
                        best.chosen)
        return best
    worst = max(parts, key=lambda e: _RANK[e.verdict])
    reasons = [r for e in parts if e.verdict != OK or e is worst for r in e.reasons]
    chosen = " AND ".join(e.chosen for e in parts)
    return Eval(worst.verdict, reasons or worst.reasons, chosen)


@dataclass
class Verdict:
    pkg: PkgLicense
    verdict: str
    reasons: list[str]
    chosen: str | None
    attribution: bool
    excepted: str | None = None


def _needs_attribution(node: Node | None) -> bool:
    return node is not None and any(L.needs_attribution(t.id) for t in spdx.terms(node))


def judge(p: PkgLicense, pol: Policy) -> Verdict:
    n = p.normalized
    if n.node is None:
        why = "no license found" if not n.raw else f"license string {n.raw!r} is not recognised"
        detail = "; ".join(x for x in (p.notes if not n.raw else n.notes)[:2])
        reasons = [why + (f" ({detail})" if detail else "") + ": UNKNOWN does not mean unlicensed, check upstream"]
        ev = Eval(REVIEW, reasons, "UNKNOWN")
        chosen = None
        attribution = True
    else:
        ev = eval_node(n.node, pol)
        chosen = ev.chosen
        attribution = _needs_attribution(n.node)
        if ev.verdict == OK and n.approximate:
            ev = Eval(REVIEW, [f"license string {n.raw!r} is ambiguous: read as {n.expression}, please confirm"],
                      ev.chosen)
    v = Verdict(p, ev.verdict, ev.reasons, chosen, attribution)
    if v.verdict != OK:
        for key in (p.pkg.name.lower(), p.label.lower()):
            if key in pol.exceptions:
                v.excepted = pol.exceptions[key]
                v.reasons = [f"accepted by policy exception: {v.excepted}", f"(otherwise {v.verdict}) " + v.reasons[0]]
                v.verdict = OK
                break
    return v


def evaluate_scan(scan: Scan, pol: Policy) -> list[Verdict]:
    return [judge(p, pol) for p in scan.pkgs]
