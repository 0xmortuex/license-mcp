"""A small, explicit compatibility table: may code under DEPENDENCY be used in a project under PROJECT?

This is guidance, not legal advice. The rules below are the whole table - there is no
hidden data. Each result carries the rule id (R1...) and the reasoning, so the answer
can be checked against the license texts and the FSF/Apache/MPL compatibility notes
cited in each rule.

Direction matters: 'dependency X into project Y' means a combined work distributed under
Y that includes or links X. Verdicts:

  compatible    fine, subject to the dependency's ordinary conditions (notices etc.)
  conditional   possible only if specific conditions are met (linking style, version choice)
  incompatible  cannot be combined and distributed as that project license
  unknown       the table has no rule (unrecognised license, or a proprietary dependency)

Rules (first matching rule wins; project 'proprietary' means closed-source distribution):

  R0  either license unrecognised, or the dependency is proprietary          -> unknown
  R1  Apache-2.0 into GPL-2.0-only / LGPL-2.1-only / LGPL-2.0-only           -> incompatible
      Apache-2.0 into GPL-2.0-or-later / LGPL-2.1-or-later                   -> conditional
      Apache-2.0 into anything else                                          -> compatible
  R2  permissive / public-domain into anything                               -> compatible
      (BSD-4-Clause, OpenSSL, Apache-1.1 into the GPL family                 -> incompatible)
  R3  MPL-2.0 into GPL/LGPL/AGPL (secondary-license clause)                  -> compatible
      MPL-2.0 into MPL-2.0                                                   -> compatible; else conditional
  R4  LGPL into proprietary/permissive/other weak                            -> conditional (link, allow relinking)
      LGPL-2.x into any GPL/LGPL/AGPL                                        -> compatible
      LGPL-3.0 into GPL-3.0 / LGPL-3.0 / AGPL-3.0                            -> compatible
      LGPL-3.0 into GPL-2.0-or-later                                         -> conditional
      LGPL-3.0 into GPL-2.0-only / LGPL-2.1-only                             -> incompatible
  R5  EPL-2.0 into the GPL family                                            -> conditional (secondary license)
      EPL-1.0 / CDDL / CPL / MPL-1.1 into the GPL family                     -> incompatible
      those into anything else                                               -> conditional (file/module copyleft)
  R6  CC-BY-SA-4.0 into GPL-3.0 / AGPL-3.0                                   -> compatible (one-way, per Creative Commons)
      OFL / Artistic / CC-BY-SA into anything else                           -> conditional
  R7  GPL-2.0-only into GPL-2.0-only                                         -> compatible
      GPL-2.0-only into GPL-2.0-or-later                                     -> conditional (result is GPL-2.0-only)
      GPL-2.0-or-later into GPL-2.0-*/GPL-3.0-*/AGPL-3.0-*                   -> compatible
      GPL-3.0-* into GPL-3.0-* / AGPL-3.0-*                                  -> compatible
      GPL-3.0-* into GPL-2.0-or-later                                        -> conditional (result is GPL-3.0)
      GPL with a linking exception into proprietary/permissive/weak          -> conditional
      any other GPL into anything else                                       -> incompatible
  R8  AGPL-3.0-* into AGPL-3.0-*                                             -> compatible
      AGPL-3.0-* into GPL-3.0-*                                              -> conditional (network clause stays)
      AGPL-3.0-* into anything else                                          -> incompatible
  R9  source-available (SSPL, BUSL, Elastic) into proprietary                -> conditional; into open source -> incompatible
  R10 non-commercial into a non-NC project                                   -> incompatible; into an NC license -> conditional
  R11 restricted (JSON license, CC-BY-ND)                                    -> conditional
  R12 anything else                                                          -> unknown

A project offered under several licenses (A OR B) must be compatible with every option, because
recipients may pick any; for a dependency offered under (X OR Y) the best option is used.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from . import licenses as L
from . import spdx
from .normalize import Normalized, normalize
from .spdx import Compound, Node, Term

COMPATIBLE = "compatible"
CONDITIONAL = "conditional"
INCOMPATIBLE = "incompatible"
UNKNOWN = "unknown"
_BAD = {COMPATIBLE: 0, CONDITIONAL: 1, UNKNOWN: 2, INCOMPATIBLE: 3}

GPL2_ONLY = {"GPL-2.0-only", "LGPL-2.1-only", "LGPL-2.0-only"}
GPL2_PLUS = {"GPL-2.0-or-later", "LGPL-2.1-or-later", "LGPL-2.0-or-later"}
GPL2 = {"GPL-2.0-only", "GPL-2.0-or-later"}
GPL3 = {"GPL-3.0-only", "GPL-3.0-or-later"}
AGPL3 = {"AGPL-3.0-only", "AGPL-3.0-or-later"}
LGPL3 = {"LGPL-3.0-only", "LGPL-3.0-or-later"}
GPL_FAMILY_PREFIX = ("GPL-", "LGPL-", "AGPL-")
ADVERTISING = {"BSD-4-Clause", "OpenSSL", "Apache-1.1"}
HARD_WEAK = {"EPL-1.0", "CDDL-1.0", "CDDL-1.1", "CPL-1.0", "MPL-1.1"}
SHARE_ALIKE = {"OFL-1.1", "Artistic-2.0", "CC-BY-SA-4.0"}

NETWORK_NOTE = (
    "AGPL/SSPL network clause: if users interact with the software over a network you must offer "
    "them the corresponding source, even if you never distribute copies. Check this before using it in a service."
)


@dataclass
class Result:
    verdict: str
    rule: str
    reason: str
    notes: list[str] = field(default_factory=list)


def _in_gpl_family(i: str) -> bool:
    return i.startswith(GPL_FAMILY_PREFIX)


def check_terms(p: Term, d: Term) -> Result:
    """Dependency term d into project term p."""
    dc = L.category_of(d.id, d.exception)
    pc = L.category_of(p.id, p.exception)
    pid, did = p.id, d.id
    notes: list[str] = []
    if did in AGPL3 or did == "SSPL-1.0" or pid in AGPL3 or pid == "SSPL-1.0":
        notes.append(NETWORK_NOTE)

    def res(v: str, rule: str, why: str) -> Result:
        return Result(v, rule, why, notes)

    proj_prop = pid == "LicenseRef-Proprietary"
    if dc is None or dc == L.PROPRIETARY:
        why = "the dependency's license is not recognised" if dc is None else \
            "proprietary dependency terms are in your contract, not in a public license"
        return res(UNKNOWN, "R0", why)
    if pc is None:
        return res(UNKNOWN, "R0", f"the project license {p} is not in the table")

    # R1 Apache-2.0
    if did == "Apache-2.0":
        if pid in GPL2_ONLY:
            return res(INCOMPATIBLE, "R1", "Apache-2.0's patent-termination and indemnity terms are extra restrictions "
                       "under GPLv2 (FSF: Apache-2.0 is compatible with GPLv3 only)")
        if pid in GPL2_PLUS:
            return res(CONDITIONAL, "R1", "Apache-2.0 works with GPL-3.0, so the combined work must be distributed "
                       "under GPL-3.0 (or LGPL-3.0), which an 'or later' project license allows")
        return res(COMPATIBLE, "R1", "Apache-2.0 is permissive; keep its notices and NOTICE file")

    # R2 permissive / public domain
    if dc in (L.PERMISSIVE, L.PUBLIC_DOMAIN):
        if did in ADVERTISING and _in_gpl_family(pid):
            return res(INCOMPATIBLE, "R2", f"{did} has an advertising clause that is a further restriction under the GPL")
        return res(COMPATIBLE, "R2", f"{did} is permissive: it can go into any project, keeping its notices"
                   if dc == L.PERMISSIVE else f"{did} is a public-domain-style dedication")

    # R3 MPL-2.0
    if did == "MPL-2.0":
        if _in_gpl_family(pid):
            return res(COMPATIBLE, "R3", "MPL-2.0 section 3.3 lets MPL code be combined into GPL/LGPL/AGPL works "
                       "(unless the file carries an 'Incompatible With Secondary Licenses' notice)")
        if pid == "MPL-2.0":
            return res(COMPATIBLE, "R3", "same license")
        return res(CONDITIONAL, "R3", "MPL-2.0 is file-level copyleft: keep MPL files under the MPL (with source) "
                   "and your own files can stay under your license")

    # R4 LGPL (no exception handling needed: LGPL is already weak copyleft)
    if did.startswith("LGPL-"):
        is_gplish = _in_gpl_family(pid)
        if not is_gplish:
            return res(CONDITIONAL, "R4", "LGPL allows use from any program if users can replace the library: link "
                       "dynamically or ship object files, publish library changes, and keep notices")
        if did in LGPL3:
            if pid in GPL3 | AGPL3 | LGPL3:
                return res(COMPATIBLE, "R4", "LGPL-3.0 is GPL-3.0 plus extra permissions")
            if pid in GPL2_PLUS:
                return res(CONDITIONAL, "R4", "LGPL-3.0 needs the combined work to be GPL-3.0; allowed by an 'or later' project")
            return res(INCOMPATIBLE, "R4", "LGPL-3.0 cannot go into a GPL-2.0-only / LGPL-2.1-only project (version conflict)")
        return res(COMPATIBLE, "R4", "LGPL-2.x section 3 lets the library be converted to the GPL (v2 or newer)")

    # R5 EPL / CDDL / CPL / MPL-1.1
    if did == "EPL-2.0":
        if _in_gpl_family(pid):
            return res(CONDITIONAL, "R5", "EPL-2.0 is GPL-compatible only if the EPL code designates the GPL as a "
                       "Secondary License; check the code")
        if pid == "EPL-2.0":
            return res(COMPATIBLE, "R5", "same license")
        return res(CONDITIONAL, "R5", "EPL-2.0 is module-level copyleft: changes to EPL modules stay EPL")
    if did in HARD_WEAK:
        if _in_gpl_family(pid):
            return res(INCOMPATIBLE, "R5", f"{did} has terms (copyleft scope / patent clause) the GPL cannot absorb")
        if pid == did:
            return res(COMPATIBLE, "R5", "same license")
        return res(CONDITIONAL, "R5", f"{did} is file/module-level copyleft: changes to its files stay under {did}")

    # R6 share-alike content licenses
    if did in SHARE_ALIKE:
        if did == "CC-BY-SA-4.0" and (pid in GPL3 or pid in AGPL3):
            return res(COMPATIBLE, "R6", "Creative Commons declares CC BY-SA 4.0 one-way compatible with GPL-3.0")
        if pid == did:
            return res(COMPATIBLE, "R6", "same license")
        return res(CONDITIONAL, "R6", f"{did} is share-alike for the covered material (and was not written for software)")

    # R7 GPL
    if did.startswith("GPL-"):
        if dc == L.WEAK:  # GPL with a linking exception
            if proj_prop or (pc in (L.PERMISSIVE, L.PUBLIC_DOMAIN, L.WEAK) and not _in_gpl_family(pid)):
                return res(CONDITIONAL, "R7", f"GPL with {d.exception}: linking is allowed, but changes to the "
                           "GPL-covered code itself stay GPL")
        if did == "GPL-2.0-only":
            if pid == "GPL-2.0-only":
                return res(COMPATIBLE, "R7", "same license")
            if pid == "GPL-2.0-or-later":
                return res(CONDITIONAL, "R7", "GPL-2.0-only code cannot be upgraded: the combined work must be GPL-2.0-only")
            return res(INCOMPATIBLE, "R7", "GPL-2.0-only cannot be combined into a project under a different license")
        if did == "GPL-2.0-or-later":
            if pid in GPL2 | GPL3 | AGPL3:
                return res(COMPATIBLE, "R7", "GPL-2.0-or-later can be used under GPL-2.0 or GPL-3.0")
            return res(INCOMPATIBLE, "R7", "GPL code makes the combined work GPL; the project license does not allow that")
        if did in GPL3:
            if pid in GPL3 | AGPL3:
                return res(COMPATIBLE, "R7", "GPL-3.0 code can go into GPL-3.0 and (via section 13) AGPL-3.0 projects")
            if pid == "GPL-2.0-or-later":
                return res(CONDITIONAL, "R7", "the combined work must be distributed as GPL-3.0")
            return res(INCOMPATIBLE, "R7", "GPL-3.0 code makes the combined work GPL-3.0; the project license does not allow that")
        return res(UNKNOWN, "R7", f"{did} is a GPL version this table does not cover")

    # R8 AGPL
    if dc == L.NETWORK:
        if pid in AGPL3:
            return res(COMPATIBLE, "R8", "same license family")
        if pid in GPL3:
            return res(CONDITIONAL, "R8", "GPL-3.0 section 13 allows combining with AGPL-3.0, but the AGPL network "
                       "clause then applies to the combined work")
        return res(INCOMPATIBLE, "R8", "AGPL code makes the combined work AGPL-3.0; the project license does not allow that")

    # R9 source-available
    if dc == L.SOURCE_AVAILABLE:
        if proj_prop:
            return res(CONDITIONAL, "R9", f"{did} is not open source: whether your use is allowed depends on its "
                       "own terms (competing-service, production-use or license-key restrictions)")
        return res(INCOMPATIBLE, "R9", f"{did} is not open source and cannot be relicensed under an open-source project license")

    # R10 non-commercial
    if dc == L.NONCOMMERCIAL:
        if pc == L.NONCOMMERCIAL:
            return res(CONDITIONAL, "R10", "both are non-commercial; check ShareAlike/NoDerivatives terms")
        return res(INCOMPATIBLE, "R10", f"{did} forbids commercial use; the project license allows it")

    # R11 restricted
    if dc == L.RESTRICTED:
        return res(CONDITIONAL, "R11", f"{did} carries a field-of-use or no-derivatives restriction; get legal review")

    return res(UNKNOWN, "R12", f"the table has no rule for {did} into {pid}")


def _flatten(node: Node) -> list[Term]:
    return spdx.terms(node)


def best_of(results: list[Result]) -> Result:
    return min(results, key=lambda r: _BAD[r.verdict])


def worst_of(results: list[Result]) -> Result:
    return max(results, key=lambda r: _BAD[r.verdict])


def eval_dep(project_term: Term, dep: Node) -> Result:
    """Dependency expression into one project term: OR picks the best option, AND the worst."""
    if isinstance(dep, Term):
        return check_terms(project_term, dep)
    parts = [eval_dep(project_term, c) for c in dep.items]
    pick = best_of(parts) if dep.op == "OR" else worst_of(parts)
    out = Result(pick.verdict, pick.rule, pick.reason, list(pick.notes))
    if dep.op == "OR" and len(parts) > 1:
        out.reason = f"best option of ({spdx.render(dep)}): {pick.reason}"
    return out


def evaluate(project: Node, dep: Node) -> Result:
    """The full answer: the dependency must work with every project license option."""
    results = [eval_dep(t, dep) for t in _flatten(project)]
    pick = worst_of(results)
    out = Result(pick.verdict, pick.rule, pick.reason, [])
    for r in results:
        for n in r.notes:
            if n not in out.notes:
                out.notes.append(n)
    if len(results) > 1 and isinstance(project, Compound):
        out.notes.append(
            "the project is offered under several licenses; the dependency must work with every one of them "
            "because recipients may choose any"
        )
    return out


def parse_side(text: str, what: str) -> Normalized:
    from .errors import LicenseError

    n = normalize(text)
    if n.unknown:
        raise LicenseError(
            f"cannot interpret {what} {text!r} as a license ({'; '.join(n.notes)}). "
            "Use an SPDX id or expression such as 'MIT', 'GPL-3.0-only', 'Apache-2.0 OR MIT', or 'proprietary'."
        )
    return n
