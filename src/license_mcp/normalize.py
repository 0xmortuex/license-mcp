"""Turn the messy license strings found in package metadata into SPDX expressions.

Real metadata contains 'MIT License', 'Apache 2', 'GPLv2+', 'BSD', 'MIT/Apache-2.0',
trove classifiers ('License :: OSI Approved :: ...'), placeholders ('UNKNOWN') and even
whole license texts. The rules here are explicit and conservative:

* an exact or deprecated SPDX id is fixed up (case, GPL-2.0 -> GPL-2.0-only);
* well-known spellings map through documented rules;
* a spelling that is genuinely ambiguous (plain 'BSD', 'Apache Software License') is
  mapped to the overwhelmingly common reading and flagged ``approximate``;
* anything else is UNKNOWN. Nothing is guessed from a license's text.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from . import licenses as L
from . import spdx
from .errors import SpdxError
from .spdx import Compound, Node, Term

PLACEHOLDERS = {
    "", "unknown", "none", "n/a", "na", "null", "undefined", "other", "custom", "tbd", "todo",
    "see license", "see licence", "see file", "license", "licence", "various", "multiple",
}
PROPRIETARY_WORDS = {
    "proprietary", "commercial", "closed", "closed source", "all rights reserved", "private",
    "proprietary license", "commercial license", "unlicensed",
}
MAX_RAW = 400  # longer text is a pasted license body, not an identifier


@dataclass
class Normalized:
    raw: str
    node: Node | None
    notes: list[str] = field(default_factory=list)
    approximate: bool = False

    @property
    def unknown(self) -> bool:
        return self.node is None

    @property
    def expression(self) -> str | None:
        return spdx.render(self.node) if self.node is not None else None

    def display(self) -> str:
        return self.expression or "UNKNOWN"


def _unknown(raw: str, why: str) -> Normalized:
    return Normalized(raw, None, [why])


_ID_LIKE = re.compile(r"[A-Za-z][A-Za-z0-9.]*(?:-[A-Za-z0-9.]+)+")
# Real SPDX ids of the GPL family and the CC non-commercial family (versions that exist).
_FAMILY_ID = re.compile(
    r"(?:GPL-(?:1\.0|2\.0|3\.0)|LGPL-(?:2\.0|2\.1|3\.0)|AGPL-(?:1\.0|3\.0))-(?:only|or-later)"
    r"|CC-BY-NC(?:-SA|-ND)?-[1-4]\.0"
)
_APPROX = "ambiguous spelling: the reading used is the most likely one, please confirm"
_FAMILY_PREFIX = ("GPL-", "LGPL-", "AGPL-", "CC-BY-NC")


def _recognized(id: str) -> bool:
    if id in L.TABLE or id.startswith("LicenseRef-") or ":LicenseRef-" in id or _FAMILY_ID.fullmatch(id):
        return True
    # a well-formed id we have no table entry for (kept, reported as unclassified) - but never a
    # GPL/CC-NC-looking id that does not exist (GPL-9.9) or is only a deprecated spelling (GPL-2)
    return (
        bool(_ID_LIKE.fullmatch(id))
        and any(c.isdigit() for c in id)
        and not id.startswith(_FAMILY_PREFIX)
    )


def _fix_term(t: Term, notes: list[str]) -> Term | None:
    """Canonicalise one SPDX term; None if it is not a recognisable license id."""
    ident, plus, exc = t.id, t.plus, t.exception
    if t.is_ref:
        return t
    case = L.canonical_case(ident)
    if case is not None and case != ident:
        notes.append(f"fixed case of {ident!r} -> {case!r}")
        ident = case
    if ident in L.DEPRECATED_WITH_EXCEPTION:
        new, e = L.DEPRECATED_WITH_EXCEPTION[ident]
        notes.append(f"{ident} is deprecated; read as {new} WITH {e}")
        ident, exc = new, e
    if plus and f"{ident}+" in L.DEPRECATED:
        new = L.DEPRECATED[f"{ident}+"]
        notes.append(f"{ident}+ is deprecated; read as {new}")
        ident, plus = new, False
    elif ident in L.DEPRECATED:
        new = L.DEPRECATED[ident]
        notes.append(f"{ident} is deprecated; read as {new}")
        ident = new
    if exc is not None:
        ec = L.canonical_case(exc)
        if ec is not None and ec != exc:
            exc = ec
    if not (ident in L.TABLE or _FAMILY_ID.fullmatch(ident)) and not t.is_ref:
        # not an exact SPDX id: maybe a short spelling like 'GPL-2' or 'BSD-3'
        alt, approx = _single(ident + ("+" if plus else ""), notes)
        if alt is not None:
            if approx:
                notes.append(_APPROX)
            notes.append(f"{ident} is not an exact SPDX id; read as {alt}")
            return Term(alt.id, alt.plus, exc or alt.exception)
    if not _recognized(ident):
        return None
    return Term(ident, plus, exc)


def _fix_tree(node: Node, notes: list[str]) -> Node | None:
    if isinstance(node, Term):
        return _fix_term(node, notes)
    items: list[Node] = []
    for c in node.items:
        f = _fix_tree(c, notes)
        if f is None:
            return None
        items.append(f)
    return Compound(node.op, tuple(items))


# ------------------------------------------------------------------ messy single names

_NUM = re.compile(r"(?<![\d.])(\d)(?:\.(\d))?(?![\d])")


def _version(s: str) -> str | None:
    m = _NUM.search(s)
    if not m:
        return None
    return f"{m.group(1)}.{m.group(2) or '0'}"


def _tokens(s: str) -> list[str]:
    return re.findall(r"[a-z0-9.+]+", s.lower().replace("_", " ").replace("-", " "))


def _gpl_family(s: str, low: str, notes: list[str]) -> Term | None:
    """GPLv2, GPL-3.0+, GNU Lesser General Public License v2.1 or later, AGPL 3 ..."""
    if "affero" in low or re.search(r"\bagpl", low):
        fam = "AGPL"
    elif "lesser" in low or "library general" in low or re.search(r"\blgpl", low):
        fam = "LGPL"
    elif "general public" in low or re.search(r"\bgpl", low):
        fam = "GPL"
    else:
        return None
    ver = _version(low)
    if ver is None:
        notes.append(f"{fam} named without a version; cannot choose a SPDX id")
        return None
    later = "+" in s or bool(re.search(r"\bor[\s-]*(any\s+)?(later|newer|higher)|\blater\b|\bplus\b", low))
    only = bool(re.search(r"\bonly\b", low))
    if later and only:
        notes.append("both 'only' and 'or later' appear; read as 'only' (the stricter)")
        later = False
    ver_ok = {"GPL": {"1.0", "2.0", "3.0"}, "LGPL": {"2.0", "2.1", "3.0"}, "AGPL": {"1.0", "3.0"}}[fam]
    if fam == "LGPL" and ver == "2.0" and not re.search(r"2\.0", low):
        notes.append("'LGPL v2' is ambiguous between LGPL-2.0 and LGPL-2.1; read as LGPL-2.0")
    if ver not in ver_ok:
        notes.append(f"{fam} version {ver} does not exist")
        return None
    exc = "Classpath-exception-2.0" if "classpath" in low else None
    return Term(f"{fam}-{ver}-{'or-later' if later else 'only'}", False, exc)


_CC = re.compile(r"\bcc[\s-]*by((?:[\s-]*(?:nc|sa|nd))*)[\s-]*(\d\.\d)\b")

_EXACT: dict[str, str] = {
    "mit": "MIT", "expat": "MIT", "mit expat": "MIT", "mit x11": "MIT",
    "mit 0": "MIT-0", "mit no attribution": "MIT-0",
    "isc": "ISC", "iscl": "ISC", "isc license iscl": "ISC",
    "zlib": "Zlib", "zlib libpng": "Zlib", "unlicense": "Unlicense", "the unlicense": "Unlicense",
    "the unlicense unlicense": "Unlicense", "cc0": "CC0-1.0", "cc0 1.0": "CC0-1.0", "cc0 1.0 universal": "CC0-1.0",
    "0bsd": "0BSD", "wtfpl": "WTFPL", "bsl 1.0": "BSL-1.0", "boost": "BSL-1.0",
    "boost software 1.0": "BSL-1.0", "boost software 1.0 bsl 1.0": "BSL-1.0",
    "psf": "PSF-2.0", "psf 2.0": "PSF-2.0", "python software foundation": "PSF-2.0",
    "python software foundation 2.0": "PSF-2.0", "python 2.0": "Python-2.0", "python": "Python-2.0",
    "postgresql": "PostgreSQL", "ncsa": "NCSA", "x11": "X11", "hpnd": "HPND", "openssl": "OpenSSL",
    "blue oak 1.0.0": "BlueOak-1.0.0", "blueoak 1.0.0": "BlueOak-1.0.0",
    "artistic 2.0": "Artistic-2.0", "artistic 2": "Artistic-2.0", "ofl 1.1": "OFL-1.1",
    "sil open font 1.1": "OFL-1.1", "sil ofl 1.1": "OFL-1.1", "eupl 1.2": "EUPL-1.2",
    "european union public 1.2": "EUPL-1.2", "european union public 1.2 eupl 1.2": "EUPL-1.2",
    "sspl 1.0": "SSPL-1.0", "server side public 1.0": "SSPL-1.0", "busl 1.1": "BUSL-1.1",
    "business source 1.1": "BUSL-1.1", "elastic 2.0": "Elastic-2.0", "json": "JSON",
    "cpl 1.0": "CPL-1.0", "common public 1.0": "CPL-1.0",
}
_DROP = {"license", "licence", "licensed", "the", "version", "ver", "v", "terms", "of"}
_FAMILIES = [
    r"\bmit\b", r"apache", r"\bbsd", r"gpl|general public|lesser|affero", r"mozilla|\bmpl\b",
    r"eclipse|\bepl\b", r"\bisc\b", r"zlib", r"unlicense", r"\bcc0\b|\bcc[\s-]by", r"\bpsf\b|python software",
    r"boost|\bbsl\b",
]


def _single(s: str, notes: list[str]) -> tuple[Term | None, bool]:
    """Resolve one messy license name -> (term, approximate)."""
    low = s.lower().strip()
    if sum(1 for f in _FAMILIES if re.search(f, low)) > 1:
        return None, False  # names several licenses: let the caller split it
    toks = _tokens(low)
    gpl = _gpl_family(s, low, notes)
    if gpl is not None:
        return gpl, False
    if re.search(r"\b(a|l)?gpl|general public|lesser|affero", low):
        return None, False  # a GPL-family name with no usable version
    outside = re.sub(r"\([^)]*\)", " ", low)
    inside = " ".join(re.findall(r"\(([^)]*)\)", low))
    for text in (low, outside, inside):
        k = " ".join(t for t in _tokens(text) if t not in _DROP)
        k = re.sub(r"\b(\S+) \1\b", r"\1", k)  # 'mit license (mit)' -> 'mit mit' -> 'mit'
        if k in _EXACT:
            return Term(_EXACT[k]), False
    m = _CC.search(low)
    if m:
        suffix = "".join("-" + x.upper() for x in re.findall(r"nc|sa|nd", m.group(1)))
        cid = f"CC-BY{suffix}-{m.group(2)}"
        return Term(cid), False
    if "mozilla" in toks or "mpl" in toks:
        v = _version(low)
        if v in ("2.0", "1.1"):
            return Term(f"MPL-{v}"), False
        notes.append("MPL named without a usable version")
        return None, False
    if "eclipse" in toks or "epl" in toks:
        v = _version(low)
        if v in ("1.0", "2.0"):
            return Term(f"EPL-{v}"), False
        return None, False
    if "cddl" in toks or "common development" in low:
        v = _version(low)
        return (Term(f"CDDL-{v}"), False) if v in ("1.0", "1.1") else (None, False)
    if "apache" in toks or "apache2" in toks or "apache2.0" in toks:
        v = _version(low)
        if "apache2" in toks:
            v = "2.0"
        if v in ("2.0", "1.1", "1.0"):
            return Term(f"Apache-{v}"), False
        if v is None:
            notes.append(
                "'Apache' without a version; read as Apache-2.0, the version in use by nearly every project"
            )
            return Term("Apache-2.0"), True
        return None, False
    if any("bsd" in t for t in toks):
        return _bsd(low, toks, notes)
    return None, False


def _bsd(low: str, toks: list[str], notes: list[str]) -> tuple[Term | None, bool]:
    if "0bsd" in toks or ("zero" in toks and "clause" in toks):
        return Term("0BSD"), False
    n: str | None = None
    m = re.search(r"\b([1234])[\s-]*clause|\bbsd[\s-]*([234])\b|\bbsd([234])\b", low)
    if m:
        n = next(g for g in m.groups() if g)
    elif re.search(r"simplified|freebsd|two[\s-]clause", low):
        n = "2"
    elif re.search(r"\bnew\b|revised|modified|three[\s-]clause", low):
        n = "3"
    elif re.search(r"original|four[\s-]clause", low):
        n = "4"
    if n in ("2", "3", "4"):
        return Term(f"BSD-{n}-Clause"), False
    notes.append("plain 'BSD' is ambiguous (2-clause or 3-clause); read as BSD-3-Clause, the most common")
    return Term("BSD-3-Clause"), True


# ------------------------------------------------------------------ top level

_SPLIT_STRONG = re.compile(r"\s+or\s+|\s*/\s*|\s+and\s+|\s*&\s*|\s*;\s*", re.IGNORECASE)
_COMMA = re.compile(r"\s*,\s*")


def _part(s: str, notes: list[str]) -> tuple[Node | None, bool]:
    s = s.strip()
    if s.startswith("(") and s.endswith(")") and s.count("(") == 1:
        s = s[1:-1].strip()
    if not s:
        return None, False
    try:
        node = spdx.parse(s)
    except SpdxError:
        node = None
    if node is not None:
        fixed = _fix_tree(node, notes)
        if fixed is not None and not _is_bare_word(node):
            return fixed, _APPROX in notes
    term, approx = _single(s, notes)
    return term, approx


def _is_bare_word(node: Node) -> bool:
    """'Apache', 'BSD', 'Proprietary' parse as SPDX ids but are not: demand a hyphen+digit or a table hit."""
    if isinstance(node, Term):
        return not _recognized(node.id) and not L.canonical_case(node.id)
    return False


def _split_compound(s: str, notes: list[str], comma: bool) -> tuple[Node | None, bool]:
    if not comma and re.search(r"\bor[\s-]+(any\s+)?(later|newer|higher)", s, re.IGNORECASE):
        return None, False  # 'v2 or later' is one license, not an OR of two
    for pat, default_op in (((_COMMA, "AND"),) if comma else ((_SPLIT_STRONG, None),)):
        parts = pat.split(s)
        if len(parts) < 2:
            continue
        seps = [m.group(0).strip().lower() for m in pat.finditer(s)]
        resolved: list[Node] = []
        approx = False
        for p in parts:
            n, a = _part(p, notes)
            if n is None:
                break
            resolved.append(n)
            approx = approx or a
        else:
            if default_op is None:
                ops = {"AND" if sp in ("and", "&", ";") else "OR" for sp in seps}
                if len(ops) > 1:
                    notes.append("mixed 'and'/'or' separators cannot be ordered reliably")
                    return None, False
                op = ops.pop()
                if any(sp == "/" for sp in seps):
                    notes.append("'/' read as OR (the npm/Cargo convention)")
                if ";" in seps:
                    notes.append("';' read as AND (the conservative reading)")
            else:
                op = default_op
                notes.append("comma-separated licenses read as AND (the conservative reading)")
            return spdx._make(op, resolved), approx
    return None, False


_CLASSIFIER_PREFIX = "license ::"


def normalize(raw: str | None) -> Normalized:
    """Normalise any license string to an SPDX expression, or UNKNOWN with the reason."""
    if raw is None:
        return _unknown("", "no license information")
    s = " ".join(raw.split())
    if len(s) > MAX_RAW or "\n" in raw.strip():
        return _unknown(
            s[:60] + "...",
            "the license field holds long text (probably a pasted license body), not an identifier",
        )
    low = s.lower()
    if low in PLACEHOLDERS or low.startswith("see license") or low.startswith("see licence") \
            or low.startswith("see file") or low.startswith("see the "):
        return _unknown(s, f"placeholder value {s!r}: the package does not say which license it uses")
    if low in PROPRIETARY_WORDS:
        n = Normalized(s, Term("LicenseRef-Proprietary"))
        n.notes.append(f"{s!r} read as proprietary / no open-source license granted")
        return n
    if low in ("public domain", "public-domain", "publicdomain"):
        return Normalized(s, Term("LicenseRef-Public-Domain"), ["'public domain' without a dedication text"])
    if low.startswith(_CLASSIFIER_PREFIX):
        return _classifier(s)

    notes: list[str] = []
    # 1. a real SPDX expression (possibly with deprecated ids)
    try:
        node: Node | None = spdx.parse(s)
    except SpdxError:
        node = None
    if node is not None and not _is_bare_word(node):
        fixed = _fix_tree(node, notes)
        if fixed is not None:
            if spdx.render(fixed) != s:
                notes.insert(0, f"normalised {s!r} to {spdx.render(fixed)!r}")
            return Normalized(s, fixed, notes, _APPROX in notes)
    # 2. several licenses joined by or/and/slash (only if every part resolves)
    trial: list[str] = []
    node1, approx1 = _split_compound(s, trial, comma=False)
    if node1 is not None:
        notes.extend(trial)
        notes.insert(0, f"read {s!r} as {spdx.render(node1)}")
        return Normalized(s, node1, notes, approx1)
    # 3. one messy name
    term, approx = _single(s, notes)
    if term is not None:
        notes.insert(0, f"read {s!r} as {term}")
        return Normalized(s, term, notes, approx)
    # 4. comma-separated list
    node2, approx2 = _split_compound(s, notes, comma=True)
    if node2 is not None:
        notes.insert(0, f"read {s!r} as {spdx.render(node2)}")
        return Normalized(s, node2, notes, approx2)
    notes.append(f"unrecognised license string {s!r}")
    return Normalized(s, None, notes)


def _classifier(s: str) -> Normalized:
    parts = [p.strip() for p in s.split("::")]
    tail = parts[-1] if parts else ""
    low = tail.lower()
    if low in ("osi approved", "license", "") or low.startswith("freely distributable") \
            or low.startswith("free for") or low.startswith("free to"):
        return _unknown(s, f"classifier {s!r} does not name a specific license")
    if "other/proprietary" in low or low == "proprietary":
        return Normalized(s, Term("LicenseRef-Proprietary"), ["classifier says other/proprietary"])
    if low == "public domain":
        return Normalized(s, Term("LicenseRef-Public-Domain"), ["classifier says public domain"])
    if low.startswith("dfsg approved"):
        return _unknown(s, "the DFSG classifier does not name a license")
    notes: list[str] = []
    term, approx = _single(tail, notes)
    if term is None:
        n = normalize(tail) if not tail.lower().startswith("license ::") else _unknown(s, "unrecognised")
        n.raw = s
        return n
    if low == "apache software license":
        notes.append("the 'Apache Software License' classifier covers every Apache version; read as Apache-2.0")
        approx = True
    notes.insert(0, f"read classifier {tail!r} as {term}")
    return Normalized(s, term, notes, approx)


def combine_all(items: list[Normalized], op: str = "AND") -> Normalized:
    """Combine several normalisations (e.g. several trove classifiers) into one."""
    known = [i for i in items if i.node is not None]
    raw = "; ".join(i.raw for i in items)
    if not items:
        return _unknown("", "no license information")
    if len(known) != len(items):
        out = _unknown(raw, "; ".join(n for i in items if i.node is None for n in i.notes))
        return out
    if len(known) == 1:
        return known[0]
    nodes: list[Node] = [i.node for i in known if i.node is not None]
    # drop duplicates, keep order
    uniq: list[Node] = []
    for n in nodes:
        if n not in uniq:
            uniq.append(n)
    notes = [n for i in known for n in i.notes]
    if len(uniq) == 1:
        return Normalized(raw, uniq[0], notes, any(i.approximate for i in known))
    notes.append(
        "several classifiers/licenses listed without saying AND or OR; combined with AND, the conservative reading"
    )
    return Normalized(raw, spdx._make(op, uniq), notes, any(i.approximate for i in known))
