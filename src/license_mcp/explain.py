"""explain_license: plain-words permissions / conditions / limitations from the embedded table."""

from __future__ import annotations

from . import licenses as L
from . import spdx
from .normalize import normalize

CATEGORY_NOTES = {
    L.PUBLIC_DOMAIN: "Public-domain style: essentially no conditions.",
    L.PERMISSIVE: "Permissive: you can include it in closed-source products; just meet the listed conditions.",
    L.WEAK: "Weak copyleft: changes to this component itself must be shared, but code that merely uses it "
            "(for example by linking) can keep its own license, subject to the license's linking terms.",
    L.STRONG: "Strong copyleft: a product that includes or is combined with it and is distributed generally must "
              "be offered as a whole under the same license, with source.",
    L.NETWORK: "Network copyleft: like strong copyleft, and also triggered by letting users interact with a modified "
               "version over a network (a hosted service), even without distributing copies.",
    L.SOURCE_AVAILABLE: "Source-available, NOT open source: you can read the code, but there are significant use "
                        "restrictions. Read the license carefully before using it commercially.",
    L.NONCOMMERCIAL: "Non-commercial: commercial use is prohibited. Not suitable for products you sell or use for business.",
    L.RESTRICTED: "Restricted: carries a field-of-use or no-derivatives restriction. Needs legal review.",
    L.PROPRIETARY: "Proprietary: no open-source rights are granted; your rights come from a separate agreement.",
}


def _term(t: spdx.Term) -> list[str]:
    out: list[str] = []
    info = L.info(t.id)
    if info is None:
        cat = L.category_of(t.id, t.exception)
        out.append(f"{t} - not in the built-in table of ~50 common licenses.")
        if cat:
            out.append(f"  By its family it is: {cat}. {CATEGORY_NOTES[cat]}")
        else:
            out.append("  I will not guess its terms. Look it up at https://spdx.org/licenses/ and read the license text.")
        return out
    cat = L.category_of(t.id, t.exception) or info.category
    out.append(f"{info.name} ({info.id}{'+' if t.plus else ''}) - category: {cat}")
    out.append(f"  In short: {info.summary}")
    if t.plus:
        out.append("  The '+' means 'this version or any later version' is also allowed.")
    out.append(f"  You can: {', '.join(info.permissions)}")
    out.append("  You must: " + (", ".join(info.conditions) if info.conditions else "nothing in particular"))
    out.append(f"  Limits: {', '.join(info.limitations) if info.limitations else 'see the license text'}")
    out.append(f"  Notice/attribution needed when you distribute: {'yes' if info.attribution else 'no'}")
    if t.exception:
        text = L.EXCEPTIONS.get(t.exception)
        if text:
            out.append(f"  Exception {t.exception}: {text[0]}")
            if text[1] and info.category == L.STRONG:
                out.append("  With this linking-type exception it behaves like weak copyleft for code that links to it.")
        else:
            out.append(f"  Exception {t.exception}: not in the built-in table; read its text.")
    out.append(f"  {CATEGORY_NOTES[cat]}")
    return out


def explain(text: str) -> str:
    n = normalize(text)
    if n.node is None:
        return (
            f"Cannot interpret {text!r} as a license ({'; '.join(n.notes)}). "
            "Pass an SPDX id such as 'MIT', 'Apache-2.0', 'GPL-3.0-only' or an expression like 'MIT OR Apache-2.0'."
        )
    lines: list[str] = []
    if n.expression != text.strip():
        lines.append(f"Read {text!r} as SPDX: {n.expression}" + (" (approximate - confirm)" if n.approximate else ""))
    terms = spdx.terms(n.node)
    if len(terms) > 1:
        lines.append(f"This is a compound expression ({n.expression}): AND means all of them apply, OR means the "
                     "licensee may pick one.")
    for t in terms:
        lines += _term(t)
        lines.append("")
    lines.append("These are concise hand-written summaries, not the license texts, and are guidance, not legal advice; "
                 "read the actual license for anything that matters.")
    return "\n".join(lines)
