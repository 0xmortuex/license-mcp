"""Embedded knowledge about the ~50 licenses people actually meet.

This is a concise, hand-written summary table (permissions / conditions / limitations
in plain words) - not the license texts, and not legal advice. Anything not listed
here is reported as 'unclassified' rather than guessed.
"""

from __future__ import annotations

from dataclasses import dataclass

# Categories, from least to most restrictive for a downstream project.
PUBLIC_DOMAIN = "public-domain"
PERMISSIVE = "permissive"
WEAK = "weak-copyleft"
STRONG = "strong-copyleft"
NETWORK = "network-copyleft"
SOURCE_AVAILABLE = "source-available"
NONCOMMERCIAL = "noncommercial"
RESTRICTED = "restricted"
PROPRIETARY = "proprietary"

COPYLEFT_CATEGORIES = {WEAK, STRONG, NETWORK}

_STD_PERMS = ("commercial use", "modification", "distribution", "private use")
_NO_WARRANTY = ("provided without warranty", "authors are not liable")


@dataclass(frozen=True)
class LicenseInfo:
    id: str
    name: str
    category: str
    summary: str
    permissions: tuple[str, ...]
    conditions: tuple[str, ...]
    limitations: tuple[str, ...]
    attribution: bool  # must you reproduce a copyright/license notice when you distribute?


TABLE: dict[str, LicenseInfo] = {}


def _add(
    id: str,
    name: str,
    category: str,
    summary: str,
    conditions: tuple[str, ...] = (),
    limitations: tuple[str, ...] = _NO_WARRANTY,
    permissions: tuple[str, ...] = _STD_PERMS,
    attribution: bool = True,
) -> None:
    TABLE[id] = LicenseInfo(id, name, category, summary, permissions, conditions, limitations, attribution)


_NOTICE = ("keep the copyright and license notice",)

# ---- permissive
_add("MIT", "MIT License", PERMISSIVE,
     "Do almost anything, as long as the copyright and license notice travel with the code.", _NOTICE)
_add("MIT-0", "MIT No Attribution", PERMISSIVE,
     "Like MIT but without even the notice requirement.", (), attribution=False)
_add("Apache-2.0", "Apache License 2.0", PERMISSIVE,
     "Permissive, with an explicit patent grant (which ends if you sue over patents) and a NOTICE-file convention.",
     ("keep the license and copyright notices", "state significant changes", "carry over the NOTICE file",
      "patent license terminates if you start patent litigation over the work"),
     ("provided without warranty", "authors are not liable", "no trademark rights"),
     _STD_PERMS + ("patent use",))
_add("Apache-1.1", "Apache License 1.1", PERMISSIVE,
     "Older Apache license: permissive, with an advertising-style acknowledgement and name restrictions.",
     ("keep notices", "acknowledge Apache in documentation", "do not use the Apache name to endorse"))
_add("BSD-2-Clause", 'BSD 2-Clause "Simplified" License', PERMISSIVE,
     "Permissive; keep the notice in source and binary distributions.", _NOTICE)
_add("BSD-3-Clause", 'BSD 3-Clause "New" or "Revised" License', PERMISSIVE,
     "Permissive; keep the notice, and do not use the authors' names to endorse your product.",
     _NOTICE + ("no use of the authors' names for endorsement",))
_add("BSD-4-Clause", 'BSD 4-Clause "Original" License', PERMISSIVE,
     "Permissive, but with the obnoxious advertising clause, which makes it incompatible with the GPL.",
     _NOTICE + ("advertising materials must acknowledge the authors", "no endorsement"))
_add("ISC", "ISC License", PERMISSIVE, "Functionally the same as MIT/BSD-2-Clause in fewer words.", _NOTICE)
_add("Zlib", "zlib License", PERMISSIVE,
     "Permissive; do not misrepresent the origin, mark altered source, keep the notice in source.",
     ("do not claim you wrote the original", "mark altered versions", "keep the notice in source distributions"))
_add("PostgreSQL", "PostgreSQL License", PERMISSIVE, "MIT-style permissive license.", _NOTICE)
_add("NCSA", "University of Illinois/NCSA Open Source License", PERMISSIVE,
     "Permissive, BSD-like with a documentation acknowledgement.", _NOTICE)
_add("X11", "X11 License", PERMISSIVE, "MIT-style permissive license with a no-endorsement clause.", _NOTICE)
_add("HPND", "Historical Permission Notice and Disclaimer", PERMISSIVE,
     "Permissive; keep the notice and do not use the authors' names in advertising.", _NOTICE)
_add("BSL-1.0", "Boost Software License 1.0", PERMISSIVE,
     "Permissive; the notice is only required with source distributions, not compiled binaries.",
     ("keep the notice in source distributions",))
_add("PSF-2.0", "Python Software Foundation License 2.0", PERMISSIVE,
     "Permissive license of the Python ecosystem.", _NOTICE)
_add("Python-2.0", "Python License 2.0", PERMISSIVE, "Permissive license used by CPython itself.", _NOTICE)
_add("BlueOak-1.0.0", "Blue Oak Model License 1.0.0", PERMISSIVE,
     "Permissive, with a patent grant and plain-language drafting.", ("pass the license terms on",))
_add("OpenSSL", "OpenSSL License", PERMISSIVE,
     "Permissive with an advertising clause (not GPL-compatible).",
     _NOTICE + ("advertising materials must acknowledge the OpenSSL project",))
_add("CC-BY-4.0", "Creative Commons Attribution 4.0", PERMISSIVE,
     "Permissive for content: reuse freely with attribution. Not designed for software.",
     ("give credit", "indicate changes", "link the license"))

# ---- public domain-like
_add("0BSD", "BSD Zero Clause License", PUBLIC_DOMAIN,
     "Do anything; no conditions at all.", (), attribution=False)
_add("Unlicense", "The Unlicense", PUBLIC_DOMAIN,
     "A public-domain dedication with a fallback license; no conditions.", (), attribution=False)
_add("CC0-1.0", "Creative Commons Zero 1.0", PUBLIC_DOMAIN,
     "A public-domain dedication with a fallback license. Grants no patent or trademark rights.", (),
     ("no patent rights granted", "no trademark rights granted", "provided without warranty"), attribution=False)
_add("WTFPL", "Do What The F*ck You Want To Public License", PUBLIC_DOMAIN,
     "Do whatever you like. Not OSI-approved and legally informal.", (), attribution=False)

# ---- weak copyleft
_add("MPL-2.0", "Mozilla Public License 2.0", WEAK,
     "File-level copyleft: changes to MPL-covered files must be shared under the MPL; your other files stay yours.",
     ("share source of modified MPL files", "keep notices", "state the MPL applies to those files"),
     ("provided without warranty", "no trademark rights"), _STD_PERMS + ("patent use",))
_add("MPL-1.1", "Mozilla Public License 1.1", WEAK,
     "Older file-level copyleft with a patent clause; not compatible with the GPL.",
     ("share source of modified files", "keep notices"))
_add("EPL-1.0", "Eclipse Public License 1.0", WEAK,
     "Module-level copyleft with a patent clause; not compatible with the GPL.",
     ("share source of modifications to the covered module", "keep notices"))
_add("EPL-2.0", "Eclipse Public License 2.0", WEAK,
     "Module-level copyleft; can opt into GPL compatibility through a secondary license.",
     ("share source of modifications to the covered module", "keep notices"))
_add("CDDL-1.0", "Common Development and Distribution License 1.0", WEAK,
     "File-level copyleft derived from the MPL; not compatible with the GPL.",
     ("share source of modified files", "keep notices"))
_add("CDDL-1.1", "Common Development and Distribution License 1.1", WEAK,
     "File-level copyleft derived from the MPL; not compatible with the GPL.",
     ("share source of modified files", "keep notices"))
_add("CPL-1.0", "Common Public License 1.0", WEAK,
     "Predecessor of the EPL: module-level copyleft with a patent clause.",
     ("share source of modifications to the covered module", "keep notices"))
_add("LGPL-2.1-only", "GNU Lesser General Public License v2.1 only", WEAK,
     "Library copyleft: you may link it from any program, but changes to the library itself stay LGPL "
     "and users must be able to swap in a modified library.",
     ("share source of library changes", "allow relinking with a modified library", "keep notices",
      "state changes"))
_add("LGPL-2.1-or-later", "GNU Lesser General Public License v2.1 or later", WEAK,
     "As LGPL-2.1, and you may also follow any later LGPL version.",
     ("share source of library changes", "allow relinking with a modified library", "keep notices"))
_add("LGPL-3.0-only", "GNU Lesser General Public License v3.0 only", WEAK,
     "Library copyleft on top of the GPL-3.0; adds anti-lockdown (installation information) duties and a patent grant.",
     ("share source of library changes", "allow relinking with a modified library",
      "provide installation information for locked-down devices", "keep notices"),
     ("provided without warranty", "authors are not liable"), _STD_PERMS + ("patent use",))
_add("LGPL-3.0-or-later", "GNU Lesser General Public License v3.0 or later", WEAK,
     "As LGPL-3.0, and you may also follow any later LGPL version.",
     ("share source of library changes", "allow relinking with a modified library",
      "provide installation information for locked-down devices", "keep notices"),
     ("provided without warranty", "authors are not liable"), _STD_PERMS + ("patent use",))
_add("Artistic-2.0", "Artistic License 2.0", WEAK,
     "Permissive-leaning: modified versions must be clearly marked and, if you distribute them, made available.",
     ("mark modified versions", "document changes", "keep notices"))
_add("OFL-1.1", "SIL Open Font License 1.1", WEAK,
     "For fonts: use and embed freely; derivatives stay under the OFL; the font cannot be sold on its own.",
     ("keep notices", "derivatives under the OFL", "no sale of the font by itself",
      "no use of reserved font names in modified versions"))
_add("CC-BY-SA-4.0", "Creative Commons Attribution-ShareAlike 4.0", WEAK,
     "Content license: reuse with credit, and share adaptations under the same license. Not designed for software.",
     ("give credit", "indicate changes", "share adaptations under CC BY-SA"))

# ---- strong copyleft
_add("GPL-2.0-only", "GNU General Public License v2.0 only", STRONG,
     "Strong copyleft: if you distribute a combined work, all of it must be offered under GPL-2.0 with source.",
     ("offer complete source under the GPL", "keep notices", "state changes"))
_add("GPL-2.0-or-later", "GNU General Public License v2.0 or later", STRONG,
     "Strong copyleft; the combined work may follow GPL-2.0 or any later version.",
     ("offer complete source under the GPL", "keep notices", "state changes"))
_add("GPL-3.0-only", "GNU General Public License v3.0 only", STRONG,
     "Strong copyleft with a patent grant and anti-lockdown duties; the combined work must be GPL-3.0 with source.",
     ("offer complete source under the GPL", "provide installation information for locked-down devices",
      "keep notices", "state changes"),
     ("provided without warranty", "authors are not liable"), _STD_PERMS + ("patent use",))
_add("GPL-3.0-or-later", "GNU General Public License v3.0 or later", STRONG,
     "As GPL-3.0, and you may also follow any later GPL version.",
     ("offer complete source under the GPL", "provide installation information for locked-down devices",
      "keep notices", "state changes"),
     ("provided without warranty", "authors are not liable"), _STD_PERMS + ("patent use",))
_add("EUPL-1.2", "European Union Public Licence 1.2", STRONG,
     "Strong copyleft with a compatibility list (GPL, AGPL, MPL, EPL...) that lets you relicense to those.",
     ("offer source", "keep notices", "share-alike (or an allowed compatible license)"))

# ---- network copyleft
_add("AGPL-3.0-only", "GNU Affero General Public License v3.0 only", NETWORK,
     "GPL-3.0 plus a network clause: if users interact with a modified version over a network, you must offer them the source.",
     ("offer complete source, including to network users of modified versions", "keep notices", "state changes"),
     ("provided without warranty", "authors are not liable"), _STD_PERMS + ("patent use",))
_add("AGPL-3.0-or-later", "GNU Affero General Public License v3.0 or later", NETWORK,
     "As AGPL-3.0, and you may also follow any later AGPL version.",
     ("offer complete source, including to network users of modified versions", "keep notices", "state changes"),
     ("provided without warranty", "authors are not liable"), _STD_PERMS + ("patent use",))

# ---- source-available (not open source)
_add("SSPL-1.0", "Server Side Public License 1.0", SOURCE_AVAILABLE,
     "Source-available: if you offer the software as a service you must release the source of your whole service stack.",
     ("release the complete service source if you offer it as a service",),
     ("not approved by the OSI", "provided without warranty"))
_add("BUSL-1.1", "Business Source License 1.1", SOURCE_AVAILABLE,
     "Source-available: production use is restricted by an 'Additional Use Grant' until a change date, "
     "after which it converts to an open license.",
     ("production use only as the Additional Use Grant allows", "converts to the change license on the change date"),
     ("not approved by the OSI", "provided without warranty"), ("copy", "modification", "non-production use"))
_add("Elastic-2.0", "Elastic License 2.0", SOURCE_AVAILABLE,
     "Source-available: you may not offer it as a managed service, circumvent license-key functionality, "
     "or remove notices.",
     ("no managed-service offering", "no circumventing license keys", "keep notices"),
     ("not approved by the OSI", "provided without warranty"))

# ---- non-commercial / restricted
_add("CC-BY-NC-4.0", "Creative Commons Attribution-NonCommercial 4.0", NONCOMMERCIAL,
     "Reuse with credit, but NOT for commercial purposes.",
     ("give credit", "no commercial use"), ("commercial use is forbidden", "provided without warranty"),
     ("modification", "distribution", "private use"))
_add("CC-BY-NC-SA-4.0", "Creative Commons Attribution-NonCommercial-ShareAlike 4.0", NONCOMMERCIAL,
     "Reuse with credit, share-alike, NOT for commercial purposes.",
     ("give credit", "no commercial use", "share adaptations under the same license"),
     ("commercial use is forbidden", "provided without warranty"), ("modification", "distribution", "private use"))
_add("CC-BY-NC-ND-4.0", "Creative Commons Attribution-NonCommercial-NoDerivatives 4.0", NONCOMMERCIAL,
     "Share with credit, but no commercial use and no modified versions.",
     ("give credit", "no commercial use", "no derivatives"),
     ("commercial use is forbidden", "modification is forbidden", "provided without warranty"),
     ("distribution", "private use"))
_add("CC-BY-ND-4.0", "Creative Commons Attribution-NoDerivatives 4.0", RESTRICTED,
     "Share with credit, but you may not distribute modified versions.",
     ("give credit", "no derivatives"), ("modification may not be shared", "provided without warranty"),
     ("commercial use", "distribution", "private use"))
_add("JSON", "The JSON License", RESTRICTED,
     "MIT-style but adds 'The Software shall be used for Good, not Evil' - a field-of-use restriction that "
     "is not OSI open source and that many legal teams reject.",
     _NOTICE + ("the software shall be used for Good, not Evil",))

# ---- pseudo-licenses used by normalization
_add("LicenseRef-Proprietary", "Proprietary / all rights reserved", PROPRIETARY,
     "No license to copy or redistribute is granted, or the terms are custom. Read the actual terms.",
     ("whatever the vendor's terms say",), ("no rights beyond those the vendor grants",), (), attribution=False)
_add("LicenseRef-Public-Domain", "Public domain (unspecified)", PUBLIC_DOMAIN,
     "Declared public domain without a specific dedication text. Legally murkier than CC0 or the Unlicense "
     "because public-domain dedication is not recognised everywhere.",
     (), ("legal effect varies by jurisdiction",), attribution=False)

# SPDX ids deprecated in favour of -only / -or-later.
DEPRECATED: dict[str, str] = {
    "GPL-1.0": "GPL-1.0-only", "GPL-1.0+": "GPL-1.0-or-later",
    "GPL-2.0": "GPL-2.0-only", "GPL-2.0+": "GPL-2.0-or-later",
    "GPL-3.0": "GPL-3.0-only", "GPL-3.0+": "GPL-3.0-or-later",
    "LGPL-2.0": "LGPL-2.0-only", "LGPL-2.0+": "LGPL-2.0-or-later",
    "LGPL-2.1": "LGPL-2.1-only", "LGPL-2.1+": "LGPL-2.1-or-later",
    "LGPL-3.0": "LGPL-3.0-only", "LGPL-3.0+": "LGPL-3.0-or-later",
    "AGPL-1.0": "AGPL-1.0-only", "AGPL-1.0+": "AGPL-1.0-or-later",
    "AGPL-3.0": "AGPL-3.0-only", "AGPL-3.0+": "AGPL-3.0-or-later",
    "BSD-2-Clause-FreeBSD": "BSD-2-Clause", "BSD-2-Clause-NetBSD": "BSD-2-Clause",
}

# Deprecated ids that embed an exception: id -> (new id, exception)
DEPRECATED_WITH_EXCEPTION: dict[str, tuple[str, str]] = {
    "GPL-2.0-with-classpath-exception": ("GPL-2.0-only", "Classpath-exception-2.0"),
    "GPL-2.0-with-GCC-exception": ("GPL-2.0-only", "GCC-exception-2.0"),
    "GPL-2.0-with-font-exception": ("GPL-2.0-only", "Font-exception-2.0"),
    "GPL-2.0-with-bison-exception": ("GPL-2.0-only", "Bison-exception-2.2"),
    "GPL-3.0-with-GCC-exception": ("GPL-3.0-only", "GCC-exception-3.1"),
}

# Exceptions: id -> (summary, narrows_copyleft). A linking-type exception turns
# a strong-copyleft base license into something that behaves like weak copyleft.
EXCEPTIONS: dict[str, tuple[str, bool]] = {
    "Classpath-exception-2.0": (
        "GNU Classpath linking exception: code that merely links with the library is not forced under the GPL.", True),
    "GCC-exception-3.1": (
        "GCC Runtime Library Exception: programs compiled with GCC may use its runtime libraries without "
        "becoming GPL.", True),
    "GCC-exception-2.0": ("Older GCC runtime exception: linking against the runtime does not trigger the GPL.", True),
    "Linux-syscall-note": (
        "Linux kernel syscall note: user programs that only use the kernel's syscall interface are not "
        "derivative works.", True),
    "Bison-exception-2.2": ("Parsers generated by Bison may be distributed under any license.", True),
    "Autoconf-exception-3.0": ("Configure scripts generated by Autoconf may be distributed under any license.", True),
    "Font-exception-2.0": ("Documents that merely embed the font are not forced under the GPL.", True),
    "GPL-3.0-linking-exception": ("Allows linking with code under other licenses.", True),
    "LLVM-exception": (
        "LLVM exception to Apache-2.0: compiled object code may be distributed without the Apache notice duties.",
        False),
}


def info(id: str) -> LicenseInfo | None:
    return TABLE.get(id)


def canonical_case(id: str) -> str | None:
    """'apache-2.0' -> 'Apache-2.0', 'gpl-2.0' -> 'GPL-2.0' (case fix only; deprecation handled elsewhere)."""
    low = id.lower()
    for pool in (TABLE, DEPRECATED, DEPRECATED_WITH_EXCEPTION, EXCEPTIONS):
        for k in pool:
            if k.lower() == low:
                return k
    return None


def category_of(id: str, exception: str | None = None) -> str | None:
    """Category of an SPDX id (after deprecation mapping), or None if unclassified.

    Families (GPL-/LGPL-/AGPL- and CC-BY-NC) are classified by prefix because their
    category is the same for every version; other unlisted ids stay unclassified.
    """
    li = TABLE.get(id)
    cat: str | None
    if li is not None:
        cat = li.category
    elif id.startswith("AGPL-"):
        cat = NETWORK
    elif id.startswith("LGPL-"):
        cat = WEAK
    elif id.startswith("GPL-"):
        cat = STRONG
    elif id.startswith("CC-BY-NC"):
        cat = NONCOMMERCIAL
    else:
        cat = None
    if cat == STRONG and exception and EXCEPTIONS.get(exception, ("", False))[1]:
        return WEAK
    return cat


def needs_attribution(id: str) -> bool:
    li = TABLE.get(id)
    return li.attribution if li is not None else True
