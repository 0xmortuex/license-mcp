"""Normalisation of messy license strings: expression, or UNKNOWN. Nothing guessed."""

from __future__ import annotations

import pytest

from license_mcp.normalize import combine_all, normalize

# raw -> (expected SPDX expression, approximate?)
KNOWN = [
    # plain SPDX, case and deprecated-id fixes
    ("MIT", "MIT", False),
    ("mit", "MIT", False),
    ("Apache-2.0", "Apache-2.0", False),
    ("apache-2.0", "Apache-2.0", False),
    ("BSD-3-Clause", "BSD-3-Clause", False),
    ("bsd-2-clause", "BSD-2-Clause", False),
    ("ISC", "ISC", False),
    ("GPL-2.0", "GPL-2.0-only", False),
    ("GPL-2.0+", "GPL-2.0-or-later", False),
    ("GPL-3.0", "GPL-3.0-only", False),
    ("GPL-3.0+", "GPL-3.0-or-later", False),
    ("gpl-3.0-or-later", "GPL-3.0-or-later", False),
    ("LGPL-2.1", "LGPL-2.1-only", False),
    ("LGPL-2.1+", "LGPL-2.1-or-later", False),
    ("LGPL-3.0", "LGPL-3.0-only", False),
    ("AGPL-3.0", "AGPL-3.0-only", False),
    ("AGPL-3.0+", "AGPL-3.0-or-later", False),
    ("GPL-2.0-with-classpath-exception", "GPL-2.0-only WITH Classpath-exception-2.0", False),
    ("GPL-2.0 WITH classpath-exception-2.0", "GPL-2.0-only WITH Classpath-exception-2.0", False),
    ("BSD-2-Clause-FreeBSD", "BSD-2-Clause", False),
    ("MPL-2.0", "MPL-2.0", False),
    ("Unlicense", "Unlicense", False),
    ("CC0-1.0", "CC0-1.0", False),
    ("0BSD", "0BSD", False),
    ("Foo-1.0", "Foo-1.0", False),  # well-formed but not in the table: kept, flagged unclassified later
    ("LicenseRef-Acme", "LicenseRef-Acme", False),
    # expressions
    ("MIT OR Apache-2.0", "MIT OR Apache-2.0", False),
    ("mit or apache-2.0", "MIT OR Apache-2.0", False),
    ("(MIT OR Apache-2.0)", "MIT OR Apache-2.0", False),
    ("MIT AND (Apache-2.0 OR BSD-3-Clause)", "MIT AND (Apache-2.0 OR BSD-3-Clause)", False),
    ("GPL-2.0 OR MIT", "GPL-2.0-only OR MIT", False),
    # npm / Cargo style joins
    ("MIT/Apache-2.0", "MIT OR Apache-2.0", False),
    ("Apache-2.0/MIT", "Apache-2.0 OR MIT", False),
    ("MIT / Apache-2.0", "MIT OR Apache-2.0", False),
    ("MIT or Apache 2", "MIT OR Apache-2.0", False),
    ("MIT and BSD", "MIT AND BSD-3-Clause", True),
    ("MIT; ISC", "MIT AND ISC", False),
    ("BSD, MIT", "BSD-3-Clause AND MIT", True),
    ("Apache-2.0, MIT", "Apache-2.0 AND MIT", False),
    # MIT family
    ("MIT License", "MIT", False),
    ("The MIT License", "MIT", False),
    ("MIT license (MIT)", "MIT", False),
    ("Expat", "MIT", False),
    ("MIT No Attribution", "MIT-0", False),
    # Apache
    ("Apache 2", "Apache-2.0", False),
    ("Apache 2.0", "Apache-2.0", False),
    ("Apache2", "Apache-2.0", False),
    ("Apache License 2.0", "Apache-2.0", False),
    ("Apache License, Version 2.0", "Apache-2.0", False),
    ("Apache Software License 2.0", "Apache-2.0", False),
    ("Apache Software License", "Apache-2.0", True),
    ("Apache", "Apache-2.0", True),
    ("Apache License 1.1", "Apache-1.1", False),
    # BSD
    ("BSD", "BSD-3-Clause", True),
    ("BSD License", "BSD-3-Clause", True),
    ("BSD 3-Clause", "BSD-3-Clause", False),
    ("3-Clause BSD License", "BSD-3-Clause", False),
    ("New BSD License", "BSD-3-Clause", False),
    ("Revised BSD", "BSD-3-Clause", False),
    ("Modified BSD License", "BSD-3-Clause", False),
    ("BSD 2-Clause", "BSD-2-Clause", False),
    ("BSD-2", "BSD-2-Clause", False),
    ("Simplified BSD License", "BSD-2-Clause", False),
    ("FreeBSD License", "BSD-2-Clause", False),
    ("BSD 4-Clause", "BSD-4-Clause", False),
    ("Original BSD license", "BSD-4-Clause", False),
    ("Zero-Clause BSD", "0BSD", False),
    # GPL family spellings
    ("GPL v2", "GPL-2.0-only", False),
    ("GPLv2", "GPL-2.0-only", False),
    ("GPLv2+", "GPL-2.0-or-later", False),
    ("GPL-2", "GPL-2.0-only", False),
    ("GPL 3", "GPL-3.0-only", False),
    ("GPLv3", "GPL-3.0-only", False),
    ("GPLv3+", "GPL-3.0-or-later", False),
    ("GNU General Public License v3.0", "GPL-3.0-only", False),
    ("GNU General Public License v3 or later (GPLv3+)", "GPL-3.0-or-later", False),
    ("GNU General Public License, version 2", "GPL-2.0-only", False),
    ("GNU GPL v2 or later", "GPL-2.0-or-later", False),
    ("GPL version 2 only", "GPL-2.0-only", False),
    ("LGPL v2.1", "LGPL-2.1-only", False),
    ("LGPLv3", "LGPL-3.0-only", False),
    ("LGPLv3+", "LGPL-3.0-or-later", False),
    ("GNU Lesser General Public License v3 (LGPLv3)", "LGPL-3.0-only", False),
    ("GNU Lesser General Public License v2 or later (LGPLv2+)", "LGPL-2.0-or-later", False),
    ("AGPLv3", "AGPL-3.0-only", False),
    ("GNU Affero General Public License v3", "AGPL-3.0-only", False),
    ("GNU Affero General Public License v3 or later (AGPLv3+)", "AGPL-3.0-or-later", False),
    ("GPLv2 with classpath exception", "GPL-2.0-only WITH Classpath-exception-2.0", False),
    # others
    ("Mozilla Public License 2.0", "MPL-2.0", False),
    ("Mozilla Public License 2.0 (MPL 2.0)", "MPL-2.0", False),
    ("MPL 2.0", "MPL-2.0", False),
    ("MPL-1.1", "MPL-1.1", False),
    ("Eclipse Public License 2.0", "EPL-2.0", False),
    ("Eclipse Public License 1.0 (EPL-1.0)", "EPL-1.0", False),
    ("ISC License (ISCL)", "ISC", False),
    ("Python Software Foundation License", "PSF-2.0", False),
    ("PSF", "PSF-2.0", False),
    ("Zlib/Libpng License", "Zlib", False),
    ("Boost Software License 1.0 (BSL-1.0)", "BSL-1.0", False),
    ("The Unlicense (Unlicense)", "Unlicense", False),
    ("CC0 1.0 Universal", "CC0-1.0", False),
    ("cc by 4.0", "CC-BY-4.0", False),
    ("CC BY-NC 4.0", "CC-BY-NC-4.0", False),
    ("CC-BY-NC-SA-4.0", "CC-BY-NC-SA-4.0", False),
    ("Server Side Public License", None, False),  # no version -> cannot decide
    ("Server Side Public License 1.0", "SSPL-1.0", False),
    ("European Union Public Licence 1.2 (EUPL 1.2)", "EUPL-1.2", False),
    ("WTFPL", "WTFPL", False),
    ("Public Domain", "LicenseRef-Public-Domain", False),
    ("public-domain", "LicenseRef-Public-Domain", False),
    # proprietary words
    ("UNLICENSED", "LicenseRef-Proprietary", False),
    ("Proprietary", "LicenseRef-Proprietary", False),
    ("Commercial", "LicenseRef-Proprietary", False),
    ("All rights reserved", "LicenseRef-Proprietary", False),
    # trove classifiers
    ("License :: OSI Approved :: MIT License", "MIT", False),
    ("License :: OSI Approved :: Apache Software License", "Apache-2.0", True),
    ("License :: OSI Approved :: BSD License", "BSD-3-Clause", True),
    ("License :: OSI Approved :: ISC License (ISCL)", "ISC", False),
    ("License :: OSI Approved :: GNU General Public License v2 (GPLv2)", "GPL-2.0-only", False),
    ("License :: OSI Approved :: GNU General Public License v2 or later (GPLv2+)", "GPL-2.0-or-later", False),
    ("License :: OSI Approved :: GNU General Public License v3 (GPLv3)", "GPL-3.0-only", False),
    ("License :: OSI Approved :: GNU Lesser General Public License v3 or later (LGPLv3+)", "LGPL-3.0-or-later", False),
    ("License :: OSI Approved :: GNU Affero General Public License v3", "AGPL-3.0-only", False),
    ("License :: OSI Approved :: Mozilla Public License 2.0 (MPL 2.0)", "MPL-2.0", False),
    ("License :: OSI Approved :: Python Software Foundation License", "PSF-2.0", False),
    ("License :: OSI Approved :: The Unlicense (Unlicense)", "Unlicense", False),
    ("License :: OSI Approved :: Zlib/Libpng License", "Zlib", False),
    ("License :: Public Domain", "LicenseRef-Public-Domain", False),
    ("License :: Other/Proprietary License", "LicenseRef-Proprietary", False),
]

UNKNOWN = [
    None,
    "",
    "   ",
    "UNKNOWN",
    "Unknown",
    "none",
    "N/A",
    "null",
    "Other",
    "Custom",
    "SEE LICENSE IN LICENSE.txt",
    "See LICENSE file",
    "see the license file",
    "GPL",  # no version
    "LGPL",
    "GNU General Public License",
    "GNU Library or Lesser General Public License (LGPL)",
    "Foo",
    "Some Weird Thing",
    "License :: OSI Approved",
    "License :: Freely Distributable",
    "License :: OSI Approved :: Some Unheard Of License",
    "MIT OR",  # cannot parse, and not messy-resolvable as one thing
    "GPL-9.9",  # no such version
    "x" * 500,  # a pasted license body, not an identifier
    "Permission is hereby granted,\nfree of charge, to any person obtaining a copy",
    "Apache 3.7",
]


@pytest.mark.parametrize(("raw", "expr", "approx"), KNOWN)
def test_known_spellings(raw: str, expr: str | None, approx: bool) -> None:
    n = normalize(raw)
    assert n.expression == expr, n.notes
    if expr is not None:
        assert n.approximate == approx


@pytest.mark.parametrize("raw", UNKNOWN)
def test_unknown_is_explicit_and_carries_a_reason(raw: str | None) -> None:
    n = normalize(raw)
    assert n.unknown and n.expression is None
    assert n.display() == "UNKNOWN"
    assert n.notes, "an UNKNOWN result must say why"


def test_table_has_at_least_80_cases() -> None:
    assert len(KNOWN) + len(UNKNOWN) >= 80


def test_notes_explain_what_changed() -> None:
    n = normalize("GPL-2.0+")
    assert any("deprecated" in x for x in n.notes)
    n = normalize("MIT/Apache-2.0")
    assert any("OR" in x for x in n.notes)
    n = normalize("BSD")
    assert n.approximate and any("ambiguous" in x for x in n.notes)


def test_combine_all_uses_and_for_multiple_classifiers() -> None:
    items = [normalize("License :: OSI Approved :: MIT License"),
             normalize("License :: OSI Approved :: BSD License")]
    c = combine_all(items)
    assert c.expression == "MIT AND BSD-3-Clause"
    assert any("conservative" in x for x in c.notes)
    assert combine_all([items[0], items[0]]).expression == "MIT"
    bad = combine_all([items[0], normalize("License :: OSI Approved")])
    assert bad.unknown


def test_long_text_is_never_guessed_from_content() -> None:
    n = normalize("MIT License\n\nPermission is hereby granted, free of charge, to any person ...")
    assert n.unknown
    assert any("long text" in x for x in n.notes)
