"""Resolve a license for every locked package, recording where the answer came from.

Source priority (first one that yields a *recognised* license wins):
  1. installed metadata   (Python dist-info, node_modules/package.json, ~/.cargo registry)
  2. lockfile-embedded    (package-lock.json v2/v3 `license`)
  3. online lookup        (only with online=True: PyPI / npm / crates.io)
If nothing yields a recognised license the package is UNKNOWN, with the reasons.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field

from . import installed as inst
from . import lockfiles as lf
from . import online as net
from .errors import LicenseError
from .normalize import Normalized, normalize
from .sandbox import Sandbox

SOURCE_NONE = "none"


@dataclass
class PkgLicense:
    pkg: lf.LockedPkg
    normalized: Normalized
    source: str
    files: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    installed_path: str | None = None
    lockfiles: list[str] = field(default_factory=list)

    @property
    def label(self) -> str:
        return f"{self.pkg.name}@{self.pkg.version}"


@dataclass
class Scan:
    root: str
    lockfiles: list[lf.Lockfile]
    pkgs: list[PkgLicense]
    notes: list[str]
    online: bool
    sites: list[str]
    online_errors: int = 0

    @property
    def direct_known(self) -> bool:
        return any(lock.direct_known for lock in self.lockfiles)


def _python_sites(lock_dirs: list[str], python: str | None, sandbox: Sandbox, notes: list[str]) -> list[str]:
    if python:
        p = sandbox.resolve(python, "python")
        if not os.path.exists(p):
            raise LicenseError(f"python path {p} does not exist")
        sites = inst.venv_site_packages(p)
        if not sites:
            raise LicenseError(
                f"found no site-packages for python={python!r}. Pass a virtualenv directory, its "
                "Scripts/ or bin/ python executable, or a site-packages directory."
            )
        return sites
    sites = []
    for d in lock_dirs:
        for name in (".venv", "venv"):
            cand = os.path.join(d, name)
            if os.path.isdir(cand):
                sites.extend(s for s in inst.venv_site_packages(cand) if s not in sites)
    if not sites:
        notes.append(
            "no virtualenv found (.venv/ or venv/ next to the lockfile) and no python= given: "
            "Python licenses come from the lockfile (none embedded) or online lookup only"
        )
    return sites


def scan(path: str, sandbox: Sandbox, python: str | None = None, online: bool = False) -> Scan:
    root = sandbox.resolve(path)
    lock_paths = lf.detect(root)
    for lock_path in lock_paths:
        if not sandbox.contains(lock_path):
            raise LicenseError(f"{lock_path} resolves outside the allowed directories")
    locks = [lf.parse(p) for p in lock_paths]
    notes = [f"{os.path.basename(lk.path)}: {n}" for lk in locks for n in lk.notes]
    lock_dirs = list(dict.fromkeys(lk.directory for lk in locks))

    # merge packages across lockfiles
    merged: dict[tuple[str, str, str], tuple[lf.LockedPkg, list[lf.Lockfile]]] = {}
    for lk in locks:
        for p in lk.packages:
            if p.key in merged:
                have, owners = merged[p.key]
                owners.append(lk)
                have.locations = tuple(dict.fromkeys(have.locations + p.locations))
                if p.direct:
                    have.direct = True
                elif have.direct is None:
                    have.direct = p.direct
                have.embedded_license = have.embedded_license or p.embedded_license
            else:
                merged[p.key] = (p, [lk])

    ecos = {k[0] for k in merged}
    sites: list[str] = []
    py_index: inst.PythonIndex | None = None
    if lf.PYPI in ecos:
        sites = _python_sites(lock_dirs, python, sandbox, notes)
        py_index = inst.PythonIndex(sites, sandbox)
    node_indexes = {d: inst.NodeIndex(d, sandbox) for d in lock_dirs} if lf.NPM in ecos else {}
    cargo = inst.CargoIndex(sandbox) if lf.CRATES in ecos else None
    if lf.CRATES in ecos and cargo is not None and not cargo.registries:
        notes.append(f"no cargo registry at {cargo.base}: crate licenses need online lookup or a populated registry")
    if lf.GO in ecos:
        notes.append("Go modules: go.sum carries no license data and there is no registry API; marked UNKNOWN")

    results: list[PkgLicense] = []
    for key in sorted(merged, key=lambda k: (k[0], k[1].lower(), k[2])):
        pkg, owners = merged[key]
        res = _resolve_offline(pkg, owners, py_index, node_indexes, cargo)
        results.append(res)

    errors = 0
    if online:
        pending = [r for r in results if r.normalized.unknown]
        todo = [r for r in pending if r.pkg.ecosystem in net.BASES]
        for r in pending:
            if r.pkg.ecosystem not in net.BASES:
                r.notes.append(f"no online license source exists for {r.pkg.ecosystem} packages")
        foreign = [r for r in todo if r.pkg.ecosystem == lf.CRATES and r.pkg.source
                   and "crates.io" not in r.pkg.source]
        for r in foreign:
            r.notes.append("crate comes from a registry other than crates.io; not looked up")
        todo = [r for r in todo if r not in foreign]
        answers = net.lookup_many([r.pkg for r in todo])
        for r in todo:
            ans = answers[r.pkg.key]
            if ans.error:
                errors += 1
                r.notes.append(ans.error)
            elif ans.normalized is None:
                r.notes.append(f"{ans.source}: the record has no license information")
            elif not ans.normalized.unknown:
                r.normalized, r.source = ans.normalized, ans.source
                r.notes.extend(ans.normalized.notes)
            else:
                r.notes.append(f"{ans.source}: {'; '.join(ans.normalized.notes)}")
        if errors:
            notes.append(f"{errors} online lookup(s) failed; see the per-package notes")
    return Scan(root, locks, results, notes, online, sites, errors)


def _resolve_offline(
    pkg: lf.LockedPkg,
    owners: list[lf.Lockfile],
    py_index: inst.PythonIndex | None,
    node_indexes: dict[str, inst.NodeIndex],
    cargo: inst.CargoIndex | None,
) -> PkgLicense:
    out = PkgLicense(pkg, normalize(None), SOURCE_NONE, lockfiles=[lk.path for lk in owners])
    candidates: list[tuple[Normalized, str]] = []

    looked: list[inst.Lookup] = []
    if pkg.ecosystem == lf.PYPI and py_index is not None:
        looked.append(py_index.lookup(pkg.name, pkg.version))
    elif pkg.ecosystem == lf.NPM:
        for lk in owners:
            idx = node_indexes.get(lk.directory)
            if idx is not None:
                looked.append(idx.lookup(pkg))
    elif pkg.ecosystem == lf.CRATES and cargo is not None:
        looked.append(cargo.lookup(pkg))
    for lu in looked:
        if lu.note:
            out.notes.append(lu.note)
        if lu.found is not None:
            f = lu.found
            out.installed_path = out.installed_path or f.path
            for fp in f.files:
                if fp not in out.files:
                    out.files.append(fp)
            out.notes.extend(f.notes)
            if f.normalized is not None:
                candidates.append((f.normalized, f.source))
    if pkg.embedded_license:
        candidates.append((normalize(pkg.embedded_license), f"lockfile ({os.path.basename(owners[0].path)})"))

    for n, src in candidates:
        if not n.unknown:
            out.normalized, out.source = n, src
            out.notes.extend(n.notes)
            return out
    if candidates:
        n, src = candidates[0]
        out.normalized, out.source = n, src
        out.notes.extend(n.notes)
    elif not out.notes:
        if out.installed_path:
            out.notes.append("installed, but its metadata has no license information")
        else:
            out.notes.append(
                "not installed in the environments read, and the lockfile carries no license data"
            )
    return out
