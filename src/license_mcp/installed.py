"""Read license information from packages that are already installed on disk.

* Python: ``*.dist-info`` / ``*.egg-info`` directories in a venv's site-packages
  (METADATA / PKG-INFO headers License-Expression, License, Classifier; license files).
  The headers are read directly (size-capped) rather than by importing the target
  environment, so nothing from the inspected venv is ever executed.
* Node: ``node_modules/<name>/package.json`` (``license`` / legacy ``licenses``).
* Rust: ``$CARGO_HOME/registry/src/*/<crate>-<version>/Cargo.toml`` (``license``).

Every function is read-only and refuses to follow a symlink out of the sandbox.
"""

from __future__ import annotations

import email.policy
import json
import os
import re
import sys
from dataclasses import dataclass, field
from email.parser import BytesHeaderParser

from . import lockfiles as lf
from .normalize import Normalized, combine_all, normalize
from .sandbox import Sandbox

if sys.version_info >= (3, 11):
    import tomllib
else:  # pragma: no cover
    import tomli as tomllib

MAX_META_BYTES = 1024 * 1024
MAX_TEXT_BYTES = 256 * 1024
_LICENSE_FILE = re.compile(r"^(licen[sc]e|copying|notice|copyright|unlicense|patents)(?![a-z])", re.IGNORECASE)


@dataclass
class Installed:
    """What an installed package says about its license."""

    normalized: Normalized | None  # None: installed, but no license information at all
    source: str  # human-readable origin, e.g. "installed metadata: License-Expression"
    path: str  # the dist-info / package directory
    files: list[str] = field(default_factory=list)  # absolute paths of LICENSE/NOTICE-type files
    notes: list[str] = field(default_factory=list)


@dataclass
class Lookup:
    found: Installed | None
    note: str | None = None  # why an installed copy was not used (version mismatch, outside sandbox)


def _read_capped(path: str, limit: int) -> bytes:
    with open(path, "rb") as fh:
        return fh.read(limit)


def _license_files(directory: str, sandbox: Sandbox) -> list[str]:
    out: list[str] = []
    try:
        names = sorted(os.listdir(directory))
    except OSError:
        return out
    for n in names:
        p = os.path.join(directory, n)
        if _LICENSE_FILE.match(n) and os.path.isfile(p) and sandbox.contains(p):
            out.append(p)
    return out


# ------------------------------------------------------------------ Python


def venv_site_packages(candidate: str) -> list[str]:
    """site-packages directories for a venv root, a python executable inside one, or site-packages itself."""
    c = os.path.abspath(candidate)
    if os.path.isfile(c):
        parent = os.path.dirname(c)
        c = os.path.dirname(parent) if os.path.basename(parent).lower() in ("scripts", "bin") else parent
    if os.path.basename(c).lower() == "site-packages" and os.path.isdir(c):
        return [c]
    found: list[str] = []
    win = os.path.join(c, "Lib", "site-packages")
    if os.path.isdir(win):
        found.append(win)
    for libdir in ("lib", "lib64"):
        base = os.path.join(c, libdir)
        if os.path.isdir(base):
            try:
                for d in sorted(os.listdir(base)):
                    sp = os.path.join(base, d, "site-packages")
                    if d.startswith("python") and os.path.isdir(sp):
                        found.append(sp)
            except OSError:
                pass
    return found


class PythonIndex:
    def __init__(self, site_dirs: list[str], sandbox: Sandbox) -> None:
        self.site_dirs = site_dirs
        self.sandbox = sandbox
        self.dists: dict[str, list[tuple[str, str]]] = {}  # normalized name -> [(version, metadata dir)]
        for sd in site_dirs:
            try:
                entries = sorted(os.listdir(sd))
            except OSError:
                continue
            for e in entries:
                stem, ext = os.path.splitext(e)
                if ext not in (".dist-info", ".egg-info") or "-" not in stem:
                    continue
                name, version = stem.split("-", 1)
                if ext == ".egg-info":
                    version = version.split("-py", 1)[0]
                self.dists.setdefault(lf.pypi_name(name), []).append((version, os.path.join(sd, e)))

    def lookup(self, name: str, version: str) -> Lookup:
        cands = self.dists.get(name)
        if not cands:
            return Lookup(None)
        same = [d for v, d in cands if v == version or lf.pypi_name(v) == lf.pypi_name(version)]
        if not same:
            have = ", ".join(sorted({v for v, _ in cands}))
            return Lookup(None, f"installed version {have} differs from locked {version}; installed metadata not used")
        meta_dir = same[0]
        if not self.sandbox.contains(meta_dir):
            return Lookup(None, f"{meta_dir} resolves outside the allowed directories; not read")
        return Lookup(self._read(meta_dir))

    def _read(self, meta_dir: str) -> Installed:
        notes: list[str] = []
        if os.path.isdir(meta_dir):
            meta_file = os.path.join(meta_dir, "METADATA")
            if not os.path.isfile(meta_file):
                meta_file = os.path.join(meta_dir, "PKG-INFO")
            meta_root = meta_dir
        else:
            meta_file, meta_root = meta_dir, os.path.dirname(meta_dir)
        files = _license_files(meta_root, self.sandbox)
        lic_dir = os.path.join(meta_root, "licenses")
        if os.path.isdir(lic_dir) and self.sandbox.contains(lic_dir):
            for root, dirs, names in os.walk(lic_dir, followlinks=False):
                dirs[:] = sorted(dirs)[:20]
                for fname in sorted(names)[:50]:
                    p = os.path.join(root, fname)
                    if self.sandbox.contains(p) and p not in files:
                        files.append(p)
        if not os.path.isfile(meta_file) or not self.sandbox.contains(meta_file):
            return Installed(None, "installed Python metadata", meta_dir, files, ["no METADATA/PKG-INFO file"])
        headers = BytesHeaderParser(policy=email.policy.default).parsebytes(_read_capped(meta_file, MAX_META_BYTES))
        expr = headers.get("License-Expression")
        lic = headers.get("License")
        classifiers = [str(c) for c in (headers.get_all("Classifier") or []) if str(c).startswith("License ::")]

        n, label = python_license(
            str(expr) if expr else None, str(lic) if lic else None, classifiers
        )
        if n is None:
            return Installed(None, "installed Python metadata", meta_dir, files, ["metadata has no license fields"])
        return Installed(n, label, meta_dir, files, notes)


def python_license(
    expression: str | None, license_field: str | None, classifiers: list[str]
) -> tuple[Normalized | None, str]:
    """Pick the best license statement from Python core metadata.

    Priority: License-Expression (PEP 639, already SPDX) > the License field when it is a
    recognisable short identifier > trove license classifiers (combined with AND, because
    classifiers cannot say OR). Returns (None, ...) when the metadata has no license data
    at all, and an UNKNOWN Normalized when it has data we cannot interpret.
    """
    if expression and expression.strip():
        return normalize(expression), "installed metadata (License-Expression)"
    tried: list[Normalized] = []
    if license_field and license_field.strip():
        n = normalize(license_field)
        if not n.unknown:
            return n, "installed metadata (License field)"
        tried.append(n)
    if classifiers:
        n2 = combine_all([normalize(c) for c in classifiers])
        if not n2.unknown:
            return n2, "installed metadata (license classifier%s)" % ("s" if len(classifiers) > 1 else "")
        tried.append(n2)
    if tried:
        return tried[0], "installed metadata"
    return None, "installed metadata"


# ------------------------------------------------------------------ Node


class NodeIndex:
    def __init__(self, project_dir: str, sandbox: Sandbox) -> None:
        self.dir = project_dir
        self.sandbox = sandbox

    def lookup(self, pkg: lf.LockedPkg) -> Lookup:
        cands = [os.path.join(self.dir, *loc.split("/")) for loc in pkg.locations]
        cands.append(os.path.join(self.dir, "node_modules", *pkg.name.split("/")))
        seen_any = False
        mismatch: str | None = None
        for d in dict.fromkeys(cands):
            pj = os.path.join(d, "package.json")
            if not os.path.isfile(pj):
                continue
            if not self.sandbox.contains(pj):
                return Lookup(None, f"{d} resolves outside the allowed directories; not read")
            seen_any = True
            try:
                data = json.loads(_read_capped(pj, MAX_META_BYTES).decode("utf-8", "replace"))
            except ValueError:
                continue
            if not isinstance(data, dict):
                continue
            if data.get("version") != pkg.version:
                mismatch = f"installed version {data.get('version')} differs from locked {pkg.version}"
                continue
            raw = lf._npm_license_field(data.get("license")) or lf._npm_license_field(data.get("licenses"))
            files = _license_files(d, self.sandbox)
            n = normalize(raw) if raw else None
            return Lookup(Installed(n, "installed node_modules package.json", d, files,
                                    [] if raw else ["package.json has no license field"]))
        if seen_any and mismatch:
            return Lookup(None, mismatch + "; installed package.json not used")
        return Lookup(None)


# ------------------------------------------------------------------ Rust


def cargo_home() -> str:
    return os.environ.get("CARGO_HOME") or os.path.join(os.path.expanduser("~"), ".cargo")


class CargoIndex:
    def __init__(self, sandbox: Sandbox) -> None:
        self.base = os.path.join(cargo_home(), "registry", "src")
        self.sandbox = sandbox
        self.registries: list[str] = []
        if os.path.isdir(self.base):
            sandbox.allow_extra(self.base)
            try:
                self.registries = [os.path.join(self.base, d) for d in sorted(os.listdir(self.base))]
            except OSError:
                self.registries = []

    def lookup(self, pkg: lf.LockedPkg) -> Lookup:
        for reg in self.registries:
            d = os.path.join(reg, f"{pkg.name}-{pkg.version}")
            toml_path = os.path.join(d, "Cargo.toml")
            if not os.path.isfile(toml_path):
                continue
            if not self.sandbox.contains(toml_path):
                return Lookup(None, f"{d} resolves outside the allowed directories; not read")
            try:
                data = tomllib.loads(_read_capped(toml_path, MAX_META_BYTES).decode("utf-8", "replace"))
            except tomllib.TOMLDecodeError:
                continue
            package = data.get("package", {})
            raw = package.get("license")
            files = _license_files(d, self.sandbox)
            if isinstance(raw, str) and raw.strip():
                return Lookup(Installed(normalize(raw), "cargo registry Cargo.toml", d, files))
            note = "Cargo.toml has no `license` key"
            if package.get("license-file"):
                note = f"Cargo.toml uses license-file = {package['license-file']!r} instead of an SPDX `license`"
            return Lookup(Installed(None, "cargo registry Cargo.toml", d, files, [note]))
        return Lookup(None)


# ------------------------------------------------------------------ copyright lines

_COPYRIGHT = re.compile(r"^\s*(?:copyright\b|\(c\)|©)", re.IGNORECASE)
_PLACEHOLDER = re.compile(r"<year>|\[yyyy\]|\{yyyy\}|yyyy|<owner>|\[name of|\{name of|<copyright holder>", re.IGNORECASE)


def extract_copyright(files: list[str], sandbox: Sandbox, limit: int = 4) -> list[str]:
    """Copyright lines from license files ('Copyright (c) 2020 Someone'); template placeholders skipped."""
    out: list[str] = []
    for f in files:
        if len(out) >= limit:
            break
        if not sandbox.contains(f):
            continue
        try:
            text = _read_capped(f, MAX_TEXT_BYTES).decode("utf-8", "replace")
        except OSError:
            continue
        for line in text.splitlines():
            if not _COPYRIGHT.match(line):
                continue
            s = " ".join(line.split())
            if len(s) > 200 or _PLACEHOLDER.search(s):
                continue
            if not (re.search(r"\b(19|20)\d\d\b", s) or "(c)" in s.lower() or "©" in s):
                continue
            if s not in out:
                out.append(s)
            if len(out) >= limit:
                break
    return out
