"""Hand-written lockfile parsers.

Supported: uv.lock, poetry.lock, requirements*.txt (pinned), package-lock.json (v2/v3),
pnpm-lock.yaml (v6-v9), yarn.lock (v1), Cargo.lock, go.sum (+ go.mod when next to it).

A parser returns a Lockfile: the locked packages (ecosystem, name, version), whether each
is a direct dependency (when the lockfile or its manifest lets us tell), any license text
the lockfile itself embeds, and notes about what was skipped. Nothing is ever written.
"""

from __future__ import annotations

import json
import os
import re
import sys
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from .errors import LicenseError

if sys.version_info >= (3, 11):
    import tomllib
else:  # pragma: no cover - exercised on 3.10 only
    import tomli as tomllib

PYPI = "pypi"
NPM = "npm"
CRATES = "crates"
GO = "go"

MAX_LOCKFILE_BYTES = 40 * 1024 * 1024
SKIP_DIRS = {
    "node_modules", ".git", ".venv", "venv", "env", "__pycache__", "target", "dist", "build",
    ".tox", ".mypy_cache", ".ruff_cache", ".pytest_cache", "vendor", ".idea", ".vscode", "site-packages",
}
MAX_DEPTH = 3
MAX_FILES = 40
SUPPORTED = (
    "uv.lock, poetry.lock, requirements*.txt, package-lock.json, pnpm-lock.yaml, yarn.lock, "
    "Cargo.lock, go.sum"
)


@dataclass
class LockedPkg:
    ecosystem: str
    name: str
    version: str
    direct: bool | None = None  # None: the lockfile cannot tell
    embedded_license: str | None = None
    locations: tuple[str, ...] = ()  # npm: install paths relative to the lockfile's directory
    source: str | None = None  # crates: registry url

    @property
    def key(self) -> tuple[str, str, str]:
        return (self.ecosystem, self.name, self.version)


@dataclass
class Lockfile:
    path: str
    kind: str
    ecosystem: str
    packages: list[LockedPkg] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    direct_known: bool = True

    @property
    def directory(self) -> str:
        return os.path.dirname(self.path)


# ------------------------------------------------------------------ discovery


def _kind_of(filename: str) -> str | None:
    if filename in ("uv.lock", "poetry.lock", "package-lock.json", "pnpm-lock.yaml", "yarn.lock",
                    "Cargo.lock", "go.sum"):
        return filename
    if re.fullmatch(r"requirements[-_.\w]*\.txt", filename):
        return "requirements.txt"
    return None


def detect(path: str) -> list[str]:
    """Lockfiles at `path`: the file itself, or those found up to MAX_DEPTH levels below a directory."""
    path = os.path.abspath(path)
    if os.path.isfile(path):
        if _kind_of(os.path.basename(path)) is None:
            raise LicenseError(f"{path} is not a supported lockfile. Supported: {SUPPORTED}.")
        return [path]
    if not os.path.isdir(path):
        raise LicenseError(f"{path} does not exist. Pass a project directory or a lockfile path.")
    found: list[str] = []
    base_depth = path.rstrip("\\/").count(os.sep)
    for root, dirs, files in os.walk(path, followlinks=False):
        depth = root.rstrip("\\/").count(os.sep) - base_depth
        dirs[:] = sorted(d for d in dirs if d not in SKIP_DIRS and depth < MAX_DEPTH)
        for f in sorted(files):
            if _kind_of(f) and not os.path.islink(os.path.join(root, f)):
                found.append(os.path.join(root, f))
    if not found:
        raise LicenseError(
            f"no lockfile found under {path} (looked {MAX_DEPTH} levels deep). Supported: {SUPPORTED}. "
            "Generate one first, for example `uv lock`, `npm install --package-lock-only` or "
            "`cargo generate-lockfile`."
        )
    if len(found) > MAX_FILES:
        raise LicenseError(
            f"{len(found)} lockfiles found under {path}; the limit is {MAX_FILES}. "
            "Point at a subdirectory or a single lockfile."
        )
    return found


def read_text(path: str) -> str:
    try:
        size = os.path.getsize(path)
        if size > MAX_LOCKFILE_BYTES:
            raise LicenseError(f"{path} is {size} bytes; the limit is {MAX_LOCKFILE_BYTES}")
        with open(path, encoding="utf-8") as fh:
            return fh.read()
    except OSError as e:
        raise LicenseError(f"cannot read {path}: {e.strerror or e}") from e
    except UnicodeDecodeError as e:
        raise LicenseError(f"{path} is not valid UTF-8 text: {e}") from e


def parse(path: str) -> Lockfile:
    kind = _kind_of(os.path.basename(path))
    if kind is None:
        raise LicenseError(f"{path} is not a supported lockfile. Supported: {SUPPORTED}.")
    text = read_text(path)
    try:
        lock = _PARSERS[kind](path, text)
    except LicenseError:
        raise
    except (KeyError, TypeError, ValueError, AttributeError, IndexError, tomllib.TOMLDecodeError,
            RecursionError) as e:
        raise LicenseError(f"{path} does not look like a valid {kind}: {type(e).__name__}: {e}") from e
    return _dedupe(lock)


def _dedupe(lock: Lockfile) -> Lockfile:
    merged: dict[tuple[str, str, str], LockedPkg] = {}
    for p in lock.packages:
        have = merged.get(p.key)
        if have is None:
            merged[p.key] = p
            continue
        have.locations = tuple(dict.fromkeys(have.locations + p.locations))
        if p.direct:
            have.direct = True
        have.embedded_license = have.embedded_license or p.embedded_license
    lock.packages = sorted(merged.values(), key=lambda p: (p.name.lower(), p.version))
    return lock


def _read_optional(path: str) -> str | None:
    try:
        with open(path, encoding="utf-8") as fh:
            return fh.read()
    except FileNotFoundError:
        return None
    except (OSError, UnicodeDecodeError) as e:
        raise LicenseError(f"cannot read {path}: {e}") from e


def pypi_name(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


_REQ_NAME = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)")


def _spec_names(specs: Any) -> set[str]:
    out: set[str] = set()
    for s in specs or []:
        if isinstance(s, str) and (m := _REQ_NAME.match(s)):
            out.add(pypi_name(m.group(1)))
    return out


def _set_direct(lock: Lockfile, names: set[str] | None, why: str) -> None:
    if names is None:
        lock.direct_known = False
        lock.notes.append(f"{why}; direct vs transitive is unknown")
        return
    for p in lock.packages:
        p.direct = p.name in names


# ------------------------------------------------------------------ uv.lock


def parse_uv_lock(path: str, text: str) -> Lockfile:
    data = tomllib.loads(text)
    lock = Lockfile(path, "uv.lock", PYPI)
    direct: set[str] = set()
    have_root = False
    skipped = 0
    for e in data.get("package", []):
        source = e.get("source", {})
        if "registry" in source and "version" in e:
            lock.packages.append(LockedPkg(PYPI, pypi_name(e["name"]), e["version"]))
        elif "virtual" in source or "editable" in source or "directory" in source:
            have_root = True
            groups: list[Any] = [e.get("dependencies", [])]
            groups += list((e.get("optional-dependencies") or {}).values())
            groups += list((e.get("dev-dependencies") or {}).values())
            for g in groups:
                direct |= {pypi_name(d["name"]) for d in g if isinstance(d, dict) and "name" in d}
        else:
            skipped += 1
    if skipped:
        lock.notes.append(f"{skipped} package(s) from git/url/path sources are not listed")
    _set_direct(lock, direct if have_root else None, "uv.lock names no project package")
    return lock


# ------------------------------------------------------------------ poetry.lock


def _pyproject_direct(directory: str) -> set[str] | None:
    text = _read_optional(os.path.join(directory, "pyproject.toml"))
    if text is None:
        return None
    data = tomllib.loads(text)
    names: set[str] = set()
    project = data.get("project", {})
    names |= _spec_names(project.get("dependencies"))
    for g in (project.get("optional-dependencies") or {}).values():
        names |= _spec_names(g)
    for g in (data.get("dependency-groups") or {}).values():
        names |= _spec_names(g)
    poetry = data.get("tool", {}).get("poetry", {})
    tables = [poetry.get("dependencies"), poetry.get("dev-dependencies")]
    tables += [g.get("dependencies") for g in (poetry.get("group") or {}).values()]
    for t in tables:
        for dep in t or {}:
            if dep.lower() != "python":
                names.add(pypi_name(dep))
    return names


def parse_poetry_lock(path: str, text: str) -> Lockfile:
    data = tomllib.loads(text)
    lock = Lockfile(path, "poetry.lock", PYPI)
    skipped = 0
    for e in data.get("package", []):
        if e.get("source", {}).get("type") in ("git", "directory", "file", "url"):
            skipped += 1
            continue
        lock.packages.append(LockedPkg(PYPI, pypi_name(e["name"]), e["version"]))
    if skipped:
        lock.notes.append(f"{skipped} package(s) from git/url/path sources are not listed")
    _set_direct(lock, _pyproject_direct(lock.directory), "no pyproject.toml next to poetry.lock")
    return lock


# ------------------------------------------------------------------ requirements.txt

_REQ_PIN = re.compile(
    r"^([A-Za-z0-9][A-Za-z0-9._-]*)\s*(?:\[[^\]]*\])?\s*==\s*([A-Za-z0-9][A-Za-z0-9._+!-]*)\s*(?:;.*)?$"
)


def parse_requirements(path: str, text: str) -> Lockfile:
    lock = Lockfile(path, "requirements.txt", PYPI)
    logical: list[str] = []
    buf = ""
    for raw in text.splitlines():
        line = raw.rstrip()
        if line.endswith("\\"):
            buf += line[:-1] + " "
            continue
        logical.append(buf + line)
        buf = ""
    if buf:
        logical.append(buf)
    unpinned = 0
    for line in logical:
        line = re.sub(r"\s#.*$", "", line).strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("-"):
            if re.match(r"-(r|c|-requirement|-constraint)\b", line):
                lock.notes.append(f"'{line}' is not followed; scan the referenced file directly")
            continue
        line = re.sub(r"\s--hash=\S+", "", line).strip()
        m = _REQ_PIN.match(line)
        if m and "*" not in m.group(2):
            lock.packages.append(LockedPkg(PYPI, pypi_name(m.group(1)), m.group(2), direct=True))
        else:
            unpinned += 1
    if unpinned:
        lock.notes.append(f"{unpinned} requirement(s) not pinned with == were skipped")
    lock.notes.append("requirements.txt has no dependency graph: every pin is listed as direct")
    return lock


# ------------------------------------------------------------------ package-lock.json


def _npm_license_field(value: Any) -> str | None:
    """npm's `license` may be a string, {type: ...}, or (legacy) a list of those."""
    if isinstance(value, str):
        return value
    if isinstance(value, dict):
        t = value.get("type")
        return t if isinstance(t, str) else None
    if isinstance(value, list):
        parts = [p for p in (_npm_license_field(v) for v in value) if p]
        return " OR ".join(parts) if parts else None
    return None


def parse_package_lock(path: str, text: str) -> Lockfile:
    data = json.loads(text)
    version = data.get("lockfileVersion")
    packages = data.get("packages")
    if not isinstance(packages, dict) or version not in (2, 3):
        raise LicenseError(
            f"{path}: npm lockfileVersion {version} has no flat 'packages' map. Only v2 and v3 are "
            "supported; regenerate with npm 7 or newer (`npm install --package-lock-only`)."
        )
    lock = Lockfile(path, "package-lock.json", NPM)
    direct_keys: set[str] = set()
    for key, entry in packages.items():
        if not isinstance(entry, dict):
            continue
        if not key.startswith("node_modules/"):
            # root project ("") or a workspace member: its declared deps are direct
            for f in ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies"):
                for dep in entry.get(f) or {}:
                    direct_keys.add(f"node_modules/{dep}")
            continue
    for key, entry in packages.items():
        if not isinstance(entry, dict) or not key.startswith("node_modules/"):
            continue
        if entry.get("link") or "version" not in entry:
            continue
        name = entry.get("name") or key.rsplit("node_modules/", 1)[1]
        lock.packages.append(LockedPkg(
            NPM, name, entry["version"], direct=key in direct_keys,
            embedded_license=_npm_license_field(entry.get("license")), locations=(key,),
        ))
    return lock


# ------------------------------------------------------------------ YAML subset (pnpm)


def _unquote(s: str) -> str:
    s = s.strip()
    if len(s) >= 2 and s[0] == s[-1] and s[0] in "'\"":
        return s[1:-1].replace("''", "'") if s[0] == "'" else s[1:-1]
    return s


def _split_key(body: str) -> tuple[str, str]:
    if body[0] in "'\"":
        q = body[0]
        i = 1
        while i < len(body):
            if body[i] == q:
                if q == "'" and body[i + 1 : i + 2] == "'":
                    i += 2
                    continue
                break
            i += 1
        rest = body[i + 1 :]
        if not rest.startswith(":"):
            raise ValueError(f"expected ':' after quoted key in {body[:60]!r}")
        return _unquote(body[: i + 1]), rest[1:].strip()
    idx = body.find(": ")
    if idx >= 0:
        return body[:idx], body[idx + 2 :].strip()
    if body.endswith(":"):
        return body[:-1], ""
    raise ValueError(f"not a 'key: value' line: {body[:60]!r}")


def parse_yaml_map(text: str) -> dict[str, Any]:
    """The block-mapping subset of YAML lockfiles use. List items are skipped; flow values
    ({...}, [...]) stay raw strings."""
    root: dict[str, Any] = {}
    stack: list[tuple[int, dict[str, Any]]] = [(-1, root)]
    for lineno, raw in enumerate(text.splitlines(), 1):
        if not raw.strip() or raw.lstrip().startswith("#"):
            continue
        indent = len(raw) - len(raw.lstrip(" "))
        body = raw.strip()
        if body.startswith("- ") or body == "-":
            continue
        while len(stack) > 1 and stack[-1][0] >= indent:
            stack.pop()
        try:
            key, rest = _split_key(body)
        except ValueError as e:
            raise ValueError(f"line {lineno}: {e}") from e
        container = stack[-1][1]
        if rest == "":
            child: dict[str, Any] = {}
            container[key] = child
            stack.append((indent, child))
        else:
            container[key] = _unquote(rest)
    return root


def _pnpm_split(spec: str) -> tuple[str, str] | None:
    """'/@scope/name@1.2.3(peer@1)' or 'name@1.2.3' -> ('@scope/name', '1.2.3')."""
    spec = spec.split("(", 1)[0].lstrip("/")
    idx = spec.rfind("@")
    if idx <= 0:
        return None
    return spec[:idx], spec[idx + 1 :]


def parse_pnpm_lock(path: str, text: str) -> Lockfile:
    doc = parse_yaml_map(text)
    raw_version = str(doc.get("lockfileVersion", "")).strip("'\"")
    try:
        major = int(raw_version.split(".")[0])
    except ValueError as e:
        raise LicenseError(f"{path}: cannot read lockfileVersion {raw_version!r}") from e
    if major < 6:
        raise LicenseError(
            f"{path}: pnpm lockfileVersion {raw_version} is older than 6.0, which is not supported. "
            "Run `pnpm install --lockfile-only` with pnpm 8 or newer to upgrade it."
        )
    lock = Lockfile(path, "pnpm-lock.yaml", NPM)
    meta: dict[str, Any] = doc["packages"] if isinstance(doc.get("packages"), dict) else {}
    snaps: dict[str, Any] = doc["snapshots"] if isinstance(doc.get("snapshots"), dict) else {}
    seen: set[tuple[str, str]] = set()
    for key in [*meta, *snaps]:
        nv = _pnpm_split(key)
        if nv is None:
            continue
        entry = meta.get(key)
        res = entry.get("resolution", "") if isinstance(entry, dict) else ""
        if isinstance(res, str) and ("directory:" in res or "repo:" in res):
            continue
        seen.add(nv)

    direct: set[tuple[str, str]] = set()

    def note_direct(name: str, value: str) -> None:
        value = value.split("(", 1)[0].lstrip("/")
        if value.startswith(("link:", "file:", "workspace:", "git+", "http")):
            return
        nv = _pnpm_split(value) if "@" in value else (name, value)
        if nv is not None:
            direct.add(nv)

    importers = doc.get("importers")
    scopes = list(importers.values()) if isinstance(importers, dict) else [doc]
    for imp in scopes:
        if not isinstance(imp, dict):
            continue
        for f in ("dependencies", "devDependencies", "optionalDependencies"):
            deps = imp.get(f)
            if isinstance(deps, dict):
                for dname, dval in deps.items():
                    if isinstance(dval, dict):
                        v = dval.get("version")
                        if isinstance(v, str):
                            note_direct(dname, v)
                    elif isinstance(dval, str):
                        note_direct(dname, dval)
    for name, version in sorted(seen):
        lock.packages.append(LockedPkg(
            NPM, name, version, direct=(name, version) in direct,
            locations=(f"node_modules/.pnpm/{name.replace('/', '+')}@{version}/node_modules/{name}",
                       f"node_modules/{name}"),
        ))
    if not direct:
        lock.direct_known = False
        lock.notes.append("pnpm-lock.yaml lists no importer dependencies; direct vs transitive is unknown")
    return lock


# ------------------------------------------------------------------ yarn.lock v1


def parse_yarn_lock(path: str, text: str) -> Lockfile:
    if "__metadata:" in text:
        raise LicenseError(
            f"{path} is a Yarn Berry (v2+) lockfile; only Yarn v1 is supported. "
            "Scan a package-lock.json or pnpm-lock.yaml instead, or export one."
        )
    lock = Lockfile(path, "yarn.lock", NPM)
    specs: dict[str, tuple[str, str]] = {}  # "name@range" -> (name, version)
    header: list[str] | None = None
    fields: dict[str, str] = {}

    def flush() -> None:
        if header is not None and "version" in fields:
            name = header[0].rsplit("@", 1)[0]
            for s in header:
                specs[s] = (name, fields["version"])
            lock.packages.append(LockedPkg(NPM, name, fields["version"]))

    for raw in text.splitlines():
        if not raw.strip() or raw.lstrip().startswith("#"):
            continue
        indent = len(raw) - len(raw.lstrip(" "))
        body = raw.strip()
        if indent == 0:
            flush()
            if not body.endswith(":"):
                raise ValueError(f"bad yarn.lock header line: {body[:60]!r}")
            header = [_unquote(s) for s in body[:-1].split(", ")]
            fields = {}
        elif indent == 2 and not body.endswith(":"):
            k, _, v = body.partition(" ")
            fields[k] = _unquote(v)
    flush()
    manifest = _read_optional(os.path.join(lock.directory, "package.json"))
    if manifest is None:
        _set_direct(lock, None, "no package.json next to yarn.lock")
    else:
        pj = json.loads(manifest)
        direct: set[tuple[str, str]] = set()
        for f in ("dependencies", "devDependencies", "optionalDependencies"):
            for dname, rng in (pj.get(f) or {}).items():
                hit = specs.get(f"{dname}@{rng}")
                if hit:
                    direct.add(hit)
        for p in lock.packages:
            p.direct = (p.name, p.version) in direct
    return lock


# ------------------------------------------------------------------ Cargo.lock


def parse_cargo_lock(path: str, text: str) -> Lockfile:
    data = tomllib.loads(text)
    lock = Lockfile(path, "Cargo.lock", CRATES)
    entries: list[dict[str, Any]] = data.get("package", [])
    by_name: dict[str, list[tuple[str, str]]] = {}
    direct: set[tuple[str, str]] = set()
    have_member = False
    skipped = 0
    for e in entries:
        source = e.get("source", "")
        if source.startswith(("registry+", "sparse+")):
            lock.packages.append(LockedPkg(CRATES, e["name"], e["version"], source=source))
            by_name.setdefault(e["name"], []).append((e["name"], e["version"]))
        elif source:
            skipped += 1
    for e in entries:
        if e.get("source"):
            continue
        have_member = True  # workspace member: what it depends on is direct
        for spec in e.get("dependencies", []):
            parts = spec.split(" ")
            cands = by_name.get(parts[0], [])
            if len(parts) >= 2:
                direct.update(c for c in cands if c[1] == parts[1])
            else:
                direct.update(cands)
    if skipped:
        lock.notes.append(f"{skipped} package(s) from git sources are not listed")
    for p in lock.packages:
        p.direct = (p.name, p.version) in direct
    if not have_member:
        lock.direct_known = False
        lock.notes.append("Cargo.lock lists no workspace member; direct vs transitive is unknown")
    lock.notes.append("Cargo.lock embeds no license data; licenses come from ~/.cargo/registry or crates.io")
    return lock


# ------------------------------------------------------------------ go.sum


def parse_go_sum(path: str, text: str) -> Lockfile:
    lock = Lockfile(path, "go.sum", GO)
    for line in text.splitlines():
        parts = line.split()
        if len(parts) >= 2 and not parts[1].endswith("/go.mod"):
            lock.packages.append(LockedPkg(GO, parts[0], parts[1]))
    mod = _read_optional(os.path.join(lock.directory, "go.mod"))
    if mod is None:
        lock.direct_known = False
        lock.notes.append("no go.mod next to go.sum; direct vs transitive is unknown")
    else:
        direct: set[str] = set()
        in_block = False
        for line in mod.splitlines():
            s = line.strip()
            if s.startswith("require ("):
                in_block = True
                continue
            if in_block and s == ")":
                in_block = False
                continue
            if in_block or s.startswith("require "):
                entry = s.removeprefix("require ").strip()
                if entry and "// indirect" not in entry and not entry.startswith("//"):
                    direct.add(entry.split()[0])
        for p in lock.packages:
            p.direct = p.name in direct
    lock.notes.append("Go has no license metadata in go.sum: licenses are UNKNOWN unless you supply policy exceptions")
    return lock


_PARSERS: dict[str, Callable[[str, str], Lockfile]] = {
    "uv.lock": parse_uv_lock,
    "poetry.lock": parse_poetry_lock,
    "requirements.txt": parse_requirements,
    "package-lock.json": parse_package_lock,
    "pnpm-lock.yaml": parse_pnpm_lock,
    "yarn.lock": parse_yarn_lock,
    "Cargo.lock": parse_cargo_lock,
    "go.sum": parse_go_sum,
}
