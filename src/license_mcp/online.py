"""Optional network lookups (only when a tool is called with online=true).

Safety properties:
* Only three fixed hostnames are ever contacted (pypi.org, registry.npmjs.org, crates.io).
  The URL is built from a fixed base plus a package name/version that passed a strict
  allow-list pattern; redirects are refused, so a response cannot send us elsewhere.
* Polite: at most MAX_WORKERS requests in flight, a per-request timeout, a response size
  cap, a descriptive User-Agent, an in-process cache, and a ceiling on lookups per call.
* Failures are reported per package (they never become a silent 'unknown').
"""

from __future__ import annotations

import json
import re
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from typing import Any

from . import lockfiles as lf
from .installed import python_license
from .normalize import Normalized, normalize

# Module-level so tests can point them at a local server; never settable through a tool.
BASES: dict[str, str] = {
    lf.PYPI: "https://pypi.org/pypi",
    lf.NPM: "https://registry.npmjs.org",
    lf.CRATES: "https://crates.io/api/v1/crates",
}
LABELS = {lf.PYPI: "PyPI", lf.NPM: "npm registry", lf.CRATES: "crates.io"}
MAX_WORKERS = 6
TIMEOUT_S = 10.0
MAX_RESPONSE_BYTES = 2 * 1024 * 1024
MAX_LOOKUPS = 400
CACHE_TTL_S = 3600.0
USER_AGENT = "license-mcp/0.1 (+https://github.com/0xmortuex/license-mcp)"

_NAME = {
    lf.PYPI: re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,200}"),
    lf.NPM: re.compile(r"(@[A-Za-z0-9~._-]{1,100}/)?[A-Za-z0-9~._-]{1,200}"),
    lf.CRATES: re.compile(r"[A-Za-z0-9_-]{1,100}"),
}
_VERSION = re.compile(r"[A-Za-z0-9][A-Za-z0-9._+!-]{0,100}")


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args: Any, **kwargs: Any) -> None:
        return None


_OPENER = urllib.request.build_opener(_NoRedirect)
_cache: dict[tuple[str, str, str], tuple[float, "OnlineResult"]] = {}
_lock = threading.Lock()


@dataclass
class OnlineResult:
    normalized: Normalized | None
    source: str
    error: str | None = None


def clear_cache() -> None:
    with _lock:
        _cache.clear()


def build_url(ecosystem: str, name: str, version: str) -> str:
    """The one URL we would fetch for this package. Raises ValueError if the name/version is suspicious."""
    base = BASES.get(ecosystem)
    if base is None:
        raise ValueError(f"no online license source for {ecosystem} packages")
    if not _NAME[ecosystem].fullmatch(name) or not _VERSION.fullmatch(version):
        raise ValueError(f"refusing to look up unusual package name/version {name!r} {version!r}")
    q = urllib.parse.quote
    if ecosystem == lf.PYPI:
        return f"{base}/{q(name, safe='')}/{q(version, safe='')}/json"
    if ecosystem == lf.NPM:
        return f"{base}/{q(name, safe='@')}/{q(version, safe='')}"
    return f"{base}/{q(name, safe='')}/{q(version, safe='')}"


def _get_json(url: str) -> Any:
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT, "Accept": "application/json"})
    with _OPENER.open(req, timeout=TIMEOUT_S) as resp:
        body = resp.read(MAX_RESPONSE_BYTES + 1)
    if len(body) > MAX_RESPONSE_BYTES:
        raise ValueError(f"response larger than {MAX_RESPONSE_BYTES} bytes")
    return json.loads(body.decode("utf-8", "replace"))


def _parse(ecosystem: str, doc: Any) -> Normalized | None:
    if not isinstance(doc, dict):
        raise ValueError("unexpected response shape")
    if ecosystem == lf.PYPI:
        info = doc.get("info") or {}
        classifiers = [c for c in (info.get("classifiers") or []) if isinstance(c, str) and c.startswith("License ::")]
        n, _ = python_license(info.get("license_expression"), info.get("license"), classifiers)
        return n
    if ecosystem == lf.NPM:
        raw = lf._npm_license_field(doc.get("license")) or lf._npm_license_field(doc.get("licenses"))
        return normalize(raw) if raw else None
    ver = doc.get("version") or {}
    raw = ver.get("license")
    return normalize(raw) if isinstance(raw, str) and raw.strip() else None


def lookup(ecosystem: str, name: str, version: str) -> OnlineResult:
    label = f"online: {LABELS.get(ecosystem, ecosystem)}"
    key = (ecosystem, name, version)
    with _lock:
        hit = _cache.get(key)
        if hit and time.monotonic() - hit[0] < CACHE_TTL_S:
            return hit[1]
    try:
        url = build_url(ecosystem, name, version)
        doc = _get_json(url)
        res = OnlineResult(_parse(ecosystem, doc), label)
    except urllib.error.HTTPError as e:
        msg = "not found" if e.code == 404 else f"HTTP {e.code}"
        res = OnlineResult(None, label, f"{LABELS.get(ecosystem, ecosystem)}: {msg}")
    except (urllib.error.URLError, TimeoutError, ConnectionError, OSError) as e:
        reason = getattr(e, "reason", e)
        res = OnlineResult(None, label, f"{LABELS.get(ecosystem, ecosystem)} unreachable: {reason}")
    except ValueError as e:
        res = OnlineResult(None, label, f"{LABELS.get(ecosystem, ecosystem)}: {e}")
    if res.error is None:
        with _lock:
            _cache[key] = (time.monotonic(), res)
    return res


def lookup_many(pkgs: list[lf.LockedPkg]) -> dict[tuple[str, str, str], OnlineResult]:
    """Look up many packages with bounded concurrency. Packages beyond MAX_LOOKUPS get an explicit error."""
    results: dict[tuple[str, str, str], OnlineResult] = {}
    todo = pkgs[:MAX_LOOKUPS]
    for p in pkgs[MAX_LOOKUPS:]:
        results[p.key] = OnlineResult(None, "online", f"not looked up: more than {MAX_LOOKUPS} packages in one call")
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as ex:
        for p, res in zip(todo, ex.map(lambda p: lookup(p.ecosystem, p.name, p.version), todo), strict=True):
            results[p.key] = res
    return results
