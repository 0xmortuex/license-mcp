"""Online lookups against a local HTTP server standing in for PyPI / npm / crates.io,
plus an opt-in real-network test (`pytest -m network`)."""

from __future__ import annotations

import json
import threading
from collections.abc import Iterator
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

import pytest

from license_mcp import lockfiles as lf
from license_mcp import online as net
from license_mcp import scan as scanner
from license_mcp.sandbox import Sandbox

from .conftest import copy_fixture, write

REQUESTS: list[str] = []

PYPI_DOCS = {
    "alpha/1.0.0": {"info": {"license_expression": "MIT", "license": "", "classifiers": []}},
    "beta/2.0.0": {"info": {"license_expression": None, "license": "BSD",
                            "classifiers": ["License :: OSI Approved :: BSD License"]}},
    "gamma/3.0.0": {"info": {"license_expression": None, "license": None,
                             "classifiers": ["License :: OSI Approved :: GNU General Public License v3 (GPLv3)"]}},
    "delta/4.0.0": {"info": {"license_expression": None, "license": "UNKNOWN", "classifiers": []}},
}
NPM_DOCS = {"debug/4.4.3": {"license": "MIT"}, "ms/2.1.3": {"license": {"type": "ISC"}},
            "semver/7.8.6": {"licenses": [{"type": "MIT"}, {"type": "Apache-2.0"}]}}
CRATE_DOCS = {"chrono/0.4.19": {"version": {"license": "MIT/Apache-2.0"}}}


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args: Any) -> None:
        pass

    def do_GET(self) -> None:  # noqa: N802
        REQUESTS.append(self.path)
        parts = self.path.strip("/").split("/")
        eco, rest = parts[0], parts[1:]
        if eco == "pypi":
            key = "/".join(rest[:2])
            doc = PYPI_DOCS.get(key)
        elif eco == "npm":
            key = "/".join(rest).replace("%2F", "/")
            doc = NPM_DOCS.get(key)
        else:
            key = "/".join(rest)
            doc = CRATE_DOCS.get(key)
        if "boom" in self.path:
            self.send_response(500)
            self.end_headers()
            return
        if "redir" in self.path:
            self.send_response(302)
            self.send_header("Location", "http://127.0.0.1:1/evil")
            self.end_headers()
            return
        if "huge" in self.path:
            body = b'{"x": "' + b"a" * (net.MAX_RESPONSE_BYTES + 10) + b'"}'
        elif doc is None:
            self.send_response(404)
            self.end_headers()
            return
        else:
            body = json.dumps(doc).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


@pytest.fixture
def fake_registries(monkeypatch: pytest.MonkeyPatch) -> Iterator[str]:
    REQUESTS.clear()
    net.clear_cache()
    srv = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=lambda: srv.serve_forever(poll_interval=0.05), daemon=True).start()
    base = f"http://127.0.0.1:{srv.server_address[1]}"
    monkeypatch.setitem(net.BASES, lf.PYPI, base + "/pypi")
    monkeypatch.setitem(net.BASES, lf.NPM, base + "/npm")
    monkeypatch.setitem(net.BASES, lf.CRATES, base + "/crates")
    yield base
    srv.shutdown()
    srv.server_close()
    net.clear_cache()


def test_lookup_each_registry(fake_registries: str) -> None:
    r = net.lookup(lf.PYPI, "alpha", "1.0.0")
    assert r.normalized is not None and r.normalized.expression == "MIT" and r.source == "online: PyPI"
    assert net.lookup(lf.PYPI, "beta", "2.0.0").normalized.expression == "BSD-3-Clause"  # type: ignore[union-attr]
    assert net.lookup(lf.PYPI, "gamma", "3.0.0").normalized.expression == "GPL-3.0-only"  # type: ignore[union-attr]
    assert net.lookup(lf.NPM, "ms", "2.1.3").normalized.expression == "ISC"  # type: ignore[union-attr]
    assert net.lookup(lf.NPM, "semver", "7.8.6").normalized.expression == "MIT OR Apache-2.0"  # type: ignore[union-attr]
    assert net.lookup(lf.CRATES, "chrono", "0.4.19").normalized.expression == "MIT OR Apache-2.0"  # type: ignore[union-attr]


def test_scoped_npm_names_are_encoded(fake_registries: str) -> None:
    net.lookup(lf.NPM, "@babel/core", "7.0.0")
    assert REQUESTS[-1] == "/npm/@babel%2Fcore/7.0.0"


def test_cache_means_one_request(fake_registries: str) -> None:
    net.lookup(lf.PYPI, "alpha", "1.0.0")
    net.lookup(lf.PYPI, "alpha", "1.0.0")
    assert len(REQUESTS) == 1


@pytest.mark.parametrize(("name", "fragment"), [
    ("missing", "not found"),
    ("boom", "HTTP 500"),
    ("redir", "HTTP 302"),
    ("huge", "larger than"),
])
def test_failures_are_reported_not_swallowed(fake_registries: str, name: str, fragment: str) -> None:
    r = net.lookup(lf.PYPI, name, "1.0.0")
    assert r.normalized is None and r.error is not None and fragment in r.error


def test_redirects_are_never_followed(fake_registries: str) -> None:
    net.lookup(lf.PYPI, "redir", "1.0.0")
    assert all("evil" not in p for p in REQUESTS)


@pytest.mark.parametrize(("eco", "name", "version"), [
    (lf.PYPI, "../../etc/passwd", "1.0"),
    (lf.PYPI, "a/b", "1.0"),
    (lf.PYPI, "alpha", "1.0/../x"),
    (lf.PYPI, "alpha", "1.0?x=1"),
    (lf.PYPI, "a b", "1.0"),
    (lf.NPM, "@scope/../x", "1.0.0"),
    (lf.NPM, "a@b", "1.0.0"),
    (lf.CRATES, "a/../b", "1.0.0"),
    (lf.PYPI, "x" * 500, "1.0"),
    (lf.GO, "example.com/a", "v1.0.0"),
])
def test_suspicious_names_never_reach_the_network(fake_registries: str, eco: str, name: str, version: str) -> None:
    r = net.lookup(eco, name, version)
    assert r.error is not None and REQUESTS == []


def test_unreachable_host_is_an_error_message(monkeypatch: pytest.MonkeyPatch) -> None:
    net.clear_cache()
    monkeypatch.setitem(net.BASES, lf.PYPI, "http://127.0.0.1:1/pypi")
    r = net.lookup(lf.PYPI, "alpha", "1.0.0")
    assert r.error is not None and "unreachable" in r.error


def test_production_bases_are_the_three_fixed_https_hosts() -> None:
    assert set(net.BASES.values()) == {
        "https://pypi.org/pypi", "https://registry.npmjs.org", "https://crates.io/api/v1/crates"}


def test_scan_online_fills_only_what_offline_could_not(tmp_path: Path, fake_registries: str) -> None:
    proj = copy_fixture("npm3", tmp_path / "web")
    # the lockfile embeds licenses, so offline is enough and nothing should be requested
    s = scanner.scan(str(proj), Sandbox([str(tmp_path)]), online=True)
    assert REQUESTS == [] and all(not p.normalized.unknown for p in s.pkgs)

    write(tmp_path / "py" / "uv.lock", (Path(__file__).parent / "fixtures" / "lock" / "uv" / "uv.lock")
          .read_text(encoding="utf-8"))
    write(tmp_path / "py2" / "requirements.txt", "alpha==1.0.0\nbeta==2.0.0\ngamma==3.0.0\ndelta==4.0.0\nmissing==9.9\n")
    s2 = scanner.scan(str(tmp_path / "py2"), Sandbox([str(tmp_path)]), online=True)
    by = {p.pkg.name: p for p in s2.pkgs}
    assert by["alpha"].normalized.expression == "MIT" and by["alpha"].source == "online: PyPI"
    assert by["gamma"].normalized.expression == "GPL-3.0-only"
    assert by["delta"].normalized.unknown  # the record exists but says UNKNOWN
    assert any("no license information" in n or "UNKNOWN" in n or "placeholder" in n for n in by["delta"].notes)
    assert by["missing"].normalized.unknown and any("not found" in n for n in by["missing"].notes)
    assert any("online lookup(s) failed" in n for n in s2.notes)


def test_online_false_never_touches_the_network(tmp_path: Path, fake_registries: str) -> None:
    write(tmp_path / "requirements.txt", "alpha==1.0.0\n")
    scanner.scan(str(tmp_path), Sandbox([str(tmp_path)]), online=False)
    assert REQUESTS == []


def test_lookup_ceiling(monkeypatch: pytest.MonkeyPatch, fake_registries: str) -> None:
    monkeypatch.setattr(net, "MAX_LOOKUPS", 2)
    pkgs = [lf.LockedPkg(lf.PYPI, n, v) for n, v in (("alpha", "1.0.0"), ("beta", "2.0.0"), ("gamma", "3.0.0"))]
    res = net.lookup_many(pkgs)
    assert res[pkgs[2].key].error is not None and "more than 2" in res[pkgs[2].key].error  # type: ignore[operator]
    assert res[pkgs[0].key].normalized is not None


@pytest.mark.network
def test_real_registries() -> None:
    net.clear_cache()
    assert net.lookup(lf.PYPI, "six", "1.16.0").normalized is not None
    r = net.lookup(lf.PYPI, "six", "1.16.0")
    assert r.normalized is not None and r.normalized.expression == "MIT"
    n = net.lookup(lf.NPM, "ms", "2.1.3")
    assert n.normalized is not None and n.normalized.expression == "MIT"
    c = net.lookup(lf.CRATES, "itoa", "1.0.0")
    assert c.error is None and c.normalized is not None and "MIT" in (c.normalized.expression or "")
    assert net.lookup(lf.PYPI, "definitely-not-a-real-package-xyz", "1.0").error is not None
