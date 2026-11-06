"""license-mcp: what licenses are my dependencies under, and can I ship this?"""

from __future__ import annotations

import argparse
import functools
import os
import sys
from collections.abc import Callable
from typing import Any, TypeVar

from mcp.server.mcpserver import MCPServer
from mcp.server.mcpserver.exceptions import ToolError
from mcp.types import ToolAnnotations

from . import __version__, compat, report
from . import explain as ex
from . import policy as pol
from . import scan as scanner
from .errors import LicenseError
from .sandbox import Sandbox

mcp = MCPServer(
    "license-mcp",
    instructions=(
        "Answers 'what licenses are my dependencies under, and can I ship this?' from a project's lockfiles "
        "(uv.lock, poetry.lock, requirements.txt, package-lock.json, pnpm-lock.yaml, yarn.lock v1, Cargo.lock, "
        "go.sum), mostly offline: it reads the licenses of packages already installed in the project's venv / "
        "node_modules / cargo registry, then lockfile data, and only looks online if online=true. Every package "
        "reports where its license came from and UNKNOWN is never guessed. Start with license_inventory; use "
        "check_policy for ok / needs review / violation verdicts; compatibility and explain_license answer "
        "general license questions without touching files; generate_notices drafts THIRD-PARTY-NOTICES.md "
        "(returned as text); find_license_files lists which dependencies ship LICENSE/NOTICE files. "
        "Read-only. Guidance, not legal advice."
    ),
)

_sandbox: Sandbox | None = None
F = TypeVar("F", bound=Callable[..., Any])
_READ_ONLY = ToolAnnotations(read_only_hint=True, destructive_hint=False, idempotent_hint=True)
_READ_ONLY_NET = ToolAnnotations(
    read_only_hint=True, destructive_hint=False, idempotent_hint=True, open_world_hint=True
)


def _sb() -> Sandbox:
    global _sandbox
    if _sandbox is None:
        env = os.environ.get("LICENSE_MCP_DIRS")
        roots = [d for d in env.split(os.pathsep) if d] if env else [os.getcwd()]
        _sandbox = Sandbox(roots)
    return _sandbox


def tool(annotations: ToolAnnotations = _READ_ONLY) -> Callable[[F], F]:
    def deco(fn: F) -> F:
        @functools.wraps(fn)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            try:
                return fn(*args, **kwargs)
            except LicenseError as e:  # includes SpdxError
                raise ToolError(str(e)) from e
            except OSError as e:
                raise ToolError(f"file system error: {e.strerror or e} ({e.filename or ''})") from e

        mcp.tool(annotations=annotations)(wrapper)
        return fn

    return deco


def _policy_dir(root: str) -> str:
    return root if os.path.isdir(root) else os.path.dirname(root)


@tool()
def license_inventory(
    path: str = ".",
    python: str | None = None,
    online: bool = False,
    allow: list[str] | None = None,
    list_limit: int = 15,
) -> str:
    """List every dependency's license, grouped, with where each answer came from.

    `path` is a project directory (lockfiles are found up to 3 levels down) or one lockfile.
    License sources, in priority order: (1) packages already installed - a Python venv at
    `.venv`/`venv` next to the lockfile, or the one you give as `python` (a venv dir, its
    python executable, or a site-packages dir), node_modules, ~/.cargo/registry; (2) data in
    the lockfile itself (package-lock.json has it); (3) a network lookup against PyPI / npm /
    crates.io, ONLY if online=true. Anything none of these answers is UNKNOWN - never guessed.

    The output groups packages by normalised SPDX expression with direct/transitive counts,
    lists UNKNOWN packages with the reason, shows dual-licensed (OR) packages and which option
    applies (`allow` is an optional list of SPDX ids you accept; otherwise the least
    restrictive option is shown), and flags ambiguous spellings such as plain 'BSD'.
    """
    s = scanner.scan(path, _sb(), python, online)
    return report.inventory(s, allow, max(1, min(list_limit, 500)))


@tool()
def check_policy(
    path: str = ".",
    allow: list[str] | None = None,
    deny: list[str] | None = None,
    project_license: str | None = None,
    python: str | None = None,
    online: bool = False,
    show_ok: bool = False,
    limit: int = 50,
) -> str:
    """Give each dependency a verdict - ok / needs review / violation - with reasons.

    Policy comes from the arguments or from a `.license-policy.toml` in `path` (arguments win,
    key by key). Entries in allow/deny are SPDX ids ('MIT', 'GPL-2.0' is read as GPL-2.0-only),
    wildcards ('BSD-*'), or category names: public-domain, permissive, weak-copyleft,
    strong-copyleft, network-copyleft, source-available, noncommercial, restricted, proprietary.
    The TOML file may also hold `project_license = "..."` and an `[exceptions]` table mapping
    a package name (or name@version) to the reason you accepted it.

    Rules: deny beats allow; with an allow list, anything known and not on it is a violation;
    otherwise, if `project_license` is given, each dependency is judged by the compatibility
    table (compatible = ok, conditional = needs review, incompatible = violation); with
    neither, permissive licenses are ok, weak copyleft (LGPL/MPL/EPL) needs review with linking
    notes, and strong/network copyleft, source-available and non-commercial licenses are
    violations. UNKNOWN and unclassified licenses always need review. OR expressions take the
    best option for you, AND expressions the worst. Same license sources as license_inventory.
    """
    s = scanner.scan(path, _sb(), python, online)
    p = pol.load_policy(_policy_dir(s.root), allow, deny, project_license)
    return report.policy_report(s, p, pol.evaluate_scan(s, p), show_ok, max(1, min(limit, 1000)))


@tool()
def compatibility(project_license: str, dependency_license: str) -> str:
    """Can code under `dependency_license` be used in a project licensed `project_license`?

    Both accept SPDX ids/expressions or common spellings ('MIT', 'Apache 2', 'GPL-3.0-only',
    'MIT OR Apache-2.0'); use 'proprietary' for a closed-source project. Answers compatible /
    conditional / incompatible / unknown from a small documented rule table (rule ids R1-R12 are
    cited), with the reasoning: e.g. Apache-2.0 into GPL-2.0-only is incompatible, into GPL-3.0
    is fine; AGPL gets a network-clause note. A project offered under several licenses must
    be compatible with each option. Does not read any files.
    """
    pn = compat.parse_side(project_license, "project_license")
    dn = compat.parse_side(dependency_license, "dependency_license")
    assert pn.node is not None and dn.node is not None
    res = compat.evaluate(pn.node, dn.node)
    lines = [
        f"Dependency {dn.expression} into a project licensed {pn.expression}: {res.verdict.upper()}",
        f"Rule {res.rule}: {res.reason}",
    ]
    for n in (*pn.notes, *dn.notes):
        if n.startswith("read ") or n.startswith("normalised"):
            lines.append(f"Note: {n}")
    for n in res.notes:
        lines.append(f"Note: {n}")
    lines += [
        "",
        "Direction: a combined work (the dependency included or linked) distributed under the project license. "
        "Using a tool as a separate program, or running a service you never distribute, is usually different "
        "(except for the AGPL/SSPL network clauses).",
        "This is guidance from a small documented table, not legal advice; for anything commercial or unusual, "
        "have a lawyer read the actual licenses.",
    ]
    return "\n".join(lines)


@tool()
def explain_license(spdx_id: str) -> str:
    """Explain a license in plain words: what you can do, what you must do, and the limits.

    Accepts an SPDX id ('MIT', 'GPL-3.0-only'), a common spelling ('Apache 2'), a deprecated id
    ('GPL-2.0' is read as GPL-2.0-only), or an expression ('MIT OR Apache-2.0',
    'GPL-2.0-only WITH Classpath-exception-2.0'). Covers about 50 common licenses from an embedded,
    hand-written table; for others it says so rather than guessing. Does not read any files.
    """
    return ex.explain(spdx_id)


@tool(_READ_ONLY_NET)
def generate_notices(path: str = ".", python: str | None = None, online: bool = False) -> str:
    """Draft a THIRD-PARTY-NOTICES.md for the project's dependencies, returned as text (nothing is written).

    One entry per package: name, version, license, where the license came from, and copyright
    lines found in the package's installed LICENSE/COPYING files (or 'not found'). Packages with
    an UNKNOWN license are grouped under a heading so they cannot be missed. License texts are
    not embedded - copy them from the packages' own files (see find_license_files). Same license
    sources as license_inventory; copyright lines only exist for packages that are installed.
    """
    s = scanner.scan(path, _sb(), python, online)
    return report.notices(s, _sb())


@tool()
def find_license_files(path: str = ".", python: str | None = None) -> str:
    """Show which dependencies ship a LICENSE / COPYING / NOTICE file in their installed copy.

    Looks in the project's venv dist-info (including PEP 639 `licenses/`), node_modules package
    directories and ~/.cargo/registry. Lists packages with files (flagging NOTICE files you must
    reproduce under Apache-2.0), packages installed without any license file, and packages with no
    installed copy to inspect. Offline only.
    """
    s = scanner.scan(path, _sb(), python, False)
    return report.license_files(s)


def main(argv: list[str] | None = None) -> None:
    global _sandbox
    ap = argparse.ArgumentParser(
        prog="license-mcp",
        description="MCP server (stdio) answering what licenses your dependencies use. Read-only.",
    )
    ap.add_argument(
        "--dir", action="append", default=[], metavar="DIR",
        help="allow reading this directory tree (repeatable; default: the current directory; "
             "can also be set with LICENSE_MCP_DIRS, separated by the OS path separator)",
    )
    ap.add_argument("--version", action="version", version=f"license-mcp {__version__}")
    args = ap.parse_args(argv if argv is not None else sys.argv[1:])
    if args.dir:
        for d in args.dir:
            if not os.path.isdir(d):
                ap.error(f"--dir {d!r} is not a directory")
        _sandbox = Sandbox([os.path.abspath(d) for d in args.dir])
    mcp.run()


if __name__ == "__main__":
    main()
