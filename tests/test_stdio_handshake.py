"""MCP stdio smoke test: spawns the installed server as a real process, lists the tools, calls them,
and checks that instructive errors survive the trip to the agent (MCPServer hides any exception that
is not a ToolError)."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

pytest.importorskip("mcp")

from mcp import ClientSession  # noqa: E402
from mcp.client.stdio import StdioServerParameters, stdio_client  # noqa: E402

from .conftest import MIT_TEXT, add_dist, site_packages, write  # noqa: E402
from .test_scan_policy import UV_LOCK  # noqa: E402

EXPECTED_TOOLS = {
    "license_inventory",
    "check_policy",
    "compatibility",
    "explain_license",
    "generate_notices",
    "find_license_files",
}


def make_project(tmp: Path) -> Path:
    proj = tmp / "proj"
    write(proj / "uv.lock", UV_LOCK)
    sp = site_packages(proj / ".venv")
    add_dist(sp, "alpha", "1.0.0", expression="MIT", files={"LICENSE": MIT_TEXT})
    add_dist(sp, "gamma", "3.0.0", expression="GPL-3.0-only")
    add_dist(sp, "delta", "4.0.0", expression="MIT OR GPL-3.0-only")
    return proj


def params(allowed: Path) -> StdioServerParameters:
    return StdioServerParameters(command=sys.executable, args=["-m", "license_mcp", "--dir", str(allowed)])


def text(res: object) -> str:
    return res.content[0].text  # type: ignore[attr-defined,no-any-return]


@pytest.mark.anyio
async def test_tools_and_a_session_over_stdio(tmp_path: Path) -> None:
    proj = make_project(tmp_path)
    async with stdio_client(params(tmp_path)) as (read, write_), ClientSession(read, write_) as session:
        init = await session.initialize()
        assert init.server_info.name == "license-mcp"
        tools = (await session.list_tools()).tools
        assert {t.name for t in tools} == EXPECTED_TOOLS
        assert all(t.description and len(t.description) > 100 for t in tools)
        assert all(t.annotations is not None and t.annotations.read_only_hint for t in tools)

        res = await session.call_tool("license_inventory", {"path": str(proj)})
        assert not res.is_error
        out = text(res)
        assert "MIT  -  " in out and "GPL-3.0-only" in out and "not legal advice" in out

        res = await session.call_tool("check_policy", {"path": str(proj), "allow": ["MIT"]})
        assert not res.is_error and "RESULT: FAIL" in text(res) and "gamma@3.0.0" in text(res)

        res = await session.call_tool("check_policy", {"path": str(proj), "project_license": "GPL-3.0-only"})
        assert "gamma@3.0.0" not in text(res).split("OK (")[0]

        res = await session.call_tool("compatibility", {"project_license": "GPL-2.0-only", "dependency_license": "Apache-2.0"})
        assert "INCOMPATIBLE" in text(res)
        res = await session.call_tool("explain_license", {"spdx_id": "MPL-2.0"})
        assert "Mozilla Public License 2.0" in text(res)
        res = await session.call_tool("generate_notices", {"path": str(proj)})
        assert "# Third-Party Notices" in text(res) and "Copyright (c) 2021 Jane Doe" in text(res)
        res = await session.call_tool("find_license_files", {"path": str(proj)})
        assert "alpha@1.0.0: LICENSE" in text(res)
        # nothing was written anywhere
        assert not (proj / "THIRD-PARTY-NOTICES.md").exists()


@pytest.mark.anyio
async def test_instructive_errors_reach_the_agent(tmp_path: Path) -> None:
    proj = make_project(tmp_path)
    outside = tmp_path.parent / (tmp_path.name + "_outside")
    write(outside / "requirements.txt", "six==1.16.0\n")
    allowed = tmp_path / "proj"
    async with stdio_client(params(allowed)) as (read, write_), ClientSession(read, write_) as session:
        await session.initialize()
        res = await session.call_tool("license_inventory", {"path": str(outside)})
        assert res.is_error and "outside the allowed directories" in text(res) and "--dir" in text(res)
        res = await session.call_tool("license_inventory", {"path": str(proj / ".." / ".." / "etc")})
        assert res.is_error and "outside the allowed" in text(res)
        res = await session.call_tool("license_inventory", {"path": str(proj / "nothing-here")})
        assert res.is_error and "does not exist" in text(res)
        res = await session.call_tool("compatibility", {"project_license": "banana", "dependency_license": "MIT"})
        assert res.is_error and "cannot interpret project_license" in text(res)
        res = await session.call_tool("check_policy", {"path": str(proj), "allow": ["not a license"]})
        assert res.is_error and "not a recognisable license" in text(res)
        res = await session.call_tool("license_inventory", {"path": str(proj), "python": str(tmp_path / "x")})
        assert res.is_error and "outside the allowed" in text(res)
        res = await session.call_tool("explain_license", {"spdx_id": "((("})
        assert not res.is_error and "Cannot interpret" in text(res)


@pytest.mark.anyio
async def test_default_sandbox_is_the_working_directory(tmp_path: Path) -> None:
    proj = make_project(tmp_path)
    p = StdioServerParameters(command=sys.executable, args=["-m", "license_mcp"], cwd=str(proj))
    async with stdio_client(p) as (read, write_), ClientSession(read, write_) as session:
        await session.initialize()
        res = await session.call_tool("license_inventory", {})  # path defaults to "."
        assert not res.is_error and "alpha@1.0.0" in text(res)
        res = await session.call_tool("license_inventory", {"path": str(tmp_path.parent)})
        assert res.is_error and "outside the allowed" in text(res)


@pytest.mark.anyio
async def test_hostile_arguments_over_stdio(tmp_path: Path) -> None:
    proj = make_project(tmp_path)
    async with stdio_client(params(tmp_path)) as (read, write_), ClientSession(read, write_) as session:
        await session.initialize()
        for args in (
            {"project_license": "A" * 3_000_000, "dependency_license": "MIT"},
            {"project_license": "(" * 50_000, "dependency_license": "MIT"},
            {"project_license": "MIT", "dependency_license": "\x00"},
            {"project_license": "MIT OR " * 5000 + "MIT", "dependency_license": "MIT"},
        ):
            res = await session.call_tool("compatibility", args)
            assert res.is_error, args
        res = await session.call_tool("license_inventory", {"path": "x\x00y"})
        assert res.is_error
        res = await session.call_tool("license_inventory", {"path": str(proj), "list_limit": -5})
        assert not res.is_error
        res = await session.call_tool("check_policy", {"path": str(proj), "limit": 10**9, "allow": ["*"]})
        assert not res.is_error
        # the server is still healthy afterwards
        res = await session.call_tool("explain_license", {"spdx_id": "MIT"})
        assert not res.is_error
