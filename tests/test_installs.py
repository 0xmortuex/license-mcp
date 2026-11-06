"""Opt-in: install a few real, tiny, pure-Python packages into a temp venv with uv and read
their genuine metadata. Needs `uv` and network; run with `pytest -m installs`."""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

from license_mcp import scan as scanner
from license_mcp.sandbox import Sandbox

from .conftest import write

pytestmark = pytest.mark.installs


def test_real_installed_packages(tmp_path: Path) -> None:
    uv = shutil.which("uv")
    if uv is None:
        pytest.skip("uv is not installed")
    proj = tmp_path / "proj"
    write(proj / "requirements.txt", "six==1.16.0\npackaging==24.0\npython-dateutil==2.9.0.post0\n")
    venv = proj / ".venv"
    subprocess.run([uv, "venv", str(venv)], check=True, capture_output=True, text=True, cwd=proj)
    subprocess.run(
        [uv, "pip", "install", "--python", str(venv), "six==1.16.0", "packaging==24.0", "python-dateutil==2.9.0.post0"],
        check=True, capture_output=True, text=True, cwd=proj,
    )
    s = scanner.scan(str(proj), Sandbox([str(tmp_path)]))
    by = {p.pkg.name: p for p in s.pkgs}
    assert by["six"].normalized.expression == "MIT"
    assert by["six"].source.startswith("installed metadata")
    assert by["six"].files, "six ships a LICENSE file in its dist-info"
    for name in ("packaging", "python-dateutil"):
        assert not by[name].normalized.unknown, by[name].notes
        assert by[name].source.startswith("installed metadata")
    # python-dateutil is dual Apache-2.0 / BSD: its classifiers list both
    assert "Apache-2.0" in (by["python-dateutil"].normalized.expression or "")
