"""Shared builders: fake site-packages (dist-info), node_modules trees, cargo registries."""

from __future__ import annotations

import os
import shutil
from collections.abc import Callable
from pathlib import Path

import pytest

from license_mcp.sandbox import Sandbox

FIXTURES = Path(__file__).parent / "fixtures" / "lock"


def write(path: Path, text: str) -> None:
    """UTF-8 with explicit LF newlines, so fixtures are identical on every OS."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(text)


def copy_fixture(name: str, dest: Path) -> Path:
    shutil.copytree(FIXTURES / name, dest, dirs_exist_ok=True)
    return dest


def site_packages(venv: Path, posix: bool = False) -> Path:
    sp = venv / "lib" / "python3.12" / "site-packages" if posix else venv / "Lib" / "site-packages"
    sp.mkdir(parents=True, exist_ok=True)
    (venv / "pyvenv.cfg").write_text("home = x\n", encoding="utf-8")
    return sp


def add_dist(
    sp: Path,
    name: str,
    version: str,
    *,
    expression: str | None = None,
    license_field: str | None = None,
    classifiers: tuple[str, ...] = (),
    files: dict[str, str] | None = None,
    pep639: dict[str, str] | None = None,
) -> Path:
    di = sp / f"{name.replace('-', '_')}-{version}.dist-info"
    lines = ["Metadata-Version: 2.4", f"Name: {name}", f"Version: {version}"]
    if expression is not None:
        lines.append(f"License-Expression: {expression}")
    if license_field is not None:
        lines.append("License: " + license_field.replace("\n", "\n        "))
    lines += [f"Classifier: {c}" for c in classifiers]
    write(di / "METADATA", "\n".join(lines) + "\n\nLong description here.\n")
    for fname, text in (files or {}).items():
        write(di / fname, text)
    for fname, text in (pep639 or {}).items():
        write(di / "licenses" / fname, text)
    return di


def add_node_pkg(root: Path, name: str, version: str, license_value: object = None,
                 files: dict[str, str] | None = None, at: str | None = None) -> Path:
    import json

    d = root / (at or f"node_modules/{name}")
    data: dict[str, object] = {"name": name, "version": version}
    if license_value is not None:
        data["license"] = license_value
    write(d / "package.json", json.dumps(data))
    for fname, text in (files or {}).items():
        write(d / fname, text)
    return d


def add_crate(registry_home: Path, name: str, version: str, license_value: str | None,
              files: dict[str, str] | None = None) -> Path:
    d = registry_home / "registry" / "src" / "index.crates.io-test" / f"{name}-{version}"
    body = f'[package]\nname = "{name}"\nversion = "{version}"\n'
    if license_value is not None:
        body += f'license = "{license_value}"\n'
    write(d / "Cargo.toml", body)
    for fname, text in (files or {}).items():
        write(d / fname, text)
    return d


MIT_TEXT = "MIT License\n\nCopyright (c) 2021 Jane Doe\n\nPermission is hereby granted, free of charge...\n"


@pytest.fixture
def sandbox(tmp_path: Path) -> Sandbox:
    return Sandbox([str(tmp_path)])


@pytest.fixture(autouse=True)
def _isolated_cargo_home(tmp_path_factory: pytest.TempPathFactory, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Never read the developer's real ~/.cargo during tests."""
    home = tmp_path_factory.mktemp("cargo_home_default")
    monkeypatch.setenv("CARGO_HOME", str(home))
    return home


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


def can_symlink(tmp: Path) -> bool:
    try:
        target = tmp / "_t"
        target.mkdir(exist_ok=True)
        link = tmp / "_l"
        os.symlink(target, link, target_is_directory=True)
        link.unlink()
        return True
    except (OSError, NotImplementedError):
        return False


SymlinkCheck = Callable[[Path], bool]
