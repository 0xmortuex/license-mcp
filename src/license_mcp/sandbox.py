"""Directory sandbox: every path the tools read must resolve inside an allowed root."""

from __future__ import annotations

import os

from .errors import LicenseError


def _norm(p: str) -> str:
    return os.path.normcase(os.path.realpath(p))


class Sandbox:
    def __init__(self, roots: list[str]) -> None:
        if not roots:
            raise LicenseError("no allowed directories configured")
        self.roots = [_norm(r) for r in roots]
        self._real = [os.path.realpath(r) for r in roots]
        self._primary_real = self._real[0]
        self.extra: list[str] = []  # fixed read-only locations such as the cargo registry

    @property
    def primary(self) -> str:
        return self._primary_real

    def allow_extra(self, path: str) -> None:
        self.extra.append(_norm(path))

    def contains(self, path: str) -> bool:
        """True if the *real* location of `path` (symlinks resolved) is inside a root."""
        real = _norm(path)
        for r in [*self.roots, *self.extra]:
            if real == r or real.startswith(r.rstrip("\\/") + os.sep):
                return True
        return False

    def resolve(self, path: str, what: str = "path") -> str:
        """Absolute form of a user-supplied path, refused if it is outside the sandbox."""
        if not path or "\x00" in path:
            raise LicenseError(f"{what} is empty or contains a NUL byte")
        p = os.path.expanduser(path)
        if not os.path.isabs(p):
            p = os.path.join(self.primary, p)
        p = os.path.abspath(p)
        real = _norm(p)
        for r in self.roots:
            if real == r or real.startswith(r.rstrip("\\/") + os.sep):
                return p
        raise LicenseError(
            f"{what} '{path}' is outside the allowed directories "
            f"({', '.join(self._real)}). Start the server with --dir for the project you want to inspect."
        )
