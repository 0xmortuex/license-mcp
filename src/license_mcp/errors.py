"""Errors the tool boundary turns into messages an agent can act on."""

from __future__ import annotations


class LicenseError(Exception):
    """An expected, user-actionable failure (bad path, unsupported lockfile, bad SPDX text)."""


class SpdxError(LicenseError):
    """A string that is not a parseable SPDX license expression."""
