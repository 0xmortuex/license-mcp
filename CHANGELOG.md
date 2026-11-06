# Changelog

## 0.1.0 - 2026-11-06

First release.

- Lockfile parsers (hand-written, read-only): uv.lock, poetry.lock, requirements*.txt (pinned),
  package-lock.json v2/v3, pnpm-lock.yaml v6-v9, yarn.lock v1, Cargo.lock, go.sum (+ go.mod).
- License sources, in priority order, each reported per package: installed metadata (Python
  dist-info, node_modules package.json, ~/.cargo/registry), lockfile-embedded data, and an optional
  online lookup (`online=true`: PyPI, npm, crates.io only). UNKNOWN is explicit, never guessed.
- Own SPDX expression parser (AND / OR / WITH / parentheses / LicenseRef) and a normaliser for messy
  strings ('MIT License', 'Apache 2', 'GPLv2+', trove classifiers, deprecated ids).
- Tools: `license_inventory`, `check_policy` (+ `.license-policy.toml`), `compatibility`,
  `explain_license`, `generate_notices`, `find_license_files`.
- `--dir` sandbox (or `LICENSE_MCP_DIRS`); defaults to the current directory.
