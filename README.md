# license-mcp

**Ask your AI agent what licenses your dependencies are under, and whether you can ship the thing.**

<!-- mcp-name: io.github.0xmortuex/license-mcp -->

license-mcp is an [MCP](https://modelcontextprotocol.io) server that reads a project's lockfiles
(`uv.lock`, `poetry.lock`, `requirements.txt`, `package-lock.json`, `pnpm-lock.yaml`, `yarn.lock`,
`Cargo.lock`, `go.sum`), works out every dependency's license **mostly offline**, normalises it to
SPDX, and gives you an inventory, ok / needs review / violation verdicts against your policy,
compatibility guidance, and a draft `THIRD-PARTY-NOTICES.md`.

## How it differs from the other license MCP servers

Several servers already do part of this: [license-scan-mcp](https://github.com/TheoryofShadows/license-scan-mcp)
scans npm lockfiles for GPL/AGPL/unknown, [license-check-mcp](https://github.com/arhancanli/license-check-mcp)
answers "does license A fit license B" from the OSADL matrix, and
[LicenseGuard](https://mcpservers.org/servers/rccaoki-wq/license-guard) checks SBOMs. What this one adds:

- **It reads what is actually installed.** Licenses come first from the Python dist-info in your venv,
  `node_modules/*/package.json`, or `~/.cargo/registry`, then from the lockfile, and only then (and
  only if you pass `online=true`) from PyPI / npm / crates.io. No network by default.
- **Every package reports its source** (`installed metadata (License-Expression)`, `lockfile
  (package-lock.json)`, `online: PyPI`, or `none`), and **UNKNOWN is explicit, never guessed**.
- **Eight lockfile formats across Python, Node, Rust and Go** in one call, with direct vs transitive
  counts, using hand-written parsers (no heavy dependencies).
- **Its own SPDX engine**: `AND` / `OR` / `WITH`, parentheses, `LicenseRef-`, deprecated ids
  (`GPL-2.0` becomes `GPL-2.0-only`), and messy strings (`MIT License`, `Apache 2`, `GPLv2+`, trove
  classifiers). `OR` expressions are resolved against *your* allow list.
- **A small, documented compatibility table** whose answers cite the rule and the reasoning.

## What it looks like

Real output from the project's own venv (51 locked packages, nothing downloaded):

```
> license_inventory
Packages: 51 (6 direct, 45 transitive)
License sources: installed metadata 41, none 10

By license (9 distinct):
  MIT  -  23 package(s) (5 direct, 18 transitive)  [permissive]
  BSD-3-Clause  -  9 package(s) (0 direct, 9 transitive)  [permissive]
  Apache-2.0 OR BSD-3-Clause  -  1 package(s)  [permissive]      <- cryptography
  MPL-2.0  -  1 package(s) (0 direct, 1 transitive)  [weak-copyleft]
  ...
Dual/multi-licensed packages (2) - the OR choice:
  cryptography@50.0.2: Apache-2.0 OR BSD-3-Clause  ->  Apache-2.0
UNKNOWN (10) - no usable license data; not guessed:
  httpx2@2.14.0 (transitive): no license information; installed version 2.16.0 differs from locked 2.14.0; ...

> compatibility project_license="GPL-2.0-only" dependency_license="Apache-2.0"
Dependency Apache-2.0 into a project licensed GPL-2.0-only: INCOMPATIBLE
Rule R1: Apache-2.0's patent-termination and indemnity terms are extra restrictions under GPLv2
(FSF: Apache-2.0 is compatible with GPLv3 only)
```

## Install

```bash
pip install license-mcp          # or: uvx license-mcp
claude mcp add license -- uvx license-mcp --dir /path/to/your/project
```

Claude Desktop (`claude_desktop_config.json`):

```json
{
  "mcpServers": {
    "license": {
      "command": "uvx",
      "args": ["license-mcp", "--dir", "C:\\Users\\you\\code\\my-project"]
    }
  }
}
```

`--dir` may be repeated. Without it, the server may read the directory it was started in.

## Try asking

- "What licenses are my dependencies under? Show me anything unknown."
- "Can I ship this as closed source? Check the policy with `permissive` allowed."
- "Check my dependencies against GPL-3.0-only as the project license."
- "Which packages are dual-licensed, and which option should I take if I only accept MIT and Apache-2.0?"
- "Is Apache-2.0 code OK in a GPL-2.0-only project?"
- "Explain the AGPL in plain words."
- "Write a THIRD-PARTY-NOTICES.md for this project."
- "Which of my dependencies ship a NOTICE file I have to reproduce?"
- "Look up the unknown ones online too." (this passes `online=true`)

## Tools

| Tool | What it does |
|------|--------------|
| `license_inventory` | Every dependency's license grouped by normalised SPDX expression with direct/transitive counts, the `OR` choices, UNKNOWN packages with reasons, and ambiguous spellings flagged. |
| `check_policy` | ok / needs review / violation per package with reasons, from arguments or a `.license-policy.toml`. Copyleft strong and weak, source-available, non-commercial, unknown, unclassified. |
| `compatibility` | May code under license X be used in a project under license Y? compatible / conditional / incompatible / unknown with the rule id (R1-R12) and reasoning. |
| `explain_license` | Permissions, conditions and limitations in plain words for about 50 common SPDX ids, plus expressions and `WITH` exceptions. |
| `generate_notices` | A `THIRD-PARTY-NOTICES.md` draft returned as text (never written to disk): name, version, license, source, copyright lines found in installed license files. |
| `find_license_files` | Which dependencies ship a LICENSE / COPYING / NOTICE file in their installed copy, which do not, and which could not be inspected. |

### Where licenses come from

1. **Installed copy**, if there is one. Python: the venv at `.venv/` or `venv/` next to the lockfile, or
   the one you pass as `python=` (a venv directory, its `python` executable, or a `site-packages`
   directory). Fields used, in order: `License-Expression`, a short `License` field, trove `License ::`
   classifiers (several classifiers combine with AND, the conservative reading). Node:
   `node_modules/<pkg>/package.json` (also the pnpm store layout). Rust: `$CARGO_HOME/registry/src`.
   An installed copy is used only when its version equals the locked version.
2. **The lockfile itself.** `package-lock.json` v2/v3 embeds `license`. The others do not.
3. **A network lookup**, only with `online=true`: `pypi.org`, `registry.npmjs.org`, `crates.io`
   and nothing else. Concurrency is capped at 6, requests time out after 10 s, responses are capped at
   2 MB, redirects are refused, results are cached for an hour, and package names are checked against a
   strict pattern before they are put into a URL. Go modules have no registry API and stay UNKNOWN.

The first source that gives a *recognised* license wins. If none does the package is `UNKNOWN`, and
the reasons are listed.

### Policy

Pass `allow`, `deny` and `project_license` as arguments, or put a `.license-policy.toml` in the project
directory (arguments override the file key by key):

```toml
allow = ["MIT", "Apache-2.0", "BSD-*", "public-domain"]   # ids, wildcards, or categories
deny = ["AGPL-3.0-only", "source-available"]
project_license = "Apache-2.0"

[exceptions]                       # packages you have reviewed and accept
"some-lib" = "vendor confirmed MIT by email, ticket 123"
"other@2.0.0" = "used only as a separate CLI"
```

Rules, in order: `deny` beats `allow`; with an `allow` list, anything known and not on it is a violation;
otherwise with a `project_license` each dependency is judged by the compatibility table (compatible =
ok, conditional = needs review, incompatible = violation); with neither, permissive and public-domain
are ok, weak copyleft (LGPL, MPL, EPL) needs review with linking notes, and strong or network
copyleft, source-available and non-commercial licenses are violations. UNKNOWN and unclassified
licenses always need review. `OR` takes the best option for you, `AND` the worst. Categories:
`public-domain`, `permissive`, `weak-copyleft`, `strong-copyleft`, `network-copyleft`,
`source-available`, `noncommercial`, `restricted`, `proprietary`.

### The compatibility table

`compatibility(project, dependency)` asks: can a combined work that includes or links the dependency be
distributed under the project license? The whole table is in the docstring of
[`compat.py`](src/license_mcp/compat.py) (R0-R12); highlights:

| Dependency into project | Verdict | Why |
|---|---|---|
| permissive (MIT, BSD, ISC...) into anything | compatible | keep the notices |
| Apache-2.0 into MIT / GPL-3.0 / AGPL | compatible | |
| Apache-2.0 into GPL-2.0-only / LGPL-2.1-only | incompatible | patent and indemnity terms are extra restrictions under GPLv2 |
| Apache-2.0 into GPL-2.0-or-later | conditional | the combined work must be GPL-3.0 |
| MPL-2.0 into GPL / LGPL / AGPL | compatible | MPL section 3.3 secondary license |
| MPL-2.0 / LGPL into MIT or closed source | conditional | file-level copyleft / relinking duty |
| GPL-3.0 into GPL-2.0-only | incompatible | version conflict |
| GPL, AGPL into MIT or closed source | incompatible | the whole combined work would have to be GPL |
| AGPL-3.0 into GPL-3.0 | conditional | the network clause stays; AGPL answers always carry a network-clause note |
| SSPL / BUSL / Elastic | conditional for closed source, incompatible for open source | source-available, not open source |
| CC-BY-NC | incompatible | forbids commercial use |

A project offered under `A OR B` must be compatible with every option (recipients may pick any); a
dependency offered under `X OR Y` uses the best option.

## Security

- **Read-only.** No tool writes anywhere. `generate_notices` returns text.
- **Directory sandbox.** Every path argument must resolve (symlinks followed) inside a `--dir`
  directory (default: the working directory), including `python=`. Symlinks inside a project that point
  outside it are not read. The one fixed extra location is `$CARGO_HOME/registry/src` (read-only), used
  only if a `Cargo.lock` is scanned.
- **Nothing from the inspected project is executed.** Python metadata is parsed as text headers
  (size-capped at 1 MB); the venv's interpreter is never started and its code is never imported.
- **Bounded inputs.** Lockfiles are capped at 40 MB, SPDX expressions at 2000 characters and 40
  nesting levels, license files read for copyright lines at 256 KB, lockfile discovery at 3 levels and 40
  files. Malformed files produce an error message, never a crash.
- **Network is opt-in and narrow**: see above. No credentials are ever sent or needed.

## Honest limits

- **Not legal advice.** The compatibility table and license summaries are guidance written from public
  license texts and FSF / Apache / MPL / Creative Commons compatibility statements. Read the licenses for
  anything that matters.
- **Metadata can lie.** A package's declared license can differ from the license file it ships, or be
  out of date, or be wrong. `find_license_files` helps you check.
- **UNKNOWN is not "unlicensed".** It means no usable license data was found. A package whose `License`
  field holds a pasted license body is UNKNOWN too: license text is never guessed from content.
- **Ambiguous spellings are flagged**, e.g. plain `BSD` is read as BSD-3-Clause and `Apache Software
  License` as Apache-2.0; both are reported as approximate, and `check_policy` makes them "needs review".
- **Multiple trove classifiers are read as AND**, because classifiers cannot say OR. A dual-licensed
  package that only lists two classifiers will therefore look more restrictive than it is.
- **Transitive means "in the lockfile".** `requirements.txt` and `go.sum` carry no graph; every
  requirement is "direct" and Go direct-ness comes from `go.mod` when present.
- Installed metadata is only used when its version equals the locked version; otherwise the note says
  so and the next source is tried. Environment markers mean a locked package may legitimately not be
  installed on your platform.
- Unsupported: npm lockfile v1, pnpm before v6, Yarn Berry (v2+), Maven/Gradle/NuGet/Ruby/PHP.

## Tests

```bash
pip install ".[test]" "ruff==0.16.0" "mypy==2.3.0"
ruff check src tests && mypy --strict src
pytest tests
```

The default run needs no network and no other tools. It uses lockfiles generated by the real tools
(`uv lock`, `npm install --package-lock-only`, `pnpm install --lockfile-only`; see
`tests/fixtures/lock/README.md`), hand-built site-packages / `node_modules` / cargo-registry trees, a
local HTTP server standing in for the registries, and a stdio test that launches the real server.
Two opt-in groups: `pytest -m network` (real PyPI, npm, crates.io) and `pytest -m installs`
(uses `uv` to install real packages into a temp venv).

There is also a from-scratch tutorial that builds a minimal version of this server step by step:
[license-mcp-the-hard-way](https://github.com/0xmortuex/license-mcp-the-hard-way).

## License

MIT
