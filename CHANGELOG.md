# Changelog

All notable changes to appsec-toolbox-mcp are documented here. Releases publish the image to
`ghcr.io/ai-ronin-systems/appsec-toolbox-mcp` with signed build provenance.

## Unreleased

### Security

- Checkov no longer contacts Prisma Cloud (`api0.prismacloud.io`) on each scan: it runs with
  `--skip-download`. Syft's update check is off.
- Inline suppression comments in the audited repository no longer hide findings: Semgrep runs
  with `--disable-nosem`, Gitleaks with `--ignore-gitleaks-allow`, and gosec with `-nosec`.
- The audited repository's scanner settings files no longer hide findings: `.semgrepignore`,
  `.bandit`, `.njsscan`, and a root `.gitleaksignore` are all ignored. Bandit and njsscan get
  toolbox config files, and Gitleaks scans a copy without the root `.gitleaksignore`, which it
  otherwise always applies. `examples/hostile-sample` tries each one in the image test.
- Checkov no longer reads the audited repository's `.checkov.yaml`. That file could name
  `external-checks-dir` and make Checkov import and run the repository's Python, and could
  skip checks. Checkov loads it only when `--directory` and its path are separate arguments,
  so the toolbox passes `--directory=target`. A hostile fixture in the image test proves it.
- Every downloaded scanner binary is checked against its published SHA-256, and the base
  image is pinned by digest, with Dependabot proposing updates.
- Bandit ignores `# nosec` comments, so the audited repository cannot hide its own findings.

### Fixed

- `security-language` no longer fails on JavaScript repositories with findings. njsscan
  exits 1 when it reports issues; that is now evidence, and only errors listed in its
  report fail the scan.

### Added

- `output/suppressions.json`, written by `security-semgrep`: inline suppression markers in the
  target (file, line, marker, never the line text) and the scanner settings files it ships.
- `docs/threat-model.md`: the audited repository as the attacker, threats and controls,
  guarantees and limits, and an operator checklist, linked from the README and SECURITY.md.
- `run-manifest.json` lists, under `limitations`, each tool that ran whose results depend on
  data fetched at scan time: Semgrep's registry ruleset, the OSV API (which receives package
  names and versions), and Trivy's vulnerability database.

## 0.2.1 — 2026-10-15

### Fixed

- Release images are signed: the attestation job logs in to GHCR so it can store build provenance
  next to the image. The 0.2.0 image was published without provenance because of this; use 0.2.1
  or later.

## 0.2.0 — 2026-10-15

First published release. 0.1.0 was never published, and its image could not be built.

### Fixed

- The image builds: Semgrep is isolated in its own virtualenv because it pins an MCP SDK that
  conflicts with Makefile MCP's.
- Scans run in the documented hardened container: Makefile MCP's lock state lives on the `/tmp`
  tmpfs instead of the read-only root filesystem, and the run recipes use the host user so reports
  are writable.
- `APPSEC_LANGS` reaches the language scanners when tasks run through Makefile MCP.
- The Java profile works: the FindSecBugs launcher's CRLF line endings are stripped.
- Semgrep runs with metrics off by using the `p/default` ruleset instead of `auto`.
- The `/tmp` tmpfs is sized for Trivy's vulnerability database (3 GB).

### Added

- `output/run-manifest.json` per task: a target fingerprint anyone can recompute with coreutils,
  pinned tool versions, execution status, and a SHA-256 per report (refactor plan phase R1).
- Makefile MCP audit log at `output/makefile-mcp-audit.jsonl`.
- `examples/agent_demo.py`, an MCP client demo, and its recording in the README.
- `examples/vulnerable-sample` and `make test-image`, a known-positive scan of the real image that
  CI runs on every push.
- Strict `toolbox-versions`: fails if any scanner is missing or cannot execute.
- Tag-triggered GHCR release: gated on full CI, builds and tests the image once, pushes it from a
  job that runs no project code, and attests build provenance.

### Changed

- Makefile MCP 0.2.2.
