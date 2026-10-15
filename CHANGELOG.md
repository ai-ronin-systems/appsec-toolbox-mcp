# Changelog

All notable changes to appsec-toolbox-mcp are documented here. Releases publish the image to
`ghcr.io/ai-ronin-systems/appsec-toolbox-mcp` with signed build provenance.

## Unreleased

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
