# appsec-toolbox-mcp

[![CI](https://github.com/ai-ronin-systems/appsec-toolbox-mcp/actions/workflows/ci.yml/badge.svg)](https://github.com/ai-ronin-systems/appsec-toolbox-mcp/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/ai-ronin-systems/appsec-toolbox-mcp)](https://github.com/ai-ronin-systems/appsec-toolbox-mcp/releases)
[![License](https://img.shields.io/github/license/ai-ronin-systems/appsec-toolbox-mcp)](LICENSE)

**Let an AI agent audit code you do not trust, without giving it a shell, a path to choose, or the repository's code to run.**

Ten pinned security scanners behind eight parameterless MCP tools, in one hardened container. The audited repository is treated as the attacker. The agent only ever collects evidence.

![An agent connects over MCP, is refused a maintenance target, audits a deliberately vulnerable repository, and reads the findings, run manifest, and audit log](docs/demo.svg)

*Recorded from [`examples/agent_demo.py`](examples/agent_demo.py) against [`examples/vulnerable-sample`](examples/vulnerable-sample). Waiting time is shortened; the real scan time is in the last line.*

## In 30 seconds

- **What it is.** Semgrep, Gitleaks, OSV-Scanner, Trivy, Checkov, Syft, and language specialists (Bandit, FindSecBugs, njsscan, gosec) exposed to any MCP client as fixed capabilities: `security.sast`, `security.secrets`, `security.dependencies`, and so on.
- **The threat model.** The repository under audit is hostile: it controls every file the scanners parse and every string the agent reads back. So the agent gets nothing to steer: no arguments, no target path, no shell, no way to run the repository's build or code.
- **What you get.** Native scanner reports, a run manifest that ties each report's SHA-256 to a recomputable fingerprint of the scanned tree, and an audit log of every tool call.

## Engineering highlights

Each claim links to the code or test that proves it.

| Problem | Approach | Proof |
| --- | --- | --- |
| A prompt-injected agent with a shell can do anything. | The agent's whole surface is eight parameterless tasks, governed by [Makefile MCP](https://github.com/ai-ronin-systems/makefile-mcp). Maintenance targets exist but are refused. | [`.makefile-mcp.yaml`](.makefile-mcp.yaml), the [demo](docs/demo.svg) |
| Scanning untrusted code usually runs it: `setup.py`, `postinstall`, Gradle plugins, Go toolchain downloads, scanner plug-ins. | Strictly passive analysis: no build, install, or dependency resolution; Go runs with `GOPROXY=off` and `GOTOOLCHAIN=local`. An adversarial review found that a planted `.checkov.yaml` could make Checkov import the repository's Python; that path is closed and regression-tested. | [`examples/hostile-sample`](examples/hostile-sample), [`tests/image.sh`](tests/image.sh) |
| A hostile repository can silence its own findings with `.semgrepignore`, `.gitleaksignore`, `# nosec`, `# nosemgrep`... | Every scanner runs on toolbox-owned configuration. Inline suppressions are disabled where the scanner allows it, and every marker found is inventoried for the reviewer either way. | [settings table](docs/TOOLING.md), `output/suppressions.json` |
| Evidence is only worth something if it is tied to what was scanned. | The manifest fingerprints the tree exactly like `find . -type f -print0 \| LC_ALL=C sort -z \| xargs -0 sha256sum \| sha256sum`, including file names that are not UTF-8 or that `sha256sum` escapes, and records each report's digest, tool versions, and data sources. | [`scripts/write-manifest.py`](scripts/write-manifest.py), [`tests/unit/test_manifest.py`](tests/unit/test_manifest.py) |
| One malformed file should not let the target stop the audit. | Input a scanner cannot read because of the target (an unloadable Go package, a corrupt lockfile) becomes a recorded coverage limit: not a failed bundle, and not a fake clean result. | [`scripts/run-language-profiles.py`](scripts/run-language-profiles.py), [`scripts/run-osv.sh`](scripts/run-osv.sh) |
| Results should be reproducible, and a compromised scanner should have nowhere to send the code. | Offline mode: fetch rule and advisory data once, then scan under `--network none`. The manifest records the data's age and digest. | [Offline mode](docs/USAGE.md#offline-mode) |
| A security tool is a supply-chain target. | Every downloaded binary is checked against its published SHA-256 per architecture; the base image is pinned by digest; Actions are pinned by commit; release jobs that run project code hold no write token; images carry signed build provenance. | [`Dockerfile`](Dockerfile), [`release.yml`](.github/workflows/release.yml) |

**Verification in layers.** Unit tests cover the scripts. A smoke test drives the Makefile through Makefile MCP with fake scanners whose stubs fail if any hardening flag is missing. The image test runs the real scanners against a known-vulnerable sample, a hostile sample that tries every attack above, and offline mode, under the documented resource limits. Independent adversarial reviews attacked the image; every confirmed finding was fixed with a regression test, and what remains is written down in the [threat model](docs/threat-model.md).

## Quick start

```bash
IMAGE=ghcr.io/ai-ronin-systems/appsec-toolbox-mcp:0.2.1
docker pull "$IMAGE"
gh attestation verify "oci://$IMAGE" --owner ai-ronin-systems
```

Offline mode, the resource limits, and the target-settings hardening are on `main` and ship in the next release. To use them now: `docker build -t appsec-toolbox-mcp:dev .` and `IMAGE=appsec-toolbox-mcp:dev`.

Run it as an MCP stdio server against one repository:

```bash
docker run --rm -i \
  --read-only --cap-drop=ALL --security-opt=no-new-privileges:true \
  --tmpfs /tmp:rw,nosuid,nodev,size=3g --memory=6g --pids-limit=512 \
  --user "$(id -u):$(id -g)" \
  -v "$PWD/my-project:/runner/target:ro" \
  -v "$PWD/appsec-output:/runner/output:rw" \
  "$IMAGE"
```

Register the same command as a stdio server in any MCP client:

```json
{
  "mcpServers": {
    "appsec-toolbox": {
      "command": "docker",
      "args": ["run", "--rm", "-i", "--read-only", "--cap-drop=ALL",
               "--security-opt=no-new-privileges:true",
               "--tmpfs", "/tmp:rw,nosuid,nodev,size=3g", "--memory=6g", "--pids-limit=512",
               "-v", "/abs/path/my-project:/runner/target:ro",
               "-v", "/abs/path/appsec-output:/runner/output:rw",
               "ghcr.io/ai-ronin-systems/appsec-toolbox-mcp:0.2.1"]
    }
  }
}
```

Compose, offline mode, language selection, and every evidence file are in [Usage](docs/USAGE.md).

## How it works

```text
untrusted repository (read-only)
          |
          v
   /runner/target
          |
          v
 trusted Makefile + Makefile MCP
    |       |       |       |       |       |
 Semgrep Gitleaks   OSV    Trivy  Checkov   Syft
          |
          +---- language profile selection ----+
                 |       |        |        |
               Bandit FindSecBugs njsscan  gosec
               Python    Java     Node/JS   Go
          |
          v
    /runner/output   reports, run-manifest.json, suppressions.json, audit log
```

The operator mounts exactly one repository at `/runner/target` and one writable directory at `/runner/output`. The audited path is never an MCP parameter, so the agent has no host-path capability. A trusted Makefile holds every scanner command; [Makefile MCP](https://github.com/ai-ronin-systems/makefile-mcp) decides which of its targets the agent may call. Language specialists are picked by detection (`APPSEC_LANGS=auto`) or by the operator, never by the agent.

| Capability | Tool | Evidence |
| --- | --- | --- |
| `security.audit` | everything below | complete bundle |
| `security.sast` | Semgrep + suppression inventory | `semgrep.json`, `suppressions.json` |
| `security.secrets` | Gitleaks | `gitleaks.json` |
| `security.dependencies` | OSV-Scanner | `osv.json` |
| `security.repository` | Trivy | `trivy.json` |
| `security.iac` | Checkov | `checkov.json` |
| `security.language` | Bandit, FindSecBugs, njsscan, gosec as applicable | `language-profile.json` + reports |
| `supply_chain.sbom` | Syft | `sbom.cdx.json` (CycloneDX) |

## Threat model

The audited repository is the attacker, and the agent reading its reports may be steered by it. **Read the [threat model](docs/threat-model.md)**: attacker goals, sixteen threats with their controls and residual risks, what is and is not guaranteed, and an operator checklist.

| Protected | Not protected |
| --- | --- |
| Target builds, installs, hooks, and Makefiles never run. | Scanner parser bugs; the container is the boundary. |
| Target-owned scanner settings files cannot suppress findings or load code. | Inline `trivy:ignore` and `njsscan-ignore` comments; Checkov lists its inline skips as `skipped_checks`. All are inventoried. |
| The agent cannot pick the target or run anything but the eight scans. | An agent that misreports what the reports say. |
| No credentials in the container; read-only, unprivileged, non-root, resource-capped. | Exfiltration by a compromised scanner in online mode. [Offline mode](docs/USAGE.md#offline-mode) runs with no network. |
| Each run's manifest ties report digests to a fingerprint of the scanned tree. | Tampering by anyone who can write `output/`; the manifest is not signed. |

## Design choices

- **Evidence, not verdicts.** Reports stay in each scanner's native format. The toolbox never grades, deduplicates, or normalizes findings; a consumer does that with the full evidence.
- **One closed set of scanners.** Four language profiles, no plug-in framework, no user-defined pipelines. Generic SCA stays with OSV and Trivy; specialists add a different analysis engine, not a duplicate one.
- **Coverage gaps are recorded, never papered over.** A source-only Java project gets no FindSecBugs pass, because the toolbox will not compile untrusted code; the manifest says so.
- **Everything pinned.** Scanner versions are pinned and updated one at a time against known-positive and hostile fixtures ([update policy](docs/TOOLING.md#update-policy)).

It is not an autonomous auditor, an LLM agent, a DAST engine, a credential manager, a report normalizer, or a shell server.

## Part of a larger system

```text
appsec-audit-hound (planned)    decides why to scan, correlates evidence, writes findings
        | MCP
appsec-toolbox-mcp              collects governed, passive evidence   <- this repository
        | built on
makefile-mcp                    exposes trusted Make targets to agents, deny-by-default
```

[Makefile MCP](https://github.com/ai-ronin-systems/makefile-mcp) is published on PyPI and the official MCP Registry, with its own [threat model](https://github.com/ai-ronin-systems/makefile-mcp/blob/main/docs/threat-model.md).

## Documentation

| Document | What it covers |
| --- | --- |
| [Threat model](docs/threat-model.md) | Attacker goals, threats and controls, guarantees, limits, operator checklist |
| [Usage](docs/USAGE.md) | Running, tools and evidence files, language profiles, offline mode, scanner behaviour, network use, versions, development |
| [Architecture](docs/ARCHITECTURE.md) | Trust boundary, ownership, design rules |
| [Tooling](docs/TOOLING.md) | Pinned versions, settings each scanner ignores, update policy |
| [Security policy](SECURITY.md) | Supported versions and private vulnerability reporting |
| [Changelog](CHANGELOG.md) | Released and unreleased changes |
| [Contributing](CONTRIBUTING.md) | How to add a scanner without widening the boundary |

## Development

```bash
pipx install pytest==8.4.2 && pipx install ruff==0.14.0
make test         # ruff, unit tests, smoke test
make image
make test-image   # the real image: known positives, hostile sample, offline mode
```

More in [Usage](docs/USAGE.md#development).

## License

Apache-2.0.
