# appsec-toolbox-mcp

**A generic, pre-provisioned AppSec evidence server built on Makefile MCP.**

`appsec-toolbox-mcp` exposes a small set of trusted, passive security scanners to MCP clients. The audited repository is data. The toolbox Makefile is the trusted execution boundary.

![An agent connects over MCP, is refused a maintenance target, audits a deliberately vulnerable repository, and reads the findings, run manifest, and audit log](docs/demo.svg)

*Recorded from [`examples/agent_demo.py`](examples/agent_demo.py) against [`examples/vulnerable-sample`](examples/vulnerable-sample). Waiting time is shortened; the real scan time is in the last line. Reproduce it with:*

```bash
docker build -t appsec-toolbox-mcp:dev .
uv run --with mcp==2.1.1 python examples/agent_demo.py examples/vulnerable-sample ./appsec-output
```

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
    /runner/output
```

## Threat model

The audited repository is the attacker, and the agent reading its reports may be steered by it. So a steered agent can do almost nothing here. It gets eight parameterless, passive scans. It cannot choose the target, pass arguments, or run the repository's code.

**Read the [threat model](docs/threat-model.md)** for the threats, the controls, what is and is not guaranteed, and the operator checklist.

| Protected | Not protected |
| --- | --- |
| Target builds, installs, hooks, and Makefiles never run. | Scanner parser bugs; the container is the boundary. |
| Target-owned scanner settings files cannot suppress findings or load code. | Inline `trivy:ignore` and `njsscan-ignore` comments; Checkov lists its inline skips as `skipped_checks`. |
| The agent cannot pick the target or run anything but the eight scans. | An agent that misreports what the reports say. |
| No credentials in the container; read-only, unprivileged, non-root. | Exfiltration by a compromised scanner in online mode. [Offline mode](#offline-mode) runs with no network. |
| Each run's manifest ties report digests to a fingerprint of the scanned tree. | Tampering by anyone who can write `output/`; the manifest is not signed. |

## Why this shape

The project intentionally does **not** execute the target repository's Makefile, scripts, CI configuration, package-manager commands, builds, remediation commands, or arbitrary shell commands. Make is used only by this trusted toolbox repository.

The audited code location is not an MCP parameter. A deployment mounts exactly one audit target at:

```text
/runner/target
```

Reports are written to:

```text
/runner/output
```

That gives every scanner the same fixed target and avoids giving an agent an arbitrary host-path capability.

## Exposed capabilities

| Capability | Make target | Tool | Evidence |
| --- | --- | --- | --- |
| `security.audit` | `appsec-full` | all applicable providers | complete bundle |
| `security.sast` | `security-semgrep` | Semgrep, suppression inventory | `output/semgrep.json`, `output/suppressions.json` |
| `security.secrets` | `security-gitleaks` | Gitleaks | `output/gitleaks.json` |
| `security.dependencies` | `security-osv` | OSV-Scanner | `output/osv.json` |
| `security.repository` | `security-trivy` | Trivy | `output/trivy.json` |
| `security.iac` | `security-checkov` | Checkov | `output/checkov.json` |
| `security.language` | `security-language` | applicable specialist SAST | `output/language-profile.json` + scanner reports |
| `supply_chain.sbom` | `supply-chain-sbom` | Syft | `output/sbom.cdx.json` |

All exposed tasks are parameterless. Exact scanner commands live in the toolbox code; `.makefile-mcp.yaml` only governs exposure, risk, timeouts, and capabilities.

## Language profiles

Language-specialized SAST is deployment-configurable without creating separate language-specific toolbox projects.

The default is:

```text
APPSEC_LANGS=auto
```

`auto` detects all applicable profiles from source files and common project manifests. Polyglot repositories can select multiple profiles automatically.

Supported profiles:

| Profile | Specialist scanner | Detection examples | Evidence |
| --- | --- | --- | --- |
| `python` | Bandit | `pyproject.toml`, `requirements.txt`, `*.py` | `output/bandit.json` |
| `java` | FindSecBugs | `pom.xml`, Gradle files, `*.java` | `output/findsecbugs.xml` when bytecode exists |
| `node` | njsscan | `package.json`, `*.js`, `*.ts`, JSX/TSX | `output/njsscan.json` |
| `go` | gosec | `go.mod`, `go.work`, `*.go` | `output/gosec.json` |

Explicit override is also supported:

```bash
APPSEC_LANGS=python,node
```

Aliases such as `py`, `js`, `javascript`, `typescript`, `nodejs`, and `golang` are accepted. Use:

```text
APPSEC_LANGS=none
```

to run only the generic scanner set.

`APPSEC_LANGS` is a **deployment/local operator setting**, not an MCP task parameter. The agent still receives only the fixed governed capabilities above.

Every task also writes `output/run-manifest.json`, which ties the evidence to exactly what was scanned and how:

- `target.content_fingerprint`: a SHA-256 over the mounted tree that anyone can recompute with coreutils: `cd <target> && find . -type f -print0 | LC_ALL=C sort -z | xargs -0 sha256sum | sha256sum`;
- `tools[]`: each scanner the task ran, with its pinned version, an execution status (`COMPLETED`, `SKIPPED_NOT_APPLICABLE`, `SKIPPED_MISSING_PREREQUISITE`, `ERROR`), and the SHA-256 of its report. Only reports produced by this task are listed;
- `coverage`: detected and selected language profiles.

The manifest records execution facts only. It never grades or normalizes findings.

`security-semgrep` also writes `output/suppressions.json`: every inline suppression marker in the target (`nosemgrep`, `nosec`, `gitleaks:allow`, `checkov:skip`, `trivy:ignore`, `tfsec:ignore`, `njsscan-ignore`) as file, line, and marker, plus the scanner settings files the target ships. The toolbox ignores most of them, but a repository that tries to silence its scanners is worth a reviewer's attention. Line text is never copied, because it is attacker-controlled. Symlinks, binaries, and files over 1 MiB are skipped and counted.

Every MCP task run also appends one JSON line to `output/makefile-mcp-audit.jsonl`: task, risk, status, exit code, duration, output size, and the tail of the scanner output. Together with the native reports, it records how the evidence was produced.

Every language-profile run writes `output/language-profile.json`, recording requested mode, detected languages, detection evidence, selected profiles, and whether each specialist scanner completed or was skipped.

### Java boundary

FindSecBugs analyzes Java bytecode. The toolbox will use existing Maven/Gradle compiled outputs when present, but it will **not compile an untrusted Java project**. For source-only Java repositories, FindSecBugs is recorded as skipped and the generic Semgrep scan still analyzes Java source.

### Go boundary

gosec uses Go package analysis. The toolbox includes a pinned Go toolchain but disables module proxy access, checksum-database access, and automatic toolchain downloads during the scan:

```text
GOPROXY=off
GOSUMDB=off
GOTOOLCHAIN=local
GOENV=off
```

A Go repository that requires unavailable dependencies may therefore produce an operational scanner error instead of causing the toolbox to download project dependencies.

## Quick start

Pull the released image and verify its signed build provenance:

```bash
docker pull ghcr.io/ai-ronin-systems/appsec-toolbox-mcp:0.2.1
gh attestation verify oci://ghcr.io/ai-ronin-systems/appsec-toolbox-mcp:0.2.1 --owner ai-ronin-systems
```

Or build it yourself with `docker build -t appsec-toolbox-mcp:dev .`.

Run as an MCP stdio server:

```bash
docker run --rm -i \
  --read-only \
  --cap-drop=ALL \
  --security-opt=no-new-privileges:true \
  --tmpfs /tmp:rw,nosuid,nodev,size=3g \
  --memory=6g --pids-limit=512 \
  --user "$(id -u):$(id -g)" \
  -e APPSEC_LANGS=auto \
  -v "$PWD/my-project:/runner/target:ro" \
  -v "$PWD/appsec-output:/runner/output:rw" \
  ghcr.io/ai-ronin-systems/appsec-toolbox-mcp:0.2.1
```

Or with Compose:

```bash
TARGET_DIR="$PWD/my-project" OUTPUT_DIR="$PWD/appsec-output" \
  HOST_UID="$(id -u)" HOST_GID="$(id -g)" APPSEC_LANGS=auto \
  docker compose run --rm -T appsec-toolbox-mcp
```

The `/tmp` tmpfs holds scanner caches, and Trivy's vulnerability database alone is about 1.6 GB, so it is sized at 3 GB. It is RAM-backed and the databases are fetched again on every run. Because it is RAM-backed, it counts toward `--memory`: the 6 GB limit leaves about 3 GB for the scanners, which peak near 2 GB on small repositories. `--pids-limit=512` caps fork bombs; scans use about 100 processes. Raise both for large repositories.

Running as your own user (`--user` / `HOST_UID`) lets the scanners write to the output directory and leaves the reports owned by you. Makefile MCP's lock files live on the `/tmp` tmpfs, so the root filesystem stays read-only.

`makefile-mcp serve` uses stdio. This project does not add HTTP transport, authentication, a queue, a database, a workflow engine, or another command DSL.

## Offline mode

By default some scanners fetch rules and advisories while they scan. Offline mode removes the network from the scan container: fetch the data once, then scan with `--network none`.

```bash
# 1. With network access: fetch Semgrep p/default, the Trivy databases, and OSV databases.
docker run --rm --read-only --cap-drop=ALL --security-opt=no-new-privileges:true \
  --tmpfs /tmp:rw,nosuid,nodev,size=3g --user "$(id -u):$(id -g)" \
  -v "$PWD/appsec-data:/runner/offline-data:rw" \
  ghcr.io/ai-ronin-systems/appsec-toolbox-mcp:0.2.1 make -s offline-data

# 2. No network at all: scan from that data, mounted read-only.
docker run --rm -i --network none --read-only --cap-drop=ALL \
  --security-opt=no-new-privileges:true --tmpfs /tmp:rw,nosuid,nodev,size=3g \
  --memory=6g --pids-limit=512 \
  --user "$(id -u):$(id -g)" -e APPSEC_OFFLINE=1 \
  -v "$PWD/my-project:/runner/target:ro" \
  -v "$PWD/appsec-data:/runner/offline-data:ro" \
  -v "$PWD/appsec-output:/runner/output:rw" \
  ghcr.io/ai-ronin-systems/appsec-toolbox-mcp:0.2.1
```

With Compose, set `APPSEC_OFFLINE=1 APPSEC_NETWORK=none OFFLINE_DATA_DIR="$PWD/appsec-data"`.

- The data takes about 3.5 GB, mostly the Trivy databases. Refresh it as often as you want fresh advisories.
- OSV databases are fetched per ecosystem. `OSV_ECOSYSTEMS` (default `PyPI npm Maven Go crates.io RubyGems Packagist NuGet Pub Hex`) picks them. An ecosystem that was not fetched fails the OSV scan rather than reporting no vulnerabilities.
- `offline-data/offline-data.json` records when each source was fetched and its SHA-256. The run manifest copies it and sets `run.network` to `offline`, so findings carry the age of the data behind them.
- `APPSEC_OFFLINE` is an operator setting like `APPSEC_LANGS`. The agent cannot change it, and `offline-data` is not an MCP tool.
- The same commit then gives the same findings until you refresh the data.

## Human/CI usage

The same Makefile is directly usable without MCP when the tools are installed locally:

```bash
ln -s /path/to/project target
make security-semgrep
APPSEC_LANGS=python,node make security-language
make appsec-full
```

For local use, ensure `target` resolves inside this repository. The Docker deployment is the recommended isolation boundary for untrusted source.

## Scanner behavior

Findings are evidence, not execution errors:

- Gitleaks uses exit code `0` when leaks are found, and `--ignore-gitleaks-allow` so target `gitleaks:allow` comments cannot hide secrets.
- Semgrep uses `--disable-nosem`, so target `# nosemgrep` comments cannot hide findings.
- OSV-Scanner normally returns `1` when vulnerabilities are found; the thin wrapper normalizes that to success while preserving genuine scanner errors.
- Trivy is configured with `--exit-code 0`.
- Checkov uses `--soft-fail`, so policy findings are evidence rather than process failures.
- Bandit uses `--exit-zero` and `--ignore-nosec`, so target `# nosec` comments cannot hide findings; malformed input/configuration can still fail the scanner.
- njsscan exits `1` when it finds issues; the toolbox treats that as success and fails only when its report lists scan errors.
- gosec uses `-no-fail` and `-nosec`, so target `#nosec` comments cannot hide findings, then the toolbox inspects its JSON for Go package-processing errors.
- FindSecBugs findings remain XML evidence; operational scanner failure still fails collection.
- Reports remain in each scanner's native structured format.

The OSV scan uses `--no-resolve` to avoid dependency-resolution behavior against an untrusted project. Every scanner uses toolbox-owned settings, never the target's: Gitleaks, OSV-Scanner, Trivy, Bandit, and njsscan get toolbox config files; Semgrep ignores `.gitignore` and `.semgrepignore`; a root `.gitleaksignore` is left out of a copy that Gitleaks scans instead. [`examples/hostile-sample`](examples/hostile-sample) tries each of these and `make test-image` checks that nothing is hidden. Checkov is restricted to static IaC/CI configuration frameworks, never reads the target's `.checkov.yaml` (which could load Python checks from the target), and does not enable external checks, package SCA, secret scanning, or external Terraform module downloads. Language specialist scanners do not invoke package-manager installs, project builds, tests, remediation, or application entrypoints.

## Network and privacy

In online mode (the default), the image needs outbound network access for some generic scanner rule/advisory data. [Offline mode](#offline-mode) removes that need. In particular, Semgrep's `p/default` registry ruleset and vulnerability databases may be fetched at scan time. Semgrep runs with metrics off, so it never sends project information; its `auto` config is not used because it requires metrics. Checkov uses its packaged policies and runs with `--skip-download`, so it does not contact Prisma Cloud; by default it would fetch guidelines from `api0.prismacloud.io` on every scan. Syft's update check is off, and Semgrep and Trivy skip their version checks. Language-specific scanners are configured to avoid project dependency downloads; notably gosec runs with the Go module proxy disabled.

Do not pass repository credentials into this container.

The target repository is mounted read-only. The output directory is the only persistent writable mount. The Compose profile also removes Linux capabilities, enables `no-new-privileges`, and makes the container root filesystem read-only.

## Tool versions

The Dockerfile pins scanner versions rather than using floating `latest` tags. See [`docs/TOOLING.md`](docs/TOOLING.md).

`MAKEFILE_MCP_SPEC` defaults to `makefile-mcp==0.2.2` and can be overridden at build time while Makefile MCP is under local development:

```bash
docker build \
  --build-arg 'MAKEFILE_MCP_SPEC=git+https://github.com/ai-ronin-systems/makefile-mcp.git@main' \
  -t appsec-toolbox-mcp:dev .
```

For releases, pin Makefile MCP to an immutable package version or commit rather than a branch.

## Non-goals

This repository is not:

- an autonomous auditor;
- an LLM agent;
- a DAST/attack engine;
- a Git clone/credential manager;
- a scanner plugin framework;
- a report normalizer;
- an arbitrary shell MCP server.

A higher-level consumer such as AuditHound can decide *why* a capability should run, correlate its evidence, and generate findings/reports. This toolbox only gathers governed evidence.

## Development

```bash
make test
make image
```

The smoke test uses fake scanner executables, so it validates Make wiring, polyglot auto-detection, explicit profile overrides, and report handling without downloading security databases.

## License

Apache-2.0.
