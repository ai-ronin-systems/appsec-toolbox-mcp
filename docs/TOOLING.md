# Tooling

The image provides a generic passive AppSec baseline plus four language-specialist SAST profiles. Language selection is runtime-configurable; scanner installation remains image-pinned and reproducible.

| Tool | Pinned version | Role |
| --- | ---: | --- |
| Makefile MCP | `0.2.2` | governed Make-to-MCP runtime |
| Semgrep | `1.174.0` | generic SAST |
| Gitleaks | `8.29.1` | working-tree secret detection |
| OSV-Scanner | `2.5.1` | dependency vulnerability evidence |
| Trivy | `0.74.0` | repository vulnerability/misconfiguration/secret/license scan |
| Checkov | `3.3.8` | IaC and CI/CD configuration security policies |
| Bandit | `1.9.4` | Python specialist SAST |
| njsscan | `0.4.3` | Node.js/JavaScript/TypeScript specialist SAST |
| gosec | `2.28.0` | Go AST/SSA/taint-oriented security analysis |
| Go | `1.27.0` | pinned gosec package-analysis toolchain |
| FindSecBugs | `1.14.0` | Java bytecode security analysis |
| Syft | `1.51.0` | CycloneDX SBOM |

## Language-selection policy

`APPSEC_LANGS=auto` is the default. Detection is based on source extensions and common project manifests and may select multiple profiles in a polyglot repository.

Explicit examples:

```text
APPSEC_LANGS=python
APPSEC_LANGS=java,node
APPSEC_LANGS=go,python,node
APPSEC_LANGS=none
```

This setting is deployment/operator configuration. It is intentionally not exposed as an MCP invocation parameter.

## Specialist scope

The language profiles add **one complementary SAST engine per ecosystem** rather than another dependency scanner for each language:

- Python: Bandit;
- Java: FindSecBugs;
- Node/JS/TS: njsscan;
- Go: gosec.

OSV-Scanner and Trivy already provide generic dependency evidence, so this release does not add pip-audit, npm audit, Dependency-Check, or govulncheck. Add those later only if real audits show a material coverage gap.

FindSecBugs requires compiled bytecode. The toolbox scans existing Maven/Gradle build outputs but never invokes Maven, Gradle, or another project build. A source-only Java repository records FindSecBugs as skipped rather than violating the passive-analysis boundary.

gosec loads Go packages. To prevent a scan from silently fetching project dependencies or a newer toolchain, runtime selection forces `GOPROXY=off`, `GOSUMDB=off`, `GOTOOLCHAIN=local`, and `GOENV=off`. Missing dependencies are therefore an operational scan limitation, not a reason to execute dependency acquisition.

## Gitleaks pin

The project intentionally does not default to `8.30.1`. A public regression report for that release described default rules failing to detect canonical secrets. Until a later release is verified, `8.29.1` is the conservative pin.

## Checkov scope

Checkov is intentionally restricted to static IaC and CI/CD frameworks. The toolbox does not enable Checkov package SCA, secret scanning, remote organization configuration, external checks, or external Terraform module downloads; those would overlap existing providers or widen the passive-analysis boundary. Checkov runs with `--soft-fail`, so policy violations are retained as JSON evidence without turning the Make target into a failed collection task.

## Update policy

Tool updates should be small, reviewable changes:

1. update one pin;
2. build the image;
3. run the smoke test;
4. run a known-positive fixture for that scanner;
5. inspect the report format for incompatible changes;
6. verify the scanner still respects the passive-analysis boundary;
7. only then merge the version bump.

Do not use floating `latest` versions in a tagged toolbox release.
