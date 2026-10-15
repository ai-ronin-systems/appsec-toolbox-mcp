# Security policy

## Threat model

The repository mounted at `target/` may be buggy, hostile, or deliberately malicious.

The toolbox therefore assumes:

- the toolbox Makefile, scripts, and `.makefile-mcp.yaml` are trusted;
- target source is untrusted and read-only;
- scanner output is untrusted data;
- the MCP caller is allowed to request only the explicitly exposed tasks;
- source acquisition and credentials happen outside this container;
- `APPSEC_LANGS` is trusted deployment/operator configuration, not an agent-supplied task argument.

## Default controls

The provided Compose configuration uses:

- read-only root filesystem;
- read-only target mount;
- writable output mount only;
- all Linux capabilities dropped;
- `no-new-privileges`;
- non-root execution (the host user via `HOST_UID`/`HOST_GID`, or uid 10001 by default);
- Makefile MCP runtime state on the `/tmp` tmpfs only;
- no Docker socket;
- no host credential mounts.

Some generic scanners need outbound network access for rules or advisory databases. Network access is therefore not disabled globally by default.

## Scanner execution policy

The default targets are passive scanners. They must not intentionally execute the audited project's build, test, package-install, remediation, deployment, or application commands.

OSV-Scanner is run with dependency resolution disabled. Gitleaks, OSV-Scanner, and Trivy receive trusted runner-owned configuration/ignore files so target-owned scanner policy cannot silently suppress evidence. Semgrep is run with Git ignore handling disabled. Checkov is limited to static IaC/CI frameworks, uses packaged policies, does not load external checks, and does not download external Terraform modules. No remediation command is exposed.

Language specialists preserve the same boundary:

- Bandit performs Python source AST analysis and does not run the target application;
- njsscan statically analyzes JavaScript/Node/TypeScript source;
- FindSecBugs scans only bytecode already present in the mounted repository and never invokes Maven/Gradle compilation;
- gosec runs against source/packages with `GOPROXY=off`, `GOSUMDB=off`, `GOTOOLCHAIN=local`, and `GOENV=off` so the scan cannot silently fetch project modules or toolchains.

An unavailable dependency or missing Java bytecode is treated as a coverage limitation or scanner error, not as permission to execute target-owned dependency/build logic.

## Language-profile metadata

`output/language-profile.json` is coverage metadata, not trusted policy. It records profile selection, detection evidence, and scanner completion/skips so downstream audit logic can distinguish "not applicable" from "not analyzed".

## Reporting vulnerabilities

Please report vulnerabilities privately to the project maintainer before opening a public issue when disclosure could put users at risk.
