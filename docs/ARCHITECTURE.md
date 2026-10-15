# Architecture

## Boundary

The trusted unit is this repository:

```text
/runner/
├── Makefile               trusted capability commands
├── .makefile-mcp.yaml     trusted MCP governance
├── scripts/               thin execution/selection helpers
├── target/                untrusted audit input, mounted read-only
└── output/                scanner evidence + Makefile MCP audit log, writable
```

Makefile MCP's repository root is `/runner`. This is deliberate: both `target/` and `output/` remain inside the same confined root.

## Ownership

### Makefile MCP owns

- Make target discovery and exposure;
- task/capability metadata;
- execution confinement;
- variable validation where variables exist;
- timeouts, cancellation, locking, and structured task results;
- stdio MCP transport.

### appsec-toolbox-mcp owns

- exact scanner selection and versions;
- exact scanner command lines;
- fixed target/report locations;
- passive-scan safety defaults;
- language detection and explicit profile selection;
- scanner-specific exit-code normalization needed for evidence collection.

### Audit consumers own

- audit strategy;
- deciding which capabilities to run;
- parsing/normalizing scanner evidence;
- correlation and deduplication;
- findings, severity policy, review, and final reports.

## Language profiles

The toolbox remains one product rather than branching into Python/Java/Node/Go repositories.

```text
                    APPSEC_LANGS
                         |
              +----------+-----------+
              | auto                 | explicit
              v                      v
        detect repository       validate requested
        technologies            profile set
              |                      |
              +----------+-----------+
                         v
                selected profiles
                 |    |    |    |
               Python Java Node  Go
                 |    |    |    |
               Bandit FSB njsscan gosec
```

The profile selector is intentionally small and closed: `python`, `java`, `node`, and `go`. It is not a plugin registry or workflow DSL.

`APPSEC_LANGS` is deployment/local configuration, not agent-controlled input. The MCP surface exposes one `security.language` capability regardless of how many profiles are selected.

The resulting `language-profile.json` documents why a scanner ran or was skipped. This gives higher-level audit consumers coverage evidence without normalizing the scanners' native findings.

## Passive Java handling

FindSecBugs requires bytecode. The selector looks only for existing conventional Maven/Gradle outputs such as `target/classes`, `build/classes/...`, and project JARs. It does not build the audited repository. If bytecode does not exist, the Java specialist is skipped and the reason is recorded.

## Passive Go handling

gosec is a source/package analyzer but Go package loading can otherwise resolve dependencies. The toolbox supplies a local pinned Go toolchain and disables the module proxy, checksum database, per-user Go environment, and automatic toolchain acquisition during scanning. This intentionally favors a failed specialist scan over widening the trust boundary through dependency downloads.

## Design rules

1. Never run the audited repository's Makefile by default.
2. Never expose a generic command or shell target.
3. Do not accept an arbitrary target path from the MCP caller.
4. Do not accept credentials for source acquisition.
5. Keep executable scanner behavior in the trusted toolbox Makefile/scripts.
6. Treat findings as successful evidence collection, not process failure.
7. Prefer passive analysis of untrusted source; do not run package install/build/remediation commands.
8. Keep language selection coarse: auto, none, or an explicit set from the supported profiles.
9. Do not turn scanner selection into a user-defined pipeline or plugin framework.
10. Prefer complementary scanner domains over duplicate engines; generic SCA remains OSV/Trivy while language profiles add specialist SAST.
