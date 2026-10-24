# Contributing

Keep contributions narrow.

For a new generic scanner:

1. add one explicit Make target;
2. give it one deterministic report path under `output/`;
3. add explicit Makefile MCP task metadata and a capability only if it is genuinely reusable;
4. keep the audited path fixed at `target/`;
5. do not add arbitrary commands, generic shell execution, credentials, HTTP transport, databases, queues, or plugin frameworks;
6. add a smoke-test stub proving the target produces its report, and unit tests for any new script logic;
7. check whether the scanner reads settings or suppression comments from the scanned directory, stop it, and add the attempt to `examples/hostile-sample` with an image-test check;
8. document network or execution behavior that matters for untrusted source.

For language coverage, first decide whether the scanner adds a genuinely different analysis engine. Prefer extending one of the closed `python`, `java`, `node`, or `go` profiles over creating another MCP capability or another repository. Do not add package-manager execution or project builds to make a specialist scanner work.

If a scanner needs an unavailable build artifact, report the limitation or skip it. Do not cross the passive-analysis boundary automatically.

Prefer deleting duplication over adding abstraction layers.
