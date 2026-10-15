# Vulnerable sample

**Deliberately insecure. Do not deploy or reuse any of this code.**

A tiny Flask app planted with one issue per scanner family, used as the toolbox's demo target
and as the known-positive fixture for `make test-image`:

| Planted issue | Expected to be reported by |
| --- | --- |
| shell injection (`subprocess` with `shell=True` and request input) | Semgrep, Bandit |
| unsafe `yaml.load` on request data | Semgrep, Bandit |
| hardcoded password and API key | Bandit, Gitleaks |
| outdated dependencies with known CVEs in `requirements.txt` | OSV-Scanner, Trivy |
| Dockerfile running as root, no `HEALTHCHECK` | Trivy, Checkov, Semgrep |

The credentials are fake. Because `requirements.txt` pins vulnerable versions, GitHub may raise
dependency alerts for this directory; they are expected.
