# Hostile sample

**Deliberately hostile. Do not reuse any of this code.**

A repository that tries to run its own code inside the toolbox and to hide its own findings
with target-owned scanner configuration. `make test-image` scans it and requires that every
attempt fails:

| Attempt | Expected result |
| --- | --- |
| `.checkov.yaml` names `checks/` as external checks, which write `output/TARGET_CODE_RAN` | the file never appears |
| `.checkov.yaml` skips the Dockerfile checks | Checkov still reports them |
| `.semgrepignore` hides `*.py` and `web/` | Semgrep reports `app.py` |
| `.bandit` excludes the repository and skips `B602` | Bandit reports `B602` |
| `.njsscan` ignores `web/` | njsscan reports `web/server.js` |
| `.gitleaksignore` lists the key in `app.py` | Gitleaks reports it |
