# Hostile sample

**Deliberately hostile. Do not reuse any of this code.**

A repository that tries to run its own code inside the toolbox and to hide its own findings
with target-owned scanner configuration. `make test-image` scans it and requires that every
attempt fails:

| Attempt | Expected result |
| --- | --- |
| `.checkov.yaml` names `checks/` as external checks, which write `output/TARGET_CODE_RAN` | the file never appears |
| `.checkov.yaml` skips the Dockerfile checks | Checkov still reports them |
