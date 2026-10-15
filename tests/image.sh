#!/bin/sh
# Known-positive test of the real image: every scanner must run in the hardened container
# from the README and report the issue planted for it in examples/vulnerable-sample.
# Needs Docker and network access (rule sets and vulnerability databases are fetched).
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
IMAGE=${IMAGE:-appsec-toolbox-mcp:dev}
OUT=$(mktemp -d)
trap 'rm -rf "$OUT"' EXIT HUP INT TERM

run() {
  docker run --rm \
    --read-only \
    --cap-drop=ALL \
    --security-opt=no-new-privileges:true \
    --tmpfs /tmp:rw,nosuid,nodev,size=3g \
    --user "$(id -u):$(id -g)" \
    -e APPSEC_LANGS=auto \
    -v "$ROOT/examples/vulnerable-sample:/runner/target:ro" \
    -v "$OUT:/runner/output:rw" \
    "$IMAGE" "$@"
}

LOG="$OUT/test.log"
quiet() {
  "$@" >>"$LOG" 2>&1 || { cat "$LOG" >&2; echo "image test: '$*' failed" >&2; exit 1; }
}

# Every scanner is installed and executes (catches broken installs such as CRLF shebangs).
quiet run make -s toolbox-versions

# The full bundle, through Makefile MCP's governed execution path.
quiet run makefile-mcp run appsec-full

python3 - "$OUT" <<'PY'
import json
import sys
from pathlib import Path

out = Path(sys.argv[1])


def load(name):
    return json.loads((out / name).read_text(encoding="utf-8"))


def check(label, ok):
    print(f"{'ok' if ok else 'FAIL'}  {label}")
    return ok


semgrep = {r["check_id"] for r in load("semgrep.json")["results"]}
bandit = {r["test_id"] for r in load("bandit.json")["results"]}
gitleaks = load("gitleaks.json")
osv = [
    v
    for result in load("osv.json").get("results", [])
    for package in result.get("packages", [])
    for v in package.get("vulnerabilities", [])
]
trivy = load("trivy.json").get("Results", [])
checkov = load("checkov.json")
checkov = checkov if isinstance(checkov, list) else [checkov]
profile = load("language-profile.json")
audit = [json.loads(line) for line in (out / "makefile-mcp-audit.jsonl").read_text().splitlines()]

results = [
    check("semgrep: shell injection", any("subprocess" in rule for rule in semgrep)),
    check("semgrep: unsafe deserialization", any("deserialization" in rule or "yaml" in rule for rule in semgrep)),
    check("bandit: shell=True (B602)", "B602" in bandit),
    check("bandit: yaml.load (B506)", "B506" in bandit),
    check("bandit: hardcoded password (B105)", "B105" in bandit),
    check("gitleaks: hardcoded API key", any(f["File"].endswith("app.py") for f in gitleaks)),
    check("osv: vulnerable dependencies", len(osv) > 0),
    check("trivy: vulnerable dependencies", any(r.get("Vulnerabilities") for r in trivy)),
    check("trivy: Dockerfile misconfiguration", any(r.get("Misconfigurations") for r in trivy)),
    check("checkov: failed Dockerfile checks", any(c["results"]["failed_checks"] for c in checkov)),
    check("syft: SBOM components", len(load("sbom.cdx.json").get("components", [])) > 0),
    check("language profile: python only", profile["selection"]["selected"] == ["python"]),
    check("audit log: appsec-full passed", [(r["task"], r["status"]) for r in audit] == [("appsec-full", "passed")]),
]
sys.exit(0 if all(results) else 1)
PY

echo "image test: ok"
