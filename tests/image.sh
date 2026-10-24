#!/bin/sh
# Known-positive test of the real image: every scanner must run in the hardened container
# from the README and report the issue planted for it in examples/vulnerable-sample.
# Needs Docker and network access (rule sets and vulnerability databases are fetched).
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
IMAGE=${IMAGE:-appsec-toolbox-mcp:dev}
OUT=$(mktemp -d)
trap 'rm -rf "$OUT"' EXIT HUP INT TERM

TARGET="$ROOT/examples/vulnerable-sample"
RUN_OUT=$OUT
run() {
  docker run --rm \
    --read-only \
    --cap-drop=ALL \
    --security-opt=no-new-privileges:true \
    --tmpfs /tmp:rw,nosuid,nodev,size=3g \
    --user "$(id -u):$(id -g)" \
    -e APPSEC_LANGS=auto \
    -v "$TARGET:/runner/target:ro" \
    -v "$RUN_OUT:/runner/output:rw" \
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

expected_fingerprint="sha256:$(cd "$ROOT/examples/vulnerable-sample" && find . -type f -print0 | LC_ALL=C sort -z | xargs -0 sha256sum | sha256sum | cut -d' ' -f1)"

python3 - "$OUT" "$expected_fingerprint" <<'PY'
import hashlib
import json
import sys
from pathlib import Path

out, expected_fingerprint = Path(sys.argv[1]), sys.argv[2]


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
manifest = load("run-manifest.json")
with_reports = [t for t in manifest["tools"] if "report" in t]
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
    check("manifest: target fingerprint matches coreutils", manifest["target"]["content_fingerprint"] == expected_fingerprint),
    check("manifest: report digests match files", len(with_reports) >= 8 and all(
        hashlib.sha256((out / t["report"]).read_bytes()).hexdigest() == t["report_sha256"] for t in with_reports)),
    check("manifest: pinned tool versions recorded", all(t["version"] for t in manifest["tools"] if t["name"] != "language-profile")
        and manifest["toolbox"]["version"] and manifest["toolbox"]["makefile_mcp"]),
    check("audit log: appsec-full passed", [(r["task"], r["status"]) for r in audit] == [("appsec-full", "passed")]),
]
sys.exit(0 if all(results) else 1)
PY

# A hostile repository tries to run its own code and hide its findings through target-owned
# scanner configuration. Every attempt must fail.
TARGET="$ROOT/examples/hostile-sample"
HOSTILE="$OUT/hostile"
RUN_OUT=$HOSTILE
mkdir -p "$HOSTILE"
for task in security-checkov security-semgrep security-gitleaks security-language; do
  quiet run makefile-mcp run "$task"
done

python3 - "$HOSTILE" <<'PY'
import json
import sys
from pathlib import Path

out = Path(sys.argv[1])


def check(label, ok):
    print(f"{'ok' if ok else 'FAIL'}  {label}")
    return ok


checkov = json.loads((out / "checkov.json").read_text(encoding="utf-8"))
checkov = checkov if isinstance(checkov, list) else [checkov]
failed = {c["check_id"] for report in checkov for c in report["results"]["failed_checks"]}
semgrep = {r["path"] for r in json.loads((out / "semgrep.json").read_text())["results"]}
bandit = {r["test_id"] for r in json.loads((out / "bandit.json").read_text())["results"]}
njsscan = json.loads((out / "njsscan.json").read_text()).get("nodejs", {})
njsscan_files = {f["file_path"] for rule in njsscan.values() for f in rule.get("files", [])}
gitleaks_lines = {(f["File"], f["StartLine"]) for f in json.loads((out / "gitleaks.json").read_text())}
gitleaks = {path for path, _ in gitleaks_lines}
semgrep_lines = {(r["path"], r["start"]["line"]) for r in json.loads((out / "semgrep.json").read_text())["results"]}
gosec = {i["file"].rsplit("/", 1)[-1] for i in json.loads((out / "gosec.json").read_text())["Issues"]}
results = [
    check("hostile: target .checkov.yaml cannot load code", not (out / "TARGET_CODE_RAN").exists()),
    check("hostile: target .checkov.yaml cannot skip checks", {"CKV_DOCKER_2", "CKV_DOCKER_3"} <= failed),
    check("hostile: target .semgrepignore is ignored", "target/app.py" in semgrep),
    check("hostile: target .bandit is ignored", "B602" in bandit),
    check("hostile: target .njsscan is ignored", any(path.endswith("web/server.js") for path in njsscan_files)),
    check("hostile: target .gitleaksignore is ignored", "target/app.py" in gitleaks),
    check("hostile: # nosemgrep does not hide a finding", ("target/app.py", 11) in semgrep_lines),
    check("hostile: gitleaks:allow does not hide a secret", ("target/app.py", 14) in gitleaks_lines),
    check("hostile: #nosec does not hide a gosec finding", "main.go" in gosec),
]
sys.exit(0 if all(results) else 1)
PY

echo "image test: ok"
