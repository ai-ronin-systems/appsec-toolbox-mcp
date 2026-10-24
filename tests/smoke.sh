#!/bin/sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT HUP INT TERM
mkdir -p "$TMP/bin" "$TMP/target/target/classes" "$TMP/output"
printf 'print("hello")\n' > "$TMP/target/app.py"
printf 'console.log("hello")\n' > "$TMP/target/app.js"
printf 'package main\nfunc main() {}\n' > "$TMP/target/main.go"
printf 'module example.invalid/test\ngo 1.25\n' > "$TMP/target/go.mod"
printf '{"dependencies":{}}\n' > "$TMP/target/package.json"
printf '<project/>\n' > "$TMP/target/pom.xml"
printf '\312\376\272\276' > "$TMP/target/target/classes/App.class"

cat > "$TMP/bin/semgrep" <<'SCANNER'
#!/bin/sh
set -eu
out=
while [ "$#" -gt 0 ]; do
  [ "$1" = "--output" ] && { shift; out=$1; }
  shift || true
done
printf '{"results":[]}\n' > "$out"
SCANNER

cat > "$TMP/bin/gitleaks" <<'SCANNER'
#!/bin/sh
set -eu
out=
while [ "$#" -gt 0 ]; do
  [ "$1" = "--report-path" ] && { shift; out=$1; }
  shift || true
done
printf '[]\n' > "$out"
SCANNER

cat > "$TMP/bin/osv-scanner" <<'SCANNER'
#!/bin/sh
printf '{"results":[{"packages":[]}]}\n'
exit 1
SCANNER

cat > "$TMP/bin/trivy" <<'SCANNER'
#!/bin/sh
set -eu
out=
while [ "$#" -gt 0 ]; do
  [ "$1" = "--output" ] && { shift; out=$1; }
  shift || true
done
printf '{"Results":[]}\n' > "$out"
SCANNER

cat > "$TMP/bin/checkov" <<'SCANNER'
#!/bin/sh
set -eu
printf '{"check_type":"terraform","results":{"passed_checks":[],"failed_checks":[],"skipped_checks":[]}}\n'
SCANNER

cat > "$TMP/bin/syft" <<'SCANNER'
#!/bin/sh
set -eu
out=
while [ "$#" -gt 0 ]; do
  if [ "$1" = "--output" ]; then
    shift
    out=${1#cyclonedx-json=}
  fi
  shift || true
done
printf '{"bomFormat":"CycloneDX","components":[]}\n' > "$out"
SCANNER

cat > "$TMP/bin/bandit" <<'SCANNER'
#!/bin/sh
set -eu
out=
while [ "$#" -gt 0 ]; do
  [ "$1" = "--output" ] && { shift; out=$1; }
  shift || true
done
printf '{"results":[],"errors":[]}\n' > "$out"
SCANNER

cat > "$TMP/bin/njsscan" <<'SCANNER'
#!/bin/sh
set -eu
out=
while [ "$#" -gt 0 ]; do
  [ "$1" = "-o" ] && { shift; out=$1; }
  shift || true
done
printf '{"nodejs":{},"templates":{}}\n' > "$out"
SCANNER

cat > "$TMP/bin/gosec" <<'SCANNER'
#!/bin/sh
set -eu
out=
while [ "$#" -gt 0 ]; do
  case "$1" in
    -out=*) out=${1#-out=} ;;
  esac
  shift || true
done
printf '{"Golang errors":{},"Issues":[],"Stats":{}}\n' > "$out"
SCANNER

cat > "$TMP/bin/findsecbugs" <<'SCANNER'
#!/bin/sh
set -eu
out=
while [ "$#" -gt 0 ]; do
  [ "$1" = "-output" ] && { shift; out=$1; }
  shift || true
done
printf '<?xml version="1.0"?><BugCollection/>\n' > "$out"
SCANNER

chmod +x "$TMP/bin/"*
cp -R "$ROOT/scripts" "$TMP/scripts"
cp "$ROOT/Makefile" "$TMP/Makefile"

(
  cd "$TMP"
  PATH="$TMP/bin:$PATH" APPSEC_LANGS=auto make appsec-full >/dev/null
)

for report in \
  semgrep.json gitleaks.json osv.json trivy.json checkov.json sbom.cdx.json \
  bandit.json njsscan.json gosec.json findsecbugs.xml language-profile.json; do
  test -s "$TMP/output/$report" || { echo "missing report: $report" >&2; exit 1; }
done

# run-manifest.json: the fingerprint must match the documented coreutils pipeline, and every
# listed report digest must match the file on disk.
expected_fingerprint="sha256:$(cd "$TMP/target" && find . -type f -print0 | LC_ALL=C sort -z | xargs -0 sha256sum | sha256sum | cut -d' ' -f1)"
python3 - "$TMP/output" "$expected_fingerprint" <<'PY'
import hashlib
import json
import sys
from pathlib import Path

output, expected = Path(sys.argv[1]), sys.argv[2]
manifest = json.loads((output / "run-manifest.json").read_text(encoding="utf-8"))
assert manifest["run"]["task"] == "appsec-full", manifest["run"]
assert manifest["target"]["content_fingerprint"] == expected, (manifest["target"], expected)
reports = {t["name"]: t for t in manifest["tools"] if "report" in t}
for tool in ("semgrep", "gitleaks", "osv-scanner", "trivy", "checkov", "syft", "bandit", "gosec"):
    entry = reports[tool]
    digest = hashlib.sha256((output / entry["report"]).read_bytes()).hexdigest()
    assert entry["report_sha256"] == digest, (tool, entry)
    assert entry["status"] == "COMPLETED", entry
live = [item.split(":")[0] for item in manifest["limitations"] if "at scan time" in item]
assert live == ["semgrep", "osv-scanner", "trivy"], manifest["limitations"]
PY

python3 - "$TMP/output/language-profile.json" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as handle:
    report = json.load(handle)

assert report["selection"]["mode"] == "auto"
assert report["selection"]["selected"] == ["python", "java", "node", "go"]
statuses = {item["scanner"]: item["status"] for item in report["scanners"]}
assert statuses == {
    "bandit": "completed",
    "findsecbugs": "completed",
    "njsscan": "completed",
    "gosec": "completed",
}
PY

rm -f "$TMP/output/"bandit.json "$TMP/output/"njsscan.json "$TMP/output/"gosec.json "$TMP/output/"findsecbugs.xml
(
  cd "$TMP"
  PATH="$TMP/bin:$PATH" APPSEC_LANGS=python,node make security-language >/dev/null
)

test -s "$TMP/output/bandit.json"
test -s "$TMP/output/njsscan.json"
test ! -e "$TMP/output/gosec.json"
test ! -e "$TMP/output/findsecbugs.xml"
python3 - "$TMP/output/language-profile.json" <<'PY'
import json
import sys
with open(sys.argv[1], encoding="utf-8") as handle:
    report = json.load(handle)
assert report["selection"]["mode"] == "explicit"
assert report["selection"]["selected"] == ["python", "node"]
PY
# A single-task run lists only that task's reports, never leftovers from the earlier bundle.
python3 - "$TMP/output/run-manifest.json" <<'PY'
import json
import sys
with open(sys.argv[1], encoding="utf-8") as handle:
    manifest = json.load(handle)
assert manifest["run"]["task"] == "security-language", manifest["run"]
names = {t["name"] for t in manifest["tools"]}
assert "semgrep" not in names and "trivy" not in names, names
assert not any("at scan time" in item for item in manifest["limitations"]), manifest
status = {t["name"]: t["status"] for t in manifest["tools"]}
assert status["bandit"] == "COMPLETED" and status["gosec"] == "SKIPPED_NOT_APPLICABLE", status
PY

# Run through Makefile MCP itself, not plain make: its governed environment policy decides
# which variables reach the Makefile. APPSEC_LANGS must survive that boundary.
cp "$ROOT/.makefile-mcp.yaml" "$TMP/.makefile-mcp.yaml"
cp -R "$ROOT/config" "$TMP/config"
rm -f "$TMP/output/"*
(
  cd "$TMP"
  PATH="$TMP/bin:$PATH" APPSEC_LANGS=go makefile-mcp run security-language >/dev/null
)
python3 - "$TMP/output/language-profile.json" <<'PY'
import json
import sys
with open(sys.argv[1], encoding="utf-8") as handle:
    report = json.load(handle)
assert report["selection"]["selected"] == ["go"], report["selection"]
PY
python3 - "$TMP/output/makefile-mcp-audit.jsonl" <<'PY'
import json
import sys
with open(sys.argv[1], encoding="utf-8") as handle:
    records = [json.loads(line) for line in handle]
assert [(r["task"], r["status"]) for r in records] == [("security-language", "passed")], records
assert records[0]["risk"] == "safe" and records[0]["approval"] == "not_required", records[0]
PY
(
  cd "$TMP"
  if PATH="$TMP/bin:$PATH" makefile-mcp run toolbox-versions >/dev/null 2>&1; then
    echo "maintenance target toolbox-versions must not be runnable through Makefile MCP" >&2
    exit 1
  fi
)

# Ensure the current Makefile MCP policy filename is present and the legacy name is absent.
test -f "$ROOT/.makefile-mcp.yaml"
test ! -e "$ROOT/.make-mcp.yaml"

# Ensure maintenance targets are explicitly hidden from Makefile MCP config.
for task in toolbox-check toolbox-versions test test-image image; do
  grep -A1 "^  ${task}:" "$ROOT/.makefile-mcp.yaml" | grep -q 'enabled: false'
done

# The language profile is one governed capability; individual scanners stay internal.
grep -A2 '^  security-language:' "$ROOT/.makefile-mcp.yaml" | grep -q 'risk: safe'
grep -q '^  security.language: security-language$' "$ROOT/.makefile-mcp.yaml"

# Reject stale pre-rename Makefile MCP identities in tracked project text.
if git -C "$ROOT" ls-files -z -- ':!tests/smoke.sh' \
  | (cd "$ROOT" && xargs -0 grep -InE \
      'make-mcp|make_mcp|MAKE_MCP|\.make-mcp\.yaml|ai-ronin-systems/make-mcp') >/dev/null 2>&1; then
  echo "stale Makefile MCP identity found" >&2
  exit 1
fi

# Release: storing the attestation in GHCR (push-to-registry) needs a GHCR login in the attest
# job; without it v0.2.0 was pushed but never signed.
awk '/^  attest:/{a=1} /^  github-release:/{a=0} a' "$ROOT/.github/workflows/release.yml" \
  | grep -q 'docker login ghcr.io' || { echo "release attest job must log in to GHCR" >&2; exit 1; }

echo "smoke: ok"
