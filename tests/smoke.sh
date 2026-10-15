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

# Ensure the current Makefile MCP policy filename is present and the legacy name is absent.
test -f "$ROOT/.makefile-mcp.yaml"
test ! -e "$ROOT/.make-mcp.yaml"

# Ensure maintenance targets are explicitly hidden from Makefile MCP config.
for task in toolbox-check toolbox-versions test image; do
  grep -A1 "^  ${task}:" "$ROOT/.makefile-mcp.yaml" | grep -q 'enabled: false'
done

# The language profile is one governed capability; individual scanners stay internal.
grep -A2 '^  security-language:' "$ROOT/.makefile-mcp.yaml" | grep -q 'risk: safe'
grep -q '^  security.language: security-language$' "$ROOT/.makefile-mcp.yaml"

# Reject stale pre-rename Makefile MCP identities in tracked project text.
if grep -RInE \
  --exclude-dir=.git \
  --exclude='smoke.sh' \
  'make-mcp|make_mcp|MAKE_MCP|\.make-mcp\.yaml|ai-ronin-systems/make-mcp' \
  "$ROOT" >/dev/null 2>&1; then
  echo "stale Makefile MCP identity found" >&2
  exit 1
fi

echo "smoke: ok"
