#!/bin/sh
set -eu

TARGET_DIR=${1:?target directory required}
REPORT_PATH=${2:?report path required}
TMP_REPORT="${REPORT_PATH}.tmp"
trap 'rm -f "$TMP_REPORT"' EXIT HUP INT TERM

set +e
osv-scanner scan source \
  --recursive \
  --no-resolve \
  --config=config/osv-scanner.toml \
  --format json \
  "$TARGET_DIR" >"$TMP_REPORT"
status=$?
set -e

# OSV-Scanner uses exit 1 for findings. Findings are evidence, not execution failure.
case "$status" in
  0|1)
    mv "$TMP_REPORT" "$REPORT_PATH"
    ;;
  128)
    # No supported packages is a valid audit outcome. Preserve machine-readable output.
    if [ -s "$TMP_REPORT" ]; then
      mv "$TMP_REPORT" "$REPORT_PATH"
    else
      printf '{"results":[]}\n' >"$REPORT_PATH"
    fi
    ;;
  *)
    if [ -s "$TMP_REPORT" ]; then
      mv "$TMP_REPORT" "$REPORT_PATH"
    fi
    exit "$status"
    ;;
esac
