#!/bin/sh
set -eu

TARGET_DIR=${1:?target directory required}
REPORT_PATH=${2:?report path required}
TMP_REPORT="${REPORT_PATH}.tmp"
TMP_STDERR="${REPORT_PATH}.stderr"
# Dependency files OSV could not parse. The manifest marks the scan as an error when present,
# so a corrupt lockfile cannot pass for "no vulnerable dependencies".
ERRORS_PATH="${REPORT_PATH%.json}.errors"
trap 'rm -f "$TMP_REPORT" "$TMP_STDERR"' EXIT HUP INT TERM
rm -f "$ERRORS_PATH"

# Offline: use the databases fetched by `make offline-data`. An ecosystem that was not fetched
# fails the scan instead of reporting no vulnerabilities.
OFFLINE_FLAG=
if [ "${APPSEC_OFFLINE:-0}" = 1 ]; then
  OFFLINE_FLAG=--offline-vulnerabilities
  OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY="$PWD/${OFFLINE_DIR:?}/osv"
  export OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY
fi

set +e
# shellcheck disable=SC2086
osv-scanner scan source \
  --recursive \
  --no-resolve \
  $OFFLINE_FLAG \
  --config=config/osv-scanner.toml \
  --format json \
  "$TARGET_DIR" >"$TMP_REPORT" 2>"$TMP_STDERR"
status=$?
set -e
cat "$TMP_STDERR" >&2
grep -E 'Error during extraction|could not extract' "$TMP_STDERR" >"$ERRORS_PATH" \
  || rm -f "$ERRORS_PATH"

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
