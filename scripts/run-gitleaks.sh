#!/bin/sh
set -eu

TARGET_DIR=${1:?target directory required}
REPORT_PATH=${2:?report path required}
CONFIG="$PWD/config/gitleaks.toml"
case "$REPORT_PATH" in /*) ;; *) REPORT_PATH="$PWD/$REPORT_PATH" ;; esac

# Gitleaks always applies <source>/.gitleaksignore, whatever --gitleaks-ignore-path says, so the
# audited repository could suppress its own findings. When the file exists, scan a copy without
# it. The copy keeps the same relative paths, so reports read exactly as a direct scan would.
# tar copies symlinks as links and never follows them.
if [ -e "$TARGET_DIR/.gitleaksignore" ] || [ -L "$TARGET_DIR/.gitleaksignore" ]; then
  VIEW=$(mktemp -d)
  trap 'rm -rf "$VIEW"' EXIT HUP INT TERM
  mkdir "$VIEW/$TARGET_DIR"
  tar -C "$TARGET_DIR" --anchored --exclude=./.gitleaksignore -cf - . | tar -C "$VIEW/$TARGET_DIR" -xf -
  cd "$VIEW"
fi

gitleaks dir \
  --no-banner \
  --redact \
  --config "$CONFIG" \
  --exit-code 0 \
  --report-format json \
  --report-path "$REPORT_PATH" \
  "$TARGET_DIR"
