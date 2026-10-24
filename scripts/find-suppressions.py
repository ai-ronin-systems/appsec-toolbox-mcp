#!/usr/bin/env python3
"""Write output/suppressions.json: where the target tries to silence scanners.

The toolbox disables or ignores most of these, but their presence is evidence of intent, and a
few (Trivy and njsscan comments, Checkov skips) are still honoured by the scanners. The report
lists file, line, and marker only. It never copies line text, which is attacker-controlled.
"""

from __future__ import annotations

import json
import os
import re
import sys
from pathlib import Path

SCHEMA_VERSION = 1
MAX_FILE_BYTES = 1 << 20
MAX_MARKERS = 10_000
SNIFF_BYTES = 8192
PRUNE_DIRS = {".git", ".hg", ".svn"}

# Inline comments that tell a scanner to skip a finding.
MARKERS = {
    "nosemgrep": re.compile(rb"\bnosem(?:grep)?\b", re.IGNORECASE),
    "nosec": re.compile(rb"#\s*nosec\b", re.IGNORECASE),
    "gitleaks:allow": re.compile(rb"gitleaks:allow", re.IGNORECASE),
    "checkov:skip": re.compile(rb"checkov:skip=", re.IGNORECASE),
    "trivy:ignore": re.compile(rb"trivy:ignore:", re.IGNORECASE),
    "tfsec:ignore": re.compile(rb"tfsec:ignore:", re.IGNORECASE),
    "njsscan-ignore": re.compile(rb"njsscan-ignore", re.IGNORECASE),
}
# Scanner settings files the toolbox never applies, but which show intent to suppress.
SETTINGS_FILES = {
    ".semgrepignore",
    ".gitleaksignore",
    ".gitleaks.toml",
    ".trivyignore",
    ".trivyignore.yaml",
    "trivy.yaml",
    ".bandit",
    ".njsscan",
    ".checkov.yaml",
    ".checkov.yml",
    "osv-scanner.toml",
}


def scan(target: Path) -> dict:
    markers: list[dict] = []
    settings: list[str] = []
    skipped = {"symlinks": 0, "large_files": 0, "binary_files": 0, "unreadable_files": 0}
    truncated = False
    for directory, subdirs, names in os.walk(target, followlinks=False):
        subdirs[:] = sorted(d for d in subdirs if d not in PRUNE_DIRS)
        for name in sorted(names):
            if truncated:
                break
            path = Path(directory, name)
            relative = path.relative_to(target).as_posix()
            if path.is_symlink():
                skipped["symlinks"] += 1
                continue
            if name in SETTINGS_FILES:
                settings.append(relative)
            try:
                if not path.is_file():
                    continue
                if path.stat().st_size > MAX_FILE_BYTES:
                    skipped["large_files"] += 1
                    continue
                data = path.read_bytes()
            except OSError:
                skipped["unreadable_files"] += 1
                continue
            if b"\0" in data[:SNIFF_BYTES]:
                skipped["binary_files"] += 1
                continue
            for number, line in enumerate(data.splitlines(), 1):
                for marker, pattern in MARKERS.items():
                    if pattern.search(line):
                        if len(markers) >= MAX_MARKERS:
                            truncated = True
                            break
                        markers.append({"file": relative, "line": number, "marker": marker})
    return {
        "schema_version": SCHEMA_VERSION,
        "markers": markers,
        "settings_files": settings,
        "skipped": skipped,
        "truncated": truncated,
        "limits": {"max_file_bytes": MAX_FILE_BYTES, "max_markers": MAX_MARKERS},
    }


def main() -> int:
    target, output = Path(sys.argv[1]), Path(sys.argv[2])
    report = scan(target)
    (output / "suppressions.json").write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
