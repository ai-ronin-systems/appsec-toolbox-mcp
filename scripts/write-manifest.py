#!/usr/bin/env python3
"""Write output/run-manifest.json: execution facts that tie evidence to the scanned snapshot.

The manifest records what was scanned (a reproducible target fingerprint), which reports this
task produced (with SHA-256 digests), and which tool versions ran with what status. It never
interprets findings.
"""

from __future__ import annotations

import hashlib
import json
import os
import sys
from datetime import UTC, datetime
from pathlib import Path

SCHEMA_VERSION = 1
TOOL_VERSIONS = Path(os.environ.get("TOOLBOX_TOOL_VERSIONS", "/runner/tool-versions.json"))

# Reports each exposed task produces: (tool, report file). Only these count for a run, so a
# report left over from an earlier task is never attributed to this one.
GENERIC = {
    "security-semgrep": [("semgrep", "semgrep.json"), ("suppression-inventory", "suppressions.json")],
    "security-gitleaks": [("gitleaks", "gitleaks.json")],
    "security-osv": [("osv-scanner", "osv.json")],
    "security-trivy": [("trivy", "trivy.json")],
    "security-checkov": [("checkov", "checkov.json")],
    "supply-chain-sbom": [("syft", "sbom.cdx.json")],
}
LANGUAGE_TASKS = {"security-language", "appsec-full"}
TOOLBOX_TOOLS = {"suppression-inventory", "language-profile"}
# Inputs fetched at scan time rather than pinned in the image: the same snapshot scanned on
# another day can produce different findings, so the manifest says so for each tool that ran.
LIVE_DATA = {
    "semgrep": "semgrep: registry ruleset p/default is fetched at scan time and not pinned",
    "osv-scanner": "osv-scanner: advisories come from the OSV API at scan time; package names "
    "and versions are sent to it",
    "trivy": "trivy: vulnerability database is downloaded at scan time",
}
STATUS = {"completed": "COMPLETED", "error": "ERROR"}


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def target_fingerprint(target: Path) -> dict:
    """Hash the tree exactly like `find . -type f -print0 | LC_ALL=C sort -z | xargs -0 sha256sum
    | sha256sum` run inside the target, so anyone can recompute it. Symlinks are not followed."""
    files: list[str] = []
    for directory, subdirs, names in os.walk(target):
        subdirs.sort()
        for name in names:
            path = Path(directory, name)
            if path.is_file() and not path.is_symlink():
                files.append("./" + path.relative_to(target).as_posix())
    files.sort(key=lambda name: name.encode())
    listing = hashlib.sha256()
    for name in files:
        listing.update(f"{sha256_file(target / name[2:])}  {name}\n".encode())
    return {
        "content_fingerprint": "sha256:" + listing.hexdigest(),
        "algorithm": "find . -type f -print0 | LC_ALL=C sort -z | xargs -0 sha256sum | sha256sum",
        "file_count": len(files),
    }


def language_tools(output: Path) -> tuple[list[tuple[str, str | None, str, str | None]], dict]:
    """Return (tool, report, status, reason) rows and coverage from language-profile.json."""
    profile = json.loads((output / "language-profile.json").read_text(encoding="utf-8"))
    rows = [("language-profile", "language-profile.json", "COMPLETED", None)]
    for item in profile["scanners"]:
        status = STATUS.get(item["status"])
        if status is None:
            not_selected = item.get("reason") == "profile not selected"
            status = "SKIPPED_NOT_APPLICABLE" if not_selected else "SKIPPED_MISSING_PREREQUISITE"
        report = Path(item["report"]).name if item.get("report") else None
        rows.append((item["scanner"], report, status, item.get("reason")))
    selection = profile["selection"]
    coverage = {
        "language_mode": selection.get("mode"),
        "detected_languages": selection.get("detected", []),
        "selected_profiles": selection.get("selected", []),
    }
    return rows, coverage


def main() -> int:
    target, output, task = Path(sys.argv[1]), Path(sys.argv[2]), sys.argv[3]
    versions = json.loads(TOOL_VERSIONS.read_text()) if TOOL_VERSIONS.is_file() else {}
    limitations = ["container image digest is not visible from inside the container"]
    if not versions:
        limitations.append(f"tool versions unavailable ({TOOL_VERSIONS} not found)")

    rows = [
        (tool, report, "COMPLETED", None)
        for name, reports in GENERIC.items()
        if task in (name, "appsec-full")
        for tool, report in reports
    ]
    coverage = None
    if task in LANGUAGE_TASKS:
        language_rows, coverage = language_tools(output)
        rows += language_rows

    limitations += [LIVE_DATA[tool] for tool, _, _, _ in rows if tool in LIVE_DATA]

    tools = []
    for tool, report, status, reason in rows:
        # Toolbox scripts carry the toolbox version.
        version = versions.get(tool) or (
            versions.get("appsec-toolbox-mcp") if tool in TOOLBOX_TOOLS else None
        )
        entry = {"name": tool, "version": version, "status": status}
        if reason:
            entry["reason"] = reason
        if report and (output / report).is_file():
            entry["report"] = report
            entry["report_sha256"] = sha256_file(output / report)
            entry["report_bytes"] = (output / report).stat().st_size
        tools.append(entry)

    manifest = {
        "schema_version": SCHEMA_VERSION,
        "toolbox": {
            "name": "appsec-toolbox-mcp",
            "version": versions.get("appsec-toolbox-mcp"),
            "makefile_mcp": versions.get("makefile-mcp"),
        },
        "target": target_fingerprint(target),
        "run": {"task": task, "completed_at": datetime.now(UTC).isoformat(timespec="seconds")},
        "tools": tools,
        "coverage": coverage,
        "limitations": limitations,
    }
    (output / "run-manifest.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
