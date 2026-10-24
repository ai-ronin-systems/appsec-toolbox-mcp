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
OFFLINE_DATA = Path("offline-data/offline-data.json")

# Reports each exposed task produces: (tool, report file). Only these count for a run, so a
# report left over from an earlier task is never attributed to this one.
GENERIC = {
    "security-semgrep": [
        ("semgrep", "semgrep.json"),
        ("suppression-inventory", "suppressions.json"),
    ],
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


def _sha256sum_line(digest: str, name: bytes) -> bytes:
    """Format one line exactly as GNU sha256sum does, escaping names it would escape."""
    if not any(char in name for char in b"\\\n\r"):
        return digest.encode() + b"  " + name + b"\n"
    escaped = name.replace(b"\\", b"\\\\").replace(b"\n", b"\\n").replace(b"\r", b"\\r")
    return b"\\" + digest.encode() + b"  " + escaped + b"\n"


def target_fingerprint(target: Path) -> dict:
    """Hash the tree exactly like `find . -type f -print0 | LC_ALL=C sort -z | xargs -0 sha256sum
    | sha256sum` run inside the target, so anyone can recompute it. Symlinks are not followed.

    Names are handled as raw bytes: a hostile repository can hold names that are not UTF-8.
    """
    root = os.fsencode(target)
    files: list[bytes] = []
    for directory, subdirs, names in os.walk(root):
        subdirs.sort()
        for name in names:
            path = os.path.join(directory, name)
            if os.path.isfile(path) and not os.path.islink(path):
                files.append(b"./" + os.path.relpath(path, root))
    files.sort()
    listing = hashlib.sha256()
    for name in files:
        digest = sha256_file(Path(os.fsdecode(os.path.join(root, name[2:]))))
        listing.update(_sha256sum_line(digest, name))
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


def offline_limitations(data: dict, ran: list[str]) -> list[str]:
    """Say which fetched data an offline scan used, so its age is visible next to the findings."""
    fetched = data.get("fetched_at")
    texts = {
        "semgrep": f"semgrep: offline ruleset {data['semgrep']['ruleset']} fetched {fetched}",
        "osv-scanner": f"osv-scanner: offline databases fetched {fetched} for "
        + ", ".join(sorted(data["osv"]["ecosystems"]))
        + "; other ecosystems fail the scan",
        "trivy": f"trivy: offline database updated {data['trivy'].get('db_updated_at')}",
    }
    return [texts[tool] for tool in ran if tool in texts]


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

    offline = os.environ.get("APPSEC_OFFLINE") == "1"
    offline_data = None
    ran = [tool for tool, _, _, _ in rows]
    if offline:
        offline_data = json.loads(OFFLINE_DATA.read_text(encoding="utf-8"))
        limitations += offline_limitations(offline_data, ran)
    else:
        limitations += [LIVE_DATA[tool] for tool in ran if tool in LIVE_DATA]

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
        "run": {
            "task": task,
            "completed_at": datetime.now(UTC).isoformat(timespec="seconds"),
            "network": "offline" if offline else "online",
        },
        "offline_data": offline_data,
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
