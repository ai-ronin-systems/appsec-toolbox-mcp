#!/usr/bin/env python3
"""Fetch the rule and advisory data that scans otherwise download, for APPSEC_OFFLINE=1.

Operator-run with network access, never through MCP. It writes into one directory that scans
later mount read-only:

    semgrep/p-default.yml               Semgrep registry ruleset p/default
    trivy/                               Trivy vulnerability and Java databases
    osv/osv-scalibr/<ecosystem>/all.zip  OSV databases, one per ecosystem
    offline-data.json                    what was fetched, when, and its SHA-256

The data comes from the same sources an online scan uses. It is not signed by its publishers,
so the digests record what was fetched rather than prove where it came from.
"""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path

SCHEMA_VERSION = 1
SEMGREP_RULESET = "p/default"
SEMGREP_URL = "https://semgrep.dev/c/p/default"
OSV_URL = "https://osv-vulnerabilities.storage.googleapis.com/{ecosystem}/all.zip"
DEFAULT_ECOSYSTEMS = "PyPI npm Maven Go crates.io RubyGems Packagist NuGet Pub Hex"


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def download(url: str, path: Path) -> dict:
    path.parent.mkdir(parents=True, exist_ok=True)
    partial = path.with_suffix(path.suffix + ".part")
    subprocess.run(["curl", "-fsSL", "--retry", "3", "-o", str(partial), url], check=True)
    partial.replace(path)
    return {"url": url, "sha256": sha256_file(path), "bytes": path.stat().st_size}


def trivy_updated_at(metadata: Path) -> str | None:
    try:
        return json.loads(metadata.read_text(encoding="utf-8")).get("UpdatedAt")
    except (OSError, json.JSONDecodeError):
        return None


def main() -> int:
    data = Path(sys.argv[1] if len(sys.argv) > 1 else "offline-data")
    ecosystems = os.environ.get("OSV_ECOSYSTEMS", DEFAULT_ECOSYSTEMS).split()
    data.mkdir(parents=True, exist_ok=True)
    (data / "offline-data.json").unlink(missing_ok=True)

    rules = data / "semgrep" / "p-default.yml"
    semgrep = {"ruleset": SEMGREP_RULESET, "file": "semgrep/p-default.yml", **download(SEMGREP_URL, rules)}

    osv = {}
    for ecosystem in ecosystems:
        target = data / "osv" / "osv-scalibr" / ecosystem / "all.zip"
        osv[ecosystem] = download(OSV_URL.format(ecosystem=ecosystem), target)

    trivy_dir = data / "trivy"
    for flag in ("--download-db-only", "--download-java-db-only"):
        subprocess.run(["trivy", "fs", "--quiet", "--cache-dir", str(trivy_dir), flag], check=True)
    trivy = {
        "db_updated_at": trivy_updated_at(trivy_dir / "db" / "metadata.json"),
        "java_db_updated_at": trivy_updated_at(trivy_dir / "java-db" / "metadata.json"),
    }

    manifest = {
        "schema_version": SCHEMA_VERSION,
        "fetched_at": datetime.now(UTC).isoformat(timespec="seconds"),
        "semgrep": semgrep,
        "osv": {"ecosystems": osv},
        "trivy": trivy,
    }
    # Written last: its presence means the directory is complete.
    (data / "offline-data.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    print(f"offline data: {data} ({', '.join(ecosystems)})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
