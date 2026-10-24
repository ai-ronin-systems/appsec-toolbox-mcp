import json
import subprocess
import sys

import pytest


def _coreutils_fingerprint(target):
    pipeline = "find . -type f -print0 | LC_ALL=C sort -z | xargs -0 sha256sum | sha256sum"
    out = subprocess.run(
        ["sh", "-c", pipeline], cwd=target, capture_output=True, text=True, check=True
    )
    return "sha256:" + out.stdout.split()[0]


def test_fingerprint_matches_the_documented_coreutils_pipeline(manifest, tmp_path):
    (tmp_path / "b").mkdir()
    (tmp_path / "b" / "z.txt").write_text("z")
    (tmp_path / "B.txt").write_text("upper")
    (tmp_path / "a b.txt").write_text("space")
    (tmp_path / "link").symlink_to("/etc/hostname")

    fingerprint = manifest.target_fingerprint(tmp_path)

    assert fingerprint["content_fingerprint"] == _coreutils_fingerprint(tmp_path)
    assert fingerprint["file_count"] == 3


def _run(manifest, tmp_path, task, monkeypatch, offline=None):
    target, output = tmp_path / "target", tmp_path / "output"
    target.mkdir(exist_ok=True)
    output.mkdir(exist_ok=True)
    versions = tmp_path / "versions.json"
    versions.write_text(json.dumps({"appsec-toolbox-mcp": "9.9.9", "semgrep": "1.0"}))
    monkeypatch.setattr(manifest, "TOOL_VERSIONS", versions)
    monkeypatch.chdir(tmp_path)
    if offline is not None:
        monkeypatch.setenv("APPSEC_OFFLINE", "1")
        (tmp_path / "offline-data").mkdir(exist_ok=True)
        (tmp_path / "offline-data" / "offline-data.json").write_text(json.dumps(offline))
    else:
        monkeypatch.delenv("APPSEC_OFFLINE", raising=False)
    monkeypatch.setattr(sys, "argv", ["write-manifest", str(target), str(output), task])
    assert manifest.main() == 0
    return json.loads((output / "run-manifest.json").read_text())


def test_only_reports_of_the_requested_task_are_listed(manifest, tmp_path, monkeypatch):
    (tmp_path / "output").mkdir()
    (tmp_path / "output" / "semgrep.json").write_text("{}")
    (tmp_path / "output" / "suppressions.json").write_text("{}")
    (tmp_path / "output" / "trivy.json").write_text("{}")

    result = _run(manifest, tmp_path, "security-semgrep", monkeypatch)

    tools = {tool["name"]: tool for tool in result["tools"]}
    assert set(tools) == {"semgrep", "suppression-inventory"}
    assert tools["suppression-inventory"]["version"] == "9.9.9"
    assert tools["semgrep"]["report_bytes"] == 2
    assert result["run"]["network"] == "online"
    assert result["offline_data"] is None
    assert any(
        item.startswith("semgrep:") and "at scan time" in item for item in result["limitations"]
    )


OFFLINE = {
    "fetched_at": "2026-10-01T00:00:00+00:00",
    "semgrep": {"ruleset": "p/default", "sha256": "ab"},
    "osv": {"ecosystems": {"npm": {}, "PyPI": {}}},
    "trivy": {"db_updated_at": "2026-09-30T00:00:00Z"},
}


def test_offline_runs_record_the_data_they_used(manifest, tmp_path, monkeypatch):
    result = _run(manifest, tmp_path, "security-gitleaks", monkeypatch, offline=OFFLINE)

    assert result["run"]["network"] == "offline"
    assert result["offline_data"] == OFFLINE


def test_offline_limitations_name_the_data_age_for_each_tool_that_ran(manifest):
    limitations = manifest.offline_limitations(
        OFFLINE, ["semgrep", "gitleaks", "osv-scanner", "trivy"]
    )

    assert limitations == [
        "semgrep: offline ruleset p/default fetched 2026-10-01T00:00:00+00:00",
        "osv-scanner: offline databases fetched 2026-10-01T00:00:00+00:00 for PyPI, npm; "
        "other ecosystems fail the scan",
        "trivy: offline database updated 2026-09-30T00:00:00Z",
    ]


def test_offline_without_data_fails_instead_of_claiming_offline(manifest, tmp_path, monkeypatch):
    monkeypatch.setenv("APPSEC_OFFLINE", "1")
    monkeypatch.chdir(tmp_path)
    (tmp_path / "target").mkdir()
    (tmp_path / "output").mkdir()
    monkeypatch.setattr(sys, "argv", ["write-manifest", "target", "output", "security-semgrep"])

    with pytest.raises(FileNotFoundError):
        manifest.main()
