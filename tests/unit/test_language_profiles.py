import json
import os

import pytest


def test_auto_selects_detected_profiles_in_supported_order(profiles):
    detected = {"go": ["main.go"], "python": ["app.py"]}

    assert profiles.parse_selection(" AUTO ", detected) == ("auto", ["python", "go"])


@pytest.mark.parametrize(
    ("requested", "selected"),
    [
        ("none", []),
        ("py,js", ["python", "node"]),
        ("golang,typescript,python,py", ["python", "node", "go"]),
    ],
)
def test_explicit_selection_resolves_aliases_and_ignores_detection(profiles, requested, selected):
    assert profiles.parse_selection(requested, {"java": ["pom.xml"]}) == ("explicit", selected)


@pytest.mark.parametrize("requested", ["", " , ", "auto,python", "none,go", "rust", "python;id"])
def test_invalid_selection_is_rejected(profiles, requested):
    with pytest.raises(ValueError):
        profiles.parse_selection(requested, {})


def test_detection_uses_markers_and_suffixes_and_skips_only_vcs_metadata(profiles, tmp_path):
    (tmp_path / "pom.xml").write_text("<project/>")
    (tmp_path / "web").mkdir()
    (tmp_path / "web" / "App.TSX").write_text("")
    (tmp_path / ".git" / "hooks").mkdir(parents=True)
    (tmp_path / ".git" / "hooks" / "x.go").write_text("")
    # A hostile repository chooses its layout: code under build/ must still select a profile.
    (tmp_path / "build").mkdir()
    (tmp_path / "build" / "app.py").write_text("")

    assert profiles.detect_languages(tmp_path) == {
        "python": ["build/app.py"],
        "java": ["pom.xml"],
        "node": ["web/App.TSX"],
    }


def test_detection_evidence_is_capped(profiles, tmp_path):
    for index in range(20):
        (tmp_path / f"m{index}.py").write_text("")

    assert len(profiles.detect_languages(tmp_path)["python"]) == 8


def test_detection_does_not_follow_symlinked_directories(profiles, tmp_path):
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "x.go").write_text("")
    target = tmp_path / "target"
    target.mkdir()
    (target / "link").symlink_to(outside, target_is_directory=True)

    assert profiles.detect_languages(target) == {}


def test_bytecode_comes_only_from_existing_build_outputs_inside_the_target(profiles, tmp_path):
    target = tmp_path / "target"
    (target / "svc" / "target" / "classes").mkdir(parents=True)
    (target / "svc" / "pom.xml").write_text("<project/>")
    (target / "lib" / "build" / "libs").mkdir(parents=True)
    (target / "lib" / "build.gradle").write_text("")
    (target / "lib" / "build" / "libs" / "lib.jar").write_bytes(b"PK")
    outside = tmp_path / "outside-classes"
    outside.mkdir()
    (target / "evil" / "target").mkdir(parents=True)
    (target / "evil" / "pom.xml").write_text("<project/>")
    (target / "evil" / "target" / "classes").symlink_to(outside, target_is_directory=True)

    found = profiles.java_bytecode_inputs(target)

    assert found == [
        (target / "lib" / "build" / "libs" / "lib.jar").resolve(),
        (target / "svc" / "target" / "classes").resolve(),
    ]


@pytest.mark.parametrize(
    ("payload", "has_errors"),
    [
        ({"Golang errors": {}, "Issues": []}, False),
        ({"Golang errors": {"main.go": [{"error": "cannot load"}]}}, True),
        (None, True),
    ],
)
def test_gosec_processing_errors(profiles, tmp_path, payload, has_errors):
    report = tmp_path / "gosec.json"
    report.write_text("not json" if payload is None else json.dumps(payload))

    assert profiles.gosec_has_processing_errors(report) is has_errors


@pytest.mark.parametrize(
    ("payload", "has_errors"),
    [
        ({"errors": [], "nodejs": {"eval": {}}}, False),
        ({"errors": ["parse failed"]}, True),
        (None, True),
    ],
)
def test_njsscan_errors(profiles, tmp_path, payload, has_errors):
    report = tmp_path / "njsscan.json"
    report.write_text("{" if payload is None else json.dumps(payload))

    assert profiles.njsscan_has_errors(report) is has_errors


def _scanner(profiles, tmp_path, script, **kwargs):
    report = tmp_path / "output" / "r.json"
    report.parent.mkdir(exist_ok=True)
    command = ["sh", "-c", script, "scanner", str(report)]
    return profiles.run_scanner("fake", "python", command, report, report.parent, **kwargs)


def test_scanner_completes_when_it_writes_a_report(profiles, tmp_path):
    result = _scanner(profiles, tmp_path, 'echo "{}" > "$1"')

    assert result == {
        "scanner": "fake",
        "profile": "python",
        "status": "completed",
        "report": "output/r.json",
    }


def test_scanner_error_on_disallowed_exit_code_or_missing_report(profiles, tmp_path):
    failed = _scanner(profiles, tmp_path, 'echo "{}" > "$1"; exit 1')
    silent = _scanner(profiles, tmp_path, "exit 0")

    assert (failed["status"], failed["reason"]) == ("error", "scanner exited with code 1")
    assert (silent["status"], silent["reason"]) == ("error", "report was not produced")


def test_scanner_accepts_findings_exit_code_when_allowed(profiles, tmp_path):
    result = _scanner(profiles, tmp_path, 'echo "{}" > "$1"; exit 1', allowed_codes={0, 1})

    assert result["status"] == "completed"


def test_stale_report_is_removed_before_the_scanner_runs(profiles, tmp_path):
    (tmp_path / "output").mkdir()
    (tmp_path / "output" / "r.json").write_text("{}")

    assert _scanner(profiles, tmp_path, "exit 0")["status"] == "error"
    assert not os.path.exists(tmp_path / "output" / "r.json")


@pytest.mark.parametrize(
    ("gosec", "exit_code", "cause"),
    [
        # Go packages that cannot load are the audited code's doing: a coverage limit.
        (
            'echo \'{"Golang errors": {"main.go": [{"error": "cannot load"}]}}\' > "${4#-out=}"',
            0,
            "target",
        ),
        # A scanner that cannot run at all still fails the task.
        ("exit 3", 2, None),
    ],
)
def test_only_scanner_failures_fail_the_task(
    profiles, tmp_path, monkeypatch, gosec, exit_code, cause
):
    target, output, bin_dir = tmp_path / "target", tmp_path / "output", tmp_path / "bin"
    for directory in (target, output, bin_dir):
        directory.mkdir()
    (target / "go.mod").write_text("module x\n")
    (bin_dir / "gosec").write_text(f"#!/bin/sh\n{gosec}\n")
    (bin_dir / "gosec").chmod(0o755)
    monkeypatch.setenv("PATH", f"{bin_dir}:{os.environ['PATH']}")
    monkeypatch.setenv("APPSEC_LANGS", "go")
    monkeypatch.setattr("sys.argv", ["run-language-profiles.py", str(target), str(output)])

    assert profiles.main() == exit_code
    report = json.loads((output / "language-profile.json").read_text())
    gosec_result = next(item for item in report["scanners"] if item["scanner"] == "gosec")
    assert gosec_result["status"] == "error"
    assert gosec_result.get("cause") == cause
