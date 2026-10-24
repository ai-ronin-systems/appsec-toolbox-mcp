import json


def test_markers_are_located_without_copying_line_text(suppressions, tmp_path):
    (tmp_path / "app.py").write_text("x = 1\nos.system(cmd)  # nosec B605\n")
    (tmp_path / "main.tf").write_text("#trivy:ignore:AVD-AWS-0086\n#checkov:skip=CKV_AWS_20: ok\n")
    (tmp_path / "keys.js").write_text('const k = "s3cr3t"; // gitleaks:allow nosemgrep\n')

    report = suppressions.scan(tmp_path)

    assert report["markers"] == [
        {"file": "app.py", "line": 2, "marker": "nosec"},
        {"file": "keys.js", "line": 1, "marker": "nosemgrep"},
        {"file": "keys.js", "line": 1, "marker": "gitleaks:allow"},
        {"file": "main.tf", "line": 1, "marker": "trivy:ignore"},
        {"file": "main.tf", "line": 2, "marker": "checkov:skip"},
    ]
    text = json.dumps(report)
    assert "s3cr3t" not in text and "os.system" not in text


def test_settings_files_are_listed_and_vcs_directories_pruned(suppressions, tmp_path):
    (tmp_path / ".semgrepignore").write_text("*.py\n")
    (tmp_path / "sub").mkdir()
    (tmp_path / "sub" / ".checkov.yaml").write_text("skip-check: []\n")
    (tmp_path / ".git").mkdir()
    (tmp_path / ".git" / "COMMIT_EDITMSG").write_text("# nosec\n")

    report = suppressions.scan(tmp_path)

    assert report["settings_files"] == [".semgrepignore", "sub/.checkov.yaml"]
    assert report["markers"] == []


def test_symlinks_binaries_and_large_files_are_skipped_and_counted(
    suppressions, tmp_path, monkeypatch
):
    outside = tmp_path / "outside.py"
    outside.write_text("# nosec\n")
    target = tmp_path / "target"
    target.mkdir()
    (target / "link.py").symlink_to(outside)
    (target / "dir").symlink_to(tmp_path, target_is_directory=True)
    (target / "blob.bin").write_bytes(b"\0# nosec\n")
    (target / "big.py").write_text("# nosec\n" + "x" * 64)
    monkeypatch.setattr(suppressions, "MAX_FILE_BYTES", 32)

    report = suppressions.scan(target)

    assert report["markers"] == []
    assert report["skipped"] == {
        "symlinks": 2,
        "large_files": 1,
        "binary_files": 1,
        "unreadable_files": 0,
    }


def test_marker_list_is_capped(suppressions, tmp_path, monkeypatch):
    (tmp_path / "a.py").write_text("# nosec\n" * 10)
    (tmp_path / "b.py").write_text("# nosec\n")
    monkeypatch.setattr(suppressions, "MAX_MARKERS", 3)

    report = suppressions.scan(tmp_path)

    assert len(report["markers"]) == 3
    assert report["truncated"] is True


def test_marker_words_inside_other_words_do_not_match(suppressions, tmp_path):
    (tmp_path / "a.py").write_text("nosemaphore = 1\nnosecurity = 2\n")

    assert suppressions.scan(tmp_path)["markers"] == []
