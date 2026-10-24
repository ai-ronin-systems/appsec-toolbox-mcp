#!/usr/bin/env python3
"""Select and run passive language-specific AppSec scanners."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any

CONFIG = Path(__file__).resolve().parent.parent / "config"
SUPPORTED = ("python", "java", "node", "go")
ALIASES = {
    "py": "python",
    "python": "python",
    "java": "java",
    "js": "node",
    "javascript": "node",
    "node": "node",
    "nodejs": "node",
    "ts": "node",
    "typescript": "node",
    "go": "go",
    "golang": "go",
}
PRUNE_DIRS = {
    ".git",
    ".hg",
    ".svn",
    ".tox",
    ".venv",
    "venv",
    "node_modules",
    "vendor",
    "dist",
    "build",
    "target",
    "out",
    "coverage",
    ".pytest_cache",
    ".mypy_cache",
}
MARKERS = {
    "python": {
        "pyproject.toml",
        "requirements.txt",
        "setup.py",
        "setup.cfg",
        "pipfile",
        "poetry.lock",
        "pdm.lock",
    },
    "java": {
        "pom.xml",
        "build.gradle",
        "build.gradle.kts",
        "settings.gradle",
        "settings.gradle.kts",
    },
    "node": {
        "package.json",
        "package-lock.json",
        "pnpm-lock.yaml",
        "yarn.lock",
    },
    "go": {"go.mod", "go.work"},
}
SUFFIXES = {
    "python": {".py"},
    "java": {".java"},
    "node": {".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx"},
    "go": {".go"},
}


def _relative(path: Path, root: Path) -> str:
    try:
        return path.relative_to(root).as_posix()
    except ValueError:
        return path.as_posix()


def detect_languages(target: Path) -> dict[str, list[str]]:
    evidence: dict[str, list[str]] = {lang: [] for lang in SUPPORTED}
    for dirpath, dirnames, filenames in os.walk(target, followlinks=False):
        dirnames[:] = [name for name in dirnames if name.lower() not in PRUNE_DIRS]
        base = Path(dirpath)
        for filename in filenames:
            lower = filename.lower()
            suffix = Path(lower).suffix
            path = base / filename
            for lang in SUPPORTED:
                if lower in MARKERS[lang] or suffix in SUFFIXES[lang]:
                    if len(evidence[lang]) < 8:
                        evidence[lang].append(_relative(path, target))
    return {lang: values for lang, values in evidence.items() if values}


def parse_selection(requested: str, detected: dict[str, list[str]]) -> tuple[str, list[str]]:
    value = requested.strip().lower()
    if not value:
        raise ValueError("APPSEC_LANGS must not be empty")
    tokens = [token.strip() for token in value.split(",") if token.strip()]
    if not tokens:
        raise ValueError("APPSEC_LANGS must not be empty")
    if "auto" in tokens:
        if len(tokens) != 1:
            raise ValueError("APPSEC_LANGS=auto cannot be combined with explicit profiles")
        return "auto", [lang for lang in SUPPORTED if lang in detected]
    if "none" in tokens:
        if len(tokens) != 1:
            raise ValueError("APPSEC_LANGS=none cannot be combined with explicit profiles")
        return "explicit", []

    selected: list[str] = []
    for token in tokens:
        lang = ALIASES.get(token)
        if lang is None:
            allowed = ", ".join(("auto", "none", *SUPPORTED))
            raise ValueError(f"unsupported APPSEC_LANGS value {token!r}; expected: {allowed}")
        if lang not in selected:
            selected.append(lang)
    return "explicit", [lang for lang in SUPPORTED if lang in selected]


def _inside(path: Path, root: Path) -> bool:
    try:
        path.resolve().relative_to(root.resolve())
        return True
    except (OSError, ValueError):
        return False


def java_bytecode_inputs(target: Path) -> list[Path]:
    inputs: list[Path] = []
    seen: set[Path] = set()
    project_roots: set[Path] = set()
    java_markers = {"pom.xml", "build.gradle", "build.gradle.kts"}

    for dirpath, dirnames, filenames in os.walk(target, followlinks=False):
        ignored = {".git", ".hg", ".svn", "node_modules", ".venv", "venv", "vendor"}
        dirnames[:] = [name for name in dirnames if name.lower() not in ignored]
        if java_markers.intersection(filenames):
            project_roots.add(Path(dirpath))

    if not project_roots:
        project_roots.add(target)

    for root in sorted(project_roots):
        candidates = (
            root / "target" / "classes",
            root / "build" / "classes" / "java" / "main",
            root / "build" / "classes" / "kotlin" / "main",
        )
        found_classes = False
        for candidate in candidates:
            if candidate.is_dir() and _inside(candidate, target):
                resolved = candidate.resolve()
                if resolved not in seen:
                    seen.add(resolved)
                    inputs.append(resolved)
                    found_classes = True

        if not found_classes:
            for pattern in ("target/*.jar", "build/libs/*.jar"):
                for jar in sorted(root.glob(pattern)):
                    if jar.is_file() and _inside(jar, target):
                        resolved = jar.resolve()
                        if resolved not in seen:
                            seen.add(resolved)
                            inputs.append(resolved)

    return inputs


def gosec_has_processing_errors(report: Path) -> bool:
    try:
        payload = json.loads(report.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return True
    errors = payload.get("Golang errors")
    return bool(errors)


def njsscan_has_errors(report: Path) -> bool:
    try:
        payload = json.loads(report.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return True
    return bool(payload.get("errors"))


def scanner_result(
    scanner: str,
    profile: str,
    status: str,
    *,
    report: str | None = None,
    reason: str | None = None,
) -> dict[str, str]:
    item = {"scanner": scanner, "profile": profile, "status": status}
    if report is not None:
        item["report"] = report
    if reason is not None:
        item["reason"] = reason
    return item


def run_scanner(
    scanner: str,
    profile: str,
    command: list[str],
    report: Path,
    output_root: Path,
    *,
    cwd: Path | None = None,
    env: dict[str, str] | None = None,
    allowed_codes: set[int] | None = None,
) -> dict[str, str]:
    report.unlink(missing_ok=True)
    code = subprocess.run(command, cwd=cwd, env=env, check=False).returncode
    allowed = {0} if allowed_codes is None else allowed_codes
    rel_report = _relative(report, output_root.parent)
    if code not in allowed or not report.is_file():
        reason = (
            f"scanner exited with code {code}"
            if code not in allowed
            else "report was not produced"
        )
        return scanner_result(
            scanner,
            profile,
            "error",
            report=rel_report if report.exists() else None,
            reason=reason,
        )
    return scanner_result(scanner, profile, "completed", report=rel_report)


def main() -> int:
    target = Path(sys.argv[1] if len(sys.argv) > 1 else "target").resolve()
    output = Path(sys.argv[2] if len(sys.argv) > 2 else "output").resolve()
    output.mkdir(parents=True, exist_ok=True)
    profile_report = output / "language-profile.json"
    stale_reports = (
        "bandit.json",
        "findsecbugs.xml",
        "njsscan.json",
        "gosec.json",
        "language-profile.json",
    )
    for stale in stale_reports:
        (output / stale).unlink(missing_ok=True)

    requested = os.environ.get("APPSEC_LANGS", "auto")
    detected = detect_languages(target)
    try:
        mode, selected = parse_selection(requested, detected)
    except ValueError as exc:
        print(f"language profiles: {exc}", file=sys.stderr)
        return 2

    results: list[dict[str, str]] = []

    if "python" in selected:
        results.append(
            run_scanner(
                "bandit",
                "python",
                [
                    "bandit",
                    "--recursive",
                    str(target),
                    "--format",
                    "json",
                    "--output",
                    str(output / "bandit.json"),
                    "--quiet",
                    "--exit-zero",
                    # The target is hostile: its "# nosec" comments must not hide findings.
                    "--ignore-nosec",
                    # Toolbox-owned settings instead of the target's .bandit file.
                    "--ini",
                    str(CONFIG / "bandit.ini"),
                ],
                output / "bandit.json",
                output,
            )
        )
    else:
        results.append(scanner_result("bandit", "python", "skipped", reason="profile not selected"))

    if "java" in selected:
        bytecode = java_bytecode_inputs(target)
        if bytecode:
            results.append(
                run_scanner(
                    "findsecbugs",
                    "java",
                    [
                        "findsecbugs",
                        "-xml:withMessages",
                        "-output",
                        str(output / "findsecbugs.xml"),
                        *[str(path) for path in bytecode],
                    ],
                    output / "findsecbugs.xml",
                    output,
                )
            )
        else:
            results.append(
                scanner_result(
                    "findsecbugs",
                    "java",
                    "skipped",
                    reason=(
                        "no compiled Java bytecode found; "
                        "toolbox does not build untrusted source"
                    ),
                )
            )
    else:
        results.append(
            scanner_result("findsecbugs", "java", "skipped", reason="profile not selected")
        )

    if "node" in selected:
        node_report = output / "njsscan.json"
        result = run_scanner(
            "njsscan",
            "node",
            [
                "njsscan",
                "--json",
                # Toolbox-owned settings instead of the target's .njsscan file.
                "-c",
                str(CONFIG / "njsscan.yml"),
                "-o",
                str(node_report),
                str(target),
            ],
            node_report,
            output,
            # njsscan exits 1 when it reports findings; findings are evidence, not failure.
            allowed_codes={0, 1},
        )
        if result["status"] == "completed" and njsscan_has_errors(node_report):
            result = scanner_result(
                "njsscan",
                "node",
                "error",
                report=_relative(node_report, output.parent),
                reason="njsscan reported scan errors",
            )
        results.append(result)
    else:
        results.append(scanner_result("njsscan", "node", "skipped", reason="profile not selected"))

    if "go" in selected:
        go_env = os.environ.copy()
        go_env.update(
            {
                "GOENV": "off",
                "GOPROXY": "off",
                "GOSUMDB": "off",
                "GOTOOLCHAIN": "local",
            }
        )
        go_report = output / "gosec.json"
        result = run_scanner(
            "gosec",
            "go",
            # -nosec: the target's "#nosec" comments must not hide findings.
            ["gosec", "-no-fail", "-nosec", "-fmt=json", f"-out={go_report}", "./..."],
            go_report,
            output,
            cwd=target,
            env=go_env,
        )
        if result["status"] == "completed" and gosec_has_processing_errors(go_report):
            result = scanner_result(
                "gosec",
                "go",
                "error",
                report=_relative(go_report, output.parent),
                reason="gosec reported Go package processing errors",
            )
        results.append(result)
    else:
        results.append(scanner_result("gosec", "go", "skipped", reason="profile not selected"))

    payload: dict[str, Any] = {
        "schema_version": 1,
        "selection": {
            "requested": requested,
            "mode": mode,
            "detected": [lang for lang in SUPPORTED if lang in detected],
            "selected": selected,
            "evidence": detected,
        },
        "scanners": results,
    }
    profile_report.write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )

    errors = [item for item in results if item["status"] == "error"]
    if errors:
        for item in errors:
            print(f"{item['scanner']}: {item.get('reason', 'scanner error')}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
