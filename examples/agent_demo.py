"""What an AI agent sees: connect to the toolbox over MCP, audit a repository, read the evidence.

    docker build -t appsec-toolbox-mcp:dev .
    uv run --with mcp==2.1.1 python examples/agent_demo.py examples/vulnerable-sample ./appsec-output

The container is started with the hardened `docker run` recipe from the README.
"""

import asyncio
import json
import os
import sys
import time
from pathlib import Path

from mcp import Client, StdioServerParameters
from mcp.client.stdio import stdio_client

IMAGE = os.environ.get("IMAGE", "appsec-toolbox-mcp:dev")
BOLD, DIM, GREEN, RED, RESET = "\033[1m", "\033[2m", "\033[32m", "\033[31m", "\033[0m"


def step(text: str) -> None:
    print(f"\n{BOLD}▶ {text}{RESET}", flush=True)
    time.sleep(0.8)


def server(target: Path, output: Path) -> StdioServerParameters:
    return StdioServerParameters(
        command="docker",
        args=[
            "run",
            "--rm",
            "-i",
            "--read-only",
            "--cap-drop=ALL",
            "--security-opt=no-new-privileges:true",
            "--tmpfs",
            "/tmp:rw,nosuid,nodev,size=3g",
            "--user",
            f"{os.getuid()}:{os.getgid()}",
            "-v",
            f"{target}:/runner/target:ro",
            "-v",
            f"{output}:/runner/output:rw",
            IMAGE,
        ],
    )


def summarize(output: Path) -> None:
    def load(name: str):
        return json.loads((output / name).read_text(encoding="utf-8"))

    trivy = load("trivy.json").get("Results", [])
    osv = [
        v
        for r in load("osv.json").get("results", [])
        for p in r.get("packages", [])
        for v in p.get("vulnerabilities", [])
    ]
    checkov = load("checkov.json")
    checkov = checkov if isinstance(checkov, list) else [checkov]
    rows = [
        ("Semgrep", f"{len(load('semgrep.json')['results'])} findings"),
        ("Bandit", f"{len(load('bandit.json')['results'])} issues"),
        ("Gitleaks", f"{len(load('gitleaks.json'))} secret(s)"),
        ("OSV-Scanner", f"{len(osv)} known vulnerabilities"),
        (
            "Trivy",
            f"{sum(len(r.get('Vulnerabilities') or []) for r in trivy)} vulns, "
            f"{sum(len(r.get('Misconfigurations') or []) for r in trivy)} misconfigs",
        ),
        (
            "Checkov",
            f"{sum(len(c['results']['failed_checks']) for c in checkov)} failed checks",
        ),
        (
            "Syft",
            f"SBOM with {len(load('sbom.cdx.json').get('components', []))} components",
        ),
    ]
    for name, result in rows:
        print(f"  {name:<12} {result}")

    manifest = load("run-manifest.json")
    step("Provenance: run-manifest.json")
    print(
        f"  target   {manifest['target']['content_fingerprint'][:23]}…  ({manifest['target']['file_count']} files)"
    )
    for tool in manifest["tools"]:
        if "report_sha256" in tool:
            print(
                f"  {tool['name']:<17} {tool['version'] or '-':<9} {tool['status']:<10} {DIM}{tool['report_sha256'][:16]}…{RESET}"
            )

    audit = json.loads(
        (output / "makefile-mcp-audit.jsonl").read_text().splitlines()[-1]
    )
    step("Audit log: makefile-mcp-audit.jsonl")
    print(
        f"  {audit['timestamp'][:19]}  {audit['task']}  {audit['status']}  "
        f"risk={audit['risk']}  {audit['duration_ms'] / 1000:.0f}s"
    )


async def main(target: Path, output: Path) -> None:
    output.mkdir(parents=True, exist_ok=True)
    # Keep the server's own logs out of the agent's view.
    with open(os.devnull, "w") as quiet:
        await run(target, output, quiet)


async def run(target: Path, output: Path, quiet) -> None:
    async with Client(
        stdio_client(server(target, output), errlog=quiet), read_timeout_seconds=1800
    ) as client:
        step("Agent connects to appsec-toolbox-mcp over MCP stdio")
        tools = sorted(t.name for t in (await client.list_tools()).tools)
        for name in tools:
            print(f"  {GREEN}✓{RESET} {name}")

        step("Agent tries a maintenance target that is not exposed")
        denied = await client.call_tool("make_toolbox-versions", {})
        print(f"  {RED}✗ refused:{RESET} {denied.content[0].text}")

        step(f"Agent runs the full passive audit on {target.name}/ (read-only mount)")
        result = await client.call_tool("make_appsec-full", {})
        status = (
            result.structured_content["data"]["status"]
            if not result.is_error
            else "error"
        )
        print(f"  status: {GREEN if status == 'passed' else RED}{status}{RESET}")
        if result.is_error:
            print(result.content[0].text)
            return

    step("Scanner-native evidence in the output directory")
    summarize(output)


if __name__ == "__main__":
    asyncio.run(main(Path(sys.argv[1]).resolve(), Path(sys.argv[2]).resolve()))
