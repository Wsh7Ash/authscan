#!/usr/bin/env python3
"""authscan — authorization testing helpers for APIs you own.

Two workflows:
  authscan inspect TOKEN       structurally inspect a JWT you already possess
  authscan matrix SPEC --url U run an endpoint x role auth matrix against a
                               base URL you supply (localhost by default)

Network checks only ever target a base URL you explicitly pass (see SECURITY.md).
"""
from __future__ import annotations

import json
import pathlib
import sys

import click
from rich.console import Console
from rich.table import Table

from authscan import jwt as jwtlib

console = Console()

SEVERITY_ORDER = {"high": 3, "medium": 2, "low": 1, "info": 0, "none": -1}


@click.group()
def main() -> None:
    """Structural JWT inspection and auth-matrix testing."""


@main.command("inspect")
@click.argument("token")
@click.option("--json-out", is_flag=True, help="Emit findings as JSON.")
def inspect_cmd(token: str, json_out: bool) -> None:
    """Decode TOKEN locally and report structural findings (no network)."""
    try:
        report = jwtlib.inspect(token)
    except jwtlib.JwtError as exc:
        console.print(f"[red]error:[/red] {exc}")
        sys.exit(2)
    if json_out:
        click.echo(json.dumps(report, indent=2))
        return
    console.print(f"[bold]alg[/bold]: {report['header'].get('alg', '?')}   "
                  f"[bold]claims[/bold]: {', '.join(report['claims']) or '(none)'}")
    if not report["findings"]:
        console.print("[green]no structural findings[/green]")
        return
    table = Table(title="findings")
    table.add_column("severity")
    table.add_column("code")
    table.add_column("message")
    colors = {"high": "red", "medium": "yellow", "low": "cyan", "info": "white"}
    for f in report["findings"]:
        table.add_row(f"[{colors[f['severity']]}]{f['severity']}[/]",
                      f["code"], f["message"])
    console.print(table)
    if SEVERITY_ORDER[report["worst_severity"]] >= SEVERITY_ORDER["medium"]:
        sys.exit(1)


@main.command("matrix")
@click.argument("spec", type=click.Path(exists=True, dir_okay=False, path_type=pathlib.Path))
@click.option("--base-url", default="http://127.0.0.1:8000",
              help="Base URL of an API you own or are authorized to test.")
@click.option("--json-out", is_flag=True, help="Emit the result matrix as JSON.")
def matrix_cmd(spec: pathlib.Path, base_url: str, json_out: bool) -> None:
    """Check each (endpoint, role, expected_status) row of SPEC against BASE-URL.

    SPEC is a JSON file: {"cases": [{"method","path","role","token_header",
    "expected_status"}, ...]}. Requests are sent only to BASE-URL.
    """
    try:
        document = json.loads(spec.read_text(encoding="utf-8"))
        cases = document["cases"]
    except (json.JSONDecodeError, KeyError, OSError) as exc:
        console.print(f"[red]error:[/red] cannot read spec: {exc}")
        sys.exit(2)
    if not isinstance(cases, list) or not cases:
        console.print("[red]error:[/red] spec has no 'cases'")
        sys.exit(2)

    import urllib.error
    import urllib.request

    results = []
    failures = 0
    for case in cases:
        url = base_url.rstrip("/") + str(case["path"])
        req = urllib.request.Request(url, method=str(case.get("method", "GET")).upper())
        token = case.get("token")
        if token:
            req.add_header(case.get("token_header", "Authorization"),
                           case.get("token_prefix", "Bearer ") + token)
        try:
            with urllib.request.urlopen(req, timeout=10) as resp:
                status = resp.status
        except urllib.error.HTTPError as exc:
            status = exc.code
        except (urllib.error.URLError, OSError) as exc:
            console.print(f"[red]error:[/red] {url}: {exc}")
            sys.exit(2)
        expected = int(case["expected_status"])
        ok = status == expected
        failures += 0 if ok else 1
        results.append({"method": req.get_method(), "path": case["path"],
                        "role": case.get("role", "anonymous"),
                        "expected": expected, "actual": status, "pass": ok})

    if json_out:
        click.echo(json.dumps({"base_url": base_url, "results": results}, indent=2))
    else:
        table = Table(title=f"auth matrix vs {base_url}")
        for column in ("method", "path", "role", "expected", "actual", "pass"):
            table.add_column(column)
        for r in results:
            verdict = "[green]PASS[/green]" if r["pass"] else "[red]FAIL[/red]"
            table.add_row(r["method"], r["path"], r["role"],
                          str(r["expected"]), str(r["actual"]), verdict)
        console.print(table)
    if failures:
        console.print(f"[red]{failures}/{len(results)} case(s) did not match "
                      f"the expected authorization behavior[/red]")
        sys.exit(1)
    console.print(f"[green]all {len(results)} cases matched[/green]")


if __name__ == "__main__":
    main()