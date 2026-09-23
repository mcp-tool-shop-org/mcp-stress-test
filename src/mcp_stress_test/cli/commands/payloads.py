"""Poison-payload discovery commands."""

from __future__ import annotations

import json

import click
from rich.console import Console
from rich.table import Table

console = Console()

_PAYLOAD_CATEGORIES = [
    "data_exfil",
    "privilege_escalation",
    "cross_tool",
    "context_manipulation",
    "error_injection",
    "parameter",
    "sampling_exploit",
    "obfuscated",
]


@click.group("payloads")
def payloads_group() -> None:
    """Discover poison payloads from the library."""
    pass


@payloads_group.command("list")
@click.option(
    "--category",
    type=click.Choice(_PAYLOAD_CATEGORIES),
    help="Filter by payload category",
)
@click.option(
    "--json-output",
    is_flag=True,
    help="Output as JSON",
)
def payloads_list(category: str | None, json_output: bool) -> None:
    """List available poison payloads."""
    from mcp_stress_test.patterns import load_payloads

    payloads = load_payloads(category)

    if json_output:
        output = [p.model_dump() for p in payloads]
        click.echo(json.dumps(output, indent=2, default=str))
        return

    table = Table(title=f"Poison Payloads ({len(payloads)} results)")
    table.add_column("Category", style="red")
    table.add_column("Injection Point", style="yellow")
    table.add_column("Content Preview", style="white", max_width=60)

    for payload in payloads:
        preview = payload.content[:57] + "..." if len(payload.content) > 60 else payload.content
        table.add_row(
            payload.category.value,
            payload.injection_point,
            preview,
        )

    console.print(table)
