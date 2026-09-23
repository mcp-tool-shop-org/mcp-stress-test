"""Builtin tool-schema discovery commands."""

from __future__ import annotations

import json

import click
from rich.console import Console
from rich.table import Table

from mcp_stress_test.models import ServerDomain

console = Console()


@click.group("tools")
def tools_group() -> None:
    """Discover builtin tool schemas from the PatternLibrary."""
    pass


@tools_group.command("list")
@click.option(
    "--domain",
    type=click.Choice([d.value for d in ServerDomain]),
    help="Filter by server domain",
)
@click.option(
    "--json-output",
    is_flag=True,
    help="Output as JSON",
)
def tools_list(domain: str | None, json_output: bool) -> None:
    """List available tool definitions."""
    from mcp_stress_test.patterns import PatternLibrary

    library = PatternLibrary()
    library.load()

    domain_enum = ServerDomain(domain) if domain else None
    tools = library.get_tools(domain=domain_enum)

    if json_output:
        output = [t.model_dump() for t in tools]
        click.echo(json.dumps(output, indent=2, default=str))
        return

    table = Table(title=f"Tool Definitions ({len(tools)} results)")
    table.add_column("Name", style="cyan")
    table.add_column("Domain", style="yellow")
    table.add_column("Risk Level", style="red")
    table.add_column("Capabilities", style="green")

    for tool in tools:
        caps = ", ".join(tool.capabilities[:3])
        table.add_row(
            tool.name,
            tool.domain.value,
            tool.risk_level,
            caps,
        )

    console.print(table)
