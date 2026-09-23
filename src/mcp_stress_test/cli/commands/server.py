"""Synthetic MCP server farm commands."""

from __future__ import annotations

import asyncio
import json

import click
from rich.console import Console
from rich.table import Table

from mcp_stress_test.models import ServerDomain

console = Console()


@click.group("server")
def server_group() -> None:
    """Start and inspect the synthetic MCP server farm.

    ``serve`` binds one domain server to stdio via BaseMCPServer.run_stdio
    so an external MCP client or scanner can connect.
    """
    pass


@server_group.command("serve")
@click.option(
    "--domain",
    type=click.Choice([d.value for d in ServerDomain]),
    default="filesystem",
    show_default=True,
    help="Demo server domain to expose on stdio",
)
def server_serve(domain: str) -> None:
    """Start a documented demo server on stdio.

    Starts the farm for the selected domain, then calls
    BaseMCPServer.run_stdio on that server (one process, one transport).

    Example:
        mcp-stress server serve --domain filesystem
    """
    from mcp_stress_test.servers import FarmConfig, ServerFarm

    domain_enum = ServerDomain(domain)

    async def _serve() -> None:
        farm = ServerFarm(FarmConfig(domains=[domain_enum], enable_logging=True))
        await farm.start()
        server = farm.get_server(domain_enum)
        if server is None:
            await farm.stop()
            raise click.ClickException(f"No demo server registered for domain '{domain}'.")
        console.print(
            f"[cyan]Serving {server.config.name} ({domain}) on stdio "
            f"(MCP JSON-RPC, one message per line).[/cyan]",
            err=True,
        )
        try:
            await server.run_stdio()
        finally:
            await farm.stop()

    asyncio.run(_serve())


@server_group.command("list")
@click.option(
    "--domain",
    type=click.Choice([d.value for d in ServerDomain]),
    default=None,
    help="Filter by domain",
)
@click.option(
    "--json-output",
    is_flag=True,
    help="Output as JSON",
)
def server_list(domain: str | None, json_output: bool) -> None:
    """List available server domains and their tools."""
    from mcp_stress_test.servers import FarmConfig, ServerFarm

    domain_list = [ServerDomain(domain)] if domain else list(ServerDomain)
    farm = ServerFarm(FarmConfig(domains=domain_list))

    async def list_tools() -> None:
        await farm.start()
        try:
            tools = farm.get_all_tools()
        finally:
            await farm.stop()

        if json_output:
            output = [t.model_dump() for t in tools]
            click.echo(json.dumps(output, indent=2, default=str))
            return

        console.print(f"\n[bold cyan]Server Farm Tools ({len(tools)} total)[/bold cyan]\n")
        table = Table()
        table.add_column("Tool", style="cyan")
        table.add_column("Domain", style="yellow")
        table.add_column("Risk", style="red")
        table.add_column("Description", max_width=50)
        for tool in tools:
            desc = tool.description[:47] + "..." if len(tool.description) > 50 else tool.description
            table.add_row(
                tool.name,
                tool.domain.value if tool.domain else "N/A",
                tool.risk_level,
                desc,
            )
        console.print(table)

    asyncio.run(list_tools())
