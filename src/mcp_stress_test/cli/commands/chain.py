"""Attack chain commands."""

from __future__ import annotations

import json

import click
from rich.console import Console
from rich.table import Table

console = Console()


@click.group("chain")
def chain_group() -> None:
    """Multi-tool attack chain commands.

    Execute coordinated attacks across multiple tools to simulate
    realistic multi-step attack scenarios.
    """
    pass


@chain_group.command("list")
@click.option("--json-output", is_flag=True, help="Output as JSON")
def chain_list(json_output: bool) -> None:
    """List all available attack chains."""
    from mcp_stress_test.chains.library import BUILTIN_CHAINS

    if json_output:
        data = [
            {
                "name": c.name,
                "description": c.description,
                "steps": len(c.steps),
                "tools_required": c.tools_required,
            }
            for c in BUILTIN_CHAINS
        ]
        console.print(json.dumps(data, indent=2))
        return

    table = Table(title="Attack Chains")
    table.add_column("Name", style="cyan")
    table.add_column("Steps", justify="right")
    table.add_column("Tools Required")
    table.add_column("Description", overflow="fold")

    for chain in BUILTIN_CHAINS:
        table.add_row(
            chain.name,
            str(len(chain.steps)),
            ", ".join(chain.tools_required[:3]) + ("..." if len(chain.tools_required) > 3 else ""),
            chain.description[:50] + "...",
        )

    console.print(table)


@chain_group.command("show")
@click.argument("chain_name")
def chain_show(chain_name: str) -> None:
    """Show details of a specific chain."""
    from mcp_stress_test.chains.library import get_chain

    chain = get_chain(chain_name)
    if not chain:
        console.print(f"[red]Chain '{chain_name}' not found[/red]")
        return

    console.print(f"\n[bold cyan]{chain.name}[/bold cyan]")
    console.print(f"[dim]{chain.description}[/dim]\n")

    console.print("[bold]Required Tools:[/bold]")
    for tool in chain.tools_required:
        console.print(f"  • {tool}")

    console.print("\n[bold]Steps:[/bold]")
    table = Table(show_header=True, box=None)
    table.add_column("#", style="dim")
    table.add_column("Name")
    table.add_column("Tool", style="cyan")
    table.add_column("Type", style="yellow")
    table.add_column("Depends On")

    for i, step in enumerate(chain.steps):
        deps = ", ".join(step.depends_on) if step.depends_on else "-"
        table.add_row(
            str(i + 1),
            step.name,
            step.tool_name,
            step.step_type.value,
            deps,
        )

    console.print(table)

    console.print("\n[bold]Payloads:[/bold]")
    for i, step in enumerate(chain.steps):
        console.print(f"\n[dim]Step {i + 1} ({step.name}):[/dim]")
        console.print(f"  {step.payload[:100]}...")


@chain_group.command("execute")
@click.option("--chain", "-c", "chain_names", multiple=True, help="Chains to execute (default: all)")
@click.option("--scanner", "-s", default="mock", help="Scanner to test against")
@click.option("--output", "-o", type=click.Path(), help="Output file for results")
@click.option("--json-output", is_flag=True, help="Output as JSON")
def chain_execute(
    chain_names: tuple[str, ...],
    scanner: str,
    output: str | None,
    json_output: bool,
) -> None:
    """Execute attack chains against a scanner.

    Example:
        mcp-stress chain execute -c data_exfil_chain -c persistence_chain
    """
    from mcp_stress_test.chains.executor import ChainExecutor
    from mcp_stress_test.chains.library import BUILTIN_CHAINS, get_chain
    from mcp_stress_test.scanners.mock import MockScanner
    from mcp_stress_test.models import ToolSchema as ToolDefinition

    # Create scanner
    scan = MockScanner()

    # Create tool definitions for all required tools
    all_tools: set[str] = set()
    for chain in BUILTIN_CHAINS:
        all_tools.update(chain.tools_required)

    tools = {
        name: ToolDefinition(
            name=name,
            description=f"Test tool: {name}",
            parameters=[],
            domain="filesystem",
            risk_level="high",
        )
        for name in all_tools
    }

    # Select chains
    if chain_names:
        chains = [get_chain(name) for name in chain_names]
        chains = [c for c in chains if c is not None]
        if not chains:
            console.print("[red]No valid chains specified[/red]")
            return
    else:
        chains = BUILTIN_CHAINS

    console.print(f"[cyan]Executing {len(chains)} chains against {scanner} scanner...[/cyan]\n")

    # Execute
    executor = ChainExecutor(scanner=scan, tools=tools)
    results = executor.execute_all(chains)

    # Display results
    if json_output:
        data = [
            {
                "chain": r.chain_name,
                "detected": r.chain_detected,
                "steps_total": len(r.steps),
                "steps_detected": r.steps_detected,
                "detection_rate": r.detection_rate,
            }
            for r in results
        ]
        console.print(json.dumps(data, indent=2))
    else:
        table = Table(title="Chain Execution Results")
        table.add_column("Chain", style="cyan")
        table.add_column("Steps", justify="right")
        table.add_column("Detected", justify="right")
        table.add_column("Rate", justify="right")
        table.add_column("Status")

        for r in results:
            status = "[green]BLOCKED[/green]" if r.chain_detected else "[red]EVADED[/red]"
            table.add_row(
                r.chain_name,
                str(len(r.steps)),
                str(r.steps_detected),
                f"{r.detection_rate:.1f}%",
                status,
            )

        console.print(table)

        # Summary
        stats = executor.get_stats()
        console.print(f"\n[bold]Summary:[/bold]")
        console.print(f"  Chains executed: {stats.chains_executed}")
        console.print(f"  Chains detected: {stats.chains_detected}")
        console.print(f"  Chain detection rate: {stats.chain_detection_rate:.1f}%")
        console.print(f"  Step detection rate: {stats.step_detection_rate:.1f}%")

    if output:
        with open(output, "w") as f:
            json.dump(
                [
                    {
                        "chain": r.chain_name,
                        "detected": r.chain_detected,
                        "steps": [
                            {"tool": s.tool_name, "detected": s.detected}
                            for s in r.steps
                        ],
                    }
                    for r in results
                ],
                f,
                indent=2,
            )
        console.print(f"\n[green]Results saved to {output}[/green]")
