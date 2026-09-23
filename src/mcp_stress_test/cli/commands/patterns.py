"""Pattern-library discovery commands."""

from __future__ import annotations

import json

import click
from rich.console import Console
from rich.table import Table

from mcp_stress_test.models import AttackParadigm, ServerDomain

console = Console()

_PARADIGM_MAP = {
    "p1": AttackParadigm.P1_EXPLICIT_HIJACKING,
    "p2": AttackParadigm.P2_IMPLICIT_HIJACKING,
    "p3": AttackParadigm.P3_PARAMETER_TAMPERING,
}


@click.group("patterns")
def patterns_group() -> None:
    """Discover attack patterns from the PatternLibrary."""
    pass


@patterns_group.command("list")
@click.option(
    "--paradigm",
    type=click.Choice(["p1", "p2", "p3"]),
    help="Filter by attack paradigm",
)
@click.option(
    "--domain",
    type=click.Choice([d.value for d in ServerDomain]),
    help="Filter by server domain",
)
@click.option(
    "--limit",
    type=int,
    default=20,
    help="Maximum number of results",
)
@click.option(
    "--json-output",
    is_flag=True,
    help="Output as JSON",
)
def patterns_list(
    paradigm: str | None,
    domain: str | None,
    limit: int,
    json_output: bool,
) -> None:
    """List available attack patterns."""
    from mcp_stress_test.patterns import PatternLibrary

    library = PatternLibrary()
    library.load()

    paradigm_enum = _PARADIGM_MAP.get(paradigm) if paradigm else None
    domain_enum = ServerDomain(domain) if domain else None
    test_cases = library.get_test_cases(
        paradigm=paradigm_enum,
        domain=domain_enum,
        limit=limit,
    )

    if json_output:
        output = [tc.model_dump(mode="json") for tc in test_cases]
        click.echo(json.dumps(output, indent=2, default=str))
        return

    table = Table(title=f"Attack Patterns ({len(test_cases)} results)")
    table.add_column("ID", style="cyan")
    table.add_column("Name", style="white")
    table.add_column("Paradigm", style="yellow")
    table.add_column("Target Tool", style="green")
    table.add_column("Risk", style="red")

    for tc in test_cases:
        paradigm_short = tc.paradigm.value.split("_")[0].upper()
        risks = ", ".join([r.value[:10] for r in tc.risk_categories[:2]])
        table.add_row(
            tc.id,
            tc.name[:40] + "..." if len(tc.name) > 40 else tc.name,
            paradigm_short,
            tc.target_tool.name,
            risks,
        )

    console.print(table)


@patterns_group.command("stats")
@click.option("--json-output", is_flag=True, help="Output as JSON")
def patterns_stats(json_output: bool) -> None:
    """Show pattern library statistics."""
    from mcp_stress_test.patterns import PatternLibrary

    library = PatternLibrary()
    library.load()
    stats = library.stats

    if json_output:
        click.echo(json.dumps(stats, indent=2))
        return

    console.print("\n[bold cyan]Pattern Library Statistics[/bold cyan]\n")

    table = Table(show_header=False)
    table.add_column("Metric", style="white")
    table.add_column("Value", style="green", justify="right")
    table.add_row("Total Test Cases", str(stats["total_test_cases"]))
    table.add_row("Total Tools", str(stats["total_tools"]))
    table.add_row("Total Profiles", str(stats["total_profiles"]))
    console.print(table)

    console.print("\n[bold]By Paradigm:[/bold]")
    paradigm_table = Table()
    paradigm_table.add_column("Paradigm", style="yellow")
    paradigm_table.add_column("Count", justify="right")
    paradigm_table.add_column("Description")
    paradigm_table.add_row(
        "P1 Explicit",
        str(stats["by_paradigm"]["p1_explicit"]),
        "Decoy tools mimicking legitimate functions",
    )
    paradigm_table.add_row(
        "P2 Implicit",
        str(stats["by_paradigm"]["p2_implicit"]),
        "Background tools with hidden triggers",
    )
    paradigm_table.add_row(
        "P3 Parameter",
        str(stats["by_paradigm"]["p3_parameter"]),
        "Poisoned descriptions altering other tools",
    )
    console.print(paradigm_table)

    console.print("\n[bold]By Domain:[/bold]")
    domain_table = Table()
    domain_table.add_column("Domain", style="cyan")
    domain_table.add_column("Tools", justify="right")
    for domain, count in stats["by_domain"].items():
        if count > 0:
            domain_table.add_row(domain, str(count))
    console.print(domain_table)
