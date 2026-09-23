"""Generate attack test-case JSON from the PatternLibrary."""

from __future__ import annotations

import json
from pathlib import Path

import click
from rich.console import Console

from mcp_stress_test.models import AttackParadigm

console = Console()

_PARADIGM_MAP = {
    "p1": AttackParadigm.P1_EXPLICIT_HIJACKING,
    "p2": AttackParadigm.P2_IMPLICIT_HIJACKING,
    "p3": AttackParadigm.P3_PARAMETER_TAMPERING,
}


@click.command("generate")
@click.option(
    "--paradigm",
    type=click.Choice(["p1", "p2", "p3"]),
    required=True,
    help="Attack paradigm to use",
)
@click.option(
    "--payload",
    type=click.Choice(
        [
            "data_exfil",
            "privilege_escalation",
            "cross_tool",
            "context_manipulation",
        ]
    ),
    required=True,
    help="Payload category to use",
)
@click.option(
    "--count",
    type=int,
    default=10,
    help="Number of test cases to generate",
)
@click.option(
    "--output",
    type=click.Path(),
    help="Output file path (JSON)",
)
@click.option(
    "--json-output",
    is_flag=True,
    help="Write test cases as JSON to stdout",
)
def generate_cmd(
    paradigm: str,
    payload: str,
    count: int,
    output: str | None,
    json_output: bool,
) -> None:
    """Generate attack test cases from the PatternLibrary.

    Example:
        mcp-stress generate --paradigm p1 --payload data_exfil --json-output
    """
    from mcp_stress_test.patterns import PatternLibrary

    library = PatternLibrary()
    library.load()

    test_cases = library.get_test_cases(
        paradigm=_PARADIGM_MAP[paradigm],
        limit=count,
    )
    output_data = [tc.model_dump(mode="json") for tc in test_cases]

    if json_output:
        click.echo(json.dumps(output_data, indent=2, default=str))
        if output:
            Path(output).write_text(
                json.dumps(output_data, indent=2, default=str), encoding="utf-8"
            )
        return

    console.print(f"\n[green]Generated {len(test_cases)} test cases[/green]\n")

    if output:
        output_path = Path(output)
        output_path.write_text(json.dumps(output_data, indent=2, default=str), encoding="utf-8")
        console.print(f"[cyan]Saved to {output_path}[/cyan]")
    else:
        for tc in test_cases[:5]:
            console.print(f"  • {tc.id}: {tc.name}")
        if len(test_cases) > 5:
            console.print(f"  ... and {len(test_cases) - 5} more")
