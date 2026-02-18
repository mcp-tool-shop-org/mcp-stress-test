"""Report generation commands."""

from __future__ import annotations

import json
from pathlib import Path

import click
from rich.console import Console

console = Console()


@click.group("report")
def report_group() -> None:
    """Report generation commands.

    Generate reports in various formats from stress test results.
    """
    pass


@report_group.command("generate")
@click.option(
    "--input",
    "-i",
    "input_file",
    required=True,
    type=click.Path(exists=True),
    help="Input JSON results file",
)
@click.option(
    "--format",
    "-f",
    "fmt",
    default="markdown",
    type=click.Choice(["json", "markdown", "html", "sarif"]),
    help="Output format",
)
@click.option("--output", "-o", type=click.Path(), help="Output file path")
@click.option("--include-chains", is_flag=True, help="Include chain results if present")
def report_generate(
    input_file: str,
    fmt: str,
    output: str | None,
    include_chains: bool,
) -> None:
    """Generate a report from stress test results.

    Example:
        mcp-stress report generate -i results.json -f html -o report.html
    """
    from mcp_stress_test.core.protocols import AttackResult, ChainResult
    from mcp_stress_test.reporters import (
        HTMLReporter,
        JSONReporter,
        MarkdownReporter,
        SARIFReporter,
    )

    # Load results
    with open(input_file) as f:
        data = json.load(f)

    # Parse results
    results = []
    if "results" in data:
        for r in data["results"]:
            results.append(
                AttackResult(
                    tool_name=r.get("tool_name", "unknown"),
                    strategy=r.get("strategy", "unknown"),
                    detected=r.get("detected", False),
                    score_before=r.get("score_before", 100.0),
                    score_after=r.get("score_after", 100.0),
                    threats_found=r.get("threats_found", []),
                    scan_time_ms=r.get("scan_time_ms", 0.0),
                    metadata=r.get("metadata", {}),
                )
            )

    # Parse chain results
    chain_results = []
    if include_chains and "chains" in data:
        for cr in data["chains"].get("results", []):
            steps = [
                AttackResult(
                    tool_name=s.get("tool_name", "unknown"),
                    strategy="chain_step",
                    detected=s.get("detected", False),
                    score_before=100.0,
                    score_after=50.0 if s.get("detected") else 100.0,
                    metadata=s.get("metadata", {}),
                )
                for s in cr.get("steps", [])
            ]
            chain_results.append(
                ChainResult(
                    chain_name=cr.get("chain_name", "unknown"),
                    steps=steps,
                    chain_detected=cr.get("chain_detected", False),
                    total_time_ms=cr.get("total_time_ms", 0.0),
                )
            )

    # Select reporter
    reporters = {
        "json": JSONReporter(),
        "markdown": MarkdownReporter(),
        "html": HTMLReporter(),
        "sarif": SARIFReporter(),
    }

    reporter = reporters[fmt]

    # Determine output path
    if not output:
        input_path = Path(input_file)
        output = str(input_path.with_suffix(f".{reporter.file_extension}"))

    # Generate report
    reporter.generate(
        results,
        chain_results if chain_results else None,
        output,
    )

    console.print(f"[green]Report generated: {output}[/green]")
    console.print(
        f"[dim]Format: {fmt}, Results: {len(results)}, Chains: {len(chain_results)}[/dim]"
    )


@report_group.command("formats")
def report_formats() -> None:
    """List available report formats."""
    from rich.table import Table

    table = Table(title="Report Formats")
    table.add_column("Format", style="cyan")
    table.add_column("Extension")
    table.add_column("Use Case")

    table.add_row("json", ".json", "Machine-readable, CI/CD integration")
    table.add_row("markdown", ".md", "Human-readable, documentation")
    table.add_row("html", ".html", "Interactive dashboard with charts")
    table.add_row("sarif", ".sarif", "IDE integration (VSCode, GitHub)")

    console.print(table)


@report_group.command("preview")
@click.option(
    "--input",
    "-i",
    "input_file",
    required=True,
    type=click.Path(exists=True),
    help="Input JSON results file",
)
def report_preview(input_file: str) -> None:
    """Preview report statistics without generating."""
    from rich.table import Table

    with open(input_file) as f:
        data = json.load(f)

    console.print(f"\n[bold]Report Preview: {input_file}[/bold]\n")

    # Summary
    if "summary" in data:
        summary = data["summary"]
        table = Table(title="Summary", show_header=False)
        table.add_column("Metric")
        table.add_column("Value", justify="right")

        table.add_row("Total Tests", str(summary.get("total_tests", 0)))
        table.add_row("Detection Rate", f"{summary.get('detection_rate', 0):.1f}%")
        table.add_row("Evasion Rate", f"{summary.get('evasion_rate', 0):.1f}%")
        table.add_row("Avg Scan Time", f"{summary.get('avg_scan_time_ms', 0):.2f}ms")

        console.print(table)

    # By strategy
    if "by_strategy" in data:
        console.print("\n[bold]By Strategy:[/bold]")
        for strategy, stats in data["by_strategy"].items():
            detected = stats.get("detected", 0)
            missed = stats.get("missed", 0)
            total = detected + missed
            rate = detected / total * 100 if total > 0 else 0
            console.print(f"  {strategy}: {detected}/{total} ({rate:.1f}%)")

    # Chains
    if "chains" in data:
        chain_data = data["chains"]
        console.print(f"\n[bold]Chains:[/bold] {len(chain_data.get('results', []))} executed")
