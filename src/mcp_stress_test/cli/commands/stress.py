"""Stress-test commands wrapping StressTestRunner."""

from __future__ import annotations

from pathlib import Path

import click
from rich.console import Console
from rich.table import Table

console = Console()

_PHASE_NAMES = ("baseline", "mutation", "temporal", "progressive")
_SCANNER_CHOICES = ("mock", "tool-scan", "custom", "cli")


def execute_stress_run(
    phases: str,
    strategies: str,
    tools: str | None,
    payloads: str,
    scanner: str,
    output: str | None,
    scanner_path: str | None = None,
    format: str = "json",
    verbose: bool = False,
) -> None:
    """Run StressTestRunner the same way the legacy CLI does.

    Raises:
        click.ClickException: If the parsed phase list is empty, or the
            library cannot supply tools/payloads for the requested filters.
    """
    from mcp_stress_test.patterns import PatternLibrary, load_payloads
    from mcp_stress_test.scanner import ScannerConfig, StressTestConfig, StressTestRunner
    from mcp_stress_test.scanner.runner import StressPhase

    library = PatternLibrary()
    library.load()

    phase_map = {
        "baseline": StressPhase.BASELINE,
        "mutation": StressPhase.MUTATION,
        "temporal": StressPhase.TEMPORAL,
        "progressive": StressPhase.PROGRESSIVE,
    }
    phase_list = [phase_map[p.strip()] for p in phases.split(",") if p.strip() in phase_map]
    if not phase_list:
        raise click.ClickException(
            "No valid phases in --phases; expected one or more of: " + ", ".join(_PHASE_NAMES)
        )

    strategy_list = [s.strip() for s in strategies.split(",") if s.strip()]
    if not strategy_list:
        raise click.ClickException("Provide at least one mutation strategy in --strategies.")

    if tools:
        tool_names = {t.strip() for t in tools.split(",") if t.strip()}
        tool_list = [t for t in library.get_tools() if t.name in tool_names]
    else:
        tool_list = library.get_tools()[:5]

    payload_list = load_payloads(payloads)[:3]

    if not tool_list:
        raise click.ClickException("No tools found for the requested --tools filter.")
    if not payload_list:
        raise click.ClickException(f"No payloads found for category '{payloads}'.")

    scanner_key = (scanner or "mock").strip().lower().replace("_", "-")
    if scanner_key == "cli":
        scanner_key = "custom"
    if scanner_key not in ("mock", "tool-scan", "custom"):
        raise click.UsageError(
            f"Unknown scanner '{scanner}'. Choose from: {', '.join(_SCANNER_CHOICES)}."
        )

    from mcp_stress_test.core.data_paths import persistent_root
    from mcp_stress_test.scanner.checkpoint import CheckpointManager

    scanner_config = ScannerConfig(
        scanner_type=scanner_key,
        scanner_path=scanner_path,
    )
    test_config = StressTestConfig(
        scanner_config=scanner_config,
        phases=phase_list,
        strategies=strategy_list,
        verbose=verbose,
    )
    data_root = persistent_root()
    checkpoint_manager = CheckpointManager() if data_root is not None else None
    runner = StressTestRunner(
        config=test_config,
        checkpoint_manager=checkpoint_manager,
    )

    console.print("\n[bold cyan]MCP Stress Test[/bold cyan]\n")
    console.print(f"Scanner: {scanner_key}")
    console.print(f"Phases: {', '.join(p.value for p in phase_list)}")
    console.print(f"Strategies: {', '.join(strategy_list)}")
    console.print(f"Tools: {len(tool_list)}")
    console.print(f"Payloads: {len(payload_list)}")
    console.print()

    def progress_callback(current: int, total: int, message: str) -> None:
        if verbose:
            console.print(f"  [{current}/{total}] {message}")

    console.print("[cyan]Running stress tests...[/cyan]")
    runner.run_full_suite(
        tools=tool_list,
        payloads=payload_list,
        progress_callback=progress_callback if verbose else None,
    )
    console.print("[green]OK[/green] Stress tests complete")

    summary = runner.get_summary()
    metrics = runner.get_metrics()

    console.print("\n[bold cyan]Results Summary[/bold cyan]\n")
    summary_table = Table(show_header=False)
    summary_table.add_column("Metric", style="white")
    summary_table.add_column("Value", style="green", justify="right")
    summary_table.add_row("Total Tests", str(summary["total_tests"]))
    summary_table.add_row("Passed", str(summary["passed"]))
    summary_table.add_row("Failed", str(summary["failed"]))
    summary_table.add_row("Detection Rate", f"{summary['detection_rate']:.1f}%")
    summary_table.add_row("Precision", f"{summary['precision']:.1f}%")
    summary_table.add_row("F1 Score", f"{summary['f1_score']:.1f}")
    summary_table.add_row("Avg Scan Time", f"{summary['avg_scan_time_ms']:.2f}ms")
    console.print(summary_table)

    if metrics.by_strategy:
        console.print("\n[bold]Detection by Strategy:[/bold]")
        strat_table = Table()
        strat_table.add_column("Strategy", style="cyan")
        strat_table.add_column("Detected", justify="right")
        strat_table.add_column("Missed", justify="right")
        strat_table.add_column("Rate", justify="right")
        for strat, stats in metrics.by_strategy.items():
            total = stats["detected"] + stats["missed"]
            rate = (stats["detected"] / total * 100) if total > 0 else 0
            color = "green" if rate >= 80 else "yellow" if rate >= 50 else "red"
            strat_table.add_row(
                strat,
                str(stats["detected"]),
                str(stats["missed"]),
                f"[{color}]{rate:.1f}%[/{color}]",
            )
        console.print(strat_table)

    if output is None and data_root is not None and checkpoint_manager is not None:
        report_dir = data_root / "reports"
        report_dir.mkdir(parents=True, exist_ok=True)
        output = str(report_dir / f"stress-{checkpoint_manager.session_id}.json")

    if output:
        output_path = Path(output)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(runner.export_results(format), encoding="utf-8")
        console.print(f"\n[green]Results saved to {output_path}[/green]")


@click.group("stress")
def stress_group() -> None:
    """Run stress tests against scanners.

    Wraps the same StressTestRunner the legacy CLI uses for
    baseline, mutation, temporal, and progressive suites.
    """
    pass


@stress_group.command("run")
@click.option(
    "--phases",
    type=str,
    default="baseline,mutation",
    help="Comma-separated test phases: baseline,mutation,temporal,progressive",
)
@click.option(
    "--strategies",
    type=str,
    default="direct_injection,semantic_blending,obfuscation",
    help="Comma-separated mutation strategies",
)
@click.option(
    "--tools",
    type=str,
    default=None,
    help="Comma-separated tool names (default: first 5 from the library)",
)
@click.option(
    "--payloads",
    type=str,
    default="data_exfil",
    help="Payload category to use",
)
@click.option(
    "--scanner",
    type=click.Choice(list(_SCANNER_CHOICES), case_sensitive=False),
    default="mock",
    help="Scanner backend to test",
)
@click.option(
    "--scanner-path",
    type=str,
    default=None,
    help="Path to scanner CLI (for tool-scan)",
)
@click.option(
    "--output",
    "-o",
    type=click.Path(),
    help="Output file for results (JSON/CSV/Markdown)",
)
@click.option(
    "--format",
    "fmt",
    type=click.Choice(["json", "csv", "markdown"]),
    default="json",
    help="Output format for --output",
)
@click.option(
    "--verbose",
    is_flag=True,
    help="Show detailed progress",
)
def stress_run(
    phases: str,
    strategies: str,
    tools: str | None,
    payloads: str,
    scanner: str,
    scanner_path: str | None,
    output: str | None,
    fmt: str,
    verbose: bool,
) -> None:
    """Run the stress-test suite against a scanner.

    Example:
        mcp-stress stress run --phases baseline,mutation
    """
    execute_stress_run(
        phases=phases,
        strategies=strategies,
        tools=tools,
        payloads=payloads,
        scanner=scanner,
        scanner_path=scanner_path,
        output=output,
        format=fmt,
        verbose=verbose,
    )
