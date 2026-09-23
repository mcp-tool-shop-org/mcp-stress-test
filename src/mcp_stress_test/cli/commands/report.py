"""Report generation commands."""

from __future__ import annotations

import html
import json
from pathlib import Path

import click
from rich.console import Console

from mcp_stress_test.core.protocols import AttackResult, ChainResult

console = Console()


def _as_float(value: object, default: float) -> float:
    try:
        return float(value)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return default


_OPTIONAL_METRIC_KEYS: dict[str, tuple[str, ...]] = {
    "false_positive_rate": ("false_positive_rate", "falsePositiveRate"),
    "time_to_detection": ("time_to_detection", "avg_time_to_detection", "timeToDetection"),
    "asr_reduction": ("asr_reduction", "asrReduction"),
}


def _read_optional_float(container: dict, keys: tuple[str, ...]) -> float | None:
    for key in keys:
        if key not in container or container[key] is None:
            continue
        try:
            return float(container[key])
        except (TypeError, ValueError):
            continue
    return None


def _optional_metrics_from_mapping(data: dict) -> dict[str, float]:
    """Copy snapshot metrics that are already present; do not invent values."""
    bags: list[dict] = []
    summary = data.get("summary")
    if isinstance(summary, dict):
        bags.append(summary)
        nested = summary.get("metrics")
        if isinstance(nested, dict):
            bags.append(nested)
    metrics_block = data.get("metrics")
    if isinstance(metrics_block, dict):
        bags.append(metrics_block)
    bags.append(data)
    extras: dict[str, float] = {}
    for dest, keys in _OPTIONAL_METRIC_KEYS.items():
        for bag in bags:
            value = _read_optional_float(bag, keys)
            if value is not None:
                extras[dest] = value
                break
    return extras


def _copy_optional_metrics(row: dict, metadata: dict) -> None:
    for dest, keys in _OPTIONAL_METRIC_KEYS.items():
        if dest in metadata:
            continue
        value = _read_optional_float(row, keys)
        if value is not None:
            metadata[dest] = value


def _attach_optional_metrics(
    results: list[AttackResult],
    chain_results: list[ChainResult],
    extras: dict[str, float],
) -> None:
    if not extras:
        return
    target: dict | None = None
    if results:
        if not isinstance(results[0].metadata, dict):
            results[0].metadata = {}
        target = results[0].metadata
    elif chain_results:
        if not isinstance(chain_results[0].metadata, dict):
            chain_results[0].metadata = {}
        target = chain_results[0].metadata
    if target is None:
        return
    for key, value in extras.items():
        if key not in target:
            target[key] = value


def _attack_result_from_row(row: dict) -> AttackResult:
    score_before = _as_float(row.get("score_before", 100.0), 100.0)
    if "score_after" in row:
        score_after = _as_float(row.get("score_after"), score_before)
    elif "score_delta" in row:
        score_after = score_before + _as_float(row.get("score_delta"), 0.0)
    else:
        score_after = score_before
    threats = row.get("threats_found")
    if threats is None:
        threats = row.get("new_threats", row.get("threats", []))
    if not isinstance(threats, list):
        threats = [str(threats)]
    metadata = row.get("metadata")
    metadata = {} if not isinstance(metadata, dict) else dict(metadata)
    if "phase" in row and "phase" not in metadata:
        metadata["phase"] = row["phase"]
    if "is_attack" in row and "is_attack" not in metadata:
        metadata["is_attack"] = row["is_attack"]
    if "detected" in row:
        detected = bool(row.get("detected"))
    elif "attack_detected" in row:
        detected = bool(row.get("attack_detected"))
    else:
        detected = False
    scan_time = row.get("scan_time_ms", row.get("scan_duration_ms", 0.0))
    _copy_optional_metrics(row, metadata)
    return AttackResult(
        tool_name=str(row.get("tool_name") or row.get("tool") or "unknown"),
        strategy=str(row.get("strategy") or "unknown"),
        detected=detected,
        score_before=score_before,
        score_after=score_after,
        threats_found=[str(t) for t in threats],
        scan_time_ms=_as_float(scan_time, 0.0),
        metadata=metadata,
    )


def _chain_result_from_row(row: dict) -> ChainResult:
    raw_steps = row.get("steps") or []
    steps = []
    if isinstance(raw_steps, list):
        for step in raw_steps:
            if not isinstance(step, dict):
                continue
            detected = bool(step.get("detected", False))
            metadata = step.get("metadata")
            if not isinstance(metadata, dict):
                metadata = {}
            _copy_optional_metrics(step, metadata)
            steps.append(
                AttackResult(
                    tool_name=str(step.get("tool_name") or step.get("tool") or "unknown"),
                    strategy=str(step.get("strategy") or "chain_step"),
                    detected=detected,
                    score_before=100.0,
                    score_after=50.0 if detected else 100.0,
                    metadata=metadata,
                )
            )
    chain_metadata = row.get("metadata")
    chain_metadata = {} if not isinstance(chain_metadata, dict) else dict(chain_metadata)
    _copy_optional_metrics(row, chain_metadata)
    return ChainResult(
        chain_name=str(row.get("chain_name") or row.get("chain") or "unknown"),
        steps=steps,
        chain_detected=bool(row.get("chain_detected", row.get("detected", False))),
        total_time_ms=_as_float(row.get("total_time_ms", 0.0), 0.0),
        metadata=chain_metadata,
    )


def _looks_like_chain_row(row: dict) -> bool:
    return "chain" in row or "chain_name" in row or "steps" in row


def parse_report_input(data: object) -> tuple[list[AttackResult], list[ChainResult]]:
    """Parse JSON written by this CLI (scan batch, chain execute, JSON reports)."""
    results: list[AttackResult] = []
    chain_results: list[ChainResult] = []

    if isinstance(data, list):
        if data and not all(isinstance(item, dict) for item in data):
            raise click.UsageError("Input JSON list must contain objects.")
        if not data:
            return [], []
        if any(_looks_like_chain_row(item) for item in data):
            return [], [_chain_result_from_row(item) for item in data]
        return [_attack_result_from_row(item) for item in data], []

    if not isinstance(data, dict):
        raise click.UsageError("Input JSON must be an object or a list of result objects.")

    recognized = False
    if "results" in data:
        recognized = True
        rows = data["results"]
        if rows is None:
            rows = []
        if not isinstance(rows, list):
            raise click.UsageError("'results' must be a list.")
        for row in rows:
            if isinstance(row, dict):
                results.append(_attack_result_from_row(row))

    if "chains" in data:
        recognized = True
        chains_block = data["chains"]
        if isinstance(chains_block, dict):
            chain_rows = chains_block.get("results", [])
        elif isinstance(chains_block, list):
            chain_rows = chains_block
        else:
            raise click.UsageError("'chains' must be an object or a list.")
        if not isinstance(chain_rows, list):
            raise click.UsageError("Chain results must be a list.")
        for row in chain_rows:
            if isinstance(row, dict):
                chain_results.append(_chain_result_from_row(row))

    if not recognized:
        raise click.UsageError(
            "Unrecognized results shape. Expected a chain-execute list, "
            "or an object with 'results' and/or 'chains'."
        )

    _attach_optional_metrics(results, chain_results, _optional_metrics_from_mapping(data))
    return results, chain_results


def load_report_json(input_file: str) -> object:
    """Load JSON from an operator-supplied results file."""
    try:
        with open(input_file, encoding="utf-8") as f:
            return json.load(f)
    except UnicodeDecodeError as e:
        raise click.ClickException(f"Could not decode {input_file} as UTF-8: {e}") from e
    except json.JSONDecodeError as e:
        raise click.ClickException(f"Invalid JSON in {input_file}: {e}") from e


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
@click.option(
    "--fail-under-detection",
    type=float,
    default=None,
    help="Exit 1 if detection rate percent is below this threshold.",
)
@click.option(
    "--fail-on-evasion",
    is_flag=True,
    default=False,
    help="Exit 1 if any attacks evaded detection (evasion rate > 0).",
)
def report_generate(
    input_file: str,
    fmt: str,
    output: str | None,
    include_chains: bool,
    fail_under_detection: float | None,
    fail_on_evasion: bool,
) -> None:
    """Generate a report from stress test results.

    Example:
        mcp-stress report generate -i results.json -f html -o report.html
    """
    from mcp_stress_test.reporters import (
        HTMLReporter,
        JSONReporter,
        MarkdownReporter,
        SARIFReporter,
    )

    data = load_report_json(input_file)

    results, parsed_chains = parse_report_input(data)
    chain_results = parsed_chains if (include_chains or parsed_chains) else []

    # Select reporter
    reporters = {
        "json": JSONReporter(),
        "markdown": MarkdownReporter(),
        "html": HTMLReporter(),
        "sarif": SARIFReporter(),
    }

    reporter = reporters[fmt]

    # Determine output path
    input_path = Path(input_file)
    if not output:
        output = str(input_path.with_suffix(f".{reporter.file_extension}"))
        if Path(output).resolve() == input_path.resolve():
            output = str(
                input_path.with_name(f"{input_path.stem}.report.{reporter.file_extension}")
            )
    elif Path(output).resolve() == input_path.resolve():
        raise click.UsageError("Output path is the same as the input file; choose a different -o.")

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

    from mcp_stress_test.cli.quality_gate import enforce_quality_gate
    from mcp_stress_test.reporters import JSONReporter

    metrics = JSONReporter()._compute_metrics(results, chain_results)
    if results:
        detection_rate = metrics.detection_rate
    elif chain_results:
        detected_chains = sum(1 for c in chain_results if c.chain_detected)
        detection_rate = detected_chains / len(chain_results) * 100
    else:
        detection_rate = 0.0
    enforce_quality_gate(
        detection_rate,
        fail_under_detection=fail_under_detection,
        fail_on_evasion=fail_on_evasion,
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

    from mcp_stress_test.reporters import JSONReporter

    data = load_report_json(input_file)
    try:
        results, chain_results = parse_report_input(data)
    except click.ClickException as e:
        raise click.ClickException(f"{input_file}: {e.format_message()}") from e
    except AttributeError as e:
        raise click.ClickException(f"{input_file}: unusable results shape ({e})") from e

    metrics = JSONReporter()._compute_metrics(results, chain_results)

    console.print(f"\n[bold]Report Preview: {input_file}[/bold]\n")

    table = Table(title="Summary", show_header=False)
    table.add_column("Metric")
    table.add_column("Value", justify="right")
    table.add_row("Total Tests", str(metrics.total_tests))
    table.add_row("Detection Rate", f"{metrics.detection_rate:.1f}%")
    table.add_row("Evasion Rate", f"{metrics.evasion_rate:.1f}%")
    table.add_row("Avg Scan Time", f"{metrics.avg_scan_time_ms:.2f}ms")
    for label, value in metrics.extra_summary_items():
        table.add_row(label, value)
    table.add_row("Chains", str(len(chain_results)))
    console.print(table)

    if metrics.by_strategy:
        console.print("\n[bold]By Strategy:[/bold]")
        for strategy, stats in metrics.by_strategy.items():
            detected = stats.get("detected", 0)
            missed = stats.get("missed", 0)
            total = detected + missed
            rate = detected / total * 100 if total > 0 else 0
            console.print(f"  {strategy}: {detected}/{total} ({rate:.1f}%)")

    if chain_results:
        console.print(f"\n[bold]Chains:[/bold] {len(chain_results)} executed")
        for chain in chain_results:
            status = "detected" if chain.chain_detected else "missed"
            console.print(f"  {chain.chain_name}: {status}")


def _flatten_for_compare(
    results: list[AttackResult],
    chain_results: list[ChainResult],
) -> list[AttackResult]:
    if results:
        return results
    flattened: list[AttackResult] = []
    for chain in chain_results:
        flattened.extend(chain.steps)
    return flattened


def _detection_rate(results: list[AttackResult]) -> float:
    if not results:
        return 0.0
    return sum(1 for row in results if row.detected) / len(results) * 100


def compare_report_snapshots(
    current: list[AttackResult],
    baseline: list[AttackResult],
) -> dict:
    """Join two snapshots on (tool, strategy) and compute evasion deltas."""
    current_map = {(row.tool_name, row.strategy): row for row in current}
    baseline_map = {(row.tool_name, row.strategy): row for row in baseline}
    added_evasions: list[dict[str, str]] = []
    removed_evasions: list[dict[str, str]] = []
    for key in sorted(set(current_map) | set(baseline_map)):
        cur = current_map.get(key)
        base = baseline_map.get(key)
        entry = {"tool": key[0], "strategy": key[1]}
        if cur is not None and cur.evaded and (base is None or not base.evaded):
            added_evasions.append(entry)
        if base is not None and base.evaded and (cur is None or not cur.evaded):
            removed_evasions.append(entry)
    current_rate = _detection_rate(current)
    baseline_rate = _detection_rate(baseline)
    return {
        "joined_on": ["tool", "strategy"],
        "baseline_tests": len(baseline),
        "current_tests": len(current),
        "baseline_detection_rate": baseline_rate,
        "current_detection_rate": current_rate,
        "detection_rate_delta": current_rate - baseline_rate,
        "baseline_evasion_rate": 100.0 - baseline_rate,
        "current_evasion_rate": 100.0 - current_rate,
        "evasion_rate_delta": (100.0 - current_rate) - (100.0 - baseline_rate),
        "added_evasions": added_evasions,
        "removed_evasions": removed_evasions,
    }


def _render_compare_markdown(diff: dict) -> str:
    lines = [
        "# Report comparison",
        "",
        f"- **Baseline tests**: {diff['baseline_tests']}",
        f"- **Current tests**: {diff['current_tests']}",
        f"- **Baseline detection rate**: {diff['baseline_detection_rate']:.1f}%",
        f"- **Current detection rate**: {diff['current_detection_rate']:.1f}%",
        f"- **Detection rate delta**: {diff['detection_rate_delta']:+.1f}%",
        f"- **Evasion rate delta**: {diff['evasion_rate_delta']:+.1f}%",
        "",
        "## Added evasions",
        "",
    ]
    if diff["added_evasions"]:
        lines.append("| Tool | Strategy |")
        lines.append("|------|----------|")
        for row in diff["added_evasions"]:
            lines.append(f"| {row['tool']} | {row['strategy']} |")
    else:
        lines.append("None.")
    lines.extend(["", "## Removed evasions", ""])
    if diff["removed_evasions"]:
        lines.append("| Tool | Strategy |")
        lines.append("|------|----------|")
        for row in diff["removed_evasions"]:
            lines.append(f"| {row['tool']} | {row['strategy']} |")
    else:
        lines.append("None.")
    lines.append("")
    return "\n".join(lines)


def _render_compare_html(diff: dict) -> str:
    def rows(items: list[dict[str, str]]) -> str:
        if not items:
            return "<tr><td colspan='2'>None</td></tr>"
        return "\n".join(
            f"<tr><td>{html.escape(row['tool'])}</td><td>{html.escape(row['strategy'])}</td></tr>"
            for row in items
        )

    return f"""<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"><title>MCP Stress Test Comparison</title></head>
<body>
<h1>Report comparison</h1>
<ul>
<li>Baseline tests: {diff["baseline_tests"]}</li>
<li>Current tests: {diff["current_tests"]}</li>
<li>Baseline detection rate: {diff["baseline_detection_rate"]:.1f}%</li>
<li>Current detection rate: {diff["current_detection_rate"]:.1f}%</li>
<li>Detection rate delta: {diff["detection_rate_delta"]:+.1f}%</li>
<li>Evasion rate delta: {diff["evasion_rate_delta"]:+.1f}%</li>
</ul>
<h2>Added evasions</h2>
<table><thead><tr><th>Tool</th><th>Strategy</th></tr></thead>
<tbody>{rows(diff["added_evasions"])}</tbody></table>
<h2>Removed evasions</h2>
<table><thead><tr><th>Tool</th><th>Strategy</th></tr></thead>
<tbody>{rows(diff["removed_evasions"])}</tbody></table>
</body>
</html>
"""


@report_group.command("compare")
@click.option(
    "--input",
    "-i",
    "input_file",
    required=True,
    type=click.Path(exists=True),
    help="Current JSON results file",
)
@click.option(
    "--baseline",
    required=True,
    type=click.Path(exists=True),
    help="Previous JSON results file to diff against",
)
@click.option(
    "--format",
    "-f",
    "fmt",
    default="json",
    type=click.Choice(["json", "markdown", "html"]),
    help="Output format",
)
@click.option("--output", "-o", type=click.Path(), help="Output file path")
def report_compare(
    input_file: str,
    baseline: str,
    fmt: str,
    output: str | None,
) -> None:
    """Diff two result snapshots on (tool, strategy).

    Example:
        mcp-stress report compare -i current.json --baseline previous.json -f markdown
    """
    current_data = load_report_json(input_file)
    baseline_data = load_report_json(baseline)
    current_results, current_chains = parse_report_input(current_data)
    baseline_results, baseline_chains = parse_report_input(baseline_data)
    diff = compare_report_snapshots(
        _flatten_for_compare(current_results, current_chains),
        _flatten_for_compare(baseline_results, baseline_chains),
    )
    if fmt == "markdown":
        content = _render_compare_markdown(diff)
    elif fmt == "html":
        content = _render_compare_html(diff)
    else:
        content = json.dumps(diff, indent=2)

    if output:
        Path(output).write_text(content, encoding="utf-8")
        console.print(f"[green]Comparison written: {output}[/green]")
    else:
        click.echo(content)
