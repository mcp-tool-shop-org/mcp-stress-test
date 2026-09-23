"""Info command showing framework capabilities."""

from __future__ import annotations

import click
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from mcp_stress_test import __version__

console = Console()


@click.command("info")
def info_cmd() -> None:
    """Show framework capabilities and quick reference."""
    console.print(
        Panel.fit(
            f"[bold cyan]MCP Stress Test Framework[/bold cyan]\n[dim]Version {__version__}[/dim]",
            border_style="cyan",
        )
    )

    console.print("\n[bold]Purpose:[/bold]")
    console.print("  Stress test MCP security tools using attack patterns from:")
    console.print("  • MCPTox benchmark (1,312 patterns)")
    console.print("  • Palo Alto Unit42 sampling exploits")
    console.print("  • CyberArk full-schema poisoning research")

    console.print("\n[bold]Features:[/bold]")
    features = Table(show_header=False, box=None, padding=(0, 2))
    features.add_column("Feature", style="green")
    features.add_column("Description")
    features.add_row("LLM Fuzzing", "Ollama-powered payload mutation for evasion")
    features.add_row("Attack Chains", "6 multi-step attack scenarios")
    features.add_row("SARIF Output", "IDE integration (VSCode, GitHub)")
    features.add_row("HTML Reports", "Interactive dashboards with charts")
    features.add_row("Plugin System", "Extensible scanners, fuzzers, reporters")
    console.print(features)

    console.print("\n[bold]Quick Start:[/bold]")
    commands = Table(show_header=False, box=None, padding=(0, 2))
    commands.add_column("Command", style="cyan")
    commands.add_column("Description")
    commands.add_row("mcp-stress stress run", "Run baseline/mutation/temporal suites")
    commands.add_row("mcp-stress patterns list", "List PatternLibrary attack patterns")
    commands.add_row("mcp-stress payloads list", "List poison payloads")
    commands.add_row("mcp-stress tools list", "List builtin tool schemas")
    commands.add_row("mcp-stress generate", "Emit test-case JSON")
    commands.add_row("mcp-stress server serve", "Start a demo MCP server on stdio")
    commands.add_row("mcp-stress fuzz run", "Run LLM-guided fuzzing")
    commands.add_row("mcp-stress chain execute", "Run attack chains")
    commands.add_row("mcp-stress scan batch", "Batch scan with optional CI gate")
    commands.add_row("mcp-stress report generate", "Generate reports")
    commands.add_row("mcp-stress report compare", "Diff two result snapshots")
    console.print(commands)

    console.print("\n[bold]Attack Chains:[/bold]")
    chains = Table(show_header=True, box=None, padding=(0, 2))
    chains.add_column("Chain", style="yellow")
    chains.add_column("Steps")
    chains.add_column("Description")
    chains.add_row("data_exfil_chain", "3", "File discovery → Read → HTTP exfil")
    chains.add_row("privilege_escalation_chain", "4", "Enum → Find writable → Modify → Execute")
    chains.add_row("credential_theft_chain", "4", "Read env → Token files → Test → Cloud access")
    chains.add_row(
        "lateral_movement_chain", "4", "Network discovery → Port scan → SSH → Remote exec"
    )
    chains.add_row("persistence_chain", "4", "Create user → Add cron → Modify startup → Clear logs")
    chains.add_row(
        "sampling_loop_chain", "4", "Inject sampling → Feedback loop → Escalate → Persist"
    )
    console.print(chains)

    console.print("\n[bold]Report Formats:[/bold]")
    console.print("  • [cyan]json[/cyan] - Machine-readable for CI/CD")
    console.print("  • [cyan]markdown[/cyan] - Human-readable for docs")
    console.print("  • [cyan]html[/cyan] - Interactive dashboard")
    console.print("  • [cyan]sarif[/cyan] - IDE integration (VSCode, GitHub)")

    console.print("\n[dim]For help: mcp-stress --help[/dim]")
