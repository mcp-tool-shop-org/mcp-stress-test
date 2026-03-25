"""Main CLI entry point with all command groups."""

from __future__ import annotations

import sys

import click
from rich.console import Console

from mcp_stress_test import __version__
from mcp_stress_test.cli.commands.chain import chain_group
from mcp_stress_test.cli.commands.fuzz import fuzz_group
from mcp_stress_test.cli.commands.info import info_cmd
from mcp_stress_test.cli.commands.report import report_group
from mcp_stress_test.cli.commands.scan import scan_group

# Fix Windows Unicode issues
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

_is_terminal = sys.stdout.isatty() if hasattr(sys.stdout, "isatty") else False
console = Console(force_terminal=_is_terminal)


@click.group()
@click.version_option(version=__version__, prog_name="mcp-stress")
@click.option("--verbose", "-v", is_flag=True, help="Enable verbose output")
@click.option("--config", "-c", type=click.Path(), help="Path to config file")
@click.pass_context
def app(ctx: click.Context, verbose: bool, config: str | None) -> None:
    """MCP Stress Test Framework - Security testing for MCP tools.

    A comprehensive toolkit for stress testing MCP security scanners using
    attack patterns from MCPTox, Unit42, and CyberArk research.

    \b
    Quick Start:
      mcp-stress info              Show framework capabilities
      mcp-stress fuzz run          Run LLM-guided fuzzing
      mcp-stress chain execute     Run attack chains
      mcp-stress report generate   Generate reports
    """
    ctx.ensure_object(dict)
    ctx.obj["verbose"] = verbose
    ctx.obj["config"] = config


app.add_command(info_cmd, name="info")
app.add_command(fuzz_group, name="fuzz")
app.add_command(chain_group, name="chain")
app.add_command(report_group, name="report")
app.add_command(scan_group, name="scan")


def main() -> None:
    """Entry point for the CLI."""
    app()


if __name__ == "__main__":
    main()
