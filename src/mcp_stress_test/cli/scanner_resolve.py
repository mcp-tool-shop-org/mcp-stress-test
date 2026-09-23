"""Resolve CLI --scanner values to scanner instances."""

from __future__ import annotations

from typing import Any

import click

SCANNER_NAMES = ("mock", "tool-scan", "cli")


def resolve_scanner(name: str, command: str | None = None) -> Any:
    """Construct the scanner named on the CLI.

    Args:
        name: Scanner identifier from --scanner (mock, tool-scan, cli).
        command: Command template for the generic CLI scanner.

    Returns:
        A scanner with ``name`` and ``scan()``.

    Raises:
        click.UsageError: If the name is unknown or ``cli`` has no command.
        click.ClickException: If the scanner exposes ``is_available()`` and it is False.
    """
    from mcp_stress_test.scanners.cli_adapter import CLIScanner
    from mcp_stress_test.scanners.mock import MockScanner
    from mcp_stress_test.scanners.tool_scan import ToolScanAdapter

    key = (name or "mock").strip().lower().replace("_", "-")
    if key == "mock":
        scanner = MockScanner()
    elif key == "tool-scan":
        scanner = ToolScanAdapter()
    elif key == "cli":
        if not command:
            raise click.UsageError(
                "Scanner 'cli' needs a command template; use --scanner mock or --scanner tool-scan."
            )
        scanner = CLIScanner(command=command)
    else:
        raise click.UsageError(
            f"Unknown scanner '{name}'. Choose from: {', '.join(SCANNER_NAMES)}."
        )
    require_scanner_available(scanner)
    return scanner


def _scanner_binary_name(scanner: Any) -> str:
    path = getattr(scanner, "tool_scan_path", None)
    if path:
        return str(path)
    command = getattr(scanner, "command", None)
    if command:
        return str(command).split()[0]
    return str(getattr(scanner, "name", "scanner"))


def require_scanner_available(scanner: Any) -> None:
    """Raise if the scanner exposes is_available() and it is False."""
    check = getattr(scanner, "is_available", None)
    if not callable(check) or check():
        return
    binary = _scanner_binary_name(scanner)
    name = getattr(scanner, "name", binary)
    if str(name).lower() == "tool-scan" or "tool-scan" in binary.lower():
        how = "Install it with: pip install tool-scan"
    else:
        how = f"Install '{binary}' and ensure it is on PATH."
    raise click.ClickException(
        f"Scanner '{name}' is not available: binary '{binary}' was not found. {how}"
    )


def raise_if_scan_error(result: Any, context: str | None = None) -> None:
    """Fail the CLI if a scan result's metadata records an error."""
    metadata = getattr(result, "metadata", None)
    if not isinstance(metadata, dict):
        return
    error = metadata.get("error")
    if not error or error == "missing_tools":
        return
    prefix = f"{context}: " if context else "Scanner error: "
    raise click.ClickException(f"{prefix}{error}")
