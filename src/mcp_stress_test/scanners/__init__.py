"""Scanner adapters for security tool integration.

This module provides adapters that wrap different security scanners
to provide a unified interface for stress testing.
"""

from __future__ import annotations

from mcp_stress_test.scanners.cli_adapter import CLIScanner
from mcp_stress_test.scanners.mock import MockScanner
from mcp_stress_test.scanners.tool_scan import ToolScanAdapter

__all__ = [
    "MockScanner",
    "ToolScanAdapter",
    "CLIScanner",
]
