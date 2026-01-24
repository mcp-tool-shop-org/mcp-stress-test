"""Core abstractions for MCP Stress Test Framework.

This module provides the foundational protocols and base classes that
enable a plugin-based architecture for scanners, fuzzers, and reporters.
"""

from __future__ import annotations

from mcp_stress_test.core.protocols import (
    AttackResult,
    ChainResult,
    FuzzResult,
    ReportFormat,
    Scanner,
    Fuzzer,
    Reporter,
    AttackChain,
)
from mcp_stress_test.core.registry import PluginRegistry, registry
from mcp_stress_test.core.config import StressConfig

__all__ = [
    # Protocols
    "Scanner",
    "Fuzzer",
    "Reporter",
    "AttackChain",
    # Results
    "AttackResult",
    "ChainResult",
    "FuzzResult",
    "ReportFormat",
    # Registry
    "PluginRegistry",
    "registry",
    # Config
    "StressConfig",
]
