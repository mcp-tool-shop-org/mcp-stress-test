"""Core abstractions for MCP Stress Test Framework.

This module provides the foundational protocols and base classes that
enable a plugin-based architecture for scanners, fuzzers, and reporters.
"""

from __future__ import annotations

from mcp_stress_test.core.config import StressConfig
from mcp_stress_test.core.protocols import (
    AttackChain,
    AttackResult,
    ChainResult,
    Fuzzer,
    FuzzResult,
    Reporter,
    ReportFormat,
    Scanner,
)
from mcp_stress_test.core.registry import PluginRegistry, registry

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
