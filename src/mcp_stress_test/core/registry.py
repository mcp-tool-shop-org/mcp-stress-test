"""Plugin registry for dynamic component discovery.

The registry allows scanners, fuzzers, reporters, and attack chains
to be registered and discovered at runtime. This enables a plugin
architecture where new implementations can be added without modifying
core code.
"""

from __future__ import annotations

from typing import TypeVar

from mcp_stress_test.core.protocols import (
    AttackChain,
    Fuzzer,
    Reporter,
    ReportFormat,
    Scanner,
)

T = TypeVar("T")


class PluginRegistry:
    """Central registry for all pluggable components.

    Usage:
        # Register a scanner
        registry.register_scanner(MyScanner())

        # Get a scanner by name
        scanner = registry.get_scanner("my-scanner")

        # List all available scanners
        for name in registry.list_scanners():
            print(name)
    """

    def __init__(self) -> None:
        self._scanners: dict[str, Scanner] = {}
        self._fuzzers: dict[str, Fuzzer] = {}
        self._reporters: dict[str, Reporter] = {}
        self._chains: dict[str, AttackChain] = {}

    # -------------------------------------------------------------------------
    # Scanners
    # -------------------------------------------------------------------------

    def register_scanner(self, scanner: Scanner) -> None:
        """Register a scanner implementation."""
        self._scanners[scanner.name] = scanner

    def get_scanner(self, name: str) -> Scanner | None:
        """Get a scanner by name."""
        return self._scanners.get(name)

    def list_scanners(self) -> list[str]:
        """List all registered scanner names."""
        return list(self._scanners.keys())

    def get_default_scanner(self) -> Scanner | None:
        """Get the first available scanner, or None."""
        if self._scanners:
            return next(iter(self._scanners.values()))
        return None

    # -------------------------------------------------------------------------
    # Fuzzers
    # -------------------------------------------------------------------------

    def register_fuzzer(self, fuzzer: Fuzzer) -> None:
        """Register a fuzzer implementation."""
        self._fuzzers[fuzzer.name] = fuzzer

    def get_fuzzer(self, name: str) -> Fuzzer | None:
        """Get a fuzzer by name."""
        return self._fuzzers.get(name)

    def list_fuzzers(self) -> list[str]:
        """List all registered fuzzer names."""
        return list(self._fuzzers.keys())

    # -------------------------------------------------------------------------
    # Reporters
    # -------------------------------------------------------------------------

    def register_reporter(self, reporter: Reporter) -> None:
        """Register a reporter implementation."""
        self._reporters[reporter.name] = reporter

    def get_reporter(self, name: str) -> Reporter | None:
        """Get a reporter by name."""
        return self._reporters.get(name)

    def get_reporter_for_format(self, fmt: ReportFormat) -> Reporter | None:
        """Get a reporter that produces the given format."""
        for reporter in self._reporters.values():
            if reporter.format == fmt:
                return reporter
        return None

    def list_reporters(self) -> list[str]:
        """List all registered reporter names."""
        return list(self._reporters.keys())

    # -------------------------------------------------------------------------
    # Attack Chains
    # -------------------------------------------------------------------------

    def register_chain(self, chain: AttackChain) -> None:
        """Register an attack chain."""
        self._chains[chain.name] = chain

    def get_chain(self, name: str) -> AttackChain | None:
        """Get an attack chain by name."""
        return self._chains.get(name)

    def list_chains(self) -> list[str]:
        """List all registered chain names."""
        return list(self._chains.keys())

    def get_chains_for_tool(self, tool_name: str) -> list[AttackChain]:
        """Get all chains that target a specific tool."""
        return [chain for chain in self._chains.values() if tool_name in chain.tools_required]

    # -------------------------------------------------------------------------
    # Utilities
    # -------------------------------------------------------------------------

    def clear(self) -> None:
        """Clear all registrations (useful for testing)."""
        self._scanners.clear()
        self._fuzzers.clear()
        self._reporters.clear()
        self._chains.clear()

    def stats(self) -> dict[str, int]:
        """Get registration statistics."""
        return {
            "scanners": len(self._scanners),
            "fuzzers": len(self._fuzzers),
            "reporters": len(self._reporters),
            "chains": len(self._chains),
        }


# Global registry instance
registry = PluginRegistry()
