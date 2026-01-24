"""Chain execution and orchestration.

The executor runs attack chains against scanners and collects results.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from mcp_stress_test.chains.base import BaseChain
from mcp_stress_test.chains.library import BUILTIN_CHAINS, get_chain
from mcp_stress_test.core.protocols import ChainResult, Scanner

if TYPE_CHECKING:
    from mcp_stress_test.models import ToolSchema as ToolDefinition


@dataclass
class ChainExecutionStats:
    """Statistics from chain execution."""

    chains_executed: int = 0
    chains_detected: int = 0
    total_steps: int = 0
    steps_detected: int = 0
    total_time_ms: float = 0.0

    @property
    def chain_detection_rate(self) -> float:
        """Percentage of chains that were detected."""
        if self.chains_executed == 0:
            return 0.0
        return self.chains_detected / self.chains_executed * 100

    @property
    def step_detection_rate(self) -> float:
        """Percentage of steps that were detected."""
        if self.total_steps == 0:
            return 0.0
        return self.steps_detected / self.total_steps * 100


@dataclass
class ChainExecutor:
    """Executes attack chains against scanners.

    Usage:
        executor = ChainExecutor(scanner, tools)

        # Execute a single chain
        result = executor.execute_chain("data_exfil_chain")

        # Execute all chains
        results = executor.execute_all()

        # Get statistics
        stats = executor.get_stats()
    """

    scanner: Scanner
    tools: dict[str, "ToolDefinition"]
    _results: list[ChainResult] = field(default_factory=list)
    _stats: ChainExecutionStats = field(default_factory=ChainExecutionStats)

    def execute_chain(self, chain_name: str) -> ChainResult | None:
        """Execute a single chain by name.

        Args:
            chain_name: Name of the chain to execute

        Returns:
            ChainResult or None if chain not found
        """
        chain = get_chain(chain_name)
        if not chain:
            return None

        return self._execute(chain)

    def execute_all(
        self,
        chains: list[BaseChain] | None = None,
    ) -> list[ChainResult]:
        """Execute all chains (or a subset).

        Args:
            chains: Optional list of chains to execute (default: all built-in)

        Returns:
            List of ChainResults
        """
        chains = chains or BUILTIN_CHAINS
        results = []

        for chain in chains:
            # Check if we have required tools
            if not chain.can_execute(self.tools):
                missing = chain.get_missing_tools(self.tools)
                result = ChainResult(
                    chain_name=chain.name,
                    steps=[],
                    chain_detected=False,
                    metadata={
                        "error": "missing_tools",
                        "missing": missing,
                    },
                )
            else:
                result = self._execute(chain)

            results.append(result)
            self._results.append(result)

        return results

    def _execute(self, chain: BaseChain) -> ChainResult:
        """Execute a chain and update stats.

        Args:
            chain: The chain to execute

        Returns:
            ChainResult
        """
        start = time.perf_counter()
        result = chain.execute(self.scanner, self.tools)
        duration = (time.perf_counter() - start) * 1000

        # Update stats
        self._stats.chains_executed += 1
        self._stats.total_time_ms += duration

        if result.chain_detected:
            self._stats.chains_detected += 1

        self._stats.total_steps += len(result.steps)
        self._stats.steps_detected += result.steps_detected

        return result

    def get_stats(self) -> ChainExecutionStats:
        """Get execution statistics."""
        return self._stats

    def get_results(self) -> list[ChainResult]:
        """Get all execution results."""
        return self._results.copy()

    def get_undetected_chains(self) -> list[ChainResult]:
        """Get chains that were not detected."""
        return [r for r in self._results if not r.chain_detected]

    def get_partial_detections(self) -> list[ChainResult]:
        """Get chains where some but not all steps were detected."""
        return [
            r
            for r in self._results
            if r.chain_detected
            and r.steps_detected > 0
            and r.steps_detected < len(r.steps)
        ]

    def clear(self) -> None:
        """Clear results and stats."""
        self._results.clear()
        self._stats = ChainExecutionStats()


def execute_chains(
    scanner: Scanner,
    tools: dict[str, "ToolDefinition"],
    chain_names: list[str] | None = None,
) -> tuple[list[ChainResult], ChainExecutionStats]:
    """Convenience function to execute chains.

    Args:
        scanner: Scanner to test against
        tools: Available tool definitions
        chain_names: Optional list of chain names (default: all)

    Returns:
        Tuple of (results, stats)
    """
    executor = ChainExecutor(scanner=scanner, tools=tools)

    if chain_names:
        chains = [get_chain(name) for name in chain_names]
        chains = [c for c in chains if c is not None]
        results = executor.execute_all(chains)
    else:
        results = executor.execute_all()

    return results, executor.get_stats()
