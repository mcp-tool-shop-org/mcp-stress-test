"""Evasion engine for systematic scanner bypass testing.

The evasion engine coordinates fuzzing attempts to find payloads
that evade detection, tracks successful evasions, and generates
reports on scanner weaknesses.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import TYPE_CHECKING

from mcp_stress_test.core.protocols import FuzzResult, Scanner
from mcp_stress_test.core.config import FuzzConfig
from mcp_stress_test.fuzzing.llm_fuzzer import LLMFuzzer, MockFuzzer

if TYPE_CHECKING:
    from mcp_stress_test.models import ToolSchema as ToolDefinition


@dataclass
class EvasionResult:
    """Result of an evasion attempt."""

    payload_id: str
    original_payload: str
    tool_name: str
    scanner_name: str
    evaded: bool
    successful_mutation: str | None = None
    mutation_type: str | None = None
    attempts: int = 0
    duration_ms: float = 0.0
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())

    def to_dict(self) -> dict:
        """Convert to dictionary for serialization."""
        return {
            "payload_id": self.payload_id,
            "original_payload": self.original_payload,
            "tool_name": self.tool_name,
            "scanner_name": self.scanner_name,
            "evaded": self.evaded,
            "successful_mutation": self.successful_mutation,
            "mutation_type": self.mutation_type,
            "attempts": self.attempts,
            "duration_ms": self.duration_ms,
            "timestamp": self.timestamp,
        }


@dataclass
class EvasionStats:
    """Statistics from evasion testing."""

    total_payloads: int = 0
    evasions_found: int = 0
    total_attempts: int = 0
    total_duration_ms: float = 0.0

    by_mutation_type: dict[str, int] = field(default_factory=dict)
    by_tool: dict[str, int] = field(default_factory=dict)

    @property
    def evasion_rate(self) -> float:
        """Percentage of payloads that found an evasion."""
        if self.total_payloads == 0:
            return 0.0
        return self.evasions_found / self.total_payloads * 100

    @property
    def avg_attempts_per_evasion(self) -> float:
        """Average attempts needed to find an evasion."""
        if self.evasions_found == 0:
            return 0.0
        return self.total_attempts / self.evasions_found


class EvasionEngine:
    """Coordinates evasion testing across payloads and tools.

    The engine:
    1. Takes a set of payloads and tools
    2. Uses fuzzers to generate mutations
    3. Tests each mutation against the scanner
    4. Tracks successful evasions
    5. Generates reports on scanner weaknesses

    Usage:
        engine = EvasionEngine(scanner, fuzzer, config)

        # Test a single payload
        result = engine.test_payload(payload, tool)

        # Test all payloads against all tools
        results = engine.test_all(payloads, tools)

        # Get statistics
        stats = engine.get_stats()

        # Save successful evasions
        engine.save_evasions("./evasions")
    """

    def __init__(
        self,
        scanner: Scanner,
        fuzzer: LLMFuzzer | None = None,
        config: FuzzConfig | None = None,
    ):
        self.scanner = scanner
        self.fuzzer = fuzzer or MockFuzzer(config=None)
        self.config = config or FuzzConfig()

        self._results: list[EvasionResult] = []
        self._evasions: list[EvasionResult] = []
        self._stats = EvasionStats()

    def test_payload(
        self,
        payload: str,
        tool: ToolDefinition,
        payload_id: str | None = None,
    ) -> EvasionResult:
        """Test a single payload for evasion potential.

        Args:
            payload: Attack payload to test
            tool: Tool to inject payload into
            payload_id: Optional identifier for tracking

        Returns:
            EvasionResult indicating if evasion was found
        """
        payload_id = payload_id or f"payload_{len(self._results)}"
        start = time.perf_counter()

        # Try to find an evasion
        fuzz_result = self.fuzzer.fuzz_until_evasion(
            payload=payload,
            scanner=self.scanner,
            tool=tool,
            max_attempts=self.config.max_generations,
        )

        duration = (time.perf_counter() - start) * 1000

        if fuzz_result and fuzz_result.evaded:
            result = EvasionResult(
                payload_id=payload_id,
                original_payload=payload,
                tool_name=tool.name,
                scanner_name=self.scanner.name,
                evaded=True,
                successful_mutation=fuzz_result.mutated_payload,
                mutation_type=fuzz_result.mutation_type,
                attempts=fuzz_result.generations,
                duration_ms=duration,
            )
            self._evasions.append(result)
            self._update_stats(result)
        else:
            result = EvasionResult(
                payload_id=payload_id,
                original_payload=payload,
                tool_name=tool.name,
                scanner_name=self.scanner.name,
                evaded=False,
                attempts=self.config.max_generations,
                duration_ms=duration,
            )

        self._results.append(result)
        self._stats.total_payloads += 1
        self._stats.total_duration_ms += duration

        return result

    def test_all(
        self,
        payloads: list[str],
        tools: list[ToolDefinition],
    ) -> list[EvasionResult]:
        """Test all payloads against all tools.

        Args:
            payloads: List of attack payloads
            tools: List of tools to test against

        Returns:
            List of all EvasionResults
        """
        results = []
        total = len(payloads) * len(tools)
        current = 0

        for payload in payloads:
            for tool in tools:
                current += 1
                payload_id = f"evasion_{current}_of_{total}"
                result = self.test_payload(payload, tool, payload_id)
                results.append(result)

        return results

    def _update_stats(self, result: EvasionResult) -> None:
        """Update statistics with a successful evasion."""
        self._stats.evasions_found += 1
        self._stats.total_attempts += result.attempts

        # Track by mutation type
        if result.mutation_type:
            self._stats.by_mutation_type[result.mutation_type] = (
                self._stats.by_mutation_type.get(result.mutation_type, 0) + 1
            )

        # Track by tool
        self._stats.by_tool[result.tool_name] = (
            self._stats.by_tool.get(result.tool_name, 0) + 1
        )

    def get_stats(self) -> EvasionStats:
        """Get current evasion statistics."""
        return self._stats

    def get_evasions(self) -> list[EvasionResult]:
        """Get all successful evasions."""
        return self._evasions.copy()

    def get_results(self) -> list[EvasionResult]:
        """Get all results (including failures)."""
        return self._results.copy()

    def save_evasions(self, output_dir: str | Path) -> Path:
        """Save successful evasions to a JSON file.

        Args:
            output_dir: Directory to save evasions to

        Returns:
            Path to the saved file
        """
        output_dir = Path(output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_file = output_dir / f"evasions_{timestamp}.json"

        data = {
            "scanner": self.scanner.name,
            "fuzzer": self.fuzzer.name,
            "stats": {
                "total_payloads": self._stats.total_payloads,
                "evasions_found": self._stats.evasions_found,
                "evasion_rate": self._stats.evasion_rate,
                "avg_attempts": self._stats.avg_attempts_per_evasion,
                "by_mutation_type": self._stats.by_mutation_type,
                "by_tool": self._stats.by_tool,
            },
            "evasions": [e.to_dict() for e in self._evasions],
        }

        with open(output_file, "w") as f:
            json.dump(data, f, indent=2)

        return output_file

    def clear(self) -> None:
        """Clear all results and statistics."""
        self._results.clear()
        self._evasions.clear()
        self._stats = EvasionStats()
