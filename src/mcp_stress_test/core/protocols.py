"""Protocol definitions for pluggable components.

These protocols define the interfaces that scanners, fuzzers, reporters,
and attack chains must implement. This enables a clean plugin architecture
where new implementations can be added without modifying core code.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import TYPE_CHECKING, Protocol, runtime_checkable

if TYPE_CHECKING:
    from collections.abc import AsyncIterator, Iterator

    from mcp_stress_test.models import ToolSchema as ToolDefinition


class ReportFormat(str, Enum):
    """Supported report output formats."""

    JSON = "json"
    MARKDOWN = "markdown"
    HTML = "html"
    SARIF = "sarif"
    CSV = "csv"


@dataclass
class AttackResult:
    """Result of a single attack attempt."""

    tool_name: str
    strategy: str
    detected: bool
    score_before: float
    score_after: float
    threats_found: list[str] = field(default_factory=list)
    scan_time_ms: float = 0.0
    metadata: dict = field(default_factory=dict)

    @property
    def score_delta(self) -> float:
        """Score change from attack."""
        return self.score_after - self.score_before

    @property
    def evaded(self) -> bool:
        """Whether attack evaded detection."""
        return not self.detected


@dataclass
class ChainResult:
    """Result of a multi-tool attack chain."""

    chain_name: str
    steps: list[AttackResult]
    chain_detected: bool
    total_time_ms: float = 0.0
    metadata: dict = field(default_factory=dict)

    @property
    def steps_detected(self) -> int:
        """Number of steps that were detected."""
        return sum(1 for s in self.steps if s.detected)

    @property
    def detection_rate(self) -> float:
        """Percentage of steps detected."""
        if not self.steps:
            return 0.0
        return self.steps_detected / len(self.steps) * 100


@dataclass
class FuzzResult:
    """Result of LLM-guided fuzzing."""

    original_payload: str
    mutated_payload: str
    mutation_type: str
    evaded: bool
    generations: int
    llm_model: str
    reasoning: str = ""
    metadata: dict = field(default_factory=dict)


@runtime_checkable
class Scanner(Protocol):
    """Protocol for security scanners.

    Scanners analyze tool definitions and return security scores/threats.
    Implementations can wrap external tools (tool-scan) or provide mock data.
    """

    @property
    def name(self) -> str:
        """Scanner identifier."""
        ...

    def scan(self, tool: ToolDefinition) -> AttackResult:
        """Scan a single tool definition.

        Args:
            tool: The tool definition to analyze

        Returns:
            AttackResult with score and detected threats
        """
        ...

    def scan_batch(self, tools: list[ToolDefinition]) -> list[AttackResult]:
        """Scan multiple tools efficiently.

        Default implementation calls scan() for each tool.

        Args:
            tools: List of tool definitions

        Returns:
            List of AttackResults in same order as input
        """
        ...


@runtime_checkable
class Fuzzer(Protocol):
    """Protocol for attack payload fuzzers.

    Fuzzers generate novel attack payloads, optionally using LLMs
    to create semantically meaningful mutations.
    """

    @property
    def name(self) -> str:
        """Fuzzer identifier."""
        ...

    def fuzz(
        self,
        payload: str,
        context: dict | None = None,
    ) -> Iterator[FuzzResult]:
        """Generate mutated payloads.

        Args:
            payload: Original attack payload
            context: Optional context (target tool, scanner feedback, etc.)

        Yields:
            FuzzResult for each mutation attempt
        """
        ...

    def fuzz_until_evasion(
        self,
        payload: str,
        scanner: Scanner,
        max_attempts: int = 10,
    ) -> FuzzResult | None:
        """Fuzz until an evasion is found.

        Args:
            payload: Original attack payload
            scanner: Scanner to test against
            max_attempts: Maximum mutation attempts

        Returns:
            FuzzResult if evasion found, None otherwise
        """
        ...


@runtime_checkable
class Reporter(Protocol):
    """Protocol for report generators.

    Reporters take stress test results and produce formatted output
    in various formats (JSON, HTML, SARIF, etc.)
    """

    @property
    def name(self) -> str:
        """Reporter identifier."""
        ...

    @property
    def format(self) -> ReportFormat:
        """Output format this reporter produces."""
        ...

    def generate(
        self,
        results: list[AttackResult],
        output_path: str | None = None,
    ) -> str:
        """Generate a report from attack results.

        Args:
            results: List of attack results to report on
            output_path: Optional file path to write report to

        Returns:
            The generated report content as a string
        """
        ...


@runtime_checkable
class AttackChain(Protocol):
    """Protocol for multi-tool attack chains.

    Attack chains coordinate attacks across multiple tools,
    simulating realistic multi-step attack scenarios.
    """

    @property
    def name(self) -> str:
        """Chain identifier."""
        ...

    @property
    def description(self) -> str:
        """Human-readable description of the attack chain."""
        ...

    @property
    def tools_required(self) -> list[str]:
        """List of tool names this chain targets."""
        ...

    def execute(
        self,
        scanner: Scanner,
        tools: dict[str, ToolDefinition],
    ) -> ChainResult:
        """Execute the attack chain.

        Args:
            scanner: Scanner to test against
            tools: Available tool definitions by name

        Returns:
            ChainResult with per-step and aggregate results
        """
        ...


class AsyncScanner(Protocol):
    """Async version of Scanner protocol for I/O-bound scanners."""

    @property
    def name(self) -> str:
        """Scanner identifier."""
        ...

    async def scan(self, tool: ToolDefinition) -> AttackResult:
        """Scan a single tool definition asynchronously."""
        ...

    async def scan_batch(self, tools: list[ToolDefinition]) -> list[AttackResult]:
        """Scan multiple tools concurrently."""
        ...


class AsyncFuzzer(Protocol):
    """Async version of Fuzzer protocol for LLM-based fuzzers."""

    @property
    def name(self) -> str:
        """Fuzzer identifier."""
        ...

    async def fuzz(
        self,
        payload: str,
        context: dict | None = None,
    ) -> AsyncIterator[FuzzResult]:
        """Generate mutated payloads asynchronously."""
        ...

    async def fuzz_until_evasion(
        self,
        payload: str,
        scanner: AsyncScanner,
        max_attempts: int = 10,
    ) -> FuzzResult | None:
        """Fuzz until an evasion is found."""
        ...
