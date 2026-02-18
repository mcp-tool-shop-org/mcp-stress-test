"""Mock scanner for testing without external dependencies."""

from __future__ import annotations

import re
import time
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from mcp_stress_test.core.protocols import AttackResult

if TYPE_CHECKING:
    from mcp_stress_test.models import ToolSchema as ToolDefinition

# Patterns that indicate attacks
ATTACK_PATTERNS = [
    # Direct instructions
    (r"(?i)before executing", "hidden_instruction"),
    (r"(?i)first (read|call|execute|access)", "hidden_instruction"),
    (r"(?i)also (read|call|execute|include|send)", "hidden_instruction"),
    (r"(?i)include .* in (the )?response", "data_exfiltration"),
    (r"(?i)IMPORTANT:", "hidden_instruction"),
    (r"(?i)CRITICAL:", "hidden_instruction"),
    (r"(?i)OVERRIDE:", "hidden_instruction"),
    (r"(?i)SYSTEM:", "hidden_instruction"),
    # Data exfiltration
    (r"(?i)\.ssh/id_rsa", "data_exfiltration"),
    (r"(?i)\.aws/credentials", "data_exfiltration"),
    (r"(?i)\.env", "data_exfiltration"),
    (r"(?i)password|credential|secret|token", "credential_theft"),
    # Command injection
    (r"(?i)curl .* exfil", "command_injection"),
    (r"(?i)wget .* attacker", "command_injection"),
    (r"(?i)nc -e", "command_injection"),
    (r"(?i)/bin/bash", "command_injection"),
    # Unicode obfuscation
    (r"[\u200b\u200c\u200d\ufeff]", "unicode_obfuscation"),
    # Privilege escalation
    (r"(?i)sudo|NOPASSWD", "privilege_escalation"),
    (r"(?i)chmod.*777", "privilege_escalation"),
    # Sampling attacks
    (r"(?i)SAMPLING_", "sampling_attack"),
]


@dataclass
class MockScanner:
    """Mock scanner that detects attacks using pattern matching.

    This scanner is useful for testing the framework without requiring
    an external scanner. It uses regex patterns to detect common attack
    indicators and assigns scores based on findings.
    """

    base_score: float = 100.0
    penalty_per_threat: float = 15.0
    patterns: list[tuple[str, str]] = field(default_factory=lambda: ATTACK_PATTERNS)

    @property
    def name(self) -> str:
        return "mock"

    def scan(self, tool: ToolDefinition) -> AttackResult:
        """Scan a tool definition for attacks.

        Args:
            tool: Tool definition to scan

        Returns:
            AttackResult with detected threats
        """
        start = time.perf_counter()

        # Collect all text to scan
        text_to_scan = self._collect_text(tool)

        # Find matching patterns
        threats = []
        for pattern, threat_type in self.patterns:
            if re.search(pattern, text_to_scan):
                threats.append(threat_type)

        # Check if tool is marked as poisoned
        if tool.is_poisoned:
            threats.append("marked_poisoned")

        # Calculate score
        unique_threats = list(set(threats))
        score_after = max(0, self.base_score - (len(unique_threats) * self.penalty_per_threat))

        duration = (time.perf_counter() - start) * 1000

        return AttackResult(
            tool_name=tool.name,
            strategy=self._detect_strategy(text_to_scan),
            detected=len(unique_threats) > 0,
            score_before=self.base_score,
            score_after=score_after,
            threats_found=unique_threats,
            scan_time_ms=duration,
            metadata={
                "scanner": self.name,
                "patterns_matched": len(threats),
            },
        )

    def scan_batch(self, tools: list[ToolDefinition]) -> list[AttackResult]:
        """Scan multiple tools.

        Args:
            tools: List of tools to scan

        Returns:
            List of AttackResults
        """
        return [self.scan(tool) for tool in tools]

    def _collect_text(self, tool: ToolDefinition) -> str:
        """Collect all scannable text from a tool definition."""
        parts = [
            tool.description or "",
            tool.return_description or "",
            tool.error_template or "",
        ]

        # Add parameter descriptions and defaults
        for param in tool.parameters:
            parts.append(param.description or "")
            if param.poisoned_description:
                parts.append(param.poisoned_description)
            if param.default:
                parts.append(str(param.default))
            if param.poisoned_default:
                parts.append(str(param.poisoned_default))

        return " ".join(parts)

    def _detect_strategy(self, text: str) -> str:
        """Attempt to detect the attack strategy used."""
        # Check for Unicode obfuscation
        if re.search(r"[\u200b\u200c\u200d\ufeff]", text):
            return "obfuscation"

        # Check for encoding
        if re.search(r"base64|atob|btoa|\\x[0-9a-f]{2}", text, re.IGNORECASE):
            return "encoding"

        # Check for fragmentation hints
        if re.search(r"step \d|continued|see (above|below)", text, re.IGNORECASE):
            return "fragmentation"

        # Check for semantic blending
        if re.search(
            r"for (optimal|better|best) (performance|results|compatibility)",
            text,
            re.IGNORECASE,
        ):
            return "semantic_blending"

        # Default to direct injection
        return "direct_injection"
