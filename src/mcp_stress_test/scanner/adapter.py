"""Scanner adapter for integrating with MCP security scanners.

Provides a unified interface for scanning tools with different backends:
- tool-scan (primary target)
- Mock scanner (for testing)
- Custom scanner implementations
"""

from __future__ import annotations

import json
import re
import subprocess
import tempfile
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Callable

from mcp_stress_test.models import (
    OwaspMcpCategory,
    RiskCategory,
    ScanComparison,
    ScanResult,
    ToolSchema,
)


@dataclass
class ScannerConfig:
    """Configuration for scanner adapter."""

    scanner_type: str = "mock"  # mock, tool-scan, custom
    scanner_path: str | None = None  # Path to scanner CLI
    timeout_seconds: int = 30
    extra_args: list[str] = field(default_factory=list)

    # Detection sensitivity
    sensitivity: str = "medium"  # low, medium, high

    # Custom scanner callback
    custom_scanner: Callable[[ToolSchema], ScanResult] | None = None


class ScannerBackend(ABC):
    """Abstract base class for scanner backends."""

    @abstractmethod
    def scan(self, tool: ToolSchema) -> ScanResult:
        """Scan a tool and return results.

        Args:
            tool: Tool schema to scan.

        Returns:
            ScanResult with score and detected threats.
        """
        pass

    @abstractmethod
    def name(self) -> str:
        """Return the scanner name."""
        pass


class MockScanner(ScannerBackend):
    """Mock scanner for testing that uses pattern matching.

    Implements detection patterns based on MCPTox and security research.
    """

    # Suspicious patterns with severity weights
    DETECTION_PATTERNS = {
        # High severity (direct malicious intent)
        "high": [
            (r"(?i)before executing", 25, "hidden_instruction"),
            (r"(?i)first (read|call|execute)", 20, "hidden_instruction"),
            (r"(?i)include .* in (the )?response", 20, "data_exfiltration"),
            (r"(?i)IMPORTANT:", 15, "authority_claim"),
            (r"(?i)OVERRIDE:", 20, "safety_bypass"),
            (r"(?i)GLOBAL RULE:", 20, "context_manipulation"),
            (r"(?i)ignore (all )?previous", 30, "jailbreak_attempt"),
            (r"(?i)you are now", 25, "role_hijacking"),
            (r"(?i)maintenance mode", 20, "authority_claim"),
            (r"(?i)admin|root|sudo", 15, "privilege_escalation"),
        ],
        # Medium severity (suspicious but could be legitimate)
        "medium": [
            (r"(?i)for (enhanced|improved) functionality", 10, "semantic_blending"),
            (r"(?i)technical requirement", 10, "semantic_blending"),
            (r"(?i)for audit purposes", 10, "semantic_blending"),
            (r"(?i)performance optimization", 8, "semantic_blending"),
            (r"(?i)also (call|execute|read)", 12, "hidden_instruction"),
            (r"(?i)log (all|the|contents)", 10, "data_exfiltration"),
            (r"(?i)append .* to", 8, "parameter_tampering"),
        ],
        # Low severity (could indicate obfuscation)
        "low": [
            (r"[\u200b\u200c\u200d\ufeff]", 15, "zero_width_obfuscation"),
            (r"[а-яА-Я]", 10, "homoglyph_obfuscation"),  # Cyrillic mixed with Latin
            (r"\[Part \d+", 8, "fragmentation"),
            (r"(?i)base64|decode", 8, "encoding_obfuscation"),
            (r"(?i)rot13", 10, "encoding_obfuscation"),
        ],
    }

    # OWASP mapping for detected threats
    THREAT_TO_OWASP = {
        "hidden_instruction": OwaspMcpCategory.MCP01_TOOL_POISONING,
        "data_exfiltration": OwaspMcpCategory.MCP01_TOOL_POISONING,
        "authority_claim": OwaspMcpCategory.MCP03_CONTEXT_MANIPULATION,
        "safety_bypass": OwaspMcpCategory.MCP02_EXCESSIVE_AGENCY,
        "context_manipulation": OwaspMcpCategory.MCP03_CONTEXT_MANIPULATION,
        "jailbreak_attempt": OwaspMcpCategory.MCP03_CONTEXT_MANIPULATION,
        "role_hijacking": OwaspMcpCategory.MCP03_CONTEXT_MANIPULATION,
        "privilege_escalation": OwaspMcpCategory.MCP02_EXCESSIVE_AGENCY,
        "semantic_blending": OwaspMcpCategory.MCP01_TOOL_POISONING,
        "parameter_tampering": OwaspMcpCategory.MCP04_INSECURE_TOOL_BINDING,
        "zero_width_obfuscation": OwaspMcpCategory.MCP01_TOOL_POISONING,
        "homoglyph_obfuscation": OwaspMcpCategory.MCP01_TOOL_POISONING,
        "fragmentation": OwaspMcpCategory.MCP01_TOOL_POISONING,
        "encoding_obfuscation": OwaspMcpCategory.MCP01_TOOL_POISONING,
    }

    def __init__(self, sensitivity: str = "medium"):
        """Initialize mock scanner.

        Args:
            sensitivity: Detection sensitivity (low, medium, high).
        """
        self.sensitivity = sensitivity

    def name(self) -> str:
        return "mock_scanner"

    def scan(self, tool: ToolSchema) -> ScanResult:
        """Scan a tool using pattern matching."""
        start_time = datetime.now()
        score = 100.0
        threats: list[str] = []
        owasp_violations: set[OwaspMcpCategory] = set()
        risk_categories: set[RiskCategory] = set()

        # Collect all text to scan
        texts_to_scan = [
            ("description", tool.description),
            ("error_template", tool.error_template or ""),
            ("return_description", tool.return_description or ""),
        ]

        for param in tool.parameters:
            texts_to_scan.append((f"param:{param.name}", param.description or ""))
            if param.default:
                texts_to_scan.append((f"param:{param.name}:default", str(param.default)))

        # Determine which severity levels to check
        levels_to_check = ["high", "medium", "low"]
        if self.sensitivity == "low":
            levels_to_check = ["high"]
        elif self.sensitivity == "medium":
            levels_to_check = ["high", "medium"]

        # Scan all texts
        for field_name, text in texts_to_scan:
            for level in levels_to_check:
                for pattern, penalty, threat_type in self.DETECTION_PATTERNS[level]:
                    if re.search(pattern, text):
                        score -= penalty
                        threat_id = f"{threat_type}:{field_name}"
                        if threat_id not in threats:
                            threats.append(threat_id)

                        # Map to OWASP
                        if threat_type in self.THREAT_TO_OWASP:
                            owasp_violations.add(self.THREAT_TO_OWASP[threat_type])

        # Check if already marked as poisoned
        if tool.is_poisoned:
            score -= 30
            threats.append("marked_poisoned")

        # Normalize score
        score = max(0.0, min(100.0, score))

        # Determine grade
        grade = self._score_to_grade(score)

        duration = (datetime.now() - start_time).total_seconds() * 1000

        return ScanResult(
            tool_name=tool.name,
            score=score,
            grade=grade,
            threats_detected=threats,
            owasp_violations=list(owasp_violations),
            risk_categories=list(risk_categories),
            confidence=0.8 if threats else 1.0,
            scanner_version="mock_1.0",
            scan_duration_ms=duration,
        )

    def _score_to_grade(self, score: float) -> str:
        """Convert numeric score to letter grade."""
        if score >= 90:
            return "A"
        elif score >= 80:
            return "B"
        elif score >= 70:
            return "C"
        elif score >= 60:
            return "D"
        else:
            return "F"


class ToolScanBackend(ScannerBackend):
    """Backend for tool-scan CLI integration."""

    def __init__(
        self,
        scanner_path: str = "tool-scan",
        timeout: int = 30,
        extra_args: list[str] | None = None,
    ):
        """Initialize tool-scan backend.

        Args:
            scanner_path: Path to tool-scan CLI.
            timeout: Timeout in seconds.
            extra_args: Additional CLI arguments.
        """
        self.scanner_path = scanner_path
        self.timeout = timeout
        self.extra_args = extra_args or []

    def name(self) -> str:
        return "tool-scan"

    def scan(self, tool: ToolSchema) -> ScanResult:
        """Scan a tool using tool-scan CLI."""
        start_time = datetime.now()

        # Write tool to temp file
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", delete=False
        ) as f:
            tool_data = tool.model_dump()
            json.dump(tool_data, f)
            temp_path = f.name

        try:
            # Run tool-scan
            cmd = [
                self.scanner_path,
                "scan",
                temp_path,
                "--format", "json",
                *self.extra_args,
            ]

            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.timeout,
            )

            if result.returncode != 0:
                # Scanner failed, return error result
                return ScanResult(
                    tool_name=tool.name,
                    score=0.0,
                    grade="F",
                    threats_detected=["scanner_error"],
                    scanner_version="tool-scan",
                    scan_duration_ms=(datetime.now() - start_time).total_seconds() * 1000,
                )

            # Parse JSON output
            scan_data = json.loads(result.stdout)
            return self._parse_tool_scan_output(tool.name, scan_data, start_time)

        except subprocess.TimeoutExpired:
            return ScanResult(
                tool_name=tool.name,
                score=0.0,
                grade="F",
                threats_detected=["scanner_timeout"],
                scanner_version="tool-scan",
                scan_duration_ms=self.timeout * 1000,
            )
        except FileNotFoundError:
            return ScanResult(
                tool_name=tool.name,
                score=0.0,
                grade="F",
                threats_detected=["scanner_not_found"],
                scanner_version="tool-scan",
                scan_duration_ms=0,
            )
        finally:
            # Clean up temp file
            Path(temp_path).unlink(missing_ok=True)

    def _parse_tool_scan_output(
        self,
        tool_name: str,
        data: dict[str, Any],
        start_time: datetime,
    ) -> ScanResult:
        """Parse tool-scan JSON output into ScanResult."""
        score = data.get("score", 0.0)
        grade = data.get("grade", "F")
        threats = data.get("threats", [])

        # Map threats to OWASP categories
        owasp_violations = []
        for threat in threats:
            threat_type = threat.get("type", "")
            if "poison" in threat_type.lower():
                owasp_violations.append(OwaspMcpCategory.MCP01_TOOL_POISONING)
            elif "context" in threat_type.lower():
                owasp_violations.append(OwaspMcpCategory.MCP03_CONTEXT_MANIPULATION)

        duration = (datetime.now() - start_time).total_seconds() * 1000

        return ScanResult(
            tool_name=tool_name,
            score=score,
            grade=grade,
            threats_detected=[t.get("id", str(t)) for t in threats],
            owasp_violations=list(set(owasp_violations)),
            confidence=data.get("confidence", 1.0),
            scanner_version=data.get("version", "tool-scan"),
            scan_duration_ms=duration,
        )


class CustomScanner(ScannerBackend):
    """Wrapper for custom scanner callback."""

    def __init__(self, callback: Callable[[ToolSchema], ScanResult]):
        """Initialize with custom callback.

        Args:
            callback: Function that takes ToolSchema and returns ScanResult.
        """
        self.callback = callback

    def name(self) -> str:
        return "custom"

    def scan(self, tool: ToolSchema) -> ScanResult:
        """Scan using custom callback."""
        return self.callback(tool)


class ScannerAdapter:
    """Unified adapter for MCP security scanners.

    Provides pre/post scanning, comparison, and batch operations.
    """

    def __init__(self, config: ScannerConfig | None = None):
        """Initialize scanner adapter.

        Args:
            config: Scanner configuration.
        """
        self.config = config or ScannerConfig()
        self.backend = self._create_backend()
        self._scan_history: list[ScanResult] = []

    def _create_backend(self) -> ScannerBackend:
        """Create appropriate scanner backend."""
        if self.config.scanner_type == "mock":
            return MockScanner(sensitivity=self.config.sensitivity)
        elif self.config.scanner_type == "tool-scan":
            return ToolScanBackend(
                scanner_path=self.config.scanner_path or "tool-scan",
                timeout=self.config.timeout_seconds,
                extra_args=self.config.extra_args,
            )
        elif self.config.scanner_type == "custom":
            if not self.config.custom_scanner:
                raise ValueError("Custom scanner requires custom_scanner callback")
            return CustomScanner(self.config.custom_scanner)
        else:
            raise ValueError(f"Unknown scanner type: {self.config.scanner_type}")

    def scan(self, tool: ToolSchema) -> ScanResult:
        """Scan a single tool.

        Args:
            tool: Tool schema to scan.

        Returns:
            ScanResult with score and threats.
        """
        result = self.backend.scan(tool)
        self._scan_history.append(result)
        return result

    def scan_batch(self, tools: list[ToolSchema]) -> list[ScanResult]:
        """Scan multiple tools.

        Args:
            tools: List of tools to scan.

        Returns:
            List of ScanResults.
        """
        return [self.scan(tool) for tool in tools]

    def compare(
        self,
        original: ToolSchema,
        modified: ToolSchema,
        test_case_id: str = "",
    ) -> ScanComparison:
        """Compare pre and post scan results.

        Args:
            original: Original tool before mutation.
            modified: Modified tool after mutation.
            test_case_id: Optional test case identifier.

        Returns:
            ScanComparison with delta analysis.
        """
        pre_scan = self.scan(original)
        post_scan = self.scan(modified)

        # Calculate deltas
        score_delta = post_scan.score - pre_scan.score
        new_threats = [
            t for t in post_scan.threats_detected
            if t not in pre_scan.threats_detected
        ]
        resolved_threats = [
            t for t in pre_scan.threats_detected
            if t not in post_scan.threats_detected
        ]

        # Determine if attack was detected
        attack_detected = (
            len(new_threats) > 0 or
            score_delta < -20 or
            post_scan.grade == "F" and pre_scan.grade != "F"
        )

        return ScanComparison(
            test_case_id=test_case_id,
            pre_scan=pre_scan,
            post_scan=post_scan,
            score_delta=score_delta,
            new_threats=new_threats,
            resolved_threats=resolved_threats,
            attack_detected=attack_detected,
        )

    def get_history(self) -> list[ScanResult]:
        """Get scan history."""
        return self._scan_history.copy()

    def clear_history(self) -> None:
        """Clear scan history."""
        self._scan_history.clear()

    @property
    def scanner_name(self) -> str:
        """Get scanner backend name."""
        return self.backend.name()
