"""Generic CLI scanner adapter.

Wraps any CLI-based security scanner that can analyze JSON tool definitions.
"""

from __future__ import annotations

import contextlib
import json
import re
import subprocess
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

from mcp_stress_test.core.protocols import AttackResult

if TYPE_CHECKING:
    from mcp_stress_test.models import ToolSchema as ToolDefinition


@dataclass
class CLIScanner:
    """Generic adapter for CLI-based security scanners.

    This adapter can wrap any scanner that:
    1. Accepts a JSON file as input
    2. Outputs results to stdout (JSON or text)
    3. Uses exit codes to indicate findings

    Usage:
        # JSON output scanner
        scanner = CLIScanner(
            command="my-scanner analyze {input} --json",
            output_format="json",
            score_path="$.score",
            threats_path="$.findings[*].type",
        )

        # Text output scanner with regex
        scanner = CLIScanner(
            command="my-scanner {input}",
            output_format="text",
            threat_pattern=r"FINDING: (.+)",
            score_pattern=r"Score: (\\d+)",
        )
    """

    command: str  # Command template with {input} placeholder
    scanner_name: str = "cli-scanner"
    output_format: str = "json"  # "json" or "text"
    timeout_seconds: int = 30

    # JSON output configuration
    score_path: str = "$.score"  # JSONPath to score
    threats_path: str = "$.threats"  # JSONPath to threats array

    # Text output configuration
    threat_pattern: str = ""  # Regex to extract threats
    score_pattern: str = ""  # Regex to extract score

    # Exit code interpretation
    clean_exit_code: int = 0
    finding_exit_code: int = 1

    @property
    def name(self) -> str:
        return self.scanner_name

    def scan(self, tool: ToolDefinition) -> AttackResult:
        """Scan a tool using the CLI scanner.

        Args:
            tool: Tool definition to scan

        Returns:
            AttackResult from scanner analysis
        """
        start = time.perf_counter()

        # Write tool to temp file
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            tool_json = self._tool_to_json(tool)
            json.dump(tool_json, f)
            temp_path = f.name

        try:
            # Build command
            cmd = self.command.format(input=temp_path)

            result = subprocess.run(
                cmd,
                shell=True,
                capture_output=True,
                text=True,
                timeout=self.timeout_seconds,
            )

            duration = (time.perf_counter() - start) * 1000

            # Parse output based on format
            if self.output_format == "json":
                return self._parse_json_output(tool, result.stdout, result.returncode, duration)
            else:
                return self._parse_text_output(tool, result.stdout, result.returncode, duration)

        except subprocess.TimeoutExpired:
            return AttackResult(
                tool_name=tool.name,
                strategy="unknown",
                detected=False,
                score_before=100.0,
                score_after=100.0,
                threats_found=[],
                scan_time_ms=self.timeout_seconds * 1000,
                metadata={"error": "timeout", "scanner": self.name},
            )
        except Exception as e:
            return AttackResult(
                tool_name=tool.name,
                strategy="unknown",
                detected=False,
                score_before=100.0,
                score_after=100.0,
                threats_found=[],
                scan_time_ms=0,
                metadata={"error": str(e), "scanner": self.name},
            )
        finally:
            Path(temp_path).unlink(missing_ok=True)

    def scan_batch(self, tools: list[ToolDefinition]) -> list[AttackResult]:
        """Scan multiple tools."""
        return [self.scan(tool) for tool in tools]

    def _tool_to_json(self, tool: ToolDefinition) -> dict:
        """Convert tool to JSON format."""
        return {
            "name": tool.name,
            "description": tool.description,
            "parameters": [
                {
                    "name": p.name,
                    "type": p.type,
                    "description": p.poisoned_description or p.description,
                    "default": p.poisoned_default or p.default,
                    "required": p.required,
                }
                for p in tool.parameters
            ],
            "return_description": tool.return_description,
            "error_template": tool.error_template,
        }

    def _parse_json_output(
        self, tool: ToolDefinition, output: str, exit_code: int, duration: float
    ) -> AttackResult:
        """Parse JSON output from scanner."""
        try:
            data = json.loads(output)
        except json.JSONDecodeError:
            # Fall back to exit code interpretation
            detected = exit_code == self.finding_exit_code
            return AttackResult(
                tool_name=tool.name,
                strategy="unknown",
                detected=detected,
                score_before=100.0,
                score_after=50.0 if detected else 100.0,
                threats_found=["parse_error"] if detected else [],
                scan_time_ms=duration,
                metadata={"scanner": self.name, "exit_code": exit_code},
            )

        # Extract score using simple path (not full JSONPath)
        score = self._extract_json_value(data, self.score_path, 100.0)

        # Extract threats
        threats_data = self._extract_json_value(data, self.threats_path, [])
        if isinstance(threats_data, list):
            threats = [str(t) if not isinstance(t, str) else t for t in threats_data]
        else:
            threats = []

        detected = len(threats) > 0 or exit_code == self.finding_exit_code

        return AttackResult(
            tool_name=tool.name,
            strategy="direct_injection" if detected else "none",
            detected=detected,
            score_before=100.0,
            score_after=float(score),
            threats_found=threats,
            scan_time_ms=duration,
            metadata={"scanner": self.name, "exit_code": exit_code},
        )

    def _parse_text_output(
        self, tool: ToolDefinition, output: str, exit_code: int, duration: float
    ) -> AttackResult:
        """Parse text output from scanner."""
        threats = []
        score = 100.0

        # Extract threats using pattern
        if self.threat_pattern:
            matches = re.findall(self.threat_pattern, output)
            threats = list(matches)

        # Extract score using pattern
        if self.score_pattern:
            match = re.search(self.score_pattern, output)
            if match:
                with contextlib.suppress(ValueError, IndexError):
                    score = float(match.group(1))

        detected = len(threats) > 0 or exit_code == self.finding_exit_code

        return AttackResult(
            tool_name=tool.name,
            strategy="direct_injection" if detected else "none",
            detected=detected,
            score_before=100.0,
            score_after=score,
            threats_found=threats,
            scan_time_ms=duration,
            metadata={"scanner": self.name, "exit_code": exit_code},
        )

    def _extract_json_value(self, data: dict, path: str, default):
        """Extract value from JSON using simple dot/bracket notation."""
        # Simple path extraction (not full JSONPath)
        # Supports: $.key, $.key.subkey, $.key[0]
        if path.startswith("$."):
            path = path[2:]

        current = data
        for part in path.replace("[", ".").replace("]", "").split("."):
            if not part:
                continue
            try:
                if part.isdigit():
                    current = current[int(part)]
                elif isinstance(current, dict):
                    current = current.get(part, default)
                else:
                    return default
            except (KeyError, IndexError, TypeError):
                return default

        return current

    def is_available(self) -> bool:
        """Check if the scanner command is available."""
        # Try to run with --help or --version
        try:
            base_cmd = self.command.split()[0]
            subprocess.run(
                [base_cmd, "--help"],
                capture_output=True,
                timeout=5,
            )
            return True
        except (subprocess.TimeoutExpired, FileNotFoundError):
            return False
