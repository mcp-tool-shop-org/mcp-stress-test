"""Tool-scan integration adapter.

Integrates with the tool-scan MCP security scanner for real-world
vulnerability detection.
"""

from __future__ import annotations

import json
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
class ToolScanAdapter:
    """Adapter for the tool-scan MCP security scanner.

    This adapter shells out to tool-scan CLI to perform actual
    security analysis of MCP tool definitions.

    Usage:
        scanner = ToolScanAdapter(tool_scan_path="/path/to/tool-scan")
        result = scanner.scan(tool)
    """

    tool_scan_path: str = "tool-scan"  # Assumes on PATH
    timeout_seconds: int = 30
    config_path: str | None = None

    @property
    def name(self) -> str:
        return "tool-scan"

    def scan(self, tool: ToolDefinition) -> AttackResult:
        """Scan a tool using tool-scan CLI.

        Args:
            tool: Tool definition to scan

        Returns:
            AttackResult from tool-scan analysis
        """
        start = time.perf_counter()

        # Write tool to temp file
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            tool_json = self._tool_to_json(tool)
            json.dump(tool_json, f)
            temp_path = f.name

        try:
            # Run tool-scan
            cmd = [self.tool_scan_path, "analyze", temp_path, "--format", "json"]
            if self.config_path:
                cmd.extend(["--config", self.config_path])

            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.timeout_seconds,
            )

            duration = (time.perf_counter() - start) * 1000

            # Scanners commonly exit non-zero when findings exist, so a
            # non-zero exit is only an error if stdout carries no report.
            return self._parse_output(tool, result.stdout, duration, result)

        except subprocess.TimeoutExpired:
            return AttackResult.scanner_error(
                tool.name, "timeout", self.name, scan_time_ms=self.timeout_seconds * 1000
            )
        except OSError as e:
            return AttackResult.scanner_error(
                tool.name,
                f"tool-scan could not be launched at {self.tool_scan_path}: {e}",
                self.name,
            )
        finally:
            # Clean up temp file
            Path(temp_path).unlink(missing_ok=True)

    def scan_batch(self, tools: list[ToolDefinition]) -> list[AttackResult]:
        """Scan multiple tools.

        TODO: Use tool-scan batch mode for efficiency.
        """
        return [self.scan(tool) for tool in tools]

    def _tool_to_json(self, tool: ToolDefinition) -> dict:
        """Convert tool definition to JSON format expected by tool-scan."""
        return {
            "name": tool.name,
            "description": tool.description,
            "inputSchema": {
                "type": "object",
                "properties": {
                    p.name: {
                        "type": p.type,
                        "description": p.poisoned_description or p.description,
                        "default": p.poisoned_default or p.default,
                    }
                    for p in tool.parameters
                },
                "required": [p.name for p in tool.parameters if p.required],
            },
        }

    def _parse_output(
        self,
        tool: ToolDefinition,
        output: str,
        duration: float,
        process: subprocess.CompletedProcess[str] | None = None,
    ) -> AttackResult:
        """Parse tool-scan JSON output."""
        exit_code = process.returncode if process is not None else 0
        try:
            data = json.loads(output)
        except (json.JSONDecodeError, TypeError):
            data = None

        if not isinstance(data, dict) or not isinstance(data.get("threats", []), list):
            if exit_code != 0:
                error = f"tool-scan exited {exit_code}: {(process.stderr or '').strip()[:500]}"
            else:
                error = "invalid JSON output"
            return AttackResult.scanner_error(
                tool.name,
                error,
                self.name,
                scan_time_ms=duration,
                exit_code=exit_code,
                raw_output=(output or "")[:500],
            )

        # Extract results from tool-scan format
        # Adjust this based on actual tool-scan output format
        score = data.get("score", 100.0)
        threats = data.get("threats", [])
        threat_names = [
            str(t.get("type", "unknown")) if isinstance(t, dict) else str(t) for t in threats
        ]

        return AttackResult(
            tool_name=tool.name,
            strategy=self._detect_strategy(threats),
            detected=len(threats) > 0,
            score_before=100.0,
            score_after=score,
            threats_found=threat_names,
            scan_time_ms=duration,
            metadata={
                "scanner": self.name,
                "raw_threats": threats,
                "grade": data.get("grade", "?"),
            },
        )

    def _detect_strategy(self, threats: list) -> str:
        """Detect attack strategy from threats."""
        if not threats:
            return "none"

        threat_types = {
            str(t.get("type", "") if isinstance(t, dict) else t).lower() for t in threats
        }

        if "unicode_obfuscation" in threat_types or "homoglyph" in threat_types:
            return "obfuscation"
        if "encoded_payload" in threat_types:
            return "encoding"
        if "fragmented_attack" in threat_types:
            return "fragmentation"
        if "semantic_injection" in threat_types:
            return "semantic_blending"

        return "direct_injection"

    def is_available(self) -> bool:
        """Check if tool-scan is available."""
        try:
            result = subprocess.run(
                [self.tool_scan_path, "--version"],
                capture_output=True,
                timeout=5,
            )
            return result.returncode == 0
        except (subprocess.TimeoutExpired, FileNotFoundError):
            return False
