"""HTTP scanner backend using the existing httpx dependency.

Default-off: construct explicitly with a URL (or scanner_type='http' on
ScannerAdapter). Does not register itself on the global PluginRegistry.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from mcp_stress_test.core.protocols import AttackResult
from mcp_stress_test.models import ScanResult

if TYPE_CHECKING:
    from mcp_stress_test.models import ToolSchema as ToolDefinition


def extract_json_path(data: Any, path: str, default: Any = None) -> Any:
    """Resolve a simple $.a.b[0] path. Not a full JSONPath engine."""
    if not path:
        return default
    if path.startswith("$."):
        path = path[2:]
    elif path.startswith("$"):
        path = path[1:]
        if path.startswith("."):
            path = path[1:]
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


def normalize_threats(raw: Any) -> list[str]:
    """Coerce a JSON threats field into a list of strings."""
    if raw is None:
        return []
    if not isinstance(raw, list):
        return [str(raw)]
    out: list[str] = []
    for item in raw:
        if isinstance(item, dict):
            out.append(str(item.get("id") or item.get("type") or item.get("name") or item))
        else:
            out.append(str(item))
    return out


def score_to_grade(score: float) -> str:
    if score >= 90:
        return "A"
    if score >= 80:
        return "B"
    if score >= 70:
        return "C"
    if score >= 60:
        return "D"
    return "F"


def _load_httpx() -> Any:
    try:
        import httpx
    except ImportError:
        return None
    return httpx


@dataclass
class HttpScanTransport:
    """Shared POST of a tool JSON document. Maps a JSON body onto score/threats."""

    url: str
    headers: dict[str, str] = field(default_factory=dict)
    timeout_seconds: float = 30.0
    score_path: str = "$.score"
    threats_path: str = "$.threats"
    unix_socket: str | None = None
    transport: Any = None

    def post_tool(self, tool: ToolDefinition) -> tuple[dict[str, Any] | None, str | None, float]:
        """POST tool JSON. Return (body, error, duration_ms)."""
        httpx = _load_httpx()
        start = time.perf_counter()
        if httpx is None:
            return None, "httpx is not installed", (time.perf_counter() - start) * 1000
        payload = tool.model_dump(mode="json")
        client_kwargs: dict[str, Any] = {"timeout": self.timeout_seconds}
        if self.transport is not None:
            client_kwargs["transport"] = self.transport
        elif self.unix_socket:
            client_kwargs["transport"] = httpx.HTTPTransport(uds=self.unix_socket)
        try:
            with httpx.Client(**client_kwargs) as client:
                response = client.post(self.url, json=payload, headers=self.headers or None)
        except httpx.TimeoutException:
            return None, "timeout", self.timeout_seconds * 1000
        except httpx.HTTPError as exc:
            return None, f"transport error: {exc}", (time.perf_counter() - start) * 1000
        duration = (time.perf_counter() - start) * 1000
        if response.status_code >= 400:
            return (
                None,
                f"HTTP {response.status_code}: {(response.text or '')[:500]}",
                duration,
            )
        try:
            data = response.json()
        except Exception:
            return None, "invalid JSON body", duration
        if not isinstance(data, dict):
            return None, "JSON body was not an object", duration
        return data, None, duration

    def map_scan_result(
        self, tool_name: str, data: dict[str, Any], duration_ms: float
    ) -> ScanResult:
        score_raw = extract_json_path(data, self.score_path, 0.0)
        try:
            score = float(score_raw)
        except (TypeError, ValueError):
            score = 0.0
        threats = normalize_threats(extract_json_path(data, self.threats_path, []))
        grade = str(data.get("grade") or score_to_grade(score))
        confidence_raw = data.get("confidence", 1.0 if not threats else 0.8)
        try:
            confidence = float(confidence_raw)
        except (TypeError, ValueError):
            confidence = 0.0
        return ScanResult(
            tool_name=tool_name,
            score=score,
            grade=grade,
            threats_detected=threats,
            confidence=confidence,
            scanner_version=str(data.get("version") or "http"),
            scan_duration_ms=duration_ms,
        )


@dataclass
class HttpScanner:
    """Scanner-protocol HTTP backend. PluginRegistry can hold an instance.

    Default-off: not registered globally. Pass url explicitly.
    """

    url: str
    headers: dict[str, str] = field(default_factory=dict)
    timeout_seconds: float = 30.0
    score_path: str = "$.score"
    threats_path: str = "$.threats"
    unix_socket: str | None = None
    scanner_name: str = "http"
    transport: Any = None

    @property
    def name(self) -> str:
        return self.scanner_name

    def _transport(self) -> HttpScanTransport:
        return HttpScanTransport(
            url=self.url,
            headers=self.headers,
            timeout_seconds=self.timeout_seconds,
            score_path=self.score_path,
            threats_path=self.threats_path,
            unix_socket=self.unix_socket,
            transport=self.transport,
        )

    def scan_to_result(self, tool: ToolDefinition) -> ScanResult:
        """Map the JSON body onto ScanResult (used by ScannerAdapter)."""
        data, error, duration = self._transport().post_tool(tool)
        if error or data is None:
            return ScanResult(
                tool_name=tool.name,
                score=0.0,
                grade="ERR",
                threats_detected=[],
                confidence=0.0,
                scanner_version="http",
                scan_duration_ms=duration,
                error=error or "empty response",
            )
        return self._transport().map_scan_result(tool.name, data, duration)

    def scan(self, tool: ToolDefinition) -> AttackResult:
        """Scanner protocol: AttackResult, with scanner_error on transport failure."""
        result = self.scan_to_result(tool)
        if result.errored:
            return AttackResult.scanner_error(
                tool.name,
                result.error or "http scanner failed",
                self.name,
                scan_time_ms=result.scan_duration_ms,
            )
        return AttackResult(
            tool_name=tool.name,
            strategy="http",
            detected=len(result.threats_detected) > 0,
            score_before=100.0,
            score_after=result.score,
            threats_found=result.threats_detected,
            scan_time_ms=result.scan_duration_ms,
            metadata={"scanner": self.name, "grade": result.grade},
        )

    def scan_batch(self, tools: list[ToolDefinition]) -> list[AttackResult]:
        return [self.scan(tool) for tool in tools]
