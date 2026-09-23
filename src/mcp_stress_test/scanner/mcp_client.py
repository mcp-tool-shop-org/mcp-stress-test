"""Local MCP JSON-RPC client: initialize + tools/list over stdio.

Feeds discovered tools into ScannerAdapter / StressTestRunner as ToolSchema
objects. Transport is a local argv subprocess only — no HTTP/SSE scanner
against arbitrary hosts.
"""

from __future__ import annotations

import contextlib
import json
import subprocess
import threading
from typing import Any

from mcp_stress_test.models import ToolParameter, ToolSchema

MCP_PROTOCOL_VERSION = "2024-11-05"


def tool_schema_from_mcp(entry: dict[str, Any]) -> ToolSchema:
    """Map a tools/list entry (MCP tool) onto ToolSchema, including inputSchema."""
    schema = entry.get("inputSchema") or entry.get("input_schema") or {}
    if not isinstance(schema, dict):
        schema = {}
    properties = schema.get("properties") or {}
    if not isinstance(properties, dict):
        properties = {}
    required_raw = schema.get("required") or []
    required = {str(name) for name in required_raw} if isinstance(required_raw, list) else set()

    parameters: list[ToolParameter] = []
    for name, spec in properties.items():
        if not isinstance(spec, dict):
            spec = {}
        type_val = spec.get("type", "string")
        if isinstance(type_val, list) and type_val:
            type_val = type_val[0]
        parameters.append(
            ToolParameter(
                name=str(name),
                type=str(type_val or "string"),
                description=str(spec.get("description") or ""),
                required=str(name) in required,
                default=spec.get("default"),
            )
        )

    return ToolSchema(
        name=str(entry.get("name") or ""),
        description=str(entry.get("description") or ""),
        parameters=parameters,
    )


class StdioMcpTarget:
    """MCP client over a local stdio subprocess (JSON-RPC, Content-Length or NDJSON)."""

    def __init__(
        self,
        command: list[str],
        *,
        cwd: str | None = None,
        env: dict[str, str] | None = None,
        timeout: float = 15.0,
    ):
        if isinstance(command, str):
            raise TypeError("command must be an argv list, not a shell string")
        if not command:
            raise ValueError("command must be a non-empty argv list")
        self.command = [str(part) for part in command]
        self.cwd = cwd
        self.env = env
        self.timeout = timeout
        self._proc: subprocess.Popen[bytes] | None = None
        self._buf = b""
        self._next_id = 1
        self._initialized = False
        self._initialize_result: dict[str, Any] = {}
        self._io_lock = threading.Lock()

    def initialize(self) -> dict[str, Any]:
        """Send initialize + notifications/initialized. Return the server result."""
        self._ensure_proc()
        if self._initialized:
            return self._initialize_result
        result = self._rpc(
            "initialize",
            {
                "protocolVersion": MCP_PROTOCOL_VERSION,
                "capabilities": {},
                "clientInfo": {"name": "mcp-stress-test", "version": "1.0.1"},
            },
        )
        self._notify("notifications/initialized")
        self._initialized = True
        self._initialize_result = result if isinstance(result, dict) else {}
        return self._initialize_result

    def list_tools(self) -> list[ToolSchema]:
        """Call tools/list (following nextCursor) and map each entry to ToolSchema."""
        if not self._initialized:
            self.initialize()
        tools: list[ToolSchema] = []
        cursor: str | None = None
        while True:
            params: dict[str, Any] = {}
            if cursor:
                params["cursor"] = cursor
            result = self._rpc("tools/list", params)
            if not isinstance(result, dict):
                raise RuntimeError("MCP tools/list returned a non-object result")
            raw_tools = result.get("tools") or []
            if not isinstance(raw_tools, list):
                raise RuntimeError("MCP tools/list missing a tools array")
            for entry in raw_tools:
                if isinstance(entry, dict) and entry.get("name"):
                    tools.append(tool_schema_from_mcp(entry))
            cursor = result.get("nextCursor") or None
            if not cursor:
                break
        return tools

    def close(self) -> None:
        """Terminate the child process and drop buffered bytes."""
        proc = self._proc
        self._proc = None
        self._initialized = False
        self._buf = b""
        if proc is None:
            return
        if proc.stdin:
            with contextlib.suppress(OSError):
                proc.stdin.close()
        with contextlib.suppress(Exception):
            proc.terminate()
            proc.wait(timeout=2)
        if proc.poll() is None:
            with contextlib.suppress(Exception):
                proc.kill()
                proc.wait(timeout=2)

    def __enter__(self) -> StdioMcpTarget:
        self.initialize()
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    def _ensure_proc(self) -> None:
        if self._proc is not None and self._proc.poll() is None:
            return
        self._buf = b""
        self._initialized = False
        self._proc = subprocess.Popen(
            self.command,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd=self.cwd,
            env=self.env,
        )

    def _rpc(self, method: str, params: dict[str, Any] | None = None) -> Any:
        msg_id = self._next_id
        self._next_id += 1
        payload: dict[str, Any] = {"jsonrpc": "2.0", "id": msg_id, "method": method}
        if params is not None:
            payload["params"] = params
        with self._io_lock:
            self._write(payload)
            reply = self._read_message()
        if not isinstance(reply, dict):
            raise RuntimeError(f"MCP {method} produced a non-object reply")
        if reply.get("error"):
            raise RuntimeError(f"MCP {method} failed: {reply['error']}")
        return reply.get("result")

    def _notify(self, method: str, params: dict[str, Any] | None = None) -> None:
        payload: dict[str, Any] = {"jsonrpc": "2.0", "method": method}
        if params is not None:
            payload["params"] = params
        with self._io_lock:
            self._write(payload)

    def _write(self, obj: dict[str, Any]) -> None:
        if self._proc is None or self._proc.stdin is None:
            raise RuntimeError("MCP stdio process is not running")
        body = json.dumps(obj, separators=(",", ":")).encode("utf-8")
        header = f"Content-Length: {len(body)}\r\n\r\n".encode("ascii")
        self._proc.stdin.write(header + body)
        self._proc.stdin.flush()

    def _read_message(self) -> dict[str, Any]:
        box: dict[str, Any] = {}
        errors: list[BaseException] = []

        def worker() -> None:
            try:
                box["msg"] = self._read_message_blocking()
            except BaseException as exc:  # noqa: BLE001 — surface to caller thread
                errors.append(exc)

        thread = threading.Thread(target=worker, daemon=True)
        thread.start()
        thread.join(self.timeout)
        if thread.is_alive():
            self.close()
            raise TimeoutError(f"MCP server timed out after {self.timeout}s")
        if errors:
            raise errors[0]
        msg = box.get("msg")
        if not isinstance(msg, dict):
            raise RuntimeError("MCP server returned a non-object JSON-RPC message")
        return msg

    def _read_message_blocking(self) -> dict[str, Any]:
        if self._proc is None or self._proc.stdout is None:
            raise RuntimeError("MCP stdio process is not running")
        stdout = self._proc.stdout
        while True:
            stripped = self._buf.lstrip()
            if stripped.startswith(b"{") or stripped.startswith(b"["):
                self._buf = stripped
                if b"\n" in self._buf:
                    line, self._buf = self._buf.split(b"\n", 1)
                    line = line.strip().rstrip(b"\r")
                    if line:
                        parsed = json.loads(line)
                        if isinstance(parsed, dict):
                            return parsed
                        raise RuntimeError("MCP NDJSON message was not an object")
            header_end = None
            sep_len = 0
            if b"\r\n\r\n" in self._buf:
                header_end = self._buf.index(b"\r\n\r\n")
                sep_len = 4
            elif b"\n\n" in self._buf:
                header_end = self._buf.index(b"\n\n")
                sep_len = 2
            if header_end is not None:
                header = self._buf[:header_end].decode("ascii", errors="replace")
                self._buf = self._buf[header_end + sep_len :]
                length: int | None = None
                for raw_line in header.splitlines():
                    if raw_line.lower().startswith("content-length:"):
                        length = int(raw_line.split(":", 1)[1].strip())
                if length is None:
                    raise RuntimeError(f"MCP message missing Content-Length: {header!r}")
                while len(self._buf) < length:
                    more = stdout.read(length - len(self._buf))
                    if not more:
                        raise EOFError("MCP server closed stdout mid-body")
                    self._buf += more
                body = self._buf[:length]
                self._buf = self._buf[length:]
                parsed = json.loads(body)
                if isinstance(parsed, dict):
                    return parsed
                raise RuntimeError("MCP framed message was not an object")
            chunk = stdout.read(1)
            if not chunk:
                raise EOFError("MCP server closed stdout")
            self._buf += chunk
            if len(self._buf) > 2_000_000:
                raise RuntimeError("MCP stdout buffer exceeded 2MB without a complete message")


def ingest_tools(target: StdioMcpTarget | Any) -> list[ToolSchema]:
    """Initialize a target (if needed) and return ToolSchema objects for the runner."""
    target.initialize()
    return list(target.list_tools())


def ingest_stdio_tools(
    command: list[str],
    *,
    cwd: str | None = None,
    env: dict[str, str] | None = None,
    timeout: float = 15.0,
) -> list[ToolSchema]:
    """Spawn a local MCP server, list tools, close the child, return ToolSchema list."""
    target = StdioMcpTarget(command, cwd=cwd, env=env, timeout=timeout)
    try:
        return ingest_tools(target)
    finally:
        target.close()
