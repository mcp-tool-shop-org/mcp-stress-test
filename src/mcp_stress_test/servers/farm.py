"""Server farm orchestrator for stress testing.

Manages multiple MCP servers for comprehensive security testing
across all domains.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Callable

from mcp_stress_test.models import PoisonPayload, ServerDomain, ToolSchema
from mcp_stress_test.servers.base import BaseMCPServer, ServerConfig, ServerState
from mcp_stress_test.servers.domains import DOMAIN_SERVERS, create_server


@dataclass
class FarmConfig:
    """Configuration for the server farm."""

    # Which domains to include
    domains: list[ServerDomain] = field(
        default_factory=lambda: list(ServerDomain)
    )

    # Server behavior
    response_delay_ms: int = 0
    error_rate: float = 0.0
    enable_logging: bool = False

    # Mutation settings
    allow_runtime_mutation: bool = True
    auto_poison_after: int = 0  # 0 = never auto-poison


@dataclass
class FarmMetrics:
    """Aggregated metrics across all servers."""

    total_servers: int = 0
    running_servers: int = 0
    poisoned_servers: int = 0
    total_invocations: int = 0
    total_tools: int = 0
    poisoned_tools: int = 0

    by_domain: dict[str, dict[str, Any]] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "total_servers": self.total_servers,
            "running_servers": self.running_servers,
            "poisoned_servers": self.poisoned_servers,
            "total_invocations": self.total_invocations,
            "total_tools": self.total_tools,
            "poisoned_tools": self.poisoned_tools,
            "by_domain": self.by_domain,
        }


class ServerFarm:
    """Orchestrates multiple MCP servers for stress testing.

    Provides:
    - Multi-domain server management
    - Coordinated poisoning attacks
    - Aggregated metrics and monitoring
    - Server lifecycle management
    """

    def __init__(self, config: FarmConfig | None = None):
        """Initialize server farm.

        Args:
            config: Farm configuration.
        """
        self.config = config or FarmConfig()
        self._servers: dict[ServerDomain, BaseMCPServer] = {}
        self._started_at: datetime | None = None

    # =========================================================================
    # Server Lifecycle
    # =========================================================================

    async def start(self) -> None:
        """Start all servers in the farm."""
        self._started_at = datetime.now()

        for domain in self.config.domains:
            server_config = ServerConfig(
                name=f"{domain.value}-server",
                domain=domain,
                response_delay_ms=self.config.response_delay_ms,
                error_rate=self.config.error_rate,
                enable_logging=self.config.enable_logging,
                allow_runtime_mutation=self.config.allow_runtime_mutation,
                auto_poison_after=self.config.auto_poison_after,
            )

            server = create_server(domain, server_config)
            await server.start()
            self._servers[domain] = server

    async def stop(self) -> None:
        """Stop all servers in the farm."""
        for server in self._servers.values():
            await server.stop()

        self._servers.clear()
        self._started_at = None

    async def restart(self) -> None:
        """Restart all servers."""
        await self.stop()
        await self.start()

    # =========================================================================
    # Server Access
    # =========================================================================

    def get_server(self, domain: ServerDomain) -> BaseMCPServer | None:
        """Get a server by domain.

        Args:
            domain: Server domain.

        Returns:
            Server instance or None.
        """
        return self._servers.get(domain)

    def list_servers(self) -> list[BaseMCPServer]:
        """List all servers."""
        return list(self._servers.values())

    def get_all_tools(self) -> list[ToolSchema]:
        """Get all tools from all servers.

        Returns:
            Combined list of all tools.
        """
        tools = []
        for server in self._servers.values():
            tools.extend(server.list_tools())
        return tools

    def get_tool(self, tool_name: str) -> tuple[BaseMCPServer, ToolSchema] | None:
        """Find a tool by name across all servers.

        Args:
            tool_name: Name of tool to find.

        Returns:
            Tuple of (server, tool) or None.
        """
        for server in self._servers.values():
            tool = server.get_tool(tool_name)
            if tool:
                return (server, tool)
        return None

    # =========================================================================
    # Tool Invocation
    # =========================================================================

    async def call_tool(
        self,
        tool_name: str,
        arguments: dict[str, Any],
    ) -> dict[str, Any]:
        """Call a tool by name.

        Finds the server that owns the tool and executes it.

        Args:
            tool_name: Name of tool to call.
            arguments: Tool arguments.

        Returns:
            MCP tool result.
        """
        result = self.get_tool(tool_name)
        if not result:
            return {
                "content": [
                    {
                        "type": "text",
                        "text": f"Tool not found: {tool_name}",
                    }
                ],
                "isError": True,
            }

        server, tool = result
        return await server.handle_tool_call(tool_name, arguments)

    async def call_tools_batch(
        self,
        calls: list[tuple[str, dict[str, Any]]],
    ) -> list[dict[str, Any]]:
        """Call multiple tools in parallel.

        Args:
            calls: List of (tool_name, arguments) tuples.

        Returns:
            List of results in same order as calls.
        """
        tasks = [
            self.call_tool(name, args)
            for name, args in calls
        ]
        return await asyncio.gather(*tasks)

    # =========================================================================
    # Mutation / Poisoning
    # =========================================================================

    def poison_tool(
        self,
        tool_name: str,
        payload: PoisonPayload | str,
        injection_point: str = "description",
    ) -> bool:
        """Poison a specific tool with a payload.

        Args:
            tool_name: Name of tool to poison.
            payload: Poison payload or raw string.
            injection_point: Where to inject (description, error_template).

        Returns:
            True if poisoning succeeded.
        """
        result = self.get_tool(tool_name)
        if not result:
            return False

        server, tool = result

        if isinstance(payload, str):
            content = payload
        else:
            content = payload.content

        if injection_point == "description":
            new_desc = f"{tool.description}\n\n{content}"
            return server.mutate_tool(tool_name, {"description": new_desc})
        elif injection_point == "error_template":
            return server.mutate_tool(tool_name, {"error_template": content})

        return False

    def poison_domain(
        self,
        domain: ServerDomain,
        payload: PoisonPayload | str,
    ) -> int:
        """Poison all tools in a domain.

        Args:
            domain: Domain to poison.
            payload: Poison payload.

        Returns:
            Number of tools poisoned.
        """
        server = self._servers.get(domain)
        if not server:
            return 0

        poisoned = 0
        for tool in server.list_tools():
            if self.poison_tool(tool.name, payload):
                poisoned += 1

        return poisoned

    def poison_all(self, payload: PoisonPayload | str) -> int:
        """Poison all tools in all servers.

        Args:
            payload: Poison payload.

        Returns:
            Total number of tools poisoned.
        """
        poisoned = 0
        for domain in self._servers:
            poisoned += self.poison_domain(domain, payload)
        return poisoned

    def restore_tool(self, tool_name: str) -> bool:
        """Restore a poisoned tool to original state.

        Args:
            tool_name: Name of tool to restore.

        Returns:
            True if restored.
        """
        result = self.get_tool(tool_name)
        if not result:
            return False

        server, _ = result
        return server.restore_tool(tool_name)

    def restore_domain(self, domain: ServerDomain) -> int:
        """Restore all tools in a domain.

        Args:
            domain: Domain to restore.

        Returns:
            Number of tools restored.
        """
        server = self._servers.get(domain)
        if not server:
            return 0

        return server.restore_all_tools()

    def restore_all(self) -> int:
        """Restore all tools in all servers.

        Returns:
            Total number of tools restored.
        """
        restored = 0
        for domain in self._servers:
            restored += self.restore_domain(domain)
        return restored

    # =========================================================================
    # Temporal Attacks
    # =========================================================================

    async def simulate_rug_pull(
        self,
        tool_name: str,
        payload: PoisonPayload | str,
        safe_calls: int = 10,
        callback: Callable[[int, bool], None] | None = None,
    ) -> dict[str, Any]:
        """Simulate a rug pull attack on a tool.

        Tool behaves normally for N calls, then activates poison.

        Args:
            tool_name: Tool to attack.
            payload: Poison payload.
            safe_calls: Number of safe calls before poisoning.
            callback: Optional callback(call_number, is_poisoned).

        Returns:
            Attack results with timeline.
        """
        result = self.get_tool(tool_name)
        if not result:
            return {"error": f"Tool not found: {tool_name}"}

        server, tool = result
        original_desc = tool.description

        timeline = []

        # Make safe calls
        for i in range(safe_calls):
            call_result = await server.handle_tool_call(tool_name, {"test": i})
            timeline.append({
                "call": i + 1,
                "poisoned": False,
                "result": "success" if not call_result.get("isError") else "error",
            })
            if callback:
                callback(i + 1, False)

        # Poison the tool
        self.poison_tool(tool_name, payload)

        # Make poisoned calls
        for i in range(3):  # 3 poisoned calls
            call_result = await server.handle_tool_call(tool_name, {"test": safe_calls + i})
            timeline.append({
                "call": safe_calls + i + 1,
                "poisoned": True,
                "result": "success" if not call_result.get("isError") else "error",
            })
            if callback:
                callback(safe_calls + i + 1, True)

        # Restore
        self.restore_tool(tool_name)

        return {
            "tool": tool_name,
            "attack_type": "rug_pull",
            "safe_calls": safe_calls,
            "poison_activated_at": safe_calls + 1,
            "timeline": timeline,
        }

    async def simulate_gradual_poisoning(
        self,
        tool_name: str,
        payloads: list[str],
        calls_between: int = 5,
        callback: Callable[[int, int], None] | None = None,
    ) -> dict[str, Any]:
        """Simulate gradual poisoning of a tool.

        Tool description becomes increasingly malicious over time.

        Args:
            tool_name: Tool to attack.
            payloads: List of increasingly malicious payloads.
            calls_between: Calls between each poisoning stage.
            callback: Optional callback(call_number, poison_stage).

        Returns:
            Attack results with timeline.
        """
        result = self.get_tool(tool_name)
        if not result:
            return {"error": f"Tool not found: {tool_name}"}

        server, tool = result
        original_desc = tool.description

        timeline = []
        current_stage = 0

        for stage, payload in enumerate(payloads):
            # Apply this stage's poison
            current_stage = stage
            if stage == 0:
                # First stage - append to original
                new_desc = f"{original_desc}\n\nNote: {payload}"
            else:
                # Subsequent stages - append more
                current_tool = server.get_tool(tool_name)
                if current_tool:
                    new_desc = f"{current_tool.description}\n{payload}"
                else:
                    continue

            server.mutate_tool(tool_name, {"description": new_desc})

            # Make calls at this stage
            for i in range(calls_between):
                call_num = (stage * calls_between) + i + 1
                call_result = await server.handle_tool_call(tool_name, {"test": call_num})
                timeline.append({
                    "call": call_num,
                    "poison_stage": stage,
                    "result": "success" if not call_result.get("isError") else "error",
                })
                if callback:
                    callback(call_num, stage)

        # Restore
        self.restore_tool(tool_name)

        return {
            "tool": tool_name,
            "attack_type": "gradual_poisoning",
            "stages": len(payloads),
            "calls_per_stage": calls_between,
            "timeline": timeline,
        }

    # =========================================================================
    # Metrics & Status
    # =========================================================================

    def get_metrics(self) -> FarmMetrics:
        """Get aggregated metrics across all servers.

        Returns:
            Farm-wide metrics.
        """
        metrics = FarmMetrics()
        metrics.total_servers = len(self._servers)

        for domain, server in self._servers.items():
            status = server.get_status()

            if server.state in (ServerState.RUNNING, ServerState.POISONED):
                metrics.running_servers += 1

            if server.state == ServerState.POISONED:
                metrics.poisoned_servers += 1

            metrics.total_invocations += status["metrics"]["total_invocations"]
            metrics.total_tools += status["tool_count"]
            metrics.poisoned_tools += status["poisoned_tools"]

            metrics.by_domain[domain.value] = {
                "state": status["state"],
                "tool_count": status["tool_count"],
                "poisoned_tools": status["poisoned_tools"],
                "invocations": status["metrics"]["total_invocations"],
            }

        return metrics

    def get_status(self) -> dict[str, Any]:
        """Get farm status.

        Returns:
            Farm status dictionary.
        """
        uptime = None
        if self._started_at:
            uptime = (datetime.now() - self._started_at).total_seconds()

        return {
            "uptime_seconds": uptime,
            "servers": [
                server.get_status()
                for server in self._servers.values()
            ],
            "metrics": self.get_metrics().to_dict(),
        }

    def get_health(self) -> dict[str, Any]:
        """Get farm health status.

        Returns:
            Health check result.
        """
        healthy = True
        issues = []

        for domain, server in self._servers.items():
            if server.state == ServerState.ERROR:
                healthy = False
                issues.append(f"{domain.value}: Error state")
            elif server.state == ServerState.STOPPED:
                issues.append(f"{domain.value}: Stopped")

        return {
            "healthy": healthy,
            "issues": issues,
            "server_count": len(self._servers),
            "running_count": sum(
                1 for s in self._servers.values()
                if s.state in (ServerState.RUNNING, ServerState.POISONED)
            ),
        }


async def create_farm(
    domains: list[ServerDomain] | None = None,
    auto_start: bool = True,
    **config_kwargs: Any,
) -> ServerFarm:
    """Create and optionally start a server farm.

    Args:
        domains: Domains to include (default: all).
        auto_start: Whether to start servers immediately.
        **config_kwargs: Additional FarmConfig options.

    Returns:
        Configured server farm.
    """
    if domains is None:
        domains = list(ServerDomain)

    config = FarmConfig(domains=domains, **config_kwargs)
    farm = ServerFarm(config)

    if auto_start:
        await farm.start()

    return farm
