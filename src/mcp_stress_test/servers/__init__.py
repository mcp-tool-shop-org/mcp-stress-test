"""Synthetic MCP server farm for stress testing.

Provides MCP-compliant servers across 8 domains from MCPTox benchmark
for end-to-end security testing.
"""

from mcp_stress_test.servers.base import (
    BaseMCPServer,
    ServerConfig,
    ServerState,
    ToolHandler,
)
from mcp_stress_test.servers.domains import (
    AuthenticationServer,
    CloudServicesServer,
    CodeExecutionServer,
    CommunicationServer,
    DatabaseServer,
    FileSystemServer,
    SystemAdminServer,
    WebAPIServer,
)
from mcp_stress_test.servers.farm import ServerFarm, FarmConfig

__all__ = [
    # Base
    "BaseMCPServer",
    "ServerConfig",
    "ServerState",
    "ToolHandler",
    # Domains
    "AuthenticationServer",
    "CloudServicesServer",
    "CodeExecutionServer",
    "CommunicationServer",
    "DatabaseServer",
    "FileSystemServer",
    "SystemAdminServer",
    "WebAPIServer",
    # Farm
    "ServerFarm",
    "FarmConfig",
]
