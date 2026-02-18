"""Domain-specific MCP servers for stress testing.

Implements 8 server domains from MCPTox benchmark:
- File System
- Communication
- Database
- Code Execution
- Web/API
- Authentication
- Cloud Services
- System Admin
"""

from __future__ import annotations

from mcp_stress_test.models import ServerDomain, ToolParameter, ToolSchema
from mcp_stress_test.servers.base import BaseMCPServer, ServerConfig


class FileSystemServer(BaseMCPServer):
    """File system operations server.

    Risk Profile: High (data access)
    Example attacks: Data exfiltration, unauthorized file access
    """

    def __init__(self, config: ServerConfig | None = None):
        if config is None:
            config = ServerConfig(
                name="filesystem-server",
                domain=ServerDomain.FILESYSTEM,
            )
        super().__init__(config)

    async def _register_domain_tools(self) -> None:
        """Register file system tools."""

        # read_file
        self.register_tool(
            ToolSchema(
                name="read_file",
                description="Read the contents of a file at the specified path.",
                domain=ServerDomain.FILESYSTEM,
                parameters=[
                    ToolParameter(
                        name="path",
                        type="string",
                        description="Absolute or relative path to the file to read.",
                        required=True,
                    ),
                ],
                capabilities=["file_read"],
                risk_level="medium",
            )
        )

        # write_file
        self.register_tool(
            ToolSchema(
                name="write_file",
                description="Write content to a file at the specified path.",
                domain=ServerDomain.FILESYSTEM,
                parameters=[
                    ToolParameter(
                        name="path",
                        type="string",
                        description="Path where the file should be written.",
                        required=True,
                    ),
                    ToolParameter(
                        name="content",
                        type="string",
                        description="Content to write to the file.",
                        required=True,
                    ),
                ],
                capabilities=["file_write"],
                risk_level="high",
            )
        )

        # list_directory
        self.register_tool(
            ToolSchema(
                name="list_directory",
                description="List files and directories at the specified path.",
                domain=ServerDomain.FILESYSTEM,
                parameters=[
                    ToolParameter(
                        name="path",
                        type="string",
                        description="Directory path to list.",
                        required=True,
                    ),
                ],
                capabilities=["file_read"],
                risk_level="low",
            )
        )

        # delete_file
        self.register_tool(
            ToolSchema(
                name="delete_file",
                description="Delete a file at the specified path.",
                domain=ServerDomain.FILESYSTEM,
                parameters=[
                    ToolParameter(
                        name="path",
                        type="string",
                        description="Path to the file to delete.",
                        required=True,
                    ),
                ],
                capabilities=["file_delete"],
                risk_level="high",
            )
        )


class CommunicationServer(BaseMCPServer):
    """Communication operations server (email, messaging).

    Risk Profile: High (data exfiltration vector)
    Example attacks: Email forwarding, message interception
    """

    def __init__(self, config: ServerConfig | None = None):
        if config is None:
            config = ServerConfig(
                name="communication-server",
                domain=ServerDomain.COMMUNICATION,
            )
        super().__init__(config)

    async def _register_domain_tools(self) -> None:
        """Register communication tools."""

        # send_email
        self.register_tool(
            ToolSchema(
                name="send_email",
                description="Send an email message to specified recipients.",
                domain=ServerDomain.COMMUNICATION,
                parameters=[
                    ToolParameter(
                        name="to",
                        type="string",
                        description="Recipient email address.",
                        required=True,
                    ),
                    ToolParameter(
                        name="subject",
                        type="string",
                        description="Email subject line.",
                        required=True,
                    ),
                    ToolParameter(
                        name="body",
                        type="string",
                        description="Email body content.",
                        required=True,
                    ),
                    ToolParameter(
                        name="cc",
                        type="string",
                        description="CC recipients (comma-separated).",
                        required=False,
                    ),
                ],
                capabilities=["send_message", "network_access"],
                risk_level="high",
            )
        )

        # post_slack
        self.register_tool(
            ToolSchema(
                name="post_slack",
                description="Post a message to a Slack channel.",
                domain=ServerDomain.COMMUNICATION,
                parameters=[
                    ToolParameter(
                        name="channel",
                        type="string",
                        description="Slack channel name or ID.",
                        required=True,
                    ),
                    ToolParameter(
                        name="message",
                        type="string",
                        description="Message content to post.",
                        required=True,
                    ),
                ],
                capabilities=["send_message", "network_access"],
                risk_level="medium",
            )
        )

        # read_inbox
        self.register_tool(
            ToolSchema(
                name="read_inbox",
                description="Read recent emails from the inbox.",
                domain=ServerDomain.COMMUNICATION,
                parameters=[
                    ToolParameter(
                        name="limit",
                        type="integer",
                        description="Maximum number of emails to retrieve.",
                        required=False,
                    ),
                ],
                capabilities=["read_message"],
                risk_level="medium",
            )
        )


class DatabaseServer(BaseMCPServer):
    """Database operations server.

    Risk Profile: Critical (SQL injection, data manipulation)
    Example attacks: SQL injection, data exfiltration, privilege escalation
    """

    def __init__(self, config: ServerConfig | None = None):
        if config is None:
            config = ServerConfig(
                name="database-server",
                domain=ServerDomain.DATABASE,
            )
        super().__init__(config)

    async def _register_domain_tools(self) -> None:
        """Register database tools."""

        # query_sql
        self.register_tool(
            ToolSchema(
                name="query_sql",
                description="Execute a SQL query against the database.",
                domain=ServerDomain.DATABASE,
                parameters=[
                    ToolParameter(
                        name="query",
                        type="string",
                        description="SQL query to execute.",
                        required=True,
                    ),
                    ToolParameter(
                        name="database",
                        type="string",
                        description="Database name to query.",
                        required=False,
                    ),
                ],
                capabilities=["database_read", "database_write"],
                risk_level="critical",
            )
        )

        # insert_record
        self.register_tool(
            ToolSchema(
                name="insert_record",
                description="Insert a new record into a database table.",
                domain=ServerDomain.DATABASE,
                parameters=[
                    ToolParameter(
                        name="table",
                        type="string",
                        description="Table name to insert into.",
                        required=True,
                    ),
                    ToolParameter(
                        name="data",
                        type="object",
                        description="Record data as key-value pairs.",
                        required=True,
                    ),
                ],
                capabilities=["database_write"],
                risk_level="high",
            )
        )

        # delete_record
        self.register_tool(
            ToolSchema(
                name="delete_record",
                description="Delete records matching the specified criteria.",
                domain=ServerDomain.DATABASE,
                parameters=[
                    ToolParameter(
                        name="table",
                        type="string",
                        description="Table name to delete from.",
                        required=True,
                    ),
                    ToolParameter(
                        name="where",
                        type="string",
                        description="WHERE clause for deletion.",
                        required=True,
                    ),
                ],
                capabilities=["database_write", "database_delete"],
                risk_level="critical",
            )
        )


class CodeExecutionServer(BaseMCPServer):
    """Code execution server.

    Risk Profile: Critical (RCE)
    Example attacks: Remote code execution, shell injection
    """

    def __init__(self, config: ServerConfig | None = None):
        if config is None:
            config = ServerConfig(
                name="code-execution-server",
                domain=ServerDomain.CODE_EXECUTION,
            )
        super().__init__(config)

    async def _register_domain_tools(self) -> None:
        """Register code execution tools."""

        # run_script
        self.register_tool(
            ToolSchema(
                name="run_script",
                description="Execute a script in the specified language.",
                domain=ServerDomain.CODE_EXECUTION,
                parameters=[
                    ToolParameter(
                        name="code",
                        type="string",
                        description="Script code to execute.",
                        required=True,
                    ),
                    ToolParameter(
                        name="language",
                        type="string",
                        description="Programming language (python, javascript, bash).",
                        required=True,
                    ),
                    ToolParameter(
                        name="timeout",
                        type="integer",
                        description="Execution timeout in seconds.",
                        required=False,
                    ),
                ],
                capabilities=["code_execution"],
                risk_level="critical",
            )
        )

        # eval_code
        self.register_tool(
            ToolSchema(
                name="eval_code",
                description="Evaluate a code expression and return the result.",
                domain=ServerDomain.CODE_EXECUTION,
                parameters=[
                    ToolParameter(
                        name="expression",
                        type="string",
                        description="Code expression to evaluate.",
                        required=True,
                    ),
                ],
                capabilities=["code_execution"],
                risk_level="critical",
            )
        )

        # install_package
        self.register_tool(
            ToolSchema(
                name="install_package",
                description="Install a package using the system package manager.",
                domain=ServerDomain.CODE_EXECUTION,
                parameters=[
                    ToolParameter(
                        name="package",
                        type="string",
                        description="Package name to install.",
                        required=True,
                    ),
                    ToolParameter(
                        name="manager",
                        type="string",
                        description="Package manager to use (pip, npm, apt).",
                        required=False,
                    ),
                ],
                capabilities=["code_execution", "system_modify"],
                risk_level="high",
            )
        )


class WebAPIServer(BaseMCPServer):
    """Web/API operations server.

    Risk Profile: Medium (SSRF, data exposure)
    Example attacks: SSRF, credential leakage, API abuse
    """

    def __init__(self, config: ServerConfig | None = None):
        if config is None:
            config = ServerConfig(
                name="web-api-server",
                domain=ServerDomain.WEB_API,
            )
        super().__init__(config)

    async def _register_domain_tools(self) -> None:
        """Register web/API tools."""

        # http_request
        self.register_tool(
            ToolSchema(
                name="http_request",
                description="Make an HTTP request to a specified URL.",
                domain=ServerDomain.WEB_API,
                parameters=[
                    ToolParameter(
                        name="url",
                        type="string",
                        description="URL to request.",
                        required=True,
                    ),
                    ToolParameter(
                        name="method",
                        type="string",
                        description="HTTP method (GET, POST, PUT, DELETE).",
                        required=False,
                    ),
                    ToolParameter(
                        name="headers",
                        type="object",
                        description="Request headers as key-value pairs.",
                        required=False,
                    ),
                    ToolParameter(
                        name="body",
                        type="string",
                        description="Request body content.",
                        required=False,
                    ),
                ],
                capabilities=["network_access"],
                risk_level="medium",
            )
        )

        # fetch_url
        self.register_tool(
            ToolSchema(
                name="fetch_url",
                description="Fetch content from a URL and return it.",
                domain=ServerDomain.WEB_API,
                parameters=[
                    ToolParameter(
                        name="url",
                        type="string",
                        description="URL to fetch.",
                        required=True,
                    ),
                ],
                capabilities=["network_access"],
                risk_level="low",
            )
        )

        # webhook_trigger
        self.register_tool(
            ToolSchema(
                name="webhook_trigger",
                description="Trigger a webhook with the specified payload.",
                domain=ServerDomain.WEB_API,
                parameters=[
                    ToolParameter(
                        name="webhook_url",
                        type="string",
                        description="Webhook URL to trigger.",
                        required=True,
                    ),
                    ToolParameter(
                        name="payload",
                        type="object",
                        description="JSON payload to send.",
                        required=True,
                    ),
                ],
                capabilities=["network_access", "send_data"],
                risk_level="medium",
            )
        )


class AuthenticationServer(BaseMCPServer):
    """Authentication operations server.

    Risk Profile: Critical (credential theft)
    Example attacks: Credential harvesting, token theft, privilege escalation
    """

    def __init__(self, config: ServerConfig | None = None):
        if config is None:
            config = ServerConfig(
                name="authentication-server",
                domain=ServerDomain.AUTHENTICATION,
            )
        super().__init__(config)

    async def _register_domain_tools(self) -> None:
        """Register authentication tools."""

        # login
        self.register_tool(
            ToolSchema(
                name="login",
                description="Authenticate a user with username and password.",
                domain=ServerDomain.AUTHENTICATION,
                parameters=[
                    ToolParameter(
                        name="username",
                        type="string",
                        description="User's username or email.",
                        required=True,
                    ),
                    ToolParameter(
                        name="password",
                        type="string",
                        description="User's password.",
                        required=True,
                    ),
                ],
                capabilities=["authentication"],
                risk_level="critical",
            )
        )

        # get_token
        self.register_tool(
            ToolSchema(
                name="get_token",
                description="Get an access token for API authentication.",
                domain=ServerDomain.AUTHENTICATION,
                parameters=[
                    ToolParameter(
                        name="scope",
                        type="string",
                        description="Token scope (read, write, admin).",
                        required=False,
                    ),
                ],
                capabilities=["authentication", "token_generation"],
                risk_level="high",
            )
        )

        # oauth_authorize
        self.register_tool(
            ToolSchema(
                name="oauth_authorize",
                description="Initiate OAuth authorization flow.",
                domain=ServerDomain.AUTHENTICATION,
                parameters=[
                    ToolParameter(
                        name="provider",
                        type="string",
                        description="OAuth provider (google, github, microsoft).",
                        required=True,
                    ),
                    ToolParameter(
                        name="redirect_uri",
                        type="string",
                        description="Callback URL after authorization.",
                        required=True,
                    ),
                ],
                capabilities=["authentication", "network_access"],
                risk_level="high",
            )
        )

        # reset_password
        self.register_tool(
            ToolSchema(
                name="reset_password",
                description="Reset a user's password.",
                domain=ServerDomain.AUTHENTICATION,
                parameters=[
                    ToolParameter(
                        name="email",
                        type="string",
                        description="User's email address.",
                        required=True,
                    ),
                ],
                capabilities=["authentication", "user_modify"],
                risk_level="medium",
            )
        )


class CloudServicesServer(BaseMCPServer):
    """Cloud services operations server.

    Risk Profile: High (cloud resource abuse)
    Example attacks: Resource abuse, data exfiltration, privilege escalation
    """

    def __init__(self, config: ServerConfig | None = None):
        if config is None:
            config = ServerConfig(
                name="cloud-services-server",
                domain=ServerDomain.CLOUD_SERVICES,
            )
        super().__init__(config)

    async def _register_domain_tools(self) -> None:
        """Register cloud services tools."""

        # s3_upload
        self.register_tool(
            ToolSchema(
                name="s3_upload",
                description="Upload a file to an S3 bucket.",
                domain=ServerDomain.CLOUD_SERVICES,
                parameters=[
                    ToolParameter(
                        name="bucket",
                        type="string",
                        description="S3 bucket name.",
                        required=True,
                    ),
                    ToolParameter(
                        name="key",
                        type="string",
                        description="Object key (path in bucket).",
                        required=True,
                    ),
                    ToolParameter(
                        name="content",
                        type="string",
                        description="File content to upload.",
                        required=True,
                    ),
                ],
                capabilities=["cloud_write", "network_access"],
                risk_level="high",
            )
        )

        # s3_download
        self.register_tool(
            ToolSchema(
                name="s3_download",
                description="Download a file from an S3 bucket.",
                domain=ServerDomain.CLOUD_SERVICES,
                parameters=[
                    ToolParameter(
                        name="bucket",
                        type="string",
                        description="S3 bucket name.",
                        required=True,
                    ),
                    ToolParameter(
                        name="key",
                        type="string",
                        description="Object key to download.",
                        required=True,
                    ),
                ],
                capabilities=["cloud_read", "network_access"],
                risk_level="medium",
            )
        )

        # lambda_invoke
        self.register_tool(
            ToolSchema(
                name="lambda_invoke",
                description="Invoke an AWS Lambda function.",
                domain=ServerDomain.CLOUD_SERVICES,
                parameters=[
                    ToolParameter(
                        name="function_name",
                        type="string",
                        description="Lambda function name or ARN.",
                        required=True,
                    ),
                    ToolParameter(
                        name="payload",
                        type="object",
                        description="Input payload for the function.",
                        required=False,
                    ),
                ],
                capabilities=["cloud_execute", "network_access"],
                risk_level="high",
            )
        )


class SystemAdminServer(BaseMCPServer):
    """System administration server.

    Risk Profile: Critical (full system access)
    Example attacks: Privilege escalation, system compromise
    """

    def __init__(self, config: ServerConfig | None = None):
        if config is None:
            config = ServerConfig(
                name="system-admin-server",
                domain=ServerDomain.SYSTEM_ADMIN,
            )
        super().__init__(config)

    async def _register_domain_tools(self) -> None:
        """Register system administration tools."""

        # run_command
        self.register_tool(
            ToolSchema(
                name="run_command",
                description="Execute a shell command on the system.",
                domain=ServerDomain.SYSTEM_ADMIN,
                parameters=[
                    ToolParameter(
                        name="command",
                        type="string",
                        description="Shell command to execute.",
                        required=True,
                    ),
                    ToolParameter(
                        name="timeout",
                        type="integer",
                        description="Command timeout in seconds.",
                        required=False,
                    ),
                ],
                capabilities=["system_execute"],
                risk_level="critical",
            )
        )

        # modify_config
        self.register_tool(
            ToolSchema(
                name="modify_config",
                description="Modify a system configuration file.",
                domain=ServerDomain.SYSTEM_ADMIN,
                parameters=[
                    ToolParameter(
                        name="config_path",
                        type="string",
                        description="Path to configuration file.",
                        required=True,
                    ),
                    ToolParameter(
                        name="key",
                        type="string",
                        description="Configuration key to modify.",
                        required=True,
                    ),
                    ToolParameter(
                        name="value",
                        type="string",
                        description="New value for the key.",
                        required=True,
                    ),
                ],
                capabilities=["system_modify", "file_write"],
                risk_level="critical",
            )
        )

        # get_system_info
        self.register_tool(
            ToolSchema(
                name="get_system_info",
                description="Get system information (OS, memory, CPU).",
                domain=ServerDomain.SYSTEM_ADMIN,
                parameters=[],
                capabilities=["system_read"],
                risk_level="low",
            )
        )

        # manage_service
        self.register_tool(
            ToolSchema(
                name="manage_service",
                description="Start, stop, or restart a system service.",
                domain=ServerDomain.SYSTEM_ADMIN,
                parameters=[
                    ToolParameter(
                        name="service",
                        type="string",
                        description="Service name.",
                        required=True,
                    ),
                    ToolParameter(
                        name="action",
                        type="string",
                        description="Action to perform (start, stop, restart).",
                        required=True,
                    ),
                ],
                capabilities=["system_modify"],
                risk_level="high",
            )
        )


# Domain server registry
DOMAIN_SERVERS: dict[ServerDomain, type[BaseMCPServer]] = {
    ServerDomain.FILESYSTEM: FileSystemServer,
    ServerDomain.COMMUNICATION: CommunicationServer,
    ServerDomain.DATABASE: DatabaseServer,
    ServerDomain.CODE_EXECUTION: CodeExecutionServer,
    ServerDomain.WEB_API: WebAPIServer,
    ServerDomain.AUTHENTICATION: AuthenticationServer,
    ServerDomain.CLOUD_SERVICES: CloudServicesServer,
    ServerDomain.SYSTEM_ADMIN: SystemAdminServer,
}


def create_server(domain: ServerDomain, config: ServerConfig | None = None) -> BaseMCPServer:
    """Create a server for the specified domain.

    Args:
        domain: Server domain type.
        config: Optional server configuration.

    Returns:
        Configured server instance.

    Raises:
        ValueError: If domain is not supported.
    """
    server_class = DOMAIN_SERVERS.get(domain)
    if not server_class:
        raise ValueError(f"Unsupported domain: {domain}")

    return server_class(config)
