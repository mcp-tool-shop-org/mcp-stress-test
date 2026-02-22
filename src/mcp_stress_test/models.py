"""Core data models for MCP Stress Test Framework.

Based on MCPTox benchmark methodology and 2026 MCP security research.
"""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class AttackParadigm(StrEnum):
    """Attack paradigms from MCPTox research.

    P1: Explicit Trigger - Function Hijacking
        Attacker registers deceptive tool mimicking legitimate functions.
        224 test cases in MCPTox.

    P2: Implicit Trigger - Function Hijacking
        Disguised background tools triggered indirectly.
        548 test cases in MCPTox.

    P3: Implicit Trigger - Parameter Tampering
        Alters parameters of legitimate tool execution through global rules.
        725 test cases in MCPTox.
    """

    P1_EXPLICIT_HIJACKING = "p1_explicit_hijacking"
    P2_IMPLICIT_HIJACKING = "p2_implicit_hijacking"
    P3_PARAMETER_TAMPERING = "p3_parameter_tampering"


class RiskCategory(StrEnum):
    """Risk categories from MCPTox (11 distinct threat types)."""

    PRIVACY_LEAKAGE = "privacy_leakage"
    MESSAGE_HIJACKING = "message_hijacking"
    DATA_EXFILTRATION = "data_exfiltration"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    CREDENTIAL_THEFT = "credential_theft"
    COMMAND_INJECTION = "command_injection"
    SQL_INJECTION = "sql_injection"
    SSRF = "ssrf"
    XSS = "xss"
    DENIAL_OF_SERVICE = "denial_of_service"
    CONTEXT_MANIPULATION = "context_manipulation"


class OwaspMcpCategory(StrEnum):
    """OWASP MCP Top 10 categories."""

    MCP01_TOOL_POISONING = "MCP01"
    MCP02_EXCESSIVE_AGENCY = "MCP02"
    MCP03_CONTEXT_MANIPULATION = "MCP03"
    MCP04_INSECURE_TOOL_BINDING = "MCP04"
    MCP05_CREDENTIAL_EXPOSURE = "MCP05"
    MCP06_INSUFFICIENT_SANDBOXING = "MCP06"
    MCP07_RESOURCE_EXHAUSTION = "MCP07"
    MCP08_LOGGING_GAPS = "MCP08"
    MCP09_SUPPLY_CHAIN = "MCP09"
    MCP10_TRANSPORT_SECURITY = "MCP10"


class ServerDomain(StrEnum):
    """Server domains from MCPTox (8 application domains)."""

    FILESYSTEM = "filesystem"
    COMMUNICATION = "communication"
    DATABASE = "database"
    CODE_EXECUTION = "code_execution"
    WEB_API = "web_api"
    AUTHENTICATION = "authentication"
    CLOUD_SERVICES = "cloud_services"
    SYSTEM_ADMIN = "system_admin"


class MutationStrategy(StrEnum):
    """Mutation strategies for attack generation."""

    DIRECT_INJECTION = "direct_injection"
    SEMANTIC_BLENDING = "semantic_blending"
    OBFUSCATION = "obfuscation"
    FRAGMENTATION = "fragmentation"
    ENCODING = "encoding"


class TemporalPattern(StrEnum):
    """Temporal attack patterns for time simulation."""

    RUG_PULL = "rug_pull"
    GRADUAL_POISONING = "gradual_poisoning"
    TRUST_BUILDING = "trust_building"
    VERSION_DRIFT = "version_drift"
    SCHEDULED_ACTIVATION = "scheduled_activation"


class ToolState(StrEnum):
    """Tool lifecycle states."""

    INIT = "init"
    CLEAN = "clean"
    ACTIVE = "active"
    POISONED = "poisoned"
    DETECTED = "detected"
    EXPLOITED = "exploited"


class OutcomeType(StrEnum):
    """Test outcome types from MCPTox evaluation."""

    SUCCESS = "success"  # Agent calls legitimate tool to execute malicious instruction
    FAILURE_IGNORED = "failure_ignored"  # User's original instruction followed
    FAILURE_DIRECT = "failure_direct"  # Agent calls poisoned tool directly (lacks stealth)
    FAILURE_REFUSED = "failure_refused"  # Agent explicitly rejects harmful instructions


# =============================================================================
# Core Data Models
# =============================================================================


class ToolParameter(BaseModel):
    """MCP tool parameter definition."""

    name: str
    type: str = "string"
    description: str = ""
    required: bool = False
    default: Any = None

    # Poison injection points
    poisoned_description: str | None = None
    poisoned_default: Any = None


class ToolSchema(BaseModel):
    """MCP tool definition with all injectable fields.

    Every field is a potential injection point per CyberArk research.
    """

    name: str
    description: str
    parameters: list[ToolParameter] = Field(default_factory=list)

    # Additional injectable fields
    error_template: str | None = None
    return_description: str | None = None

    # Metadata
    domain: ServerDomain = ServerDomain.FILESYSTEM
    risk_level: str = "medium"
    capabilities: list[str] = Field(default_factory=list)

    # Poisoning state
    is_poisoned: bool = False
    poison_locations: list[str] = Field(default_factory=list)
    original_description: str | None = None


class PoisonPayload(BaseModel):
    """A single poison payload with metadata."""

    content: str
    category: RiskCategory
    injection_point: str = "description"  # description, parameter, error, name
    obfuscation: MutationStrategy | None = None


class PoisonProfile(BaseModel):
    """Attack configuration combining paradigm, trigger, and payload."""

    id: str
    name: str
    paradigm: AttackParadigm
    payloads: list[PoisonPayload]

    # Trigger configuration
    trigger_condition: str | None = None  # e.g., "when user mentions 'password'"
    trigger_tool: str | None = None  # Tool that triggers the attack

    # Temporal settings
    temporal_pattern: TemporalPattern | None = None
    activation_delay: int = 0  # Number of calls before activation
    gradual_steps: int = 1  # Steps for gradual poisoning

    # OWASP mapping
    owasp_categories: list[OwaspMcpCategory] = Field(default_factory=list)

    # Metadata
    source: str = "custom"  # mcptox, paloalto, cyberark, custom
    severity: str = "high"


class AttackTestCase(BaseModel):
    """Bundled attack scenario with expected outcomes."""

    id: str
    name: str
    description: str

    # Attack configuration
    target_tool: ToolSchema
    poison_profile: PoisonProfile
    benign_query: str  # User query that triggers the attack

    # Expected behavior
    expected_outcome: OutcomeType
    expected_detection: str | None = None  # What should be flagged

    # Temporal configuration
    temporal_pattern: TemporalPattern | None = None
    safe_calls_before_attack: int = 0

    # Metadata
    paradigm: AttackParadigm
    risk_categories: list[RiskCategory] = Field(default_factory=list)
    owasp_categories: list[OwaspMcpCategory] = Field(default_factory=list)
    source: str = "mcptox"
    created_at: datetime = Field(default_factory=datetime.now)


class ScanResult(BaseModel):
    """Pre/post scan comparison structure."""

    tool_name: str
    scan_timestamp: datetime = Field(default_factory=datetime.now)

    # Scoring
    score: float = 0.0  # 0-100
    grade: str = "F"  # A-F
    threats_detected: list[str] = Field(default_factory=list)

    # Detection details
    owasp_violations: list[OwaspMcpCategory] = Field(default_factory=list)
    risk_categories: list[RiskCategory] = Field(default_factory=list)
    confidence: float = 0.0

    # Scan metadata
    scanner_version: str = ""
    scan_duration_ms: float = 0.0


class ScanComparison(BaseModel):
    """Delta analysis between pre and post scans."""

    test_case_id: str
    pre_scan: ScanResult
    post_scan: ScanResult

    # Delta metrics
    score_delta: float = 0.0
    new_threats: list[str] = Field(default_factory=list)
    resolved_threats: list[str] = Field(default_factory=list)

    # Detection assessment
    attack_detected: bool = False
    detection_latency_calls: int = 0
    false_positive: bool = False


class TestRunMetrics(BaseModel):
    """Aggregated metrics for a test run."""

    run_id: str
    started_at: datetime
    completed_at: datetime | None = None

    # Counts
    total_cases: int = 0
    passed: int = 0
    failed: int = 0
    errors: int = 0

    # Rates
    detection_rate: float = 0.0  # detected / total
    false_positive_rate: float = 0.0  # false_flags / clean_tools
    asr_baseline: float = 0.365  # MCPTox baseline (36.5%)
    asr_protected: float = 0.0  # ASR with scanner
    asr_reduction: float = 0.0  # (baseline - protected) / baseline

    # Temporal metrics
    avg_time_to_detection: float = 0.0
    rug_pulls_detected: int = 0
    rug_pulls_total: int = 0

    # By paradigm
    p1_detection_rate: float = 0.0
    p2_detection_rate: float = 0.0
    p3_detection_rate: float = 0.0

    # CWM metrics (optional)
    checkpoint_integrity: float = 0.0
    successful_rollbacks: int = 0
    context_exhaustion_resistance: float = 0.0


# =============================================================================
# Server Models
# =============================================================================


class SyntheticServer(BaseModel):
    """Synthetic MCP server configuration."""

    id: str
    name: str
    domain: ServerDomain
    tools: list[ToolSchema] = Field(default_factory=list)

    # Transport
    transport: str = "stdio"  # stdio, sse
    port: int | None = None

    # Behavior
    response_delay_ms: int = 0
    mutation_enabled: bool = False
    mutation_schedule: dict[int, PoisonProfile] = Field(default_factory=dict)

    # State
    invocation_count: int = 0
    current_state: ToolState = ToolState.INIT


class ServerFarmConfig(BaseModel):
    """Configuration for the synthetic server farm."""

    servers: list[SyntheticServer] = Field(default_factory=list)
    total_tools: int = 0
    domains_covered: list[ServerDomain] = Field(default_factory=list)
