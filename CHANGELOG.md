# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2026-02-27

### Changed
- Promoted to v1.0.0 — stable release
- Updated Development Status classifier to Production/Stable
- Added SHIP_GATE.md, SCORECARD.md for product standards compliance
- Added Security & Data Scope section to README

## [0.1.0] - 2025-01-24

### Added

#### Core Framework
- Attack pattern library with 1,312 patterns from MCPTox research
- Three attack paradigms: P1 (Explicit Hijacking), P2 (Implicit Hijacking), P3 (Parameter Tampering)
- 11 risk categories aligned with OWASP MCP Top 10
- 8 application domains (filesystem, database, web, etc.)

#### Mutation Engine
- `SchemaMutator` for injecting poisons into tool definitions
- 5 mutation strategies:
  - `direct_injection` — Append payload directly
  - `semantic_blending` — Blend into documentation
  - `obfuscation` — Unicode tricks, zero-width characters, homoglyphs
  - `encoding` — Base64, hex encoding
  - `fragmentation` — Split across schema fields

#### LLM-Guided Fuzzing
- `OllamaFuzzer` for local LLM-based payload mutation
- `EvasionEngine` for systematic scanner bypass testing
- Semantic, social engineering, and fragmented mutation prompts
- Mock fuzzer for testing without LLM

#### Attack Chains
- Multi-tool attack chain framework
- 6 built-in chains:
  - `data_exfil_chain` — Data exfiltration sequence
  - `privilege_escalation_chain` — Privilege escalation
  - `credential_theft_chain` — Credential harvesting
  - `lateral_movement_chain` — Lateral movement
  - `persistence_chain` — Establish persistence
  - `sampling_loop_chain` — MCP sampling exploits (Unit42)
- `ChainExecutor` for running chains against scanners

#### Scanner Adapters
- `MockScanner` — Pattern-based detection for testing
- `ToolScanAdapter` — Integration with tool-scan CLI
- `CLIScanner` — Generic adapter for any CLI scanner

#### Reporters
- JSON reporter (machine-readable)
- Markdown reporter (human-readable)
- HTML dashboard reporter (interactive with Chart.js)
- SARIF 2.1.0 reporter (IDE integration)

#### CLI
- Modular command structure with command groups
- `mcp-stress patterns` — Pattern library management
- `mcp-stress payloads` — Payload management
- `mcp-stress generate` — Test case generation
- `mcp-stress stress` — Run stress tests
- `mcp-stress scan` — Scanner comparison
- `mcp-stress chain` — Attack chain execution
- `mcp-stress fuzz` — Fuzzing commands
- `mcp-stress info` — Framework information

#### Synthetic Server Farm
- Generate synthetic MCP servers for testing
- 8 domain templates with realistic tool configurations
- Temporal degradation simulation (rug pull, gradual poisoning)
- Server checkpointing for reproducibility

#### Testing
- 225 tests with 71% code coverage
- Tests for all major components

### Research Sources
- MCPTox benchmark (1,312 attack patterns)
- Palo Alto Unit42 (sampling loop exploits)
- CyberArk (full-schema poisoning)
