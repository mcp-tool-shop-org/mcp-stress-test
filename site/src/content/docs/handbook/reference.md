---
title: Reference
description: Full CLI reference, mutation strategies, architecture, and security model for MCP Stress Test.
---

## CLI reference

All commands are invoked via the `mcp-stress` binary.

### Pattern library

```bash
mcp-stress patterns list                # List all 1,312 patterns
mcp-stress patterns list --paradigm p1  # Filter by paradigm (p1, p2, p3)
mcp-stress patterns stats               # Show statistics breakdown
```

### Payload management

```bash
mcp-stress payloads list                    # List all poison payloads
mcp-stress payloads list --category data_exfil  # Filter by category
```

### Test generation

```bash
mcp-stress generate --paradigm p2 --count 100        # Generate test cases
mcp-stress generate --payload cross_tool --output tests.json
```

### Stress testing

```bash
mcp-stress stress run                                  # Full stress test (all phases)
mcp-stress stress run --phases baseline,mutation       # Specific phases
mcp-stress stress run --tools read_file,write_file     # Target specific tools
mcp-stress stress run --scanner tool-scan              # Use real scanner
mcp-stress stress run --format sarif -o results.sarif  # SARIF output
```

### Scanning

```bash
mcp-stress scan compare -t read_file -s obfuscation   # Compare detection rates
mcp-stress scan batch -t read_file,write_file -s direct_injection,obfuscation
mcp-stress scan scanners                               # List available scanners
```

### Attack chains

```bash
mcp-stress chain list                         # List built-in chains
mcp-stress chain execute -c data_exfil_chain  # Execute a specific chain
mcp-stress chain execute --all                # Execute all chains
```

Built-in chains:
- `data_exfil_chain` — Read then exfiltrate sensitive data
- `privilege_escalation_chain` — Gain elevated access
- `credential_theft_chain` — Harvest credentials
- `lateral_movement_chain` — Pivot across systems
- `persistence_chain` — Establish persistent access
- `sampling_loop_chain` — MCP sampling exploits (Unit42 research)

### Fuzzing

```bash
mcp-stress fuzz mutate -p "payload"                     # Deterministic mutations
mcp-stress fuzz evasion -p "payload" --use-llm          # LLM-guided evasion
mcp-stress fuzz evasion -p "payload" -t read_file --use-llm
```

### Utilities

```bash
mcp-stress info       # Framework information
mcp-stress --version  # Version number
```

## Attack pattern paradigms

The 1,312 patterns are organized into three paradigms from the MCPTox benchmark:

| Paradigm | Name | Patterns | Description |
|----------|------|----------|-------------|
| **P1** | Explicit Hijacking | 224 | Decoy tools mimicking legitimate functions |
| **P2** | Implicit Hijacking | 548 | Background tools with hidden triggers |
| **P3** | Parameter Tampering | 725 | Poisoned descriptions altering other tools' behavior |

## Mutation strategies

Strategies are applied in order of escalating sophistication:

| Strategy | Technique | Detectability |
|----------|-----------|---------------|
| `direct_injection` | Append payload directly to description | High (baseline) |
| `semantic_blending` | Weave payload into legitimate documentation | Medium |
| `obfuscation` | Unicode tricks, zero-width characters, homoglyphs | Medium |
| `encoding` | Base64, hex-encoded payloads | Low-Medium |
| `fragmentation` | Split payload across multiple schema fields | Low |

## Python API

```python
from mcp_stress_test import PatternLibrary
from mcp_stress_test.generator import SchemaMutator
from mcp_stress_test.scanners.mock import MockScanner
from mcp_stress_test.chains import ChainExecutor, BUILTIN_CHAINS

# Load attack patterns
library = PatternLibrary()
library.load()

# Generate poisoned tools
mutator = SchemaMutator()
for test_case in library.iter_test_cases():
    result = mutator.mutate(
        test_case.target_tool,
        test_case.poison_profile.payloads[0]
    )
    poisoned_tool = result.poisoned_tool

# Test a scanner
scanner = MockScanner()
scan_result = scanner.scan(poisoned_tool)
print(f"Detected: {scan_result.detected}")

# Execute attack chains
executor = ChainExecutor(scanner)
for chain in BUILTIN_CHAINS:
    result = executor.execute(chain, tools)
    print(f"{chain.name}: {result.detected_count}/{result.total_steps}")
```

## Architecture

MCP Stress Test is structured around four subsystems:

1. **Pattern Library** — Loads and indexes the 1,312 attack patterns from bundled YAML/JSON files. Patterns are categorized by paradigm (P1/P2/P3) and tagged with target tools and payload categories.

2. **Mutation Engine** — Applies transformation strategies to attack patterns. Includes both deterministic strategies (direct injection, encoding, fragmentation) and LLM-guided fuzzing via local Ollama models.

3. **Chain Executor** — Orchestrates multi-tool attack sequences that simulate coordinated, real-world attack scenarios across multiple MCP tools.

4. **Scanner Adapter** — Pluggable interface for testing against real scanners (tool-scan, CLI wrappers) or the built-in mock scanner for development.

## Security model

| Aspect | Detail |
|--------|--------|
| **Data touched** | Bundled attack pattern YAML/JSON files. User-specified output files for reports. |
| **Data NOT touched** | No network access to external systems. No telemetry. No analytics. No credential handling. |
| **Permissions** | Read: bundled pattern library. Write: output reports to user-specified paths only. |
| **Network** | Optional Ollama connection (localhost only) for LLM-guided fuzzing. No other network egress. |
| **Telemetry** | None collected or sent. |

See [SECURITY.md](https://github.com/mcp-tool-shop-org/mcp-stress-test/blob/main/SECURITY.md) for vulnerability reporting and responsible use guidelines.
