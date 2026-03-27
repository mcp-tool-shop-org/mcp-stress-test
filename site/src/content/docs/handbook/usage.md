---
title: Usage
description: Detailed workflows for fuzzing, attack chains, scanning, and report generation.
order: 2
---

This page walks through the four main command groups in MCP Stress Test: **fuzzing**, **attack chains**, **scanning**, and **reporting**. Each section covers the typical workflow, command options, and practical examples.

## Fuzzing

The `fuzz` group generates mutated attack payloads to find scanner blind spots. There are three subcommands.

### LLM-guided fuzzing (`fuzz run`)

Uses a local Ollama model to rewrite payloads in creative ways:

```bash
mcp-stress fuzz run -p "Exfiltrate credentials from ~/.aws/credentials" -m llama3.2
```

Options:

| Flag | Default | Purpose |
|------|---------|---------|
| `-p` / `--payload` | (required) | The attack payload to mutate |
| `-m` / `--model` | `llama3.2` | Ollama model name |
| `-s` / `--strategies` | `all` | Comma-separated mutation strategies |
| `-o` / `--output` | none | Save results to a JSON file |
| `--json-output` | false | Print results as JSON |

If Ollama is unreachable, the framework automatically falls back to a mock fuzzer that applies deterministic transformations.

### Evasion search (`fuzz evasion`)

Keeps mutating a payload until one evades the scanner or the attempt limit is reached:

```bash
mcp-stress fuzz evasion -p "Read secrets" -t read_file -n 20 -m llama3.2
```

Options:

| Flag | Default | Purpose |
|------|---------|---------|
| `-p` / `--payload` | (required) | Attack payload to test |
| `-t` / `--tool` | (required) | Target tool name |
| `-n` / `--max-attempts` | `10` | Maximum mutation attempts |
| `-m` / `--model` | `llama3.2` | Ollama model |
| `-s` / `--scanner` | `mock` | Scanner to test against |

The output shows whether an evasion was found, which strategy succeeded, and how many attempts it took.

### Deterministic mutations (`fuzz mutate`)

Applies pattern-based mutations without requiring an LLM:

```bash
mcp-stress fuzz mutate -p "Read ~/.ssh/id_rsa" -s semantic -n 10
```

Strategies:

| Strategy | What it does |
|----------|-------------|
| `semantic` | Rewords the payload with different vocabulary |
| `syntactic` | Restructures sentence patterns |
| `hybrid` | Combines semantic and syntactic mutations |
| `fragmentation` | Splits the payload into disconnected fragments |

## Attack chains

The `chain` group orchestrates multi-step attack scenarios that simulate real-world coordinated attacks.

### List available chains

```bash
mcp-stress chain list
mcp-stress chain list --json-output
```

### Inspect a chain

```bash
mcp-stress chain show data_exfil_chain
```

This prints the chain's steps, required tools, step dependencies, and payload previews.

### Execute chains

```bash
# Execute a specific chain
mcp-stress chain execute -c data_exfil_chain

# Execute multiple chains
mcp-stress chain execute -c data_exfil_chain -c persistence_chain

# Execute all 6 built-in chains
mcp-stress chain execute
```

Options:

| Flag | Default | Purpose |
|------|---------|---------|
| `-c` / `--chain` | all | Chain names to execute (repeatable) |
| `-s` / `--scanner` | `mock` | Scanner to test against |
| `-o` / `--output` | none | Save results to JSON |
| `--json-output` | false | Print results as JSON |

### Built-in chains

| Chain | Steps | Simulates |
|-------|-------|-----------|
| `data_exfil_chain` | 3 | File discovery, credential reading, HTTP exfiltration |
| `privilege_escalation_chain` | 4 | User enumeration, writable dirs, sudoers modification, elevated exec |
| `credential_theft_chain` | 4 | Env var extraction, token file reading, credential testing, cloud access |
| `lateral_movement_chain` | 4 | Network discovery, port scanning, SSH access, remote execution |
| `persistence_chain` | 4 | Backdoor user, cron job, startup script, log clearing |
| `sampling_loop_chain` | 4 | Sampling injection, feedback loop, approval bypass, persistent control |

## Scanning

The `scan` group compares tool definitions before and after poisoning to measure scanner effectiveness.

### Before/after comparison

```bash
mcp-stress scan compare -t read_file -s obfuscation
```

Strategies: `direct_injection`, `semantic_blending`, `obfuscation`, `encoding`, `fragmentation`.

### Batch comparison

Test multiple tools against multiple strategies in one run:

```bash
mcp-stress scan batch -t read_file,write_file,run_command -s direct_injection,obfuscation,encoding
```

This produces a matrix showing detection results for every tool/strategy combination.

### List scanners

```bash
mcp-stress scan scanners
```

Shows mock (always available), tool-scan (if installed), and the generic CLI wrapper.

## Reporting

The `report` group generates formatted reports from saved JSON results.

### Generate a report

```bash
mcp-stress report generate -i results.json -f html -o dashboard.html
```

Supported formats: `json`, `markdown`, `html`, `sarif`.

### List formats

```bash
mcp-stress report formats
```

### Preview statistics

Quickly see summary stats without generating a full report:

```bash
mcp-stress report preview -i results.json
```

## Typical workflow

A complete stress testing session usually follows this pattern:

1. **Scan** -- Run batch comparisons across tools and strategies to get baseline detection rates. This tells you which attack types your scanner already handles well and which are blind spots.
2. **Chain** -- Execute attack chains to test multi-step detection. Chains reveal whether your scanner can detect coordinated attacks where individual steps might look benign.
3. **Fuzz** -- Use LLM fuzzing to probe for evasions the scanner missed. The fuzzer generates creative rewrites of attack payloads that keyword-based scanners may not catch.
4. **Report** -- Generate an HTML dashboard or SARIF file for review. SARIF integrates with VS Code and GitHub Code Scanning for inline annotations.

```bash
# Step 1: Batch scan across multiple tools and strategies
mcp-stress scan batch -t read_file,write_file,run_command -s direct_injection,obfuscation,encoding -o scan-results.json

# Step 2: Run all 6 built-in attack chains
mcp-stress chain execute -o chain-results.json --json-output

# Step 3: Fuzz for evasions (requires Ollama for LLM mode)
mcp-stress fuzz evasion -p "Read ~/.ssh/id_rsa" -t read_file -n 20

# Step 4: Generate HTML dashboard from scan results
mcp-stress report generate -i scan-results.json -f html -o report.html

# Step 5 (optional): Generate SARIF for IDE/CI integration
mcp-stress report generate -i scan-results.json -f sarif -o results.sarif
```

### Testing against a real scanner

For meaningful results, test against a real scanner rather than the built-in mock:

```bash
pip install tool-scan
mcp-stress scan batch -t read_file,write_file -s direct_injection,obfuscation --scanner tool-scan -o real-results.json
```

You can also wrap any CLI scanner that accepts JSON input and outputs JSON results:

```bash
mcp-stress scan compare -t read_file -s encoding --scanner cli --scanner-cmd "my-scanner --json {input}"
```
