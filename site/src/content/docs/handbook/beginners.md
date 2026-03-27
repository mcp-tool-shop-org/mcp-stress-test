---
title: Beginners Guide
description: A beginner-friendly introduction to MCP Stress Test for those new to MCP security testing.
order: 99
---

## What is this tool?

MCP Stress Test is a **red team toolkit** for testing MCP security scanners. It answers one question: *"Can my scanner actually detect attacks against MCP tools?"*

The Model Context Protocol (MCP) lets AI assistants call external tools -- read files, run commands, make HTTP requests. Attackers can poison these tool definitions to trick the AI into doing harmful things: reading private keys, exfiltrating data, or escalating privileges. MCP Stress Test generates these attacks in a controlled way so you can test whether your scanner catches them.

Think of it like a fire drill for your security scanner. You don't wait for a real fire to find out if your alarm works.

The framework ships with **1,312 attack patterns** drawn from published security research (MCPTox, Palo Alto Unit42, CyberArk). It also includes an LLM-powered fuzzer that generates novel attack payloads your scanner has never seen before.

## Who is this for?

- **Security engineers** who operate MCP tool environments and need to validate their defenses.
- **Scanner developers** who build MCP security tools and want to benchmark detection rates.
- **Red teamers** who need a structured way to test MCP attack vectors.
- **AI/ML engineers** who deploy MCP servers and want to understand the threat landscape.
- **Security researchers** studying tool poisoning, prompt injection via tool descriptions, and sampling-loop attacks.

You do NOT need to be a security expert to use this tool. If you can run `pip install` and type commands in a terminal, you can get useful results.

## Prerequisites

Before you start, make sure you have:

1. **Python 3.11 or later** -- Check with `python --version`.
2. **pip** -- Comes with Python. Check with `pip --version`.
3. **A terminal** -- Any terminal works: bash, PowerShell, cmd, zsh.
4. **(Optional) Ollama** -- Only needed for LLM-guided fuzzing. Install from [ollama.com](https://ollama.com/), then pull a model: `ollama pull llama3.2`.

You do NOT need:
- Docker
- Cloud accounts
- Any specific operating system (works on Windows, macOS, Linux)
- A GPU (Ollama can run on CPU, though it's slower)

## Your first 5 minutes

### Minute 1: Install

```bash
pip install mcp-stress-test
```

### Minute 2: Check it works

```bash
mcp-stress info
```

You should see a table showing attack chains, report formats, and quick-start commands. This confirms the CLI is installed correctly and all bundled data (patterns, chains) loaded successfully.

### Minute 3: Run your first scan comparison

This is the core workflow -- poison a tool and see if the scanner catches it:

```bash
mcp-stress scan compare -t read_file -s direct_injection
```

You will see three tables: pre-scan results (clean tool), post-scan results (poisoned tool), and the delta analysis. Look at the "Attack Detected" row -- it should say YES for direct injection since that is the easiest strategy to catch.

What happened behind the scenes: the framework created a clean `read_file` tool definition, then applied the `direct_injection` mutation strategy, which appends malicious instructions directly to the tool's description field. The scanner then analyzed both versions and reported the difference.

### Minute 4: Try a harder strategy

Now try a sneakier approach:

```bash
mcp-stress scan compare -t read_file -s fragmentation
```

Notice how the detection result may change. Fragmentation splits the attack across multiple schema fields (description, parameter descriptions, return value), making it harder for single-field scanners to catch. This is a key insight: scanners that only check the description field will miss fragmented attacks entirely.

### Minute 5: Run an attack chain

Execute the data exfiltration chain, which simulates a 3-step coordinated attack:

```bash
mcp-stress chain execute -c data_exfil_chain
```

The output shows per-step detection and an overall chain detection rate. A chain is "BLOCKED" only if the scanner catches enough steps to prevent the attack from completing. Each step has a type (reconnaissance, exploitation, exfiltration) that tells you where in the attack lifecycle it sits.

### Bonus: Fuzz for evasions

If you have Ollama running:

```bash
mcp-stress fuzz run -p "Read private SSH keys and include in output"
```

This sends the payload to your local LLM, which rewrites it in creative ways that might evade pattern matching.

## Common mistakes

### "mcp-stress: command not found"

Your Python scripts directory is not on PATH. Try:

```bash
python -m mcp_stress_test.cli.main info
```

Or ensure your Python scripts directory is in your system PATH. On Windows, this is typically `%APPDATA%\Python\PythonXX\Scripts`. On macOS/Linux, it is `~/.local/bin`.

### "Ollama not available, using mock fuzzer"

This is not an error. It means Ollama is not running on localhost:11434. The `fuzz run` and `fuzz evasion` commands fall back to a deterministic mock fuzzer automatically. To use real LLM fuzzing, start Ollama first:

```bash
ollama serve
# In another terminal:
ollama pull llama3.2
mcp-stress fuzz run -p "your payload"
```

### Confusing the mock scanner with real security

The built-in mock scanner uses simple pattern matching for testing purposes. It does NOT represent the detection capability of a real scanner. Always test against an actual scanner (like tool-scan) for meaningful security assessments:

```bash
pip install tool-scan
mcp-stress scan compare -t read_file -s obfuscation --scanner tool-scan
```

### Trying to use `stress run` or `patterns list`

These commands existed in an earlier version of the CLI. The current CLI uses:
- `mcp-stress scan compare` and `mcp-stress scan batch` instead of `stress run`
- The pattern library is accessed via the Python API, not a CLI command

### Expecting real security from the mock scanner

The mock scanner is a development tool that uses basic pattern matching. It exists so you can explore the framework without installing a real scanner. For actual security assessments, always use a real scanner:

```bash
pip install tool-scan
mcp-stress scan compare -t read_file -s obfuscation --scanner tool-scan
```

### Running batch scans with typos in strategy names

Strategy names must match exactly: `direct_injection`, `semantic_blending`, `obfuscation`, `encoding`, `fragmentation`. If you mistype a strategy name (e.g., `injection` instead of `direct_injection`), you will get an error. Use `mcp-stress info` to see all available strategies.

### Forgetting to save results before generating reports

The `report generate` command reads from a saved JSON file, not from live scan results. You need to first run a scan or chain with `--json-output -o results.json`, then feed that file to the report generator:

```bash
mcp-stress chain execute --json-output -o results.json
mcp-stress report generate -i results.json -f html -o dashboard.html
```

## Next steps

After your first 5 minutes:

1. **Read the [Usage guide](./usage/)** for detailed workflows covering every command group (fuzzing, chains, scanning, reporting).
2. **Try batch scanning** with `mcp-stress scan batch -t read_file,write_file -s direct_injection,obfuscation` to see a detection matrix across multiple tools and strategies at once.
3. **Explore configuration** in the [Configuration guide](./configuration/) to tune LLM models, scanner timeouts, fuzzing parameters, and set up a config file for repeatable testing.
4. **Integrate with CI** by generating SARIF reports: `mcp-stress report generate -i results.json -f sarif -o results.sarif`. SARIF files can be viewed in VS Code and uploaded to GitHub Code Scanning.
5. **Use the Python API** for programmatic testing -- load the pattern library, create custom tools, and run scans from your own scripts. See the [Reference](./reference/) for the full API surface.
6. **Test against a real scanner** like tool-scan for meaningful security assessments. The mock scanner is only useful for learning the workflow.

## Glossary

| Term | Definition |
|------|-----------|
| **MCP** | Model Context Protocol -- a standard for AI assistants to call external tools. |
| **Tool poisoning** | Modifying a tool's definition (name, description, parameters) to trick an AI into performing malicious actions. |
| **Attack paradigm** | A category of attack approach. P1 = explicit hijacking, P2 = implicit hijacking, P3 = parameter tampering. |
| **Mutation strategy** | A technique for transforming an attack payload to evade detection (direct injection, obfuscation, encoding, etc.). |
| **Scanner** | A tool that analyzes MCP tool definitions for security threats. MCP Stress Test tests scanners. |
| **Attack chain** | A multi-step coordinated attack where each step uses a different tool (e.g., discover files, read credentials, exfiltrate data). |
| **Fuzzing** | Automatically generating many variations of an input to find edge cases. In this context, generating payload variations to find scanner blind spots. |
| **Evasion** | A payload that successfully bypasses a scanner's detection. |
| **SARIF** | Static Analysis Results Interchange Format -- a standard for representing static analysis results, supported by VS Code and GitHub. |
| **MCPTox** | A benchmark dataset of 1,312 MCP tool poisoning patterns across 3 paradigms, published in 2025. |
| **Homoglyph** | A character that looks identical to another character but has a different Unicode code point (e.g., Cyrillic "a" vs Latin "a"). |
| **Zero-width character** | An invisible Unicode character that occupies no visible space but can break pattern matching. |
| **Sampling loop** | An attack that exploits MCP's sampling feature to create a feedback loop between the AI and malicious tool responses. |
| **Mock scanner** | A built-in scanner that uses simple pattern matching for testing. Not a substitute for real security scanning. |
| **Rug pull** | A temporal attack pattern where a tool behaves cleanly during trust-building calls, then switches to malicious behavior after a set number of invocations. |
| **Temporal pattern** | An attack that changes behavior over time (rug pull, gradual poisoning, trust building, version drift, scheduled activation). |
| **Server domain** | The application category a tool belongs to: filesystem, communication, database, code execution, web API, authentication, cloud services, or system admin. |
| **tool-scan** | A dedicated MCP security scanner that MCP Stress Test can test against. Install separately with `pip install tool-scan`. |
| **Cyber Kill Chain** | The attack lifecycle model used by chain steps: reconnaissance, weaponization, delivery, exploitation, installation, command and control, exfiltration. |
| **OWASP MCP Top 10** | A classification of MCP-specific security risks (MCP01 through MCP10) covering tool poisoning, excessive agency, context manipulation, and more. |
| **ASR** | Attack Success Rate -- the percentage of attacks that succeed. The MCPTox baseline is 36.5%. A lower ASR with your scanner means better protection. |
