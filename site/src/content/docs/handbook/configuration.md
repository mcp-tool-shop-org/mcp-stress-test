---
title: Configuration
description: Config files, environment variables, and tuning options for MCP Stress Test.
order: 3
---

MCP Stress Test can be configured through three methods, listed in order of precedence (highest first):

1. **CLI flags** -- Override any setting for a single command.
2. **Config file** -- A JSON file loaded via `--config` / `-c` flag.
3. **Environment variables** -- Prefixed with `MCP_STRESS_`.

If no configuration is provided, sensible defaults are used.

## Config file

Create a `stress-config.json` file:

```json
{
  "llm": {
    "provider": "ollama",
    "model": "llama3.2",
    "base_url": "http://localhost:11434",
    "temperature": 0.7,
    "max_tokens": 500,
    "timeout_seconds": 30
  },
  "scanner": {
    "default_scanner": "mock",
    "tool_scan_path": null,
    "timeout_ms": 5000,
    "retry_count": 3
  },
  "report": {
    "default_format": "markdown",
    "output_dir": "./reports",
    "include_raw_results": false,
    "html_template": null
  },
  "fuzz": {
    "max_generations": 10,
    "mutation_rate": 0.3,
    "evasion_threshold": 0.5,
    "save_evasions": true,
    "evasion_output_dir": "./evasions"
  },
  "chain": {
    "max_chain_length": 5,
    "step_delay_ms": 100,
    "fail_fast": false
  },
  "verbose": false,
  "parallel_workers": 1,
  "cache_results": true,
  "cache_dir": "./.stress-cache"
}
```

Pass it to any command:

```bash
mcp-stress -c stress-config.json scan compare -t read_file -s obfuscation
```

## Configuration sections

### LLM (`llm`)

Controls the Ollama connection used for LLM-guided fuzzing.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `provider` | string | `"ollama"` | LLM provider (currently only `ollama`) |
| `model` | string | `"llama3.2"` | Ollama model name |
| `base_url` | string | `"http://localhost:11434"` | Ollama API base URL |
| `temperature` | float | `0.7` | Sampling temperature for mutations |
| `max_tokens` | int | `500` | Max tokens per LLM response |
| `timeout_seconds` | int | `30` | Request timeout |

### Scanner (`scanner`)

Controls which scanner is used and how it behaves.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `default_scanner` | string | `"mock"` | Scanner to use: `mock`, `tool-scan`, or `cli` |
| `tool_scan_path` | string | `null` | Path to tool-scan binary (auto-detected if on PATH) |
| `timeout_ms` | int | `5000` | Scan timeout per tool |
| `retry_count` | int | `3` | Retries on scanner failure |

### Report (`report`)

Controls report generation defaults.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `default_format` | string | `"markdown"` | Default output format |
| `output_dir` | string | `"./reports"` | Directory for report output |
| `include_raw_results` | bool | `false` | Include raw scan data in reports |
| `html_template` | string | `null` | Custom Jinja2 template for HTML reports |

### Fuzz (`fuzz`)

Controls fuzzing behavior and evasion testing.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `max_generations` | int | `10` | Maximum mutation generations per run |
| `mutation_rate` | float | `0.3` | Probability of mutating each token |
| `evasion_threshold` | float | `0.5` | Scanner score below which evasion is declared |
| `save_evasions` | bool | `true` | Automatically save discovered evasions |
| `evasion_output_dir` | string | `"./evasions"` | Directory for saved evasions |

### Chain (`chain`)

Controls attack chain execution.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `max_chain_length` | int | `5` | Maximum steps in a chain |
| `step_delay_ms` | int | `100` | Delay between chain steps |
| `fail_fast` | bool | `false` | Stop chain on first detection |

### Global settings

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `verbose` | bool | `false` | Enable verbose output |
| `parallel_workers` | int | `1` | Number of parallel workers |
| `cache_results` | bool | `true` | Cache scan results |
| `cache_dir` | string | `"./.stress-cache"` | Cache directory |

## Environment variables

Every config field has a corresponding environment variable prefixed with `MCP_STRESS_`:

| Variable | Maps to |
|----------|---------|
| `MCP_STRESS_LLM_MODEL` | `llm.model` |
| `MCP_STRESS_LLM_URL` | `llm.base_url` |
| `MCP_STRESS_LLM_PROVIDER` | `llm.provider` |
| `MCP_STRESS_SCANNER_DEFAULT` | `scanner.default_scanner` |
| `MCP_STRESS_TOOL_SCAN_PATH` | `scanner.tool_scan_path` |
| `MCP_STRESS_REPORT_FORMAT` | `report.default_format` |
| `MCP_STRESS_REPORT_DIR` | `report.output_dir` |
| `MCP_STRESS_VERBOSE` | `verbose` (accepts `true`, `1`, `yes`) |
| `MCP_STRESS_WORKERS` | `parallel_workers` |

Example:

```bash
export MCP_STRESS_LLM_MODEL=codellama
export MCP_STRESS_SCANNER_DEFAULT=tool-scan
mcp-stress scan compare -t read_file -s obfuscation
```

## Python programmatic config

When using the Python API, create a `StressConfig` directly:

```python
from mcp_stress_test.core.config import StressConfig, LLMConfig, ScannerConfig

config = StressConfig(
    llm=LLMConfig(model="codellama", temperature=0.9),
    scanner=ScannerConfig(default_scanner="tool-scan"),
    verbose=True,
)

# Or load from file
config = StressConfig.from_file("stress-config.json")

# Or load from environment
config = StressConfig.from_env()

# Save current config
config.save("my-config.json")
```
