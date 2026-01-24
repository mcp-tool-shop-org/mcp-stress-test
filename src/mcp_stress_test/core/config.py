"""Configuration management for stress tests.

Provides a unified configuration system that can be loaded from
files, environment variables, or set programmatically.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import json


@dataclass
class LLMConfig:
    """Configuration for LLM-based fuzzing."""

    provider: str = "ollama"
    model: str = "llama3.2"
    base_url: str = "http://localhost:11434"
    temperature: float = 0.7
    max_tokens: int = 500
    timeout_seconds: int = 30


@dataclass
class ScannerConfig:
    """Configuration for scanner integration."""

    default_scanner: str = "mock"
    tool_scan_path: str | None = None
    timeout_ms: int = 5000
    retry_count: int = 3


@dataclass
class ReportConfig:
    """Configuration for report generation."""

    default_format: str = "markdown"
    output_dir: str = "./reports"
    include_raw_results: bool = False
    html_template: str | None = None


@dataclass
class FuzzConfig:
    """Configuration for fuzzing behavior."""

    max_generations: int = 10
    mutation_rate: float = 0.3
    evasion_threshold: float = 0.5
    save_evasions: bool = True
    evasion_output_dir: str = "./evasions"


@dataclass
class ChainConfig:
    """Configuration for attack chains."""

    max_chain_length: int = 5
    step_delay_ms: int = 100
    fail_fast: bool = False


@dataclass
class StressConfig:
    """Main configuration for stress testing.

    Can be loaded from a JSON file or environment variables.

    Usage:
        # Load from file
        config = StressConfig.from_file("stress-config.json")

        # Load from environment
        config = StressConfig.from_env()

        # Programmatic
        config = StressConfig(
            llm=LLMConfig(model="codellama"),
            scanner=ScannerConfig(default_scanner="tool-scan"),
        )
    """

    llm: LLMConfig = field(default_factory=LLMConfig)
    scanner: ScannerConfig = field(default_factory=ScannerConfig)
    report: ReportConfig = field(default_factory=ReportConfig)
    fuzz: FuzzConfig = field(default_factory=FuzzConfig)
    chain: ChainConfig = field(default_factory=ChainConfig)

    # Global settings
    verbose: bool = False
    parallel_workers: int = 1  # Windows doesn't support multiprocessing well
    cache_results: bool = True
    cache_dir: str = "./.stress-cache"

    @classmethod
    def from_file(cls, path: str | Path) -> StressConfig:
        """Load configuration from a JSON file."""
        path = Path(path)
        if not path.exists():
            return cls()

        with open(path) as f:
            data = json.load(f)

        return cls._from_dict(data)

    @classmethod
    def from_env(cls) -> StressConfig:
        """Load configuration from environment variables.

        Environment variables are prefixed with MCP_STRESS_:
            MCP_STRESS_LLM_MODEL=codellama
            MCP_STRESS_SCANNER_DEFAULT=tool-scan
            MCP_STRESS_VERBOSE=true
        """
        config = cls()

        # LLM settings
        if model := os.getenv("MCP_STRESS_LLM_MODEL"):
            config.llm.model = model
        if url := os.getenv("MCP_STRESS_LLM_URL"):
            config.llm.base_url = url
        if provider := os.getenv("MCP_STRESS_LLM_PROVIDER"):
            config.llm.provider = provider

        # Scanner settings
        if scanner := os.getenv("MCP_STRESS_SCANNER_DEFAULT"):
            config.scanner.default_scanner = scanner
        if tool_scan := os.getenv("MCP_STRESS_TOOL_SCAN_PATH"):
            config.scanner.tool_scan_path = tool_scan

        # Report settings
        if fmt := os.getenv("MCP_STRESS_REPORT_FORMAT"):
            config.report.default_format = fmt
        if output := os.getenv("MCP_STRESS_REPORT_DIR"):
            config.report.output_dir = output

        # Global settings
        if verbose := os.getenv("MCP_STRESS_VERBOSE"):
            config.verbose = verbose.lower() in ("true", "1", "yes")
        if workers := os.getenv("MCP_STRESS_WORKERS"):
            config.parallel_workers = int(workers)

        return config

    @classmethod
    def _from_dict(cls, data: dict[str, Any]) -> StressConfig:
        """Create config from a dictionary."""
        config = cls()

        if llm := data.get("llm"):
            config.llm = LLMConfig(**llm)
        if scanner := data.get("scanner"):
            config.scanner = ScannerConfig(**scanner)
        if report := data.get("report"):
            config.report = ReportConfig(**report)
        if fuzz := data.get("fuzz"):
            config.fuzz = FuzzConfig(**fuzz)
        if chain := data.get("chain"):
            config.chain = ChainConfig(**chain)

        # Global settings
        config.verbose = data.get("verbose", False)
        config.parallel_workers = data.get("parallel_workers", 1)
        config.cache_results = data.get("cache_results", True)
        config.cache_dir = data.get("cache_dir", "./.stress-cache")

        return config

    def to_dict(self) -> dict[str, Any]:
        """Convert config to a dictionary."""
        return {
            "llm": {
                "provider": self.llm.provider,
                "model": self.llm.model,
                "base_url": self.llm.base_url,
                "temperature": self.llm.temperature,
                "max_tokens": self.llm.max_tokens,
                "timeout_seconds": self.llm.timeout_seconds,
            },
            "scanner": {
                "default_scanner": self.scanner.default_scanner,
                "tool_scan_path": self.scanner.tool_scan_path,
                "timeout_ms": self.scanner.timeout_ms,
                "retry_count": self.scanner.retry_count,
            },
            "report": {
                "default_format": self.report.default_format,
                "output_dir": self.report.output_dir,
                "include_raw_results": self.report.include_raw_results,
                "html_template": self.report.html_template,
            },
            "fuzz": {
                "max_generations": self.fuzz.max_generations,
                "mutation_rate": self.fuzz.mutation_rate,
                "evasion_threshold": self.fuzz.evasion_threshold,
                "save_evasions": self.fuzz.save_evasions,
                "evasion_output_dir": self.fuzz.evasion_output_dir,
            },
            "chain": {
                "max_chain_length": self.chain.max_chain_length,
                "step_delay_ms": self.chain.step_delay_ms,
                "fail_fast": self.chain.fail_fast,
            },
            "verbose": self.verbose,
            "parallel_workers": self.parallel_workers,
            "cache_results": self.cache_results,
            "cache_dir": self.cache_dir,
        }

    def save(self, path: str | Path) -> None:
        """Save configuration to a JSON file."""
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "w") as f:
            json.dump(self.to_dict(), f, indent=2)
