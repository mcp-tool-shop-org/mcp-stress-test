"""Modular CLI for MCP Stress Test Framework.

This module provides a clean, modular CLI that integrates all framework
features including patterns, fuzzing, chains, and reporting.
"""

from __future__ import annotations

from mcp_stress_test.cli.main import app, main

__all__ = ["main", "app"]
