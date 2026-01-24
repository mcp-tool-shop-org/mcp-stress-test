"""Tests for CLI commands."""

import json

import pytest
from click.testing import CliRunner

from mcp_stress_test.cli_legacy import main


@pytest.fixture
def runner():
    """Create a CLI test runner."""
    return CliRunner()


class TestMainCommands:
    """Tests for main CLI commands."""

    def test_version(self, runner):
        """Test version command."""
        result = runner.invoke(main, ["--version"])
        assert result.exit_code == 0
        assert "0.1.0" in result.output

    def test_info(self, runner):
        """Test info command."""
        result = runner.invoke(main, ["info"])
        assert result.exit_code == 0
        assert "MCP Stress Test Framework" in result.output
        assert "MCPTox" in result.output


class TestPatternsCommands:
    """Tests for patterns commands."""

    def test_patterns_list(self, runner):
        """Test patterns list command."""
        result = runner.invoke(main, ["patterns", "list"])
        assert result.exit_code == 0
        assert "Attack Patterns" in result.output

    def test_patterns_list_with_paradigm(self, runner):
        """Test patterns list with paradigm filter."""
        result = runner.invoke(main, ["patterns", "list", "--paradigm", "p1"])
        assert result.exit_code == 0
        assert "P1" in result.output

    def test_patterns_list_with_domain(self, runner):
        """Test patterns list with domain filter."""
        result = runner.invoke(main, ["patterns", "list", "--domain", "filesystem"])
        assert result.exit_code == 0

    def test_patterns_list_limit(self, runner):
        """Test patterns list with limit."""
        result = runner.invoke(main, ["patterns", "list", "--limit", "5"])
        assert result.exit_code == 0

    def test_patterns_list_json(self, runner):
        """Test patterns list with JSON output."""
        result = runner.invoke(main, ["patterns", "list", "--json-output", "--limit", "3"])
        assert result.exit_code == 0
        # Should be valid JSON
        data = json.loads(result.output)
        assert isinstance(data, list)
        assert len(data) <= 3

    def test_patterns_stats(self, runner):
        """Test patterns stats command."""
        result = runner.invoke(main, ["patterns", "stats"])
        assert result.exit_code == 0
        assert "Pattern Library Statistics" in result.output
        assert "Total Test Cases" in result.output
        assert "By Paradigm" in result.output


class TestPayloadsCommands:
    """Tests for payloads commands."""

    def test_payloads_list(self, runner):
        """Test payloads list command."""
        result = runner.invoke(main, ["payloads", "list"])
        assert result.exit_code == 0
        assert "Poison Payloads" in result.output

    def test_payloads_list_with_category(self, runner):
        """Test payloads list with category filter."""
        result = runner.invoke(main, ["payloads", "list", "--category", "data_exfil"])
        assert result.exit_code == 0
        assert "data_exfiltration" in result.output

    def test_payloads_list_json(self, runner):
        """Test payloads list with JSON output."""
        result = runner.invoke(
            main, ["payloads", "list", "--category", "data_exfil", "--json-output"]
        )
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert isinstance(data, list)


class TestToolsCommands:
    """Tests for tools commands."""

    def test_tools_list(self, runner):
        """Test tools list command."""
        result = runner.invoke(main, ["tools", "list"])
        assert result.exit_code == 0
        assert "Tool Definitions" in result.output

    def test_tools_list_with_domain(self, runner):
        """Test tools list with domain filter."""
        result = runner.invoke(main, ["tools", "list", "--domain", "communication"])
        assert result.exit_code == 0
        assert "communication" in result.output

    def test_tools_list_json(self, runner):
        """Test tools list with JSON output."""
        result = runner.invoke(main, ["tools", "list", "--json-output"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert isinstance(data, list)
        assert len(data) > 0


class TestGenerateCommand:
    """Tests for generate command."""

    def test_generate_basic(self, runner):
        """Test basic generate command."""
        result = runner.invoke(
            main,
            [
                "generate",
                "--paradigm",
                "p1",
                "--payload",
                "data_exfil",
                "--count",
                "5",
            ],
        )
        assert result.exit_code == 0
        assert "Generated" in result.output

    def test_generate_with_output(self, runner, tmp_path):
        """Test generate with file output."""
        output_file = tmp_path / "test_cases.json"
        result = runner.invoke(
            main,
            [
                "generate",
                "--paradigm",
                "p2",
                "--payload",
                "cross_tool",
                "--count",
                "3",
                "--output",
                str(output_file),
            ],
        )
        assert result.exit_code == 0
        assert output_file.exists()

        with open(output_file) as f:
            data = json.load(f)
        assert isinstance(data, list)
