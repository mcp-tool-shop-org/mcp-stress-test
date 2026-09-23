"""Tests for the subprocess-backed scanner adapters (CLIScanner, ToolScanAdapter).

A scanner that failed to run (non-zero/unexpected exit, timeout, missing binary,
unparseable output) must never be reported as a clean result (detected=False,
score 100 — which counts as an evasion) nor as a threat detection.
"""

from __future__ import annotations

import subprocess
import tempfile
from pathlib import Path

import pytest

from mcp_stress_test.core.protocols import AttackResult
from mcp_stress_test.models import ToolParameter, ToolSchema
from mcp_stress_test.scanners import cli_adapter, tool_scan
from mcp_stress_test.scanners.cli_adapter import CLIScanner
from mcp_stress_test.scanners.tool_scan import ToolScanAdapter

CLEAN_JSON = '{"score": 100, "threats": []}'


@pytest.fixture
def tool() -> ToolSchema:
    return ToolSchema(
        name="read_file",
        description="Read a file.",
        parameters=[ToolParameter(name="path", type="string", description="Path", required=True)],
    )


@pytest.fixture
def spaced_tempdir(tmp_path, monkeypatch) -> Path:
    d = tmp_path / "dir with space"
    d.mkdir()
    monkeypatch.setattr(tempfile, "tempdir", str(d))
    return d


class _Recorder:
    def __init__(self, returncode=0, stdout="", stderr="", raises=None, watch_dir=None):
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr
        self.raises = raises
        self.watch_dir = watch_dir
        self.calls: list[tuple[tuple, dict]] = []
        self.temp_files: list[list[str]] = []

    def __call__(self, *args, **kwargs):
        self.calls.append((args, kwargs))
        cmd = args[0] if args else kwargs.get("args")
        if self.watch_dir is not None:
            self.temp_files.append([str(p) for p in Path(self.watch_dir).glob("*.json")])
        if self.raises is not None:
            raise self.raises
        return subprocess.CompletedProcess(
            args=cmd, returncode=self.returncode, stdout=self.stdout, stderr=self.stderr
        )


def _patch_run(monkeypatch, module, recorder: _Recorder) -> _Recorder:
    monkeypatch.setattr(module.subprocess, "run", recorder)
    return recorder


def _outcome(scanner, tool):
    try:
        return scanner.scan(tool)
    except Exception as e:  # raising is an acceptable way to surface a scanner failure
        return e


def _assert_error_not_clean(outcome) -> None:
    if isinstance(outcome, Exception):
        return
    assert isinstance(outcome, AttackResult)
    assert not outcome.detected, f"scanner failure reported as a detection: {outcome}"
    assert not outcome.threats_found, f"scanner failure reported threats: {outcome}"
    assert not (outcome.detected is False and outcome.score_after == 100.0), (
        f"scanner failure reported as a clean result (counts as evasion): {outcome}"
    )
    assert outcome.metadata.get("error"), f"scanner failure carries no error: {outcome}"


def _assert_path_passed_safely(recorder: _Recorder) -> None:
    assert len(recorder.calls) == 1
    assert len(recorder.temp_files) == 1 and len(recorder.temp_files[0]) == 1, (
        f"expected exactly one temp file while the scanner ran: {recorder.temp_files}"
    )
    path = recorder.temp_files[0][0]
    assert " " in path
    args, kwargs = recorder.calls[0]
    cmd = args[0] if args else kwargs["args"]
    if kwargs.get("shell"):
        assert isinstance(cmd, str)
        # cmd.exe (subprocess shell=True on Windows) does not treat POSIX
        # shlex.quote single quotes as quoting. Require a Windows-quoted path.
        assert '"' + path + '"' in cmd, (
            f"temp path with spaces not Windows-quoted for shell=True: {cmd!r}"
        )
    else:
        assert isinstance(cmd, list | tuple), f"expected argv list, got {cmd!r}"
        assert path in [str(a) for a in cmd], f"temp path split or missing in argv: {cmd!r}"


# =============================================================================
# CLIScanner
# =============================================================================


class TestCLIScanner:
    def test_temp_path_with_space_is_not_split(self, monkeypatch, tool, spaced_tempdir):
        rec = _patch_run(
            monkeypatch, cli_adapter, _Recorder(stdout=CLEAN_JSON, watch_dir=spaced_tempdir)
        )
        scanner = CLIScanner(command="my-scanner analyze {input} --json")

        scanner.scan(tool)

        _assert_path_passed_safely(rec)

    def test_clean_json_output_is_clean(self, monkeypatch, tool):
        _patch_run(monkeypatch, cli_adapter, _Recorder(stdout=CLEAN_JSON))
        result = CLIScanner(command="s {input}").scan(tool)

        assert result.detected is False
        assert result.score_after == 100.0
        assert result.threats_found == []

    def test_json_threats_are_detected(self, monkeypatch, tool):
        out = '{"score": 40, "findings": ["exfil", "hijack"]}'
        _patch_run(monkeypatch, cli_adapter, _Recorder(returncode=1, stdout=out))
        result = CLIScanner(command="s {input}", threats_path="$.findings").scan(tool)

        assert result.detected is True
        assert result.score_after == 40.0
        assert result.threats_found == ["exfil", "hijack"]

    def test_text_output_parsing(self, monkeypatch, tool):
        out = "FINDING: exfil\nFINDING: hijack\nScore: 35\n"
        _patch_run(monkeypatch, cli_adapter, _Recorder(returncode=1, stdout=out))
        scanner = CLIScanner(
            command="s {input}",
            output_format="text",
            threat_pattern=r"FINDING: (.+)",
            score_pattern=r"Score: (\d+)",
        )
        result = scanner.scan(tool)

        assert result.detected is True
        assert result.threats_found == ["exfil", "hijack"]
        assert result.score_after == 35.0

    def test_text_output_malformed_score_keeps_default(self, monkeypatch, tool):
        _patch_run(monkeypatch, cli_adapter, _Recorder(stdout="Score: n/a\n"))
        scanner = CLIScanner(
            command="s {input}",
            output_format="text",
            threat_pattern=r"FINDING: (.+)",
            score_pattern=r"Score: (\d+)",
        )
        result = scanner.scan(tool)

        assert result.detected is False
        assert result.threats_found == []

    def test_unexpected_exit_code_is_error(self, monkeypatch, tool):
        _patch_run(monkeypatch, cli_adapter, _Recorder(returncode=2, stdout=CLEAN_JSON))
        _assert_error_not_clean(_outcome(CLIScanner(command="s {input}"), tool))

    def test_timeout_is_error(self, monkeypatch, tool):
        exc = subprocess.TimeoutExpired(cmd="s", timeout=30)
        _patch_run(monkeypatch, cli_adapter, _Recorder(raises=exc))
        _assert_error_not_clean(_outcome(CLIScanner(command="s {input}"), tool))

    def test_missing_binary_is_error(self, monkeypatch, tool):
        _patch_run(monkeypatch, cli_adapter, _Recorder(raises=FileNotFoundError("s")))
        _assert_error_not_clean(_outcome(CLIScanner(command="s {input}"), tool))

    @pytest.mark.parametrize("returncode", [0, 1])
    def test_invalid_json_is_error(self, monkeypatch, tool, returncode):
        _patch_run(monkeypatch, cli_adapter, _Recorder(returncode=returncode, stdout="not json {"))
        _assert_error_not_clean(_outcome(CLIScanner(command="s {input}"), tool))


# =============================================================================
# ToolScanAdapter
# =============================================================================


class TestToolScanAdapter:
    def test_temp_path_with_space_is_single_argv(self, monkeypatch, tool, spaced_tempdir):
        rec = _patch_run(
            monkeypatch, tool_scan, _Recorder(stdout=CLEAN_JSON, watch_dir=spaced_tempdir)
        )

        ToolScanAdapter().scan(tool)

        _assert_path_passed_safely(rec)

    def test_threats_are_detected(self, monkeypatch, tool):
        out = '{"score": 30, "grade": "D", "threats": [{"type": "encoded_payload"}]}'
        _patch_run(monkeypatch, tool_scan, _Recorder(stdout=out))
        result = ToolScanAdapter().scan(tool)

        assert result.detected is True
        assert result.threats_found == ["encoded_payload"]
        assert result.strategy == "encoding"
        assert result.score_after == 30

    def test_clean_output_is_clean(self, monkeypatch, tool):
        _patch_run(monkeypatch, tool_scan, _Recorder(stdout=CLEAN_JSON))
        result = ToolScanAdapter().scan(tool)

        assert result.detected is False
        assert result.threats_found == []

    def test_nonzero_exit_is_error(self, monkeypatch, tool):
        _patch_run(monkeypatch, tool_scan, _Recorder(returncode=2, stderr="boom"))
        _assert_error_not_clean(_outcome(ToolScanAdapter(), tool))

    def test_timeout_is_error(self, monkeypatch, tool):
        exc = subprocess.TimeoutExpired(cmd="tool-scan", timeout=30)
        _patch_run(monkeypatch, tool_scan, _Recorder(raises=exc))
        _assert_error_not_clean(_outcome(ToolScanAdapter(), tool))

    def test_missing_binary_is_error(self, monkeypatch, tool):
        _patch_run(monkeypatch, tool_scan, _Recorder(raises=FileNotFoundError("tool-scan")))
        _assert_error_not_clean(_outcome(ToolScanAdapter(), tool))

    def test_invalid_json_is_error(self, monkeypatch, tool):
        _patch_run(monkeypatch, tool_scan, _Recorder(stdout="<<garbage>>"))
        _assert_error_not_clean(_outcome(ToolScanAdapter(), tool))
