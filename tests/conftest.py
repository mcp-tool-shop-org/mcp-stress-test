"""Shared pytest hooks for the tests domain."""


def pytest_configure(config) -> None:
    config.addinivalue_line(
        "markers",
        "legacy: invokes mcp_stress_test.cli_legacy, not the installed mcp-stress console script",
    )
