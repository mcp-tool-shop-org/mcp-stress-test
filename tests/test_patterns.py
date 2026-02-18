"""Tests for pattern library and payloads."""

import pytest

from mcp_stress_test.models import (
    AttackParadigm,
    RiskCategory,
    ServerDomain,
)
from mcp_stress_test.patterns import PatternLibrary, load_patterns, load_payloads
from mcp_stress_test.patterns.payloads import (
    ALL_PAYLOADS,
    get_all_payloads,
    get_payloads_by_category,
    get_payloads_by_injection_point,
)


class TestPayloads:
    """Tests for poison payloads."""

    def test_all_payloads_loaded(self):
        """Test that all payload categories exist."""
        expected_categories = [
            "data_exfil",
            "privilege_escalation",
            "cross_tool",
            "context_manipulation",
            "error_injection",
            "parameter",
            "sampling_exploit",
            "obfuscated",
        ]
        for category in expected_categories:
            assert category in ALL_PAYLOADS
            assert len(ALL_PAYLOADS[category]) > 0

    def test_get_all_payloads(self):
        """Test getting all payloads as flat list."""
        all_payloads = get_all_payloads()
        assert len(all_payloads) > 20  # Should have a good number of payloads

    def test_get_payloads_by_category(self):
        """Test filtering payloads by risk category."""
        exfil_payloads = get_payloads_by_category(RiskCategory.DATA_EXFILTRATION)
        assert len(exfil_payloads) > 0
        for payload in exfil_payloads:
            assert payload.category == RiskCategory.DATA_EXFILTRATION

    def test_get_payloads_by_injection_point(self):
        """Test filtering payloads by injection point."""
        desc_payloads = get_payloads_by_injection_point("description")
        param_payloads = get_payloads_by_injection_point("parameter")
        error_payloads = get_payloads_by_injection_point("error")

        assert len(desc_payloads) > 0
        assert len(param_payloads) > 0
        assert len(error_payloads) > 0

    def test_load_payloads_helper(self):
        """Test the load_payloads helper function."""
        all_payloads = load_payloads()
        assert len(all_payloads) > 0

        data_exfil = load_payloads("data_exfil")
        assert len(data_exfil) > 0

        empty = load_payloads("nonexistent_category")
        assert len(empty) == 0


class TestPatternLibrary:
    """Tests for PatternLibrary."""

    @pytest.fixture
    def library(self):
        """Create a loaded pattern library."""
        lib = PatternLibrary()
        lib.load()
        return lib

    def test_library_loads(self, library):
        """Test that library loads successfully."""
        assert library._loaded is True

    def test_tools_loaded(self, library):
        """Test that tools are loaded across all domains."""
        tools = library.get_tools()
        assert len(tools) > 0

        # Check we have tools in multiple domains
        domains = {t.domain for t in tools}
        assert len(domains) >= 4

    def test_tools_by_domain(self, library):
        """Test filtering tools by domain."""
        fs_tools = library.get_tools(domain=ServerDomain.FILESYSTEM)
        assert len(fs_tools) > 0
        for tool in fs_tools:
            assert tool.domain == ServerDomain.FILESYSTEM

        comm_tools = library.get_tools(domain=ServerDomain.COMMUNICATION)
        assert len(comm_tools) > 0
        for tool in comm_tools:
            assert tool.domain == ServerDomain.COMMUNICATION

    def test_profiles_loaded(self, library):
        """Test that poison profiles are loaded."""
        profiles = library.get_profiles()
        assert len(profiles) > 0

    def test_profiles_by_paradigm(self, library):
        """Test filtering profiles by paradigm."""
        p1_profiles = library.get_profiles(paradigm=AttackParadigm.P1_EXPLICIT_HIJACKING)
        p2_profiles = library.get_profiles(paradigm=AttackParadigm.P2_IMPLICIT_HIJACKING)
        p3_profiles = library.get_profiles(paradigm=AttackParadigm.P3_PARAMETER_TAMPERING)

        # Should have profiles for each paradigm
        assert len(p1_profiles) > 0
        assert len(p2_profiles) > 0
        assert len(p3_profiles) > 0

    def test_test_cases_generated(self, library):
        """Test that test cases are generated from tools and profiles."""
        test_cases = library.get_test_cases()
        assert len(test_cases) > 0

    def test_test_cases_by_paradigm(self, library):
        """Test filtering test cases by paradigm."""
        p1_cases = library.get_test_cases(paradigm=AttackParadigm.P1_EXPLICIT_HIJACKING)
        p2_cases = library.get_test_cases(paradigm=AttackParadigm.P2_IMPLICIT_HIJACKING)

        assert len(p1_cases) > 0
        assert len(p2_cases) > 0

        for tc in p1_cases:
            assert tc.paradigm == AttackParadigm.P1_EXPLICIT_HIJACKING

    def test_test_cases_by_domain(self, library):
        """Test filtering test cases by domain."""
        fs_cases = library.get_test_cases(domain=ServerDomain.FILESYSTEM)
        assert len(fs_cases) > 0
        for tc in fs_cases:
            assert tc.target_tool.domain == ServerDomain.FILESYSTEM

    def test_test_cases_limit(self, library):
        """Test limiting test case results."""
        limited = library.get_test_cases(limit=5)
        assert len(limited) <= 5

    def test_iter_test_cases(self, library):
        """Test iterating over test cases."""
        count = 0
        for _tc in library.iter_test_cases():
            count += 1
            if count >= 10:
                break
        assert count == 10

    def test_stats(self, library):
        """Test library statistics."""
        stats = library.stats

        assert "total_test_cases" in stats
        assert "total_tools" in stats
        assert "total_profiles" in stats
        assert "by_paradigm" in stats
        assert "by_domain" in stats

        assert stats["total_test_cases"] > 0
        assert stats["total_tools"] > 0
        assert stats["total_profiles"] > 0

    def test_load_patterns_helper(self):
        """Test the load_patterns helper function."""
        library = load_patterns()
        assert library._loaded is True
        assert len(library.get_tools()) > 0


class TestPatternQuality:
    """Tests for pattern quality and completeness."""

    @pytest.fixture
    def library(self):
        """Create a loaded pattern library."""
        lib = PatternLibrary()
        lib.load()
        return lib

    def test_all_domains_covered(self, library):
        """Test that all 8 domains from MCPTox are covered."""
        tools = library.get_tools()
        covered_domains = {t.domain for t in tools}

        expected_domains = {
            ServerDomain.FILESYSTEM,
            ServerDomain.COMMUNICATION,
            ServerDomain.DATABASE,
            ServerDomain.CODE_EXECUTION,
            ServerDomain.WEB_API,
            ServerDomain.AUTHENTICATION,
            ServerDomain.CLOUD_SERVICES,
            ServerDomain.SYSTEM_ADMIN,
        }

        assert covered_domains == expected_domains

    def test_tools_have_descriptions(self, library):
        """Test that all tools have descriptions."""
        for tool in library.get_tools():
            assert tool.description, f"Tool {tool.name} missing description"

    def test_profiles_have_payloads(self, library):
        """Test that all profiles have payloads."""
        for profile in library.get_profiles():
            assert len(profile.payloads) > 0 or profile.source == "custom", (
                f"Profile {profile.id} missing payloads"
            )

    def test_test_cases_have_benign_queries(self, library):
        """Test that all test cases have benign queries."""
        for tc in library.get_test_cases(limit=50):
            assert tc.benign_query, f"Test case {tc.id} missing benign query"

    def test_owasp_coverage(self, library):
        """Test OWASP MCP Top 10 coverage."""
        from mcp_stress_test.models import OwaspMcpCategory

        profiles = library.get_profiles()
        covered_categories = set()

        for profile in profiles:
            for cat in profile.owasp_categories:
                covered_categories.add(cat)

        # Should cover at least MCP01 (tool poisoning)
        assert OwaspMcpCategory.MCP01_TOOL_POISONING in covered_categories
