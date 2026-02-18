# Contributing to MCP Stress Test

Thanks for your interest in contributing! This document provides guidelines for contributing to the MCP Stress Test framework.

## Ways to Contribute

### 1. Report Bugs
Found a bug? [Open an issue](https://github.com/mcp-tool-shop/mcp-stress-test/issues/new?template=bug_report.yml) with:
- Clear description of the problem
- Steps to reproduce
- Expected vs actual behavior
- Your environment (OS, Python version)

### 2. Suggest Features
Have an idea? [Open a feature request](https://github.com/mcp-tool-shop/mcp-stress-test/issues/new?template=feature_request.yml) describing:
- The problem you're trying to solve
- Your proposed solution
- Alternatives you've considered

### 3. Submit Attack Patterns
Discovered a new attack vector? [Submit it](https://github.com/mcp-tool-shop/mcp-stress-test/issues/new?template=attack_pattern.yml) with:
- Attack description and paradigm
- Example payload
- Detection hints
- Research source (if applicable)

### 4. Submit Code
Ready to code? Follow the development workflow below.

## Development Setup

```bash
# Clone the repo
git clone https://github.com/mcp-tool-shop/mcp-stress-test
cd mcp-stress-test

# Create virtual environment
python -m venv venv
source venv/bin/activate  # or `venv\Scripts\activate` on Windows

# Install with dev dependencies
pip install -e ".[dev,fuzzing]"

# Install pre-commit hooks
pre-commit install
```

## Development Workflow

### 1. Create a Branch

```bash
git checkout -b feature/your-feature-name
# or
git checkout -b fix/your-bug-fix
```

### 2. Make Changes

Follow these guidelines:
- **Code style**: We use `ruff` for linting and formatting
- **Type hints**: All public APIs should have type hints
- **Docstrings**: Use Google-style docstrings
- **Tests**: Add tests for new functionality

### 3. Run Checks

```bash
# Format code
ruff format .

# Lint
ruff check .

# Type check
pyright src/

# Run tests
pytest tests/ -v
```

### 4. Commit Changes

We use conventional commits:

```bash
git commit -m "feat: add new mutation strategy"
git commit -m "fix: handle edge case in scanner"
git commit -m "docs: update README with examples"
git commit -m "test: add tests for attack chains"
```

Prefixes:
- `feat:` New feature
- `fix:` Bug fix
- `docs:` Documentation
- `test:` Tests
- `refactor:` Code refactoring
- `chore:` Maintenance

### 5. Submit PR

```bash
git push origin feature/your-feature-name
```

Then [open a pull request](https://github.com/mcp-tool-shop/mcp-stress-test/pulls).

## Code Guidelines

### Project Structure

```
src/mcp_stress_test/
├── core/           # Protocols, config, registry
├── chains/         # Attack chain definitions
├── fuzzing/        # LLM fuzzer, evasion engine
├── generator/      # Mutation strategies
├── patterns/       # Attack pattern library
├── reporters/      # Output formatters
├── scanners/       # Scanner adapters
├── servers/        # Synthetic server farm
└── cli/            # Command-line interface
```

### Adding Attack Patterns

1. Add patterns to `patterns/library.py`
2. Include research citations
3. Add detection hints
4. Write tests

### Adding Mutation Strategies

1. Inherit from `MutationStrategyBase` in `generator/strategies.py`
2. Implement `mutate()` and `detect_signature()`
3. Register in `STRATEGY_REGISTRY`
4. Add tests

### Adding Reporters

1. Inherit from `BaseReporter` in `reporters/base.py`
2. Implement `generate()` method
3. Register in the reporter registry
4. Add tests

### Adding Scanner Adapters

1. Implement the `Scanner` protocol from `core/protocols.py`
2. Add adapter to `scanners/` directory
3. Add CLI integration
4. Add tests

## Testing

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=mcp_stress_test --cov-report=html

# Run specific test file
pytest tests/test_generator.py -v

# Run specific test
pytest tests/test_generator.py::test_direct_injection -v
```

## Documentation

- Update README.md for user-facing changes
- Update CHANGELOG.md with your changes
- Add docstrings to public APIs
- Include examples in docstrings

## Review Process

1. All PRs require at least one review
2. CI checks must pass
3. Tests must maintain or improve coverage
4. Documentation must be updated

## Security

For security vulnerabilities, please see [SECURITY.md](SECURITY.md).

## Questions?

- Open a [discussion](https://github.com/mcp-tool-shop/mcp-stress-test/discussions)
- Check existing [issues](https://github.com/mcp-tool-shop/mcp-stress-test/issues)

## License

By contributing, you agree that your contributions will be licensed under the MIT License.
