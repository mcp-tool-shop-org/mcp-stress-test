# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 1.0.x   | :white_check_mark: |

## Reporting a Vulnerability

**Please do not report security vulnerabilities through public GitHub issues.**

If you discover a security vulnerability in MCP Stress Test, please report it by emailing:

**security@mcp-tool-shop.dev** (or open a private security advisory on GitHub)

Please include:
- Type of vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

### What to Expect

1. **Acknowledgment**: We'll acknowledge receipt within 48 hours
2. **Assessment**: We'll assess the vulnerability and determine severity
3. **Fix**: We'll develop and test a fix
4. **Disclosure**: We'll coordinate disclosure with you

### Timeline

- Critical vulnerabilities: Fix within 7 days
- High severity: Fix within 14 days
- Medium/Low: Fix in next release

## Responsible Use

MCP Stress Test is a security testing tool. Please use it responsibly:

### DO
- Test systems you own or have explicit permission to test
- Use for defensive security research
- Use for CTF challenges and educational purposes
- Report vulnerabilities you discover responsibly

### DON'T
- Test systems without authorization
- Use for malicious purposes
- Distribute attack payloads outside of testing contexts
- Use to harm others

## Security Best Practices

When using MCP Stress Test:

1. **Isolate testing environments** - Don't test against production systems
2. **Protect generated outputs** - Attack patterns and evasions contain sensitive information
3. **Review before sharing** - Sanitize reports before sharing externally
4. **Keep updated** - Use the latest version for security fixes

## Acknowledgments

We thank the security research community for responsibly disclosing vulnerabilities.

Contributors will be acknowledged (with permission) in release notes.
