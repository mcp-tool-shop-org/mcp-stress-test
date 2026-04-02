# =============================================================================
# MCP Stress Test - Multi-stage Docker Build
# =============================================================================
#
# Usage:
#   docker build -t mcp-stress-test .
#   docker run --rm mcp-stress-test stress run
#   docker run --rm mcp-stress-test scan compare -t read_file -s obfuscation
#
# With Ollama for LLM fuzzing:
#   docker run --rm --network host mcp-stress-test fuzz evasion -p "payload" --use-llm
#
# =============================================================================

# -----------------------------------------------------------------------------
# Stage 1: Build
# -----------------------------------------------------------------------------
FROM python:3.14-slim as builder

WORKDIR /build

# Install build dependencies
RUN pip install --no-cache-dir build

# Copy source
COPY pyproject.toml README.md ./
COPY src/ src/

# Build wheel
RUN python -m build --wheel

# -----------------------------------------------------------------------------
# Stage 2: Runtime
# -----------------------------------------------------------------------------
FROM python:3.14-slim as runtime

# Labels
LABEL org.opencontainers.image.title="MCP Stress Test"
LABEL org.opencontainers.image.description="Red team toolkit for stress-testing MCP security scanners"
LABEL org.opencontainers.image.source="https://github.com/mcp-tool-shop/mcp-stress-test"
LABEL org.opencontainers.image.licenses="MIT"
LABEL org.opencontainers.image.vendor="MCP Tool Shop"

# Create non-root user
RUN groupadd --gid 1000 mcp && \
    useradd --uid 1000 --gid mcp --shell /bin/bash --create-home mcp

WORKDIR /app

# Copy wheel from builder
COPY --from=builder /build/dist/*.whl /tmp/

# Install package
RUN pip install --no-cache-dir /tmp/*.whl && \
    rm /tmp/*.whl

# Create output directory
RUN mkdir -p /app/output && chown mcp:mcp /app/output

# Switch to non-root user
USER mcp

# Set environment
ENV PYTHONUNBUFFERED=1
ENV MCP_STRESS_OUTPUT=/app/output

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD mcp-stress --version || exit 1

# Default entrypoint
ENTRYPOINT ["mcp-stress"]
CMD ["--help"]
