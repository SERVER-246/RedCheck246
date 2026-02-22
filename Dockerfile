# =============================================================================
# RedCheck246 — Multi-stage Dockerfile
# =============================================================================
# Stage 1: Builder   — installs dependencies into a virtual env
# Stage 2: Runtime   — minimal production image with non-root user
# Stage 3: Dev       — adds dev dependencies + test runner
# =============================================================================

# ---------------------------------------------------------------------------
# Stage 1: Builder
# ---------------------------------------------------------------------------
FROM python:3.12-slim AS builder

WORKDIR /build

# Install build essentials (needed for C extensions in cryptography)
RUN apt-get update && \
    apt-get install -y --no-install-recommends gcc libffi-dev && \
    rm -rf /var/lib/apt/lists/*

# Create virtual env
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Install dependencies first (cacheable layer)
# README.md and LICENSE are required by hatchling for metadata generation
COPY pyproject.toml README.md LICENSE ./
RUN mkdir -p redcheck && touch redcheck/__init__.py && \
    pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir .

# Copy full source code and reinstall with real package
COPY . .
RUN pip install --no-cache-dir --no-deps .

# ---------------------------------------------------------------------------
# Stage 2: Runtime
# ---------------------------------------------------------------------------
FROM python:3.12-slim AS runtime

LABEL org.opencontainers.image.title="RedCheck246" \
      org.opencontainers.image.description="Policy-gated security assessment framework" \
      org.opencontainers.image.source="https://github.com/SERVER-246/RedCheck246" \
      org.opencontainers.image.vendor="SERVER-246" \
      org.opencontainers.image.version="0.3.0rc1"

# Install runtime system dependencies for recon tooling
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        dnsutils \
        whois \
        nmap \
        curl \
        ca-certificates && \
    rm -rf /var/lib/apt/lists/*

# Non-root user (UID 1000)
RUN groupadd -r redcheck && \
    useradd -r -g redcheck -u 1000 -m -s /bin/bash redcheck

# Copy virtual env from builder
COPY --from=builder /opt/venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH" \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

# App directory
WORKDIR /app
COPY --from=builder /build/redcheck ./redcheck

# Create directories for engagement data
RUN mkdir -p /app/engagements /app/evidence /app/logs && \
    chown -R redcheck:redcheck /app

USER redcheck

# Health check
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD redcheck status || exit 1

ENTRYPOINT ["redcheck"]
CMD ["--help"]

# ---------------------------------------------------------------------------
# Stage 3: Dev (extends runtime)
# ---------------------------------------------------------------------------
FROM runtime AS dev

USER root

# Install dev dependencies
RUN pip install --no-cache-dir \
    pytest \
    pytest-cov \
    pytest-asyncio \
    ruff \
    mypy \
    bandit

# Copy full source (including tests)
COPY --from=builder /build/ /app/

RUN chown -R redcheck:redcheck /app

USER redcheck

CMD ["pytest", "--cov=redcheck", "tests/", "-v"]
