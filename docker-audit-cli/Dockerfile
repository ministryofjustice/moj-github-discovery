FROM python:3.14-slim@sha256:a01e48f10f90ac3ee65ef6937b9d7c831a3570c81b98d39a547ff09fb359de7f AS base

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    UV_LINK_MODE=copy \
    UV_PROJECT_ENVIRONMENT=/opt/venv \
    UV_PYTHON_INSTALL_DIR=/opt/uv-python

WORKDIR /app

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*

RUN python -m pip install --no-cache-dir --upgrade pip uv

# Copy dependency metadata first for better layer caching.
COPY pyproject.toml uv.lock README.md ./
RUN uv sync --frozen --no-dev --no-install-project

# Copy the rest of the application code.
COPY core core
COPY dashboard dashboard
COPY scripts scripts
COPY config config
COPY main.py ./

# Full dependency installation, including the project itself.
RUN uv sync --frozen --no-dev

FROM base AS cli

ENV HOME=/home/audit-runner \
    XDG_CACHE_HOME=/home/audit-runner/.cache \
    PATH="/opt/venv/bin:$PATH"

# Create non-root user for security (org-wide, scheduled deployments).
RUN groupadd -r audit-runner && useradd -r -m -d /home/audit-runner -g audit-runner audit-runner

# Create volume directories and set ownership.
RUN mkdir -p outputs internal && \
    mkdir -p "$XDG_CACHE_HOME" && \
    chown -R audit-runner:audit-runner /app /home/audit-runner /opt/venv /opt/uv-python

# Switch to non-root user.
USER audit-runner

VOLUME ["/app/outputs", "/app/internal"]

# Unified CLI entrypoint; runtime args are appended by docker run / Make targets.
ENTRYPOINT ["audit-cli"]

FROM base AS dashboard

ENV HOME=/home/dashboard-runner \
    XDG_CACHE_HOME=/home/dashboard-runner/.cache \
    PATH="/opt/venv/bin:$PATH"

# Create non-root user for security (org-wide, scheduled deployments).
RUN groupadd -r dashboard-runner && useradd -r -m -d /home/dashboard-runner -g dashboard-runner dashboard-runner

# Create volume directories and set ownership.
RUN mkdir -p internal && \
    mkdir -p "$XDG_CACHE_HOME" && \
    chown -R dashboard-runner:dashboard-runner /app /home/dashboard-runner /opt/venv /opt/uv-python

# Switch to non-root user.
USER dashboard-runner

# Expose internal volume for referencing audit data
VOLUME ["/app/internal"]

# Expose port for dashboard web server
EXPOSE 8050

# Unified CLI entrypoint; runtime args are appended by docker run / Make targets.
ENTRYPOINT ["audit-cli", "--dashboard"]