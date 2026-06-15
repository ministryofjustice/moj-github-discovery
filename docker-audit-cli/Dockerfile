FROM python:3.14-slim@sha256:a01e48f10f90ac3ee65ef6937b9d7c831a3570c81b98d39a547ff09fb359de7f

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    UV_LINK_MODE=copy \
    UV_PROJECT_ENVIRONMENT=/opt/venv

WORKDIR /app

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*

RUN python -m pip install --no-cache-dir --upgrade pip uv

# Copy dependency metadata first for better layer caching.
COPY pyproject.toml uv.lock README.md ./
RUN uv sync --frozen --no-dev --no-install-project

COPY . .

# Create non-root user for security (org-wide, scheduled deployments).
RUN groupadd -r audit-runner && useradd -r -g audit-runner audit-runner

# Create volume directories and set ownership.
RUN mkdir -p /app/output /app/internal && \
    chown -R audit-runner:audit-runner /app

# Switch to non-root user.
USER audit-runner

VOLUME ["/app/output", "/app/internal"]

# Unified CLI entrypoint; runtime args are appended by docker run / Make targets.
ENTRYPOINT ["uv", "run", "python", "main.py"]