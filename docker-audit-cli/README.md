# Audit CLI Docker POC

This folder contains all files related to the Docker proof of concept for the
audit CLI.

## Quick start

Run everything with one command from repo root:

```bash
make audit-cli
```

This will:

- build the Docker image
- check `docker-audit-cli/.env` exists
- run the container with mounted `output/` and `internal/`

## Individual commands

```bash
make audit-cli-build
make audit-cli-run
```

`make audit-cli-run` forwards args to `main.py` inside the container.

Examples:

```bash
# Default behavior (same as make audit-cli-run)
make audit-cli-run AUDIT_ARGS="run --scripts list_repos"

# Equivalent to: audit-cli run --scripts list_repos archive_repos
make audit-cli-run AUDIT_ARGS="run --scripts list_repos archive_repos"

# Equivalent to: audit-cli run --all
make audit-cli-run AUDIT_ARGS="run --all"
```

The leading `run` token is optional, so these also work:

```bash
make audit-cli-run AUDIT_ARGS="--scripts list_repos"
make audit-cli-run AUDIT_ARGS="--all"
```

## Secrets and environment variables

Create a local env file from the example template:

```bash
cp docker-audit-cli/.env.example docker-audit-cli/.env
```

Put real secret values in `docker-audit-cli/.env`.

`make audit-cli-run` validates this file exists and fails with guidance if it is missing.

## Run (current placeholder entry point)

```bash
make audit-cli-run
```

The container uses the unified CLI entrypoint in `main.py`.
