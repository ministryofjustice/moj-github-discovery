# Audit CLI Docker POC

This folder contains all files related to the Docker proof of concept for the
audit CLI scripts and dashboard.

For full project setup and authentication guidance, refer to `docs/setup.md`.
For full CLI/script usage, refer to the root `README.md`.

## Audit-CLI Scripts

### Quick start

From the repo root:

```bash
make audit-cli
```

This will:

- build the Docker image - default name is `developer-experience-audit-cli`
- check `docker-audit-cli/.env` exists
- run the container with mounted `outputs/` and `internal/`

### Individual commands

```bash
make audit-cli-build
make audit-cli-run
```

`make audit-cli-run` forwards args to `main.py` inside the container.
Default args are set in the root `Makefile`.

Examples:

```bash
# Default behavior (same as make audit-cli-run)
make audit-cli-run AUDIT_ARGS="run --scripts list_repos"

# Equivalent to: audit-cli run --scripts list_repos archive_repos
make audit-cli-run AUDIT_ARGS="run --scripts list_repos archive_repos"

# Equivalent to: audit-cli run --all
make audit-cli-run AUDIT_ARGS="run --all"
```

The leading `run` token is optional:

```bash
make audit-cli-run AUDIT_ARGS="--scripts list_repos"
```

### Secrets and environment variables

For required credentials and setup options, refer to `docs/setup.md`.

Create a local env file from the example template:

```bash
cp docker-audit-cli/.env.example docker-audit-cli/.env
```

Put real secret values in `docker-audit-cli/.env`.

`make audit-cli-run` validates this file exists and fails with guidance if it is missing.

## Audit-CLI Dashboard

Ensuring at least one script from `audit-cli` has been ran e.g. `uv run audit-cli --scripts list_repos` (or the commands above), from the repo root, execute

```shell
make audit-dashboard
```

Similar to `make audit-cli`, this will

- build the dashboard container image, default name is `developer-experience-audit-dashboard`
- run the built image on `localhost:8050` with `internal/` mounted as a volume

The dashboard can then be accessed via `http://localhost:8050`, allowing viewing of `internal/`'s data.
