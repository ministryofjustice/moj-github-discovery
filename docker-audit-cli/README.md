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
make audit-cli-list-repos-10
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

## Run list_repos for 10 repositories

```bash
make audit-cli-list-repos-10
```

This runs `scripts/list_repos.py` in the container using
`docker-audit-cli/list-repos-10.yaml`.

Expected outputs:

- Excel file at `output/list_repos/list_repos_10.xlsx`
- SQLite data at `internal/repo_audit.db`
- Runtime logs directly in your terminal

The container entry point currently executes `main.py`. Once issue #133 lands,
update the Docker entry point to target the unified CLI.
