# Audit CLI Docker POC

This folder contains all files related to the Docker proof of concept for the
audit CLI scripts and dashboard.

## Status

This Docker and Kubernetes setup is intentionally a placeholder/POC.

- It is not production-ready.
- It is not yet intended for active feature development.
- CI/CD is not yet established for image build/publish/deploy.
- Kubernetes manifests currently provide an initial deployment shape only.

Use this folder as a starting point for future platform work, not as a final
runtime architecture.

Both the CLI scripts and the dashboard run from a single unified Docker image
built via `docker-audit-cli/Dockerfile`.

## Initial Workflows in This POC

The initial workflows included here are manual/local workflows:

- Build the image using `make audit-cli-build`.
- Run CLI scripts via `make audit-cli-run`.
- Run the dashboard via `make audit-dashboard-run`.

The repo root `Makefile` provides these convenience targets:

- `make audit-cli-build`
- `make audit-cli-run`
- `make audit-dashboard-build`
- `make audit-dashboard-run`

At this stage, these workflows are intentionally lightweight and are not yet
integrated into a release pipeline.

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

- build the Docker image (`developer-experience-audit-cli`) if not already built
- run the container on `localhost:8050` with `internal/` mounted as a read volume
- the dashboard reads collected data from `internal/` and requires at least one script to have been run first

## Build and Run

From the repo root, the explicit build command is:

```bash
# Unified image (CLI and dashboard)
docker build --platform linux/amd64 -f docker-audit-cli/Dockerfile -t developer-experience-audit-cli .
```

To run the dashboard directly:

```bash
docker run --rm \
  --platform linux/amd64 \
  --env-file docker-audit-cli/.env \
  -p 8050:8050 \
  -v "$(PWD)/internal:/app/internal" \
  developer-experience-audit-cli --dashboard
```

If you are using the root `Makefile`, these are wrapped by:

```bash
make audit-cli-build
make audit-dashboard-run
```

The dashboard can then be accessed via `http://localhost:8050`, allowing viewing of `internal/`'s data.

## CI/CD and Cloud Platform Considerations

### Deployment Workflows (POC)

Initial placeholder workflow files are included at:

- `docker-audit-cli/workflows/publish-package.yml`
- `docker-audit-cli/workflows/publish-container.yml`

These are draft workflows intended to describe a future deployment shape:

- Build/push audit-cli Python package to GitHub Packages.
- Build/push audit-cli Docker image to GitHub Container Registry

Important limitations:

- These files are POC-only and not yet treated as active delivery pipelines.
- They are currently stored under `docker-audit-cli/workflows` as draft assets.
- Final GitHub Actions wiring/location and promotion controls are still to be
    defined.

### Kubernetes Manifests (POC)

Initial Kubernetes manifests are included at:

- `docker-audit-cli/k8s/dev/deployment.yaml`
- `docker-audit-cli/k8s/prod/deployment.yaml`

They currently include:

- Deployment, Service, and Ingress resources for the dashboard.
- `IMAGE_PLACEHOLDER` image references for manual substitution.
- Basic pod/container hardening defaults (`runAsNonRoot`, dropped capabilities,
  no service account token mount).

POC constraints and follow-up work:

- No automated image promotion or manifest templating.
- No readiness/liveness probes yet.
- No resource requests/limits yet.
- No environment-specific overlay tooling yet.
