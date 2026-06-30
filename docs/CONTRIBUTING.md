# Contributing

This repository is organized around a reusable `core/` module, with root scripts acting as thin entry points.

## Core Module Structure

```text
┌────────────────────────────────────────────────────────────────────────────┐
│                                CLI entry points                            │
│  list_repos.py  archive_repos.py  org_security_posture.py                  │
│  dashboard.py / dashboard_cli.py (UI layers)                               │
└───────────────────────────────┬────────────────────┬───────────────────────┘
                                │                    │
                        ┌───────▼────────┐    ┌──────▼─────────┐
                        │  collector.py  │    │  compiler.py   │
                        │ (fetch + store │    │ (read SQLite → │
                        │  immediately)  │    │  Excel/CSV)    │
                        └──┬───┬────┬────┘    └──────┬─────────┘
                           │   │    │                │
                   ┌───────▼┐ ┌▼────▼───┐     ┌──────▼─────────┐
                   │github_ │ │storage  │     │ transforms.py  │
                   │api.py  │ │.py      │     │ (flags, age,   │
                   │(all EP │ │(SQLite  │     │ derived fields)│
                   │ calls) │ │ R/W)    │     └────────────────┘
                   └───┬────┘ └─────────┘
                       │
                 ┌─────▼──────────┐
                 │ github_client  │
                 │ .py (session,  │
                 │  retry, rate   │
                 │  limiting)     │
                 └────────────────┘
```

## Development Setup

1. Follow setup instructions in [setup.md](setup.md).

## Testing

Regular test runs exclude integration tests by default.

```bash
uv run pytest -q
```

Run integration tests explicitly when needed (requires owner level permissions to `ministryofjustice-test`).

```bash
uv run pytest tests/test_integration.py -m integration -o addopts='' -v
```

## Design Principles

- Keep root scripts thin: argument parsing, orchestration, and user-facing output only.
- Keep GitHub API logic in `core/github_api.py` and HTTP behavior in `core/github_client.py`.
- Keep persistence logic in `core/storage.py`.
- Keep row/report shaping in `core/presenters.py` and `core/transforms.py`.
- Prefer extending existing core abstractions over adding ad-hoc logic in root scripts.

## Adding New Functionality

### 1. Add a new repository endpoint

1. Add or update Pydantic models in `core/models.py`.
2. Add a new endpoint class in `core/github_api.py` by subclassing `BaseEndpoint`.
3. Register it in `REPO_ENDPOINTS` (or add an explicit endpoint list in the calling script/collector).
4. Add tests in `tests/test_github_api.py` and `tests/test_collector.py`.

### 2. Add a new organization endpoint

1. Add model updates in `core/models.py`.
2. Implement endpoint class in `core/github_api.py` via `BaseOrgEndpoint`.
3. Register it in `ORG_ENDPOINTS`.
4. Add tests in `tests/test_github_api.py` and, where relevant, `tests/test_collector.py`.

### 3. Add or change output fields

1. Keep raw collection in `RepoData` models.
2. Update mapping/derived logic in `core/presenters.py` and `core/transforms.py`.
3. If tabular compilation is impacted, update compiler tests (`tests/test_compiler.py`).

### 4. Add a new export/report format

1. Add a compiler class in `core/compiler.py` by subclassing `BaseCompiler`.
2. Register it in `COMPILERS`.
3. Add tests for the new compiler behavior in `tests/test_compiler.py`.

## uv Maintenance Expectations

- Do not update uv pins in only one place.
- Prefer Renovate PRs for uv-related updates.
- If a manual bump is needed, update all uv pin locations together: `.github/workflows/lint.yml` (`uv-version`), `.github/workflows/pytest.yml` (`uv-version`),
`docker-audit-cli/Dockerfile` (`uv==...`), `.pre-commit-config.yaml` (`uv-pre-commit` `rev`), and `docs/setup.md` (documented expected uv version).
- Preserve SHA pinning for GitHub Action refs and Docker image digests.

## Pull Request Checklist

- Tests pass locally (`pytest -q`).
- Any new behavior has tests.
- Root scripts remain orchestration-focused.
- README and/or this file are updated for user-visible CLI or architecture changes.
- Pre-commit checks pass.
