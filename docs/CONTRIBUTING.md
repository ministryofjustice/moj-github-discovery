# Contributing

This repository is organized around a reusable `core/` module, with root scripts acting as thin entry points.

## Core Module Structure

```text
┌────────────────────────────────────────────────────────────────────────────┐
│                                CLI entry points                            │
│  list_repos.py  archive_repos.py  org_security_posture.py                  │
│  dashboard/main.py (UI layer)                                               │
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

### 5. Add a new audit script

1. Decide whether the script should be an `audit-cli` entry point or a true
   standalone script.
2. For `audit-cli` scripts, keep the root script thin, add a `run()` entry
   point matching the existing audit scripts, and register it in the
   `SCRIPTS` dict in `main.py`.
3. Add the direct invocation guard to non-standalone audit scripts so
   unsupported direct execution fails with a clear message instead of
   exiting silently:

   ```python
   from core.validation import direct_invocation_guard

   if __name__ == "__main__":
       direct_invocation_guard(__file__)
   ```

4. Add any script-specific config to `config/audit_config.yaml` with the
   corresponding model in `core/config.py`, and tests in
   `tests/test_<script_name>.py`.
5. Update `README.md` or the relevant docs if the new script changes
   supported usage or examples.

For standalone scripts, document why they are standalone and how they
should be executed directly.

## Pull Request Checklist

- Tests pass locally (`pytest -q`).
- Any new behavior has tests.
- Root scripts remain orchestration-focused.
- README and/or this file are updated for user-visible CLI or architecture changes.
- Pre-commit checks pass.
