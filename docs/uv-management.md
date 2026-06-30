# uv Management

This document is the source of truth for `uv` version policy and local management guidance.

## Policy

- This repository pins `uv` CLI `0.11.24` for CI and Docker parity.
- Related `uv` integrations are updated alongside the CLI where compatible.
- `uv-pre-commit` is currently SHA pinned to the commit for `0.11.24`.
- GitHub Action references and Docker base images remain SHA pinned where supported.

## Managed Pin Locations

When `uv` is bumped manually, update these together:

- `.github/workflows/lint.yml` (`uv-version`)
- `.github/workflows/pytest.yml` (`uv-version`)
- `docker-audit-cli/Dockerfile` (`uv==...`)
- `.pre-commit-config.yaml` (`uv-pre-commit` `rev`)
- `docs/uv-management.md` (documented expected `uv` version)

Prefer Renovate PRs for routine updates.

## Local `uv` Parity

If local `uv --version` differs from `0.11.24`, upgrade/reinstall local `uv` so local runs stay aligned with CI and Docker where practical.

### Upgrade local `uv`

Use one of the supported approaches below, then verify with `uv --version`.

```shell
# Homebrew (latest available formula)
brew upgrade uv

# Or install an explicit version in user site-packages
python3 -m pip install --user --upgrade "uv==0.11.24"
```

If `uv --version` still reports an older Homebrew version after `pip --user` install, your shell is likely resolving `uv` from `/opt/homebrew/bin` first.
Prefer the user binary path and refresh shell command lookup:

```shell
export PATH="$HOME/.local/bin:$PATH"
hash -r
uv --version
```

To persist this for future shells:

```shell
echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.zshrc
source ~/.zshrc
```

## Pre-commit Enforcement

Pre-commit includes a `uv version sync` check that fails if:

- managed `uv` pins are not aligned,
- local `uv` is out of sync with the managed pin,
- `docs/uv-management.md` is older than or mismatched with the managed version.

Hook reference:

- `.pre-commit-config.yaml` hook id: `uv-version-sync`
- checker script: `utils/check_uv_sync.py`

## `uv.lock` Scope

`uv.lock` is managed by normal `uv` workflows and is not the source of truth for the `uv` binary version.

Use standard dependency-resolution commands when needed:

```shell
uv sync --group dev
uv lock
```
