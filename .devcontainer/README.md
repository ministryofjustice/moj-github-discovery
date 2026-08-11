# Dev Container

> [!NOTE]
> This is a faster alternative to the manual setup in [`docs/setup.md`](../docs/setup.md).

To assist with working on this repository, the community has configured a dev container with the required tooling.

It uses the shared Ministry of Justice [devcontainer base image](https://github.com/ministryofjustice/.devcontainer).

## Locally

> [!WARNING]
> This has only been tested on macOS

### Prerequisites

- Docker
- Visual Studio Code
  - [Dev Containers extension](https://marketplace.visualstudio.com/items?itemName=ms-vscode-remote.remote-containers)

To launch locally, ensure the prerequisites are met, then click the button below.

[![Open in Dev Container](https://raw.githubusercontent.com/ministryofjustice/.devcontainer/refs/heads/main/contrib/badge.svg)](https://vscode.dev/redirect?url=vscode://ms-vscode-remote.remote-containers/cloneInVolume?url=https://github.com/ministryofjustice/moj-github-discovery)

### Prefer the terminal, or a different editor?

This also works via the Dev Containers CLI without needing VS Code at all.

**First time only**, install the CLI:

```shell
npm install -g @devcontainers/cli
```

**Every time**, from inside the cloned repo:

```shell
devcontainer up --workspace-folder . && devcontainer exec --workspace-folder . bash
```

## GitHub Codespaces

> [!IMPORTANT]
> GitHub Codespaces are not currently paid for by the Ministry of Justice and are subject to [billing quotas](https://docs.github.com/en/billing/managing-billing-for-your-products/managing-billing-for-github-codespaces/about-billing-for-github-codespaces#monthly-included-storage-and-core-hours-for-personal-accounts).

To launch a GitHub Codespace, use the "Code" button on the repo, then the "Codespaces" tab.

## What's inside

- Base image: [`ghcr.io/ministryofjustice/devcontainer-base:latest`](https://github.com/ministryofjustice/.devcontainer)
- The shared Ministry of Justice base image, maintained by the Dev Container Community of Practice.
- Runs as a non-root `vscode` user by design.
- **Features:**
  - [`astral`](https://github.com/ministryofjustice/.devcontainer/tree/main/features/src/astral) - installs `uv` and `ruff`
  - [`node:2`](https://github.com/devcontainers/features/tree/main/src/node) - installs Node.js and npm, pinned to version 22 (required by `cspell` and `markdownlint-cli2`)
- **`postCreateCommand`** (`post-create.sh`) runs:
  - `uv sync --group dev` — installs Python dependencies, including `pytest`, `ruff`, `pre-commit`
  - `npm install --ignore-scripts` — installs `markdownlint-cli2` and `cspell`
  - `pre-commit install` — wires up git hooks

## Support

If you need help or assistance, please post in [`#devcontainer-community`](https://moj.enterprise.slack.com/archives/C06DZ4F04JZ) or [`#ask-developer-experience`](https://moj.enterprise.slack.com/archives/C0AJBK3P5A8).
