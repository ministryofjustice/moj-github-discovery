# Setup

## Prerequisites

### Brew

Most of the prerequisites will require `homebrew` and the `brew` utility, this can be installed via the below command (also found in the `brew` [docs](https://brew.sh/).)

```shell
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
```

- Follow the instructions post-install before continuing.

### uv

[UV](https://docs.astral.sh/uv/) has been chosen for package management to align with standard MoJ usage, and its high performance in comparison to `requirements.txt`.

It can be installed via `brew` : `brew install uv`

Verify via `uv --version`

Install dependencies (including local dev dependencies) via `uv sync --group dev`

### Github Setup

- [GitHub CLI](https://cli.github.com/) (`gh`) installed and authenticated
- GitHub personal access token (PAT) with appropriate scopes (minimum: `repo`) - [Guidance](https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/managing-your-personal-access-tokens)
- Note: If you are contributing to this repository, signed commits are required - guidance is available on how to do this via SSH or GPG keys here: [guidance](https://docs.github.com/en/authentication/managing-commit-signature-verification/signing-commits).

GitHub App credentials available for `Developer Experience GitHub Audit`:

- `GH_APP_ID` (or `GITHUB_APP_ID`)
- `GH_APP_PRIVATE_KEY` (or `GITHUB_APP_PRIVATE_KEY`) with full PEM key content
- `GH_APP_INSTALLATION_ID` (or `GITHUB_APP_INSTALLATION_ID`) **or** `GH_ORG` / `GITHUB_ORG` / `GITHUB_OWNER` for installation auto-discovery

**Note:** `GH_APP_PRIVATE_KEY` can be extracted from the **Developer Experience Team** 1Password Vault.

### Environment Variables

Set your GitHub token as an environment variable:

```bash
# Using a personal access token
export GITHUB_TOKEN=ghp_xxxxxxxxxxxxxxxxxxxx

# Or if using the GitHub CLI default:
export GH_TOKEN=ghp_xxxxxxxxxxxxxxxxxxxx
```

The tools will automatically use whichever token is available (checks both `GH_TOKEN` and `GITHUB_TOKEN`).

Set the required GitHub App Credentials as environment variables:

```shell
export GH_APP_ID="<app id>"
export GH_ORG="<github organisation>"
export GH_APP_PRIVATE_KEY="$(cat /path/to/private-key.pem)"

# Optional: Set explicitly if you do not want installation auto-discovery
# export GH_APP_INSTALLATION_ID="<your_installation_id>"

# Optional: force GitHub App path by clearing PAT vars
# unset GH_TOKEN GITHUB_TOKEN
```

Authentication resolution order is:

1. `GITHUB_TOKEN` or `GH_TOKEN`
2. GitHub App credentials (`GH_APP_ID` + `GH_APP_PRIVATE_KEY`)
3. GitHub CLI token from `~/.config/gh/hosts.yml`

If you want to ensure app-only auth is used, keep PAT variables unset.

### Compliance Tooling

To align with MOJ standards, the following tools are required:

- **Pre-commit**
  - **NPM**
  - **Markdownlint CLI 2**
  - **Docker-Desktop** (to allow pre-commit hook to run)

Install the key dependencies via `brew`:

```shell
brew install pre-commit npm docker-desktop
```

And the `npm` dependencies:

```shell
npm install --ignore-scripts
```

Verify pre-commit and install:

```shell
pre-commit install
```

Optionally, run pre-commit against all files:

```shell
pre-commit run --all-files
```

Authenticate to the Github Docker Container Registry with your PAT, providing your username after the `-u` flag and your Github password upon command execution:

```shell
gh auth token | docker login ghcr.io -u <github username> --password-stdin
```
