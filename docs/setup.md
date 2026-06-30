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

Repository policy for uv versioning:

- This repository pins `uv` CLI `0.11.24` for CI and Docker parity.
- Related `uv` integrations are updated alongside the CLI where compatible; `uv-pre-commit` is currently SHA pinned to the commit for `0.11.24`.
- GitHub Action references and Docker base images remain SHA pinned where supported.

If your local `uv --version` output differs from `0.11.24`, upgrade or reinstall `uv` so local runs stay aligned with CI and Docker where practical.

#### Upgrading local `uv`

Use one of the supported approaches below, then verify with `uv --version`.

```shell
# Homebrew (latest available formula)
brew upgrade uv

# Or install an explicit version in user site-packages
python3 -m pip install --user --upgrade "uv==0.11.24"
```

If `uv --version` still reports an older Homebrew version after a `pip --user` install, your shell is likely resolving `uv` from `/opt/homebrew/bin` first.
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

Pre-commit includes a `uv version sync` check that fails if local `uv` is out of sync with the managed pin, or if `docs/setup.md` is behind the managed version.

Install dependencies (including local dev dependencies) via `uv sync --group dev`

`uv.lock` is managed by normal `uv` workflows and is not the source of truth for the `uv` binary version.
Use the standard commands below when dependency resolution changes:

```shell
uv sync --group dev
uv lock
```

### Github Setup

- [GitHub CLI](https://cli.github.com/) (`gh`) installed and authenticated
- GitHub personal access token (PAT) with appropriate scopes (minimum: `repo`) - [Guidance](https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/managing-your-personal-access-tokens)
- Note: If you are contributing to this repository, signed commits are required - guidance is
  available on how to do this via SSH or GPG keys here:
  [guidance](https://docs.github.com/en/authentication/managing-commit-signature-verification/signing-commits).

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

Authenticate to the Github Docker Container Registry with your PAT
Provide your username after the `-u` flag and your Github PAT (if using `GITHUB_TOKEN` / `GH_TOKEN`) upon command execution:

```shell
gh auth token | docker login ghcr.io -u <github username> --password-stdin
```
