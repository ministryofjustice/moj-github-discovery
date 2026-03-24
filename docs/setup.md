# Setup

## Prerequisites

### Python

- Python 3.7+ (Self Service or [Direct Download](https://www.python.org/downloads/))

### Brew

Most of the prerequisites will require `homebrew` and the `brew` utility, this can be installed via the below command (also found in the `brew` [docs](https://brew.sh/).)

```shell
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
```

- Follow the instructions post-install before continuing.

### Github Setup

- [GitHub CLI](https://cli.github.com/) (`gh`) installed and authenticated
- GitHub App credentials available for `Developer Experience GitHub Audit`
  - `GH_APP_ID` (or `GITHUB_APP_ID`)
  - `GH_APP_PRIVATE_KEY` (or `GITHUB_APP_PRIVATE_KEY`) with full PEM key content
  - `GH_APP_INSTALLATION_ID` (or `GITHUB_APP_INSTALLATION_ID`) **or** `GH_ORG` / `GITHUB_ORG` / `GITHUB_OWNER` for installation auto-discovery
- Note: If you are contributing to this repository, signed commits are required - guidance is available on how to do this via SSH or GPG keys here: [guidance](https://docs.github.com/en/authentication/managing-commit-signature-verification/signing-commits).

### Environment Variables

Set GitHub App credentials as environment variables:

```bash
export GH_APP_ID="<your_app_id>"
export GH_ORG="<your_org>"
export GH_APP_PRIVATE_KEY="$(cat /path/to/github-app-private-key.pem)"

# Optional: set explicitly if you don't want installation auto-discovery
# export GH_APP_INSTALLATION_ID="<your_installation_id>"

# Optional: force GitHub App path by clearing PAT vars
unset GH_TOKEN GITHUB_TOKEN
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
  - **Markdownlint CLI**
  - **Docker-Desktop** (to allow pre-commit hook to run)

All can be installed via `brew`:

```shell
brew install pre-commit npm markdownlint-cli docker-desktop
```

Verify pre-commit and install:

```shell
pre-commit install
```

Optionally, run pre-commit against all files:

```shell
pre-commit run --all-files
```

Authenticate to the Github Docker Container Registry using your GitHub CLI auth token, providing your username after the `-u` flag:

```shell
gh auth token | docker login ghcr.io -u <github username> --password-stdin
```

### Installation

The requirements can now be installed for the python scripts, and development can be carried out.

```bash
pip install -r requirements-dashboard.txt
```
