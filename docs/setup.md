# Setup

## Prerequisites

### Python

- Python 3.7+ (Self Service or [Direct Download](https://www.python.org/downloads/))
- NodeJS (Self-Service or [Direct Download](https://nodejs.org/en/download))

### Brew

Most of the prerequisites will require `homebrew` and the `brew` utility, this can be installed via the below command (also found in the `brew` [docs](https://brew.sh/).)

```shell
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
```

- Follow the instructions post-install before continuing.

### Github Setup

- [GitHub CLI](https://cli.github.com/) (`gh`) installed and authenticated
- GitHub personal access token (PAT) with appropriate scopes (minimum: `repo`) - [Guidance](https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/managing-your-personal-access-tokens)
- Note: If you are contributing to this repository, signed commits are required - guidance is available on how to do this via SSH or GPG keys here: [guidance](https://docs.github.com/en/authentication/managing-commit-signature-verification/signing-commits).

### Environment Variables

Set your GitHub token as an environment variable:

```bash
# Using a personal access token
export GITHUB_TOKEN=ghp_xxxxxxxxxxxxxxxxxxxx

# Or if using the GitHub CLI default:
export GH_TOKEN=ghp_xxxxxxxxxxxxxxxxxxxx
```

The tools will automatically use whichever token is available (checks both `GH_TOKEN` and `GITHUB_TOKEN`).

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

Authenticate to the Github Docker Container Registry with your PAT, providing your username after the `-u` flag and your Github password upon command execution:

```shell
gh auth token | docker login ghcr.io -u <github username> --password-stdin
```

### Installation

The requirements can now be installed for the python scripts, and development can be carried out.

```bash
pip install -r requirements-dashboard.txt
```
