#!/usr/bin/env bash
set -euo pipefail

echo "Running 'uv sync --group dev'"
uv sync --group dev

echo "Installing npm dependencies"
npm install --ignore-scripts

echo "Running 'pre-commit install'"
uv run pre-commit install