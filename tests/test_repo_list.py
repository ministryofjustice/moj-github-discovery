from __future__ import annotations

import pytest

from core.repo_list import load_repo_list_file, load_repo_list_yaml


def test_load_repo_list_yaml_with_repos_key(tmp_path):
    path = tmp_path / "repos.yaml"
    path.write_text(
        """
repos:
  - ministryofjustice/hmpps-auth
  - ministryofjustice/hmpps-auth
  - ministryofjustice/hmpps-github-discovery
""".strip()
    )

    result = load_repo_list_yaml(path)

    assert result == [
        "ministryofjustice/hmpps-auth",
        "ministryofjustice/hmpps-github-discovery",
    ]


def test_load_repo_list_yaml_with_root_list(tmp_path):
    path = tmp_path / "repos.yaml"
    path.write_text(
        """
- ministryofjustice/hmpps-auth
- ministryofjustice/hmpps-github-discovery
""".strip()
    )

    result = load_repo_list_yaml(path)

    assert result == [
        "ministryofjustice/hmpps-auth",
        "ministryofjustice/hmpps-github-discovery",
    ]


def test_load_repo_list_yaml_invalid_entry(tmp_path):
    path = tmp_path / "repos.yaml"
    path.write_text(
        """
repos:
  - invalid
""".strip()
    )

    with pytest.raises(ValueError, match="Invalid repo entry"):
        load_repo_list_yaml(path)


def test_load_repo_list_file_text_compatibility(tmp_path):
    path = tmp_path / "repos.txt"
    path.write_text(
        """
# ignored comment
ministryofjustice/hmpps-auth
ministryofjustice/hmpps-github-discovery
""".strip()
    )

    result = load_repo_list_file(path)

    assert result == [
        "ministryofjustice/hmpps-auth",
        "ministryofjustice/hmpps-github-discovery",
    ]
