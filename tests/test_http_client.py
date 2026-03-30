"""Tests for core/github_client.py — HTTP transport layer."""

from __future__ import annotations

import time
from unittest.mock import MagicMock, patch

import pytest
import requests

from core.github_client import BaseHttpClient, GitHubHttpClient


# ── BaseHttpClient contract ───────────────────────────────────────────


class TestBaseHttpClient:
    def test_base_url(self):
        assert BaseHttpClient.BASE_URL == "https://api.github.com"

    def test_cannot_instantiate(self):
        with pytest.raises(TypeError):
            BaseHttpClient()


# ── Token resolution ──────────────────────────────────────────────────


class TestTokenResolution:
    def test_explicit_token(self):
        client = GitHubHttpClient(token="my-token")
        assert client._token == "my-token"

    def test_github_token_env(self, monkeypatch):
        monkeypatch.setenv("GITHUB_TOKEN", "env-token")
        monkeypatch.delenv("GH_TOKEN", raising=False)
        client = GitHubHttpClient()
        assert client._token == "env-token"

    def test_gh_token_env(self, monkeypatch):
        monkeypatch.delenv("GITHUB_TOKEN", raising=False)
        monkeypatch.setenv("GH_TOKEN", "gh-token")
        client = GitHubHttpClient()
        assert client._token == "gh-token"

    def test_github_token_takes_precedence(self, monkeypatch):
        monkeypatch.setenv("GITHUB_TOKEN", "primary")
        monkeypatch.setenv("GH_TOKEN", "secondary")
        client = GitHubHttpClient()
        assert client._token == "primary"

    def test_no_token_raises(self, monkeypatch, tmp_path):
        monkeypatch.delenv("GITHUB_TOKEN", raising=False)
        monkeypatch.delenv("GH_TOKEN", raising=False)
        # Point config path to a non-existent location
        monkeypatch.setattr(
            "os.path.expanduser",
            lambda p: str(tmp_path / "nonexistent" / "hosts.yml"),
        )
        with pytest.raises(RuntimeError, match="No GitHub token found"):
            GitHubHttpClient()

    def test_token_from_gh_cli_config(self, monkeypatch, tmp_path):
        monkeypatch.delenv("GITHUB_TOKEN", raising=False)
        monkeypatch.delenv("GH_TOKEN", raising=False)
        config_path = tmp_path / "hosts.yml"
        config_path.write_text("github.com:\n  oauth_token: cli-token\n")
        monkeypatch.setattr("os.path.expanduser", lambda p: str(config_path))
        client = GitHubHttpClient()
        assert client._token == "cli-token"


# ── Session headers ───────────────────────────────────────────────────


class TestSession:
    def test_session_headers(self):
        client = GitHubHttpClient(token="test-token")
        sess = client._get_session()
        assert sess.headers["Authorization"] == "token test-token"
        assert "X-GitHub-Api-Version" in sess.headers
        assert sess.headers["X-GitHub-Api-Version"] == "2022-11-28"

    def test_session_reused(self):
        client = GitHubHttpClient(token="test-token")
        s1 = client._get_session()
        s2 = client._get_session()
        assert s1 is s2


# ── Rate limit delay ─────────────────────────────────────────────────


class TestRateLimitDelay:
    def _make_response(self, headers: dict) -> MagicMock:
        resp = MagicMock(spec=requests.Response)
        resp.headers = headers
        return resp

    def test_retry_after_header(self):
        resp = self._make_response({"Retry-After": "30"})
        delay = GitHubHttpClient._rate_limit_delay(resp, attempt=1)
        assert delay == 30

    def test_retry_after_zero_becomes_one(self):
        resp = self._make_response({"Retry-After": "0"})
        delay = GitHubHttpClient._rate_limit_delay(resp, attempt=1)
        assert delay == 1

    def test_rate_limit_reset_header(self):
        future = int(time.time()) + 60
        resp = self._make_response(
            {
                "X-RateLimit-Remaining": "0",
                "X-RateLimit-Reset": str(future),
            }
        )
        delay = GitHubHttpClient._rate_limit_delay(resp, attempt=1)
        assert 55 <= delay <= 65  # approximately 60s

    def test_exponential_backoff(self):
        resp = self._make_response({})
        d1 = GitHubHttpClient._rate_limit_delay(resp, attempt=1)
        d2 = GitHubHttpClient._rate_limit_delay(resp, attempt=2)
        d3 = GitHubHttpClient._rate_limit_delay(resp, attempt=3)
        assert d1 == 15
        assert d2 == 30
        assert d3 == 60

    def test_backoff_capped_at_300(self):
        resp = self._make_response({})
        delay = GitHubHttpClient._rate_limit_delay(resp, attempt=10)
        assert delay == 300


# ── Link header pagination ────────────────────────────────────────────


class TestLinkHeaderParsing:
    def test_next_link(self):
        header = (
            '<https://api.github.com/repos?page=2>; rel="next", '
            '<https://api.github.com/repos?page=5>; rel="last"'
        )
        url = GitHubHttpClient._next_page_url(header)
        assert url == "https://api.github.com/repos?page=2"

    def test_no_next(self):
        header = '<https://api.github.com/repos?page=5>; rel="last"'
        assert GitHubHttpClient._next_page_url(header) is None

    def test_none_header(self):
        assert GitHubHttpClient._next_page_url(None) is None

    def test_empty_header(self):
        assert GitHubHttpClient._next_page_url("") is None


# ── GET with retry ────────────────────────────────────────────────────


class TestRequestRetry:
    def test_successful_get(self):
        client = GitHubHttpClient(token="t")
        mock_resp = MagicMock()
        mock_resp.raise_for_status.return_value = None
        mock_resp.json.return_value = {"id": 1}

        with patch.object(client, "_get_session") as mock_sess:
            mock_sess.return_value.request.return_value = mock_resp
            result = client.get("/repos/org/repo")

        assert result == {"id": 1}

    def test_retry_on_403(self):
        client = GitHubHttpClient(token="t", max_attempts=3)

        fail_resp = MagicMock()
        fail_resp.status_code = 403
        fail_resp.headers = {"Retry-After": "1"}
        http_error = requests.HTTPError(response=fail_resp)
        fail_resp.raise_for_status.side_effect = http_error

        ok_resp = MagicMock()
        ok_resp.raise_for_status.return_value = None
        ok_resp.json.return_value = {"ok": True}

        with patch.object(client, "_get_session") as mock_sess:
            mock_sess.return_value.request.side_effect = [fail_resp, ok_resp]
            with patch.object(client, "_sleep_with_progress") as mock_wait:
                result = client.get("/test")

        assert result == {"ok": True}
        mock_wait.assert_called_once()

    @patch("core.github_client.time.sleep")
    def test_exhausted_retries_raises(self, mock_sleep):
        client = GitHubHttpClient(token="t", max_attempts=2)

        fail_resp = MagicMock()
        fail_resp.status_code = 403
        fail_resp.headers = {}
        http_error = requests.HTTPError(response=fail_resp)
        fail_resp.raise_for_status.side_effect = http_error

        with patch.object(client, "_get_session") as mock_sess:
            mock_sess.return_value.request.return_value = fail_resp
            with pytest.raises(requests.HTTPError):
                client.get("/test")

    def test_non_403_error_not_retried(self):
        client = GitHubHttpClient(token="t", max_attempts=3)

        fail_resp = MagicMock()
        fail_resp.status_code = 404
        http_error = requests.HTTPError(response=fail_resp)
        fail_resp.raise_for_status.side_effect = http_error

        with patch.object(client, "_get_session") as mock_sess:
            mock_sess.return_value.request.return_value = fail_resp
            with pytest.raises(requests.HTTPError):
                client.get("/test")
        # Only called once — no retries
        mock_sess.return_value.request.assert_called_once()


# ── Paginated GET ─────────────────────────────────────────────────────


class TestGetPaginated:
    def test_single_page_list(self):
        client = GitHubHttpClient(token="t")

        resp = MagicMock()
        resp.raise_for_status.return_value = None
        resp.json.return_value = [{"id": 1}, {"id": 2}]
        resp.headers = {}

        with patch.object(client, "_get_session") as mock_sess:
            mock_sess.return_value.request.return_value = resp
            result = client.get_paginated("/orgs/org/repos")

        assert result == [{"id": 1}, {"id": 2}]

    def test_multi_page(self):
        client = GitHubHttpClient(token="t")

        resp1 = MagicMock()
        resp1.raise_for_status.return_value = None
        resp1.json.return_value = [{"id": 1}]
        resp1.headers = {
            "Link": '<https://api.github.com/orgs/org/repos?page=2>; rel="next"'
        }

        resp2 = MagicMock()
        resp2.raise_for_status.return_value = None
        resp2.json.return_value = [{"id": 2}]
        resp2.headers = {}

        with patch.object(client, "_get_session") as mock_sess:
            mock_sess.return_value.request.side_effect = [resp1, resp2]
            result = client.get_paginated("/orgs/org/repos")

        assert result == [{"id": 1}, {"id": 2}]

    def test_search_api_dict_response(self):
        """Search API wraps items in {"total_count": N, "items": [...]}."""
        client = GitHubHttpClient(token="t")

        resp = MagicMock()
        resp.raise_for_status.return_value = None
        resp.json.return_value = {"total_count": 2, "items": [{"id": 1}, {"id": 2}]}
        resp.headers = {}

        with patch.object(client, "_get_session") as mock_sess:
            mock_sess.return_value.request.return_value = resp
            result = client.get_paginated('/search/code?q="repo"')

        assert result == [{"id": 1}, {"id": 2}]

    def test_absolute_url_not_prefixed(self):
        client = GitHubHttpClient(token="t")

        resp = MagicMock()
        resp.raise_for_status.return_value = None
        resp.json.return_value = []
        resp.headers = {}

        with patch.object(client, "_get_session") as mock_sess:
            mock_sess.return_value.request.return_value = resp
            client.get("https://custom.api.com/foo")

        call_args = mock_sess.return_value.request.call_args
        assert call_args[0][1] == "https://custom.api.com/foo"
