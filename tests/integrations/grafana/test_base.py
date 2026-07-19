"""Direct unit tests for integrations.grafana.base.GrafanaClientBase.

Currently covers create_annotation(): the happy path (payload/header shape,
optional timeEnd), an HTTP error response (e.g. a token without write scope),
and a transport-level exception — both failure cases must return a
{"success": False, "error": ...} dict rather than raising.
"""

from __future__ import annotations

from unittest.mock import Mock, patch

import requests

from integrations.grafana.base import GrafanaClientBase
from integrations.grafana.config import GrafanaAccountConfig


def _make_client(**overrides) -> GrafanaClientBase:
    defaults = {
        "account_id": "test-account",
        "instance_url": "https://grafana.example.com",
        "read_token": "read-token",
    }
    defaults.update(overrides)
    return GrafanaClientBase(config=GrafanaAccountConfig(**defaults))


class TestCreateAnnotation:
    @patch("integrations.grafana.base.requests.post")
    def test_successful_post_returns_success(self, mock_post) -> None:
        client = _make_client()
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"id": 42, "message": "Annotation added"}
        mock_post.return_value = mock_response

        result = client.create_annotation(
            text="OpenSRE investigation: checkout-api down",
            tags=["opensre", "investigation"],
            time_ms=1717079669000,
        )

        assert result == {"success": True, "id": 42, "message": "Annotation added"}
        mock_post.assert_called_once_with(
            "https://grafana.example.com/api/annotations",
            headers={
                "Authorization": "Bearer read-token",
                "Content-Type": "application/json",
            },
            json={
                "time": 1717079669000,
                "tags": ["opensre", "investigation"],
                "text": "OpenSRE investigation: checkout-api down",
            },
            timeout=10,
            verify=True,
        )

    @patch("integrations.grafana.base.requests.post")
    def test_includes_time_end_when_provided(self, mock_post) -> None:
        client = _make_client()
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"id": 1}
        mock_post.return_value = mock_response

        client.create_annotation(text="deploy window", time_ms=1000, time_end_ms=2000)

        _, kwargs = mock_post.call_args
        assert kwargs["json"]["timeEnd"] == 2000

    @patch("integrations.grafana.base.requests.post")
    def test_http_error_returns_failure_without_raising(self, mock_post) -> None:
        client = _make_client(read_token="viewer-scoped-token")
        mock_response = Mock()
        mock_response.status_code = 403
        mock_response.raise_for_status.side_effect = requests.HTTPError("403 Forbidden")
        mock_post.return_value = mock_response

        result = client.create_annotation(text="should fail")

        assert result["success"] is False
        assert "403" in result["error"]

    @patch("integrations.grafana.base.requests.post")
    def test_request_exception_returns_failure_without_raising(self, mock_post) -> None:
        client = _make_client()
        mock_post.side_effect = requests.ConnectionError("could not connect")

        result = client.create_annotation(text="should fail")

        assert result == {"success": False, "error": "could not connect"}
