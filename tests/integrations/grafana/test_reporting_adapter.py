"""Unit tests for the Grafana ReportDeliveryAdapter (annotation-on-completion)."""

from __future__ import annotations

import logging
from typing import Any
from unittest.mock import MagicMock, patch

from integrations.config_models import GrafanaIntegrationConfig
from integrations.grafana.reporting_adapter import grafana_delivery_adapter
from tools.investigation.reporting.delivery.bootstrap import (
    ensure_delivery_adapters_registered,
)

MESSAGES: dict[str, Any] = {"slack_text": "root cause: disk full on checkout-api"}


def _make_state(**overrides: Any) -> dict[str, Any]:
    base: dict[str, Any] = {"resolved_integrations": {}}
    base.update(overrides)
    return base


def test_grafana_delivery_skipped_when_no_integration_configured() -> None:
    with patch(
        "integrations.grafana.reporting_adapter.get_grafana_client_from_credentials"
    ) as mock_factory:
        result = grafana_delivery_adapter.deliver(_make_state(), messages=MESSAGES, blocks=[])

    assert result is False
    mock_factory.assert_not_called()


def test_grafana_delivery_skipped_when_creds_missing_endpoint() -> None:
    state = _make_state(resolved_integrations={"grafana": {"api_key": "tok"}})
    with patch(
        "integrations.grafana.reporting_adapter.get_grafana_client_from_credentials"
    ) as mock_factory:
        result = grafana_delivery_adapter.deliver(state, messages=MESSAGES, blocks=[])

    assert result is False
    mock_factory.assert_not_called()


def test_grafana_delivery_skipped_when_client_not_configured() -> None:
    state = _make_state(
        resolved_integrations={"grafana": {"endpoint": "https://grafana.example.com"}}
    )
    mock_client = MagicMock(is_configured=False)
    with patch(
        "integrations.grafana.reporting_adapter.get_grafana_client_from_credentials",
        return_value=mock_client,
    ):
        result = grafana_delivery_adapter.deliver(state, messages=MESSAGES, blocks=[])

    assert result is False
    mock_client.create_annotation.assert_not_called()


def test_grafana_delivery_creates_annotation_from_grafana_local_key() -> None:
    """classify() may resolve credentials under 'grafana_local' instead of 'grafana'."""
    state = _make_state(
        resolved_integrations={
            "grafana_local": {
                "endpoint": "http://localhost:3000",
                "api_key": "",
            }
        },
        alert_name="checkout-api down",
        root_cause="disk full on checkout-api",
    )
    mock_client = MagicMock(is_configured=True)
    mock_client.create_annotation.return_value = {"success": True, "id": 7}
    with patch(
        "integrations.grafana.reporting_adapter.get_grafana_client_from_credentials",
        return_value=mock_client,
    ) as mock_factory:
        result = grafana_delivery_adapter.deliver(state, messages=MESSAGES, blocks=[])

    assert result is True
    mock_factory.assert_called_once()
    _, kwargs = mock_factory.call_args
    assert kwargs["endpoint"] == "http://localhost:3000"

    _, annotate_kwargs = mock_client.create_annotation.call_args
    assert "checkout-api down" in annotate_kwargs["text"]
    assert "disk full on checkout-api" in annotate_kwargs["text"]
    assert annotate_kwargs["tags"] == ["opensre", "investigation"]


def test_grafana_delivery_normalizes_pydantic_model_credentials() -> None:
    """The env-var fallback path stores a plain dict; the store path keeps a
    GrafanaIntegrationConfig model instance — both must work."""
    cfg = GrafanaIntegrationConfig(
        endpoint="https://grafana.example.com",
        api_key="tok",
        integration_id="acct-1",
    )
    state = _make_state(resolved_integrations={"grafana": cfg})
    mock_client = MagicMock(is_configured=True)
    mock_client.create_annotation.return_value = {"success": True}
    with patch(
        "integrations.grafana.reporting_adapter.get_grafana_client_from_credentials",
        return_value=mock_client,
    ) as mock_factory:
        result = grafana_delivery_adapter.deliver(state, messages=MESSAGES, blocks=[])

    assert result is True
    _, kwargs = mock_factory.call_args
    assert kwargs["endpoint"] == "https://grafana.example.com"
    assert kwargs["api_key"] == "tok"


def test_grafana_delivery_tags_include_severity_and_category_when_present() -> None:
    state = _make_state(
        resolved_integrations={
            "grafana": {"endpoint": "https://grafana.example.com", "api_key": "tok"}
        },
        severity="critical",
        root_cause_category="infra",
    )
    mock_client = MagicMock(is_configured=True)
    mock_client.create_annotation.return_value = {"success": True}
    with patch(
        "integrations.grafana.reporting_adapter.get_grafana_client_from_credentials",
        return_value=mock_client,
    ):
        grafana_delivery_adapter.deliver(state, messages=MESSAGES, blocks=[])

    _, annotate_kwargs = mock_client.create_annotation.call_args
    assert annotate_kwargs["tags"] == [
        "opensre",
        "investigation",
        "severity:critical",
        "category:infra",
    ]


def test_grafana_delivery_truncates_long_annotation_text() -> None:
    state = _make_state(
        resolved_integrations={
            "grafana": {"endpoint": "https://grafana.example.com", "api_key": "tok"}
        },
        root_cause="x" * 1000,
    )
    mock_client = MagicMock(is_configured=True)
    mock_client.create_annotation.return_value = {"success": True}
    with patch(
        "integrations.grafana.reporting_adapter.get_grafana_client_from_credentials",
        return_value=mock_client,
    ):
        grafana_delivery_adapter.deliver(state, messages=MESSAGES, blocks=[])

    _, annotate_kwargs = mock_client.create_annotation.call_args
    assert len(annotate_kwargs["text"]) <= 500


def test_grafana_delivery_returns_true_and_logs_warning_when_annotation_post_fails(
    caplog,
) -> None:
    state = _make_state(
        resolved_integrations={
            "grafana": {"endpoint": "https://grafana.example.com", "api_key": "tok"}
        }
    )
    mock_client = MagicMock(is_configured=True)
    mock_client.create_annotation.return_value = {
        "success": False,
        "error": "403 Forbidden",
    }
    with (
        patch(
            "integrations.grafana.reporting_adapter.get_grafana_client_from_credentials",
            return_value=mock_client,
        ),
        caplog.at_level(logging.WARNING),
    ):
        result = grafana_delivery_adapter.deliver(state, messages=MESSAGES, blocks=[])

    assert result is True
    assert any("403 Forbidden" in message for message in caplog.messages)


def test_grafana_adapter_is_registered_via_bootstrap() -> None:
    assert "grafana" in ensure_delivery_adapters_registered()
