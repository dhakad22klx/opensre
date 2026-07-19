"""Grafana ``ReportDeliveryAdapter`` implementation.

Posts a Grafana annotation marking investigation completion, so investigations
show up on the same timeline as deploys/config changes (see
``docs/grafana_annotations.mdx``). Registers itself into the platform-level
delivery registry at import time so
``tools.investigation.reporting.delivery.dispatch`` never imports
``integrations.grafana`` directly (T-4 layering audit, issue #3352).
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime
from typing import Any

from pydantic import BaseModel

from integrations.grafana.client import get_grafana_client_from_credentials
from platform.reporting.delivery_registry import (
    DeliveryContext,
    register_delivery_adapter,
)

logger = logging.getLogger(__name__)

_MAX_ANNOTATION_TEXT_LENGTH = 500


def _grafana_credentials(resolved: Any) -> dict[str, Any]:
    """Normalize ``resolved_integrations["grafana"/"grafana_local"]`` to a plain dict.

    The value may be a ``GrafanaIntegrationConfig`` pydantic instance (local
    onboarding/store path) or a plain dict (env-var fallback path).
    """
    if isinstance(resolved, BaseModel):
        return resolved.model_dump(exclude_none=True)
    if isinstance(resolved, dict):
        return resolved
    return {}


def _build_annotation_text(state: DeliveryContext, messages: DeliveryContext) -> str:
    alert_name = state.get("alert_name") or "investigation"
    root_cause = state.get("root_cause") or ""
    text = f"OpenSRE investigation: {alert_name}"
    if root_cause:
        text = f"{text}\n{root_cause}"
    elif messages.get("slack_text"):
        text = f"{text}\n{messages['slack_text']}"
    if len(text) > _MAX_ANNOTATION_TEXT_LENGTH:
        text = text[: _MAX_ANNOTATION_TEXT_LENGTH - 1].rstrip() + "…"
    return text


def _build_annotation_tags(state: DeliveryContext) -> list[str]:
    tags = ["opensre", "investigation"]
    severity = state.get("severity")
    if severity:
        tags.append(f"severity:{severity}")
    root_cause_category = state.get("root_cause_category")
    if root_cause_category:
        tags.append(f"category:{root_cause_category}")
    return tags


class _GrafanaReportDeliveryAdapter:
    """Grafana delivery adapter — posts an annotation when credentials are set."""

    name = "grafana"

    def deliver(
        self,
        state: DeliveryContext,
        *,
        messages: DeliveryContext,
        blocks: list[dict[str, Any]],  # noqa: ARG002
    ) -> bool:
        resolved = state.get("resolved_integrations") or {}
        if not isinstance(resolved, dict):
            return False
        raw_creds = resolved.get("grafana") or resolved.get("grafana_local")
        grafana_creds = _grafana_credentials(raw_creds)
        endpoint = grafana_creds.get("endpoint")
        if not endpoint:
            logger.debug("[publish] grafana delivery: no grafana integration configured")
            return False

        client = get_grafana_client_from_credentials(
            endpoint=endpoint,
            api_key=grafana_creds.get("api_key", ""),
            username=grafana_creds.get("username", ""),
            password=grafana_creds.get("password", ""),
            verify_ssl=grafana_creds.get("verify_ssl", True),
            ca_bundle=grafana_creds.get("ca_bundle", ""),
        )
        if not client.is_configured:
            logger.debug("[publish] grafana delivery: skipped - client not configured")
            return False

        text = _build_annotation_text(state, messages)
        tags = _build_annotation_tags(state)
        time_ms = int(datetime.now(UTC).timestamp() * 1000)
        result = client.create_annotation(text=text, tags=tags, time_ms=time_ms)
        if not result.get("success"):
            logger.warning(
                "[publish] Grafana annotation delivery failed: endpoint=%s error=%s",
                endpoint,
                result.get("error"),
            )
        else:
            logger.debug("[publish] grafana delivery: annotation created id=%s", result.get("id"))
        return True


grafana_delivery_adapter = _GrafanaReportDeliveryAdapter()
register_delivery_adapter(grafana_delivery_adapter)

__all__ = ["grafana_delivery_adapter"]
