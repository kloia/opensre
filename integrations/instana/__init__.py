"""Instana integration classifier."""

from __future__ import annotations

import logging
from typing import Any

from integrations._validation_helpers import report_classify_failure
from integrations.config_models import InstanaIntegrationConfig

logger = logging.getLogger(__name__)


def classify(
    credentials: dict[str, Any], record_id: str
) -> tuple[InstanaIntegrationConfig | None, str | None]:
    try:
        cfg = InstanaIntegrationConfig.model_validate(
            {
                "base_url": credentials.get("base_url", ""),
                "api_token": credentials.get("api_token", ""),
                "integration_id": record_id,
            }
        )
    except Exception as exc:
        report_classify_failure(exc, logger=logger, integration="instana", record_id=record_id)
        return None, None
    if cfg.base_url and cfg.api_token:
        return cfg, "instana"
    return None, None
