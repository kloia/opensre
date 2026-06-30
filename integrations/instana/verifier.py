"""Instana integration verifier."""

from __future__ import annotations

from integrations.instana.client import InstanaClient, InstanaConfig
from integrations.verification import register_probe_verifier

verify_instana = register_probe_verifier(
    "instana",
    config=InstanaConfig.model_validate,
    client=InstanaClient,
)
