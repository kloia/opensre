"""Instana wiring into source→tool routing + seed selection."""

from __future__ import annotations

from core.domain.alerts.alert_source import (
    ALERT_SOURCE_TO_SEED_TOOL_SOURCES,
    ALERT_SOURCE_TO_TOOL_SOURCES,
    SOURCE_ALIASES,
    primary_sources_for_alert,
    relevant_sources_for_alert,
    resolve_alert_source,
)


def test_instana_is_a_primary_tool_source() -> None:
    assert ALERT_SOURCE_TO_TOOL_SOURCES["instana"] == ("instana",)


def test_instana_is_a_seed_source() -> None:
    assert ALERT_SOURCE_TO_SEED_TOOL_SOURCES["instana"] == ("instana",)


def test_primary_sources_for_instana_alert() -> None:
    state = {"alert_source": "instana", "raw_alert": {"entity_type": "service"}}
    assert resolve_alert_source(state) == "instana"
    assert primary_sources_for_alert(state) == ("instana",)


def test_instana_content_relevance_matches_aliases() -> None:
    assert "instana" in SOURCE_ALIASES
    state = {"raw_alert": {"title": "Smart Alert firing on application perspective"}}
    result = relevant_sources_for_alert(state, {"instana", "datadog"})
    assert result == ["instana"]
