"""Instana wiring into source→tool routing + seed selection."""

from __future__ import annotations

from core.domain.alerts.alert_source import (
    ALERT_SOURCE_TO_SEED_TOOL_SOURCES,
    ALERT_SOURCE_TO_TOOL_SOURCES,
    INSTANA_DEFAULT_SEED_TOOL,
    SOURCE_ALIASES,
    primary_sources_for_alert,
    relevant_sources_for_alert,
    resolve_alert_source,
    select_seed_tool_names,
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


def _instana_state(entity_type: str | None) -> dict:
    raw = {"entity_type": entity_type} if entity_type is not None else {}
    return {"alert_source": "instana", "raw_alert": raw}


def test_select_seed_application() -> None:
    assert select_seed_tool_names(_instana_state("application"), "instana") == [
        "instana_get_application_context"
    ]


def test_select_seed_service() -> None:
    assert select_seed_tool_names(_instana_state("service"), "instana") == [
        "instana_get_investigation_context"
    ]


def test_select_seed_host_and_infra() -> None:
    assert select_seed_tool_names(_instana_state("host"), "instana") == [
        "instana_infrastructure_health"
    ]
    assert select_seed_tool_names(_instana_state("infrastructure"), "instana") == [
        "instana_infrastructure_health"
    ]


def test_select_seed_unknown_falls_back_to_default() -> None:
    assert select_seed_tool_names(_instana_state("weird"), "instana") == [
        INSTANA_DEFAULT_SEED_TOOL
    ]
    assert select_seed_tool_names(_instana_state(None), "instana") == [
        INSTANA_DEFAULT_SEED_TOOL
    ]


def test_select_seed_non_instana_returns_none() -> None:
    assert select_seed_tool_names({"alert_source": "datadog"}, "datadog") is None


def test_select_seed_missing_raw_alert_falls_back_to_default() -> None:
    assert select_seed_tool_names({"alert_source": "instana"}, "instana") == [
        INSTANA_DEFAULT_SEED_TOOL
    ]
