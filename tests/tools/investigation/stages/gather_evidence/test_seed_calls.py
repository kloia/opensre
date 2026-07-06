"""Instana seeding: one entity-type-correct, scoped, time-anchored primary call."""

from __future__ import annotations

from tools.investigation.stages.gather_evidence.tools import build_seed_calls
from tools.registry import get_registered_tools


def _instana_tools():
    return [t for t in get_registered_tools("investigation") if str(t.source) == "instana"]


def _state(entity_type: str, **raw_extra) -> dict:
    raw = {
        "alert_source": "instana",
        "entity_type": entity_type,
        "to_ms": 1_700_000_000_000,
        "window_size_ms": 3_600_000,
        **raw_extra,
    }
    return {
        "alert_source": "instana",
        "raw_alert": raw,
        "resolved_integrations": {
            "instana": {"base_url": "https://x.instana.io", "api_token": "tok"}
        },
    }


def test_application_alert_seeds_application_context_anchored() -> None:
    state = _state("application", entity_label="Checkout App")
    calls = build_seed_calls(state, _instana_tools(), llm=None)
    assert len(calls) == 1
    call = calls[0]
    assert call.name == "instana_get_application_context"
    assert call.input["application"] == "Checkout App"
    assert call.input["to_ms"] == 1_700_000_000_000
    assert call.input["window_size_ms"] == 3_600_000


def test_service_alert_seeds_investigation_context_anchored() -> None:
    state = _state("service", service_name="be-orders")
    calls = build_seed_calls(state, _instana_tools(), llm=None)
    assert len(calls) == 1
    assert calls[0].name == "instana_get_investigation_context"
    assert calls[0].input["service_name"] == "be-orders"
    assert calls[0].input["to_ms"] == 1_700_000_000_000


def test_host_alert_seeds_infrastructure_health_with_query() -> None:
    state = _state("host", entity_label="ip-10-20-1-5", hosts=["ip-10-20-1-5"])
    calls = build_seed_calls(state, _instana_tools(), llm=None)
    assert len(calls) == 1
    assert calls[0].name == "instana_infrastructure_health"
    assert calls[0].input["query"] == "ip-10-20-1-5"
    assert "to_ms" not in calls[0].input


def test_thin_alert_omits_absent_params() -> None:
    state = {
        "alert_source": "instana",
        "raw_alert": {"alert_source": "instana", "entity_type": "service"},
        "resolved_integrations": {"instana": {"base_url": "x", "api_token": "t"}},
    }
    calls = build_seed_calls(state, _instana_tools(), llm=None)
    assert len(calls) == 1
    assert calls[0].name == "instana_get_investigation_context"
    assert "to_ms" not in calls[0].input
    assert "service_name" not in calls[0].input


def test_instana_narrows_to_single_seed() -> None:
    state = _state("service", service_name="be-orders")
    calls = build_seed_calls(state, _instana_tools(), llm=None)
    assert len(calls) == 1


def test_non_instana_source_seeds_all_its_tools() -> None:
    dd_tools = [
        t for t in get_registered_tools("investigation") if str(t.source) == "datadog"
    ]
    assert len(dd_tools) >= 2  # guard: this test only means something with multiple tools
    state = {
        "alert_source": "datadog",
        "raw_alert": {"alert_source": "datadog"},
        "resolved_integrations": {
            "datadog": {"api_key": "k", "app_key": "a", "site": "datadoghq.com"}
        },
    }
    calls = build_seed_calls(state, dd_tools, llm=None)
    # No entity-type narrowing for non-instana → every source tool is seeded.
    assert len(calls) == len(dd_tools)
