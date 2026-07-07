"""Contract + happy-path tests for the native Instana tools (source="instana")."""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from integrations.instana.tools import (
    instana_error_analysis,
    instana_get_application_context,
    instana_get_events,
    instana_get_investigation_context,
    instana_get_trace_detail,
    instana_search_logs,
    instana_traces,
)
from tests.tools.conftest import BaseToolContract

_SOURCES = {"instana": {"base_url": "https://x.instana.io", "api_token": "tok"}}


# ---------------------------------------------------------------------------
# Contract tests (one representative ported tool + the 3 RCA tools)
# ---------------------------------------------------------------------------


class TestInstanaGetEventsContract(BaseToolContract):
    def get_tool_under_test(self):
        return instana_get_events.__opensre_registered_tool__


class TestInstanaInvestigationContextContract(BaseToolContract):
    def get_tool_under_test(self):
        return instana_get_investigation_context.__opensre_registered_tool__


class TestInstanaTraceDetailContract(BaseToolContract):
    def get_tool_under_test(self):
        return instana_get_trace_detail.__opensre_registered_tool__


class TestInstanaSearchLogsContract(BaseToolContract):
    def get_tool_under_test(self):
        return instana_search_logs.__opensre_registered_tool__


class TestInstanaErrorAnalysisContract(BaseToolContract):
    def get_tool_under_test(self):
        return instana_error_analysis.__opensre_registered_tool__


# ---------------------------------------------------------------------------
# is_available / extract_params
# ---------------------------------------------------------------------------


def test_is_available_requires_base_url_and_token() -> None:
    rt = instana_get_events.__opensre_registered_tool__
    assert rt.is_available(_SOURCES) is True
    assert rt.is_available({"instana": {"base_url": "x"}}) is False
    assert rt.is_available({"instana": {"api_token": "t"}}) is False
    assert rt.is_available({}) is False


def test_extract_params_returns_creds() -> None:
    rt = instana_get_events.__opensre_registered_tool__
    params = rt.extract_params(_SOURCES)
    assert params["base_url"] == "https://x.instana.io"
    assert params["api_token"] == "tok"


def test_extract_params_passes_client_override() -> None:
    fake = MagicMock()
    rt = instana_search_logs.__opensre_registered_tool__
    params = rt.extract_params(
        {"instana": {"base_url": "x", "api_token": "t", "_client_override": fake}}
    )
    assert params["_client_override"] is fake


# ---------------------------------------------------------------------------
# Happy-path runs with a fake client
# ---------------------------------------------------------------------------


def test_get_events_happy_path() -> None:
    fake = MagicMock()
    fake.get_events.return_value = [
        {"eventId": "e1", "severity": 10, "state": "open", "start": 2},
        {"eventId": "e2", "severity": 5, "state": "closed", "start": 1},
        {"eventId": "e3", "severity": 1, "state": "closed", "start": 0},
    ]
    result = instana_get_events(min_severity=5, _client_override=fake)
    assert result["available"] is True
    assert result["totals"]["all"] == 3
    assert result["totals"]["open"] == 1
    assert result["shown"] == 2  # severity 1 dropped by min_severity
    assert result["events"][0]["eventId"] == "e1"  # open + highest severity first


def test_get_events_excludes_change_noise_by_default() -> None:
    fake = MagicMock()
    fake.get_events.return_value = [
        {"eventId": "i1", "type": "issue", "severity": 10, "state": "open", "start": 3},
        {"eventId": "c1", "type": "change", "severity": 10, "state": "open", "start": 2},
        {"eventId": "i2", "type": "issue", "severity": 5, "state": "closed", "start": 1},
    ]
    result = instana_get_events(min_severity=5, _client_override=fake)
    ids = [e["eventId"] for e in result["events"]]
    assert "c1" not in ids            # change excluded even at high severity
    assert ids == ["i1", "i2"]        # issues kept, open+severity ranked
    assert result["totals"]["all"] == 3


def test_get_events_include_changes_opt_in() -> None:
    fake = MagicMock()
    fake.get_events.return_value = [
        {"eventId": "c1", "type": "change", "severity": 10, "state": "open", "start": 2},
    ]
    result = instana_get_events(min_severity=5, include_changes=True, _client_override=fake)
    assert [e["eventId"] for e in result["events"]] == ["c1"]


def test_instana_traces_passes_erroneous_only() -> None:
    fake = MagicMock()
    fake.traces.return_value = [{"trace_id": "t1", "erroneous": True}]
    result = instana_traces(service_name="be-payments", erroneous_only=True, _client_override=fake)
    assert result["available"] is True
    _, kwargs = fake.traces.call_args
    assert kwargs["erroneous_only"] is True


def test_trace_detail_surfaces_error_counts() -> None:
    fake = MagicMock()
    fake.get_trace_detail.return_value = [
        {"name": "GET /ok", "duration": 50, "errorCount": 0,
         "destination": {"service": {"label": "svc-a"}, "endpoint": {"label": "/ok"}}},
        {"name": "POST /db", "duration": 120, "errorCount": 1,
         "destination": {"service": {"label": "svc-db"}, "endpoint": {"label": "/db"}}},
    ]
    result = instana_get_trace_detail(trace_id="t1", _client_override=fake)
    assert result["available"] is True
    assert result["span_count"] == 2
    assert result["error_span_count"] == 1
    slowest = result["slowest_spans"]
    assert slowest[0]["name"] == "POST /db"  # duration-ranked
    assert slowest[0]["error_count"] == 1
    assert slowest[0]["destination_service"] == "svc-db"
    # error_type/error_message keys removed (no longer probed)
    assert "error_type" not in slowest[0]
    assert "error_message" not in slowest[0]


def test_investigation_context_bundles_signals() -> None:
    fake = MagicMock()
    fake.get_events.return_value = [{"eventId": "e1", "severity": 5, "state": "open"}]
    fake.application_metrics.return_value = {"metrics": {"latency": {"latest": 1.2}}}
    fake.traces.return_value = [
        {"trace_id": "t1", "erroneous": True},
        {"trace_id": "t2", "erroneous": False},
    ]
    fake.error_messages.return_value = [{"message": "boom", "count": 5}]
    fake.error_http_status.return_value = [{"status": "500", "count": 9}]
    fake.error_endpoints.return_value = [{"endpoint": "POST /pay", "count": 9}]
    result = instana_get_investigation_context(service_name="svc", _client_override=fake)
    assert result["available"] is True
    assert result["service_name"] == "svc"
    assert [e["eventId"] for e in result["events"]] == ["e1"]
    assert result["metrics"] == {"latency": {"latest": 1.2}}
    assert len(result["slowest_traces"]) == 2
    assert result["error_spans"] == [{"trace_id": "t1", "erroneous": True}]
    assert result["error_messages"] == [{"message": "boom", "count": 5}]
    assert result["http_status"] == [{"status": "500", "count": 9}]
    assert result["error_endpoints"] == [{"endpoint": "POST /pay", "count": 9}]
    assert "truncation_note" in result


def test_investigation_context_events_are_ranked_and_denoised() -> None:
    fake = MagicMock()
    fake.get_events.return_value = [
        {"eventId": "c1", "type": "change", "severity": 10, "state": "open", "start": 5},
        {"eventId": "i1", "type": "issue", "severity": 7, "state": "open", "start": 4},
    ]
    fake.application_metrics.return_value = {"metrics": {}}
    fake.traces.return_value = []
    fake.error_messages.return_value = []
    fake.error_http_status.return_value = []
    fake.error_endpoints.return_value = []
    result = instana_get_investigation_context(service_name="svc", _client_override=fake)
    ids = [e["eventId"] for e in result["events"]]
    assert ids == ["i1"]   # change c1 dropped, issue kept


def test_search_logs_happy_path() -> None:
    fake = MagicMock()
    fake.search_logs.return_value = [
        {"message": "ERROR: boom"},
        {"message": "normal line"},
    ]
    result = instana_search_logs(service_name="svc", _client_override=fake)
    assert result["available"] is True
    assert len(result["logs"]) == 2
    assert len(result["error_logs"]) == 1


def test_search_logs_graceful_unavailable() -> None:
    # A non-404 transport failure stays retryable and surfaces the raw detail.
    fake = MagicMock()
    fake.search_logs.side_effect = RuntimeError("500 upstream boom")
    result = instana_search_logs(service_name="svc", _client_override=fake)
    assert result["available"] is False
    assert result["source"] == "instana_logs"
    assert result["logs"] == []
    assert result["retry"] is True
    assert "500 upstream boom" in result["error"]


def test_search_logs_404_is_non_retryable() -> None:
    fake = MagicMock()
    fake.search_logs.side_effect = RuntimeError("HTTP 404: not found")
    result = instana_search_logs(service_name="svc", _client_override=fake)
    assert result["available"] is False
    assert result["retry"] is False
    assert "Log Management" in result["error"]
    assert result["logs"] == []


def test_error_analysis_happy_path() -> None:
    fake = MagicMock()
    fake.error_messages.return_value = [
        {"message": "NOT_FOUND: National ID not found", "count": 7702},
        {"message": "FAILED_PRECONDITION: dup", "count": 33},
    ]
    fake.error_http_status.return_value = [{"status": "500", "count": 40}]
    fake.error_endpoints.return_value = [{"endpoint": "POST /profile", "count": 40}]
    fake.errors_by_service.return_value = [
        {"service": "catalog", "count": 4498},
        {"service": "tiam-ms-profile", "count": 803},
    ]
    result = instana_error_analysis(service_name="tiam-ms-profile", _client_override=fake)
    assert result["available"] is True
    assert result["source"] == "instana"
    assert result["error_messages"][0]["count"] == 7702
    assert result["http_status"] == [{"status": "500", "count": 40}]
    assert result["error_endpoints"] == [{"endpoint": "POST /profile", "count": 40}]
    # with a service_name, top_services is empty (focused on the service)
    fake.error_messages.assert_called_once()
    assert result["top_services"] == []
    fake.errors_by_service.assert_not_called()


def test_error_analysis_status_code_scenario_no_message() -> None:
    # The lab scenario: injected 5xx -> erroneous traces but empty call.error.message.
    # The HTTP status + endpoint facets must still name the cause.
    fake = MagicMock()
    fake.error_messages.return_value = []
    fake.error_http_status.return_value = [{"status": "500", "count": 1873}]
    fake.error_endpoints.return_value = [{"endpoint": "POST /payments", "count": 1873}]
    result = instana_error_analysis(service_name="be-payments", _client_override=fake)
    assert result["available"] is True
    assert result["error_messages"] == []
    assert result["http_status"][0] == {"status": "500", "count": 1873}
    assert result["error_endpoints"][0] == {"endpoint": "POST /payments", "count": 1873}


def test_error_analysis_no_service_returns_top_services() -> None:
    fake = MagicMock()
    fake.error_messages.return_value = []
    fake.error_http_status.return_value = []
    fake.error_endpoints.return_value = []
    fake.errors_by_service.return_value = [{"service": "catalog", "count": 4498}]
    result = instana_error_analysis(_client_override=fake)
    assert result["available"] is True
    assert result["top_services"][0]["service"] == "catalog"


def test_error_analysis_graceful_unavailable() -> None:
    fake = MagicMock()
    fake.error_messages.side_effect = RuntimeError("422 bad body")
    result = instana_error_analysis(service_name="svc", _client_override=fake)
    assert result["available"] is False
    assert result["error_messages"] == []
    assert result["http_status"] == []
    assert result["error_endpoints"] == []


def test_investigation_context_passes_to_ms() -> None:
    fake = MagicMock()
    fake.get_events.return_value = []
    fake.application_metrics.return_value = {"metrics": {}}
    fake.traces.return_value = []
    fake.error_messages.return_value = []
    fake.error_http_status.return_value = []
    fake.error_endpoints.return_value = []
    instana_get_investigation_context(service_name="svc", to_ms=123, _client_override=fake)
    # every timeframe-bearing client call receives to_ms=123
    assert fake.application_metrics.call_args.kwargs.get("to_ms") == 123
    assert fake.error_messages.call_args.kwargs.get("to_ms") == 123
    assert fake.traces.call_args.kwargs.get("to_ms") == 123


def test_traces_tool_passes_to_ms() -> None:
    fake = MagicMock()
    fake.traces.return_value = []
    instana_traces(service_name="svc", to_ms=123, _client_override=fake)
    assert fake.traces.call_args.kwargs.get("to_ms") == 123


def test_application_context_tool_happy_and_graceful() -> None:
    fake = MagicMock()
    fake.application_context.return_value = {"application": "App", "application_id": "APPID1",
        "services": [{"service": "fe", "count": 100}],
        "top_error_services": [{"service": "be-payments", "count": 42}]}
    r = instana_get_application_context(application="App", to_ms=999, _client_override=fake)
    assert r["available"] is True
    assert r["services"][0]["service"] == "fe"                     # member services surfaced
    assert r["top_error_services"][0]["service"] == "be-payments"
    assert fake.application_context.call_args.kwargs.get("to_ms") == 999
    fake2 = MagicMock(); fake2.application_context.side_effect = RuntimeError("400 bad app")
    r2 = instana_get_application_context(application="App", _client_override=fake2)
    assert r2["available"] is False
    assert r2["services"] == [] and r2["top_error_services"] == []


def test_get_events_tool_forwards_to_ms() -> None:
    fake = MagicMock()
    fake.get_events.return_value = []
    instana_get_events(to_ms=777, _client_override=fake)
    assert fake.get_events.call_args.kwargs.get("to_ms") == 777


def test_error_analysis_tool_forwards_to_ms() -> None:
    fake = MagicMock()
    fake.error_messages.return_value = []
    fake.error_http_status.return_value = []
    fake.error_endpoints.return_value = []
    fake.errors_by_service.return_value = []
    instana_error_analysis(service_name="svc", to_ms=777, _client_override=fake)
    assert fake.error_messages.call_args.kwargs.get("to_ms") == 777
    assert fake.error_http_status.call_args.kwargs.get("to_ms") == 777
    assert fake.error_endpoints.call_args.kwargs.get("to_ms") == 777


@pytest.mark.parametrize(
    "tool_fn_name",
    [
        "instana_get_application_context",
        "instana_get_investigation_context",
        "instana_error_analysis",
        "instana_application_metrics",
        "instana_get_events",
        "instana_infrastructure_health",
        "instana_traces",
    ],
)
def test_primary_instana_tools_have_rich_metadata(tool_fn_name) -> None:
    import integrations.instana.tools as mod

    rt = getattr(mod, tool_fn_name).__opensre_registered_tool__
    assert len(rt.use_cases) >= 2, f"{tool_fn_name} needs >=2 use_cases"
    assert rt.tags, f"{tool_fn_name} needs tags"
