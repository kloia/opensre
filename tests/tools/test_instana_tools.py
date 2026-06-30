"""Contract + happy-path tests for the native Instana tools (source="instana")."""

from __future__ import annotations

from unittest.mock import MagicMock

from integrations.instana.tools import (
    instana_error_analysis,
    instana_get_events,
    instana_get_investigation_context,
    instana_get_trace_detail,
    instana_search_logs,
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
    fake.get_events.return_value = [{"eventId": "e1"}]
    fake.application_metrics.return_value = {"metrics": {"latency": {"latest": 1.2}}}
    fake.traces.return_value = [
        {"trace_id": "t1", "erroneous": True},
        {"trace_id": "t2", "erroneous": False},
    ]
    fake.error_messages.return_value = [{"message": "boom", "count": 5}]
    result = instana_get_investigation_context(service_name="svc", _client_override=fake)
    assert result["available"] is True
    assert result["service_name"] == "svc"
    assert result["events"] == [{"eventId": "e1"}]
    assert result["metrics"] == {"latency": {"latest": 1.2}}
    assert len(result["slowest_traces"]) == 2
    assert result["error_spans"] == [{"trace_id": "t1", "erroneous": True}]
    assert result["error_messages"] == [{"message": "boom", "count": 5}]
    assert "truncation_note" in result


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
    fake = MagicMock()
    fake.search_logs.side_effect = RuntimeError("404 no log API")
    result = instana_search_logs(service_name="svc", _client_override=fake)
    assert result["available"] is False
    assert result["source"] == "instana_logs"
    assert result["logs"] == []
    assert "404" in result["error"]


def test_error_analysis_happy_path() -> None:
    fake = MagicMock()
    fake.error_messages.return_value = [
        {"message": "NOT_FOUND: National ID not found", "count": 7702},
        {"message": "FAILED_PRECONDITION: dup", "count": 33},
    ]
    fake.errors_by_service.return_value = [
        {"service": "catalog", "count": 4498},
        {"service": "tiam-ms-profile", "count": 803},
    ]
    result = instana_error_analysis(service_name="tiam-ms-profile", _client_override=fake)
    assert result["available"] is True
    assert result["source"] == "instana"
    assert result["error_messages"][0]["count"] == 7702
    # with a service_name, top_services is omitted or empty (focused on the service)
    fake.error_messages.assert_called_once()
    assert result["top_services"] == []
    fake.errors_by_service.assert_not_called()


def test_error_analysis_no_service_returns_top_services() -> None:
    fake = MagicMock()
    fake.error_messages.return_value = []
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
