"""Unit tests for InstanaClient.analyze/call-groups error helpers (A0-validated shapes)."""

from __future__ import annotations

from typing import Any

from integrations.instana.client import InstanaClient, InstanaConfig


def _client_with_post(captured: dict[str, Any], response: dict[str, Any]) -> InstanaClient:
    client = InstanaClient(
        InstanaConfig.model_validate({"base_url": "https://x.instana.io", "api_token": "t"})
    )

    def fake_post(path: str, json: dict[str, Any] | None = None) -> Any:
        captured["path"] = path
        captured["body"] = json
        return response

    client.post = fake_post  # type: ignore[method-assign]
    return client


_RESPONSE = {
    "items": [
        {"name": "NOT_FOUND: National ID not found",
         "metrics": {"calls.sum.3600": [[1, 7000.0], [2, 702.0]]}},
        {"name": "FAILED_PRECONDITION: dup", "metrics": {"calls.sum.3600": [[1, 33.0]]}},
        {"name": None, "metrics": {"calls.sum.3600": [[1, 5.0]]}},
    ]
}


_TRACES_RESPONSE = {"items": [{"trace": {"id": "t1", "label": "POST /pay", "duration": 9,
                                          "erroneous": True, "service": {"label": "be-payments"}}}]}


def test_traces_erroneous_only_adds_erroneous_filter() -> None:
    cap: dict[str, Any] = {}
    client = _client_with_post(cap, _TRACES_RESPONSE)
    client.traces(service_name="be-payments", erroneous_only=True)
    tfe = cap["body"]["tagFilterExpression"]
    assert tfe["type"] == "EXPRESSION" and tfe["logicalOperator"] == "AND"
    names = {e["name"] for e in tfe["elements"]}
    assert names == {"service.name", "trace.erroneous"}


def test_traces_default_is_single_service_filter() -> None:
    cap: dict[str, Any] = {}
    client = _client_with_post(cap, _TRACES_RESPONSE)
    client.traces(service_name="be-payments")
    assert cap["body"]["tagFilterExpression"]["type"] == "TAG_FILTER"  # no erroneous AND


def test_error_messages_unfiltered_body_and_parsing() -> None:
    cap: dict[str, Any] = {}
    client = _client_with_post(cap, _RESPONSE)
    out = client.error_messages(window_size_ms=6_000, limit=10)
    # endpoint + group tag
    assert cap["path"] == "/api/application-monitoring/analyze/call-groups"
    assert cap["body"]["group"]["groupbyTag"] == "call.error.message"
    # no service filter -> single trace.erroneous TAG_FILTER (no EXPRESSION wrapper)
    tfe = cap["body"]["tagFilterExpression"]
    assert tfe["type"] == "TAG_FILTER"
    assert tfe["name"] == "trace.erroneous"
    assert tfe["value"] is True
    # parsing: name + summed count, ranked desc, None name -> "(no message)"
    assert out[0] == {"message": "NOT_FOUND: National ID not found", "count": 7702}
    assert out[1] == {"message": "FAILED_PRECONDITION: dup", "count": 33}
    assert out[2]["message"] == "(no message)"


def test_call_groups_omits_granularity() -> None:
    # Regression: Instana returns 412 when the metric granularity >= the window
    # (default 1h window + 3600s granularity). The body must send NO granularity.
    cap: dict[str, Any] = {}
    client = _client_with_post(cap, _RESPONSE)
    client.error_messages(window_size_ms=3_600_000, limit=5)
    metrics = cap["body"]["metrics"]
    assert metrics == [{"metric": "calls", "aggregation": "SUM"}]
    assert "granularity" not in metrics[0]


def test_error_http_status_and_endpoints_facets() -> None:
    cap: dict[str, Any] = {}
    client = _client_with_post(cap, _RESPONSE)

    status = client.error_http_status(service_name="be-payments", window_size_ms=6_000)
    assert cap["body"]["group"]["groupbyTag"] == "call.http.status"
    assert status[0]["status"] == "NOT_FOUND: National ID not found"  # from _RESPONSE names
    assert status[0]["count"] == 7702

    endpoints = client.error_endpoints(service_name="be-payments", window_size_ms=6_000)
    assert cap["body"]["group"]["groupbyTag"] == "call.name"
    assert endpoints[0]["endpoint"] == "NOT_FOUND: National ID not found"
    assert "count" in endpoints[0]


def test_error_messages_with_service_filter_uses_AND_expression() -> None:
    cap: dict[str, Any] = {}
    client = _client_with_post(cap, _RESPONSE)
    client.error_messages(service_name="tiam-ms-profile", window_size_ms=6_000)
    tfe = cap["body"]["tagFilterExpression"]
    assert tfe["type"] == "EXPRESSION"
    assert tfe["logicalOperator"] == "AND"
    names = {e["name"] for e in tfe["elements"]}
    assert names == {"trace.erroneous", "service.name"}
    svc = next(e for e in tfe["elements"] if e["name"] == "service.name")
    assert svc["value"] == "tiam-ms-profile"


def test_errors_by_service_groups_by_service_name() -> None:
    cap: dict[str, Any] = {}
    client = _client_with_post(cap, _RESPONSE)
    out = client.errors_by_service(window_size_ms=6_000)
    assert cap["body"]["group"]["groupbyTag"] == "service.name"
    assert out[0]["count"] == 7702  # ranked desc, summed
    assert "service" in out[0]


def test_call_groups_includes_to_when_set() -> None:
    cap: dict[str, Any] = {}
    client = _client_with_post(cap, _RESPONSE)
    client.error_messages(window_size_ms=6_000, limit=5, to_ms=1782983492003)
    tf = cap["body"]["timeFrame"]
    assert tf == {"to": 1782983492003, "windowSize": 6_000}


def test_call_groups_omits_to_when_none() -> None:
    cap: dict[str, Any] = {}
    client = _client_with_post(cap, _RESPONSE)
    client.error_messages(window_size_ms=6_000, limit=5)
    assert "to" not in cap["body"]["timeFrame"]


def test_traces_includes_to_when_set() -> None:
    cap: dict[str, Any] = {}
    client = _client_with_post(cap, _TRACES_RESPONSE)
    client.traces(service_name="be-payments", window_size_ms=6_000, to_ms=1782983492003)
    assert cap["body"]["timeFrame"] == {"to": 1782983492003, "windowSize": 6_000}
