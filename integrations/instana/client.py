"""Instana REST API client for events, traces, metrics, and infrastructure.

Uses the Instana REST API directly via httpx (no SDK dependency). Endpoint paths
follow the Instana REST API; tools that consume this client never raise into the
agent loop — the low-level ``get``/``post`` raise, and the tool layer wraps them.

Credentials come from the user's Instana integration (resolved natively or
injected per-request by the sidecar).
"""

from __future__ import annotations

import logging
from typing import Any

import httpx

from integrations.config_models import InstanaIntegrationConfig
from integrations.probes import ProbeResult

logger = logging.getLogger(__name__)

_DEFAULT_TIMEOUT = 30

InstanaConfig = InstanaIntegrationConfig


def _summarize_series(series: list[Any]) -> dict[str, Any]:
    """Collapse a [[ts, value], ...] series into magnitude + trend stats (no raw points)."""
    vals = [v for _ts, v in series if v is not None]
    if not vals:
        return {"points": 0}
    first, last = vals[0], vals[-1]
    trend = "rising" if last > first * 1.1 else "falling" if last < first * 0.9 else "flat"
    return {
        "latest": last,
        "min": min(vals),
        "max": max(vals),
        "mean": round(sum(vals) / len(vals), 2),
        "first": first,
        "last": last,
        "trend": trend,
        "points": len(vals),
    }


def _timeframe(window_size_ms: int, to_ms: int | None) -> dict[str, Any]:
    """Instana timeFrame — anchored to `to_ms` (event end) when given, else window ends at now."""
    tf: dict[str, Any] = {"windowSize": window_size_ms}
    if to_ms is not None:
        tf["to"] = to_ms
    return tf


def _sum_series(metrics: dict[str, Any]) -> int:
    """Sum every value across all metric series in a call-groups item."""
    total = 0.0
    for series in (metrics or {}).values():
        for point in series or []:
            # Instana call-groups series points are always [ts, value] 2-tuples
            if isinstance(point, (list, tuple)) and len(point) == 2 and point[1] is not None:
                total += point[1]
    return int(total)


def _service_filter(service_name: str) -> dict[str, Any]:
    """Build the Instana TAG_FILTER for a service.name EQUALS match."""
    return {"type": "TAG_FILTER", "name": "service.name", "operator": "EQUALS", "value": service_name}


def _region_from(data: dict[str, Any]) -> str:
    for k, v in data.items():
        if k.endswith("_arn") and isinstance(v, str) and v.startswith("arn:"):
            parts = v.split(":")
            if len(parts) > 3 and parts[3]:
                return parts[3]
    az = data.get("availability_zone") or ""
    return az[:-1] if az and az[-1].isalpha() else az


class InstanaClient:
    """Synchronous client for querying Instana events, traces, metrics, and infra."""

    def __init__(self, config: InstanaConfig) -> None:
        self.config = config
        self._client: httpx.Client | None = None

    def _get_client(self) -> httpx.Client:
        if self._client is None:
            self._client = httpx.Client(
                base_url=self.config.base_url,
                headers=self.config.headers,
                timeout=_DEFAULT_TIMEOUT,
            )
        return self._client

    @property
    def is_configured(self) -> bool:
        return bool(self.config.base_url and self.config.api_token)

    def get(self, path: str, params: dict[str, Any] | None = None) -> Any:
        resp = self._get_client().get(path, params=params or {})
        resp.raise_for_status()
        return resp.json()

    def post(self, path: str, json: dict[str, Any] | None = None) -> Any:
        resp = self._get_client().post(path, json=json or {})
        resp.raise_for_status()
        return resp.json()

    def probe_access(self) -> ProbeResult:
        """Validate Instana credentials with a lightweight application list call."""
        if not self.is_configured:
            return ProbeResult.missing("Missing base_url or api_token.")
        try:
            resp = self._get_client().get(
                "/api/application-monitoring/applications", params={"pageSize": 1}
            )
            resp.raise_for_status()
        except Exception as exc:
            return ProbeResult.failed(
                f"Instana API check failed: {exc}", base_url=self.config.base_url
            )
        return ProbeResult.passed(
            f"Connected to {self.config.base_url}.", base_url=self.config.base_url
        )

    # ------------------------------------------------------------------
    # Endpoint helpers (ported from the sidecar Instana tools)
    # ------------------------------------------------------------------

    def get_events(
        self,
        window_size_ms: int = 3_600_000,
        event_type_filters: list[str] | None = None,
        to_ms: int | None = None,
    ) -> list[dict[str, Any]]:
        """Return the raw list of Instana events in a window."""
        params: dict[str, Any] = {"windowSize": window_size_ms}
        if to_ms is not None:
            params["to"] = to_ms
        if event_type_filters:
            params["eventTypeFilters"] = event_type_filters
        events = self.get("/api/events", params=params)
        return events if isinstance(events, list) else []

    def get_event_detail(self, event_id: str) -> dict[str, Any]:
        """Return a single Instana event by id."""
        detail = self.get(f"/api/events/{event_id}")
        return detail if isinstance(detail, dict) else {}

    def application_metrics(
        self,
        service_name: str | None = None,
        window_size_ms: int = 3_600_000,
        granularity_s: int = 60,
        to_ms: int | None = None,
    ) -> dict[str, Any]:
        """Return application golden-signal metrics (v2 API) as magnitude+trend summaries."""
        body: dict[str, Any] = {
            "metrics": [
                {"metric": "latency", "aggregation": "MEAN", "granularity": granularity_s},
                {"metric": "latency", "aggregation": "P90", "granularity": granularity_s},
                {"metric": "errors", "aggregation": "MEAN", "granularity": granularity_s},
                {"metric": "calls", "aggregation": "SUM", "granularity": granularity_s},
            ],
            "timeFrame": _timeframe(window_size_ms, to_ms),
        }
        if service_name:
            body["tagFilterExpression"] = _service_filter(service_name)
        m = self.post("/api/application-monitoring/v2/metrics", json=body)
        series_map = (m.get("metrics") or {}) if isinstance(m, dict) else {}
        summary = {name: _summarize_series(series) for name, series in series_map.items()}
        return {
            "timeframe": m.get("adjustedTimeframe") if isinstance(m, dict) else None,
            "metrics": summary,
        }

    def infrastructure_health(
        self,
        query: str,
        window_size_ms: int = 3_600_000,
        to_ms: int | None = None,
    ) -> Any:
        """Return infrastructure entities matching a query."""
        params: dict[str, Any] = {"query": query, "windowSize": window_size_ms}
        if to_ms is not None:
            params["to"] = to_ms
        return self.get("/api/infrastructure-monitoring/snapshots", params=params)

    def traces(
        self,
        service_name: str,
        window_size_ms: int = 3_600_000,
        max_traces: int = 10,
        erroneous_only: bool = False,
        to_ms: int | None = None,
    ) -> list[dict[str, Any]]:
        """Return traces for a service, ordered by latency DESC.

        With ``erroneous_only`` the result is filtered to erroneous traces — use it for
        error-rate investigations so drilling in shows actually-failing spans rather than
        the slowest (often non-errored) ones. Default returns the slowest traces.
        """
        svc_filter = _service_filter(service_name)
        if erroneous_only:
            tag_filter: dict[str, Any] = {
                "type": "EXPRESSION",
                "logicalOperator": "AND",
                "elements": [svc_filter, dict(self._ERRONEOUS_FILTER)],
            }
        else:
            tag_filter = svc_filter
        body = {
            "timeFrame": _timeframe(window_size_ms, to_ms),
            "tagFilterExpression": tag_filter,
            "order": {"by": "latency", "direction": "DESC"},
            "pagination": {"retrievalSize": max_traces},
        }
        resp = self.post("/api/application-monitoring/analyze/traces", json=body)
        items = resp.get("items", []) if isinstance(resp, dict) else []
        slowest: list[dict[str, Any]] = []
        for it in items:
            t = it.get("trace") or {}
            slowest.append(
                {
                    "trace_id": t.get("id"),
                    "label": t.get("label"),
                    "duration_ms": t.get("duration"),
                    "erroneous": t.get("erroneous"),
                    "service": (t.get("service") or {}).get("label"),
                }
            )
        return slowest

    _ERRONEOUS_FILTER = {
        "type": "TAG_FILTER",
        "name": "trace.erroneous",
        "operator": "EQUALS",
        "value": True,
    }

    def _call_groups(
        self,
        groupby_tag: str,
        window_size_ms: int,
        service_name: str | None,
        limit: int,
        to_ms: int | None = None,
    ) -> list[dict[str, Any]]:
        """POST analyze/call-groups grouped by a tag, filtered to erroneous calls.

        Returns the raw ``items`` list (each ``{"name", "metrics", ...}``). A0-validated
        endpoint: ``/api/application-monitoring/analyze/call-groups`` (NOT ``analyze/calls``).

        No ``granularity`` is sent: Instana rejects call-groups with 412 when the metric
        granularity is >= the window (the default 1h window + a 3600s granularity trips
        this). Omitting it lets Instana auto-roll the series; ``_sum_series`` totals
        whatever buckets come back regardless of the metric key.
        """
        if service_name:
            tag_filter: dict[str, Any] = {
                "type": "EXPRESSION",
                "logicalOperator": "AND",
                "elements": [
                    self._ERRONEOUS_FILTER,
                    _service_filter(service_name),
                ],
            }
        else:
            tag_filter = dict(self._ERRONEOUS_FILTER)
        body = {
            "timeFrame": _timeframe(window_size_ms, to_ms),
            "tagFilterExpression": tag_filter,
            "group": {"groupbyTag": groupby_tag},
            "metrics": [{"metric": "calls", "aggregation": "SUM"}],
            "pagination": {"retrievalSize": limit},
        }
        resp = self.post("/api/application-monitoring/analyze/call-groups", json=body)
        items = resp.get("items", []) if isinstance(resp, dict) else []
        return items if isinstance(items, list) else []

    def _grouped_error_counts(
        self,
        groupby_tag: str,
        key: str,
        fallback: str,
        service_name: str | None,
        window_size_ms: int,
        limit: int,
        to_ms: int | None = None,
    ) -> list[dict[str, Any]]:
        """Group erroneous calls by a tag and return ``[{<key>: name, "count": n}]`` ranked desc."""
        items = self._call_groups(groupby_tag, window_size_ms, service_name, limit, to_ms=to_ms)
        out = [
            {key: (it.get("name") or fallback), "count": _sum_series(it.get("metrics", {}))}
            for it in items
        ]
        out.sort(key=lambda r: r["count"], reverse=True)
        return out

    def error_messages(
        self,
        service_name: str | None = None,
        window_size_ms: int = 3_600_000,
        limit: int = 10,
        to_ms: int | None = None,
    ) -> list[dict[str, Any]]:
        """Return ranked real error messages (``call.error.message``) with occurrence counts.

        The strongest RCA signal when present: actual exception strings (Postgres/Mongo/app
        errors). Empty for services whose errors are HTTP status codes without an exception
        message (see ``error_http_status`` / ``error_endpoints``). Ranked by occurrences.
        """
        return self._grouped_error_counts(
            "call.error.message", "message", "(no message)", service_name, window_size_ms, limit,
            to_ms=to_ms,
        )

    def error_http_status(
        self,
        service_name: str | None = None,
        window_size_ms: int = 3_600_000,
        limit: int = 10,
        to_ms: int | None = None,
    ) -> list[dict[str, Any]]:
        """Return the HTTP status codes (``call.http.status``) of erroneous calls, ranked.

        The RCA signal for status-code failures (e.g. a service returning 500) that carry no
        exception message. Ranked by occurrences, descending.
        """
        return self._grouped_error_counts(
            "call.http.status", "status", "(none)", service_name, window_size_ms, limit,
            to_ms=to_ms,
        )

    def error_endpoints(
        self,
        service_name: str | None = None,
        window_size_ms: int = 3_600_000,
        limit: int = 10,
        to_ms: int | None = None,
    ) -> list[dict[str, Any]]:
        """Return which endpoints (``call.name``) are erroring, ranked by occurrences."""
        return self._grouped_error_counts(
            "call.name", "endpoint", "(unknown)", service_name, window_size_ms, limit,
            to_ms=to_ms,
        )

    def errors_by_service(
        self,
        window_size_ms: int = 3_600_000,
        limit: int = 10,
        to_ms: int | None = None,
    ) -> list[dict[str, Any]]:
        """Return which services are erroring (``service.name``) with occurrence counts, ranked."""
        return self._grouped_error_counts(
            "service.name", "service", "(unknown)", None, window_size_ms, limit,
            to_ms=to_ms,
        )

    def application_context(
        self,
        application_name: str,
        window_size_ms: int = 3_600_000,
        to_ms: int | None = None,
        limit: int = 10,
    ) -> dict[str, Any]:
        """Resolve an Instana Application Perspective by name and return its member services
        + which member services are erroring most (application-scoped, time-anchored)."""
        apps = self.get("/api/application-monitoring/applications", params={"nameFilter": application_name, "pageSize": 20})
        items = apps.get("items", []) if isinstance(apps, dict) else (apps if isinstance(apps, list) else [])
        match = next((a for a in items if (a.get("label") or "").strip() == application_name.strip()), (items[0] if items else None))
        app_id = (match or {}).get("id")
        # Top-erroring member services within this application boundary.
        tag_filter: dict[str, Any] = {
            "type": "EXPRESSION", "logicalOperator": "AND",
            "elements": [dict(self._ERRONEOUS_FILTER),
                         {"type": "TAG_FILTER", "name": "application.name", "operator": "EQUALS", "value": application_name}],
        }
        body = {
            "timeFrame": _timeframe(window_size_ms, to_ms),
            "tagFilterExpression": tag_filter,
            "group": {"groupbyTag": "service.name"},
            "metrics": [{"metric": "calls", "aggregation": "SUM"}],
            "pagination": {"retrievalSize": limit},
        }
        resp = self.post("/api/application-monitoring/analyze/call-groups", json=body)
        rows = resp.get("items", []) if isinstance(resp, dict) else []
        top = [{"service": (r.get("name") or "(unknown)"), "count": _sum_series(r.get("metrics", {}))} for r in rows]
        top.sort(key=lambda r: r["count"], reverse=True)
        return {"application": application_name, "application_id": app_id, "top_error_services": top}

    def get_trace_detail(
        self,
        trace_id: str,
        retrieval_size: int = 200,
    ) -> list[dict[str, Any]]:
        """Return the raw span items for a single Instana trace."""
        detail = self.get(
            f"/api/application-monitoring/v2/analyze/traces/{trace_id}",
            params={"retrievalSize": retrieval_size},
        )
        return detail.get("items", []) if isinstance(detail, dict) else []

    def search_logs(
        self,
        query: str = "",
        service_name: str = "",
        window_size_ms: int = 3_600_000,
        limit: int = 50,
        to_ms: int | None = None,
    ) -> list[dict[str, Any]]:
        """Search Instana logs by query/service within a time window.

        Targets the Instana Log Management API (``/api/log/analyze/logs``), which is
        the intended endpoint but is unavailable on APM-only tenants: every
        ``/api/log/...`` path returns 404 there, and the endpoint could NOT be
        verified against the A0 sandbox (Log Management was not licensed). This method
        raises on any transport/HTTP error so the tool layer degrades to the
        graceful-unavailable path.
        """
        body: dict[str, Any] = {
            "timeFrame": _timeframe(window_size_ms, to_ms),
            "pagination": {"retrievalSize": limit},
        }
        if query:
            body["query"] = query
        if service_name:
            body["tagFilterExpression"] = _service_filter(service_name)
        resp = self.post("/api/log/analyze/logs", json=body)
        items = resp.get("items", []) if isinstance(resp, dict) else []
        return items if isinstance(items, list) else []

    def resolve_aws_resource(self, snapshot_id: str) -> dict[str, Any]:
        """Return {aws_account_id, region, arn, ...} for an Instana AWS entity snapshot."""
        snap = self.get(f"/api/infrastructure-monitoring/snapshots/{snapshot_id}")
        data = snap.get("data") or {}
        account = data.get("aws_account_id") or data.get("account_id")
        arn = next(
            (
                v
                for k, v in data.items()
                if k.endswith("_arn") and isinstance(v, str) and v.startswith("arn:")
            ),
            "",
        )
        return {
            "aws_account_id": account,
            "region": _region_from(data),
            "arn": arn,
            "resource_label": snap.get("label"),
            "plugin": snap.get("plugin"),
        }
