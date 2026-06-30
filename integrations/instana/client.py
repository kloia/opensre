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
    ) -> list[dict[str, Any]]:
        """Return the raw list of Instana events in a window."""
        params: dict[str, Any] = {"windowSize": window_size_ms}
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
    ) -> dict[str, Any]:
        """Return application golden-signal metrics (v2 API) as magnitude+trend summaries."""
        body: dict[str, Any] = {
            "metrics": [
                {"metric": "latency", "aggregation": "MEAN", "granularity": granularity_s},
                {"metric": "latency", "aggregation": "P90", "granularity": granularity_s},
                {"metric": "errors", "aggregation": "MEAN", "granularity": granularity_s},
                {"metric": "calls", "aggregation": "SUM", "granularity": granularity_s},
            ],
            "timeFrame": {"windowSize": window_size_ms},
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
    ) -> Any:
        """Return infrastructure entities matching a query."""
        params = {"query": query, "windowSize": window_size_ms}
        return self.get("/api/infrastructure-monitoring/snapshots", params=params)

    def traces(
        self,
        service_name: str,
        window_size_ms: int = 3_600_000,
        max_traces: int = 10,
    ) -> list[dict[str, Any]]:
        """Return the slowest traces (latency desc) for a service from Instana."""
        body = {
            "timeFrame": {"windowSize": window_size_ms},
            "tagFilterExpression": _service_filter(service_name),
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
        granularity_s: int = 3600,
    ) -> list[dict[str, Any]]:
        """POST analyze/call-groups grouped by a tag, filtered to erroneous calls.

        Returns the raw ``items`` list (each ``{"name", "metrics", ...}``). A0-validated
        endpoint: ``/api/application-monitoring/analyze/call-groups`` (NOT ``analyze/calls``).
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
            "timeFrame": {"windowSize": window_size_ms},
            "tagFilterExpression": tag_filter,
            "group": {"groupbyTag": groupby_tag},
            "metrics": [{"metric": "calls", "aggregation": "SUM", "granularity": granularity_s}],
            "pagination": {"retrievalSize": limit},
        }
        resp = self.post("/api/application-monitoring/analyze/call-groups", json=body)
        items = resp.get("items", []) if isinstance(resp, dict) else []
        return items if isinstance(items, list) else []

    def error_messages(
        self,
        service_name: str | None = None,
        window_size_ms: int = 3_600_000,
        limit: int = 10,
    ) -> list[dict[str, Any]]:
        """Return ranked real error messages (``call.error.message``) with occurrence counts.

        This is the primary RCA signal: the actual exception strings (Postgres/Mongo/app
        errors), not just an error count. Ranked by total occurrences, descending.
        """
        items = self._call_groups("call.error.message", window_size_ms, service_name, limit)
        out = [
            {"message": (it.get("name") or "(no message)"), "count": _sum_series(it.get("metrics", {}))}
            for it in items
        ]
        out.sort(key=lambda r: r["count"], reverse=True)
        return out

    def errors_by_service(
        self,
        window_size_ms: int = 3_600_000,
        limit: int = 10,
    ) -> list[dict[str, Any]]:
        """Return which services are erroring (``service.name``) with occurrence counts, ranked."""
        items = self._call_groups("service.name", window_size_ms, None, limit)
        out = [
            {"service": (it.get("name") or "(unknown)"), "count": _sum_series(it.get("metrics", {}))}
            for it in items
        ]
        out.sort(key=lambda r: r["count"], reverse=True)
        return out

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
            "timeFrame": {"windowSize": window_size_ms},
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
