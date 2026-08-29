"""Native Instana REST tools for incident investigation (read-only).

Ported from the sidecar's custom Instana tools. Now that OpenSRE's
``EvidenceSource`` enum includes ``"instana"``, these tools declare
``source="instana"`` directly (the old ``source="datadog"`` +
``source_id="instana"`` workaround is gone).

Tools never raise into the agent loop — the low-level client ``get``/``post``
raise, and the tool layer wraps them into structured ``available: False`` dicts.

Availability is driven by ``_instana_available`` reading the ``"instana"`` key in
resolved/injected integrations (base_url + api_token presence), independent of
any verify step — this keeps both native-resolution and per-request injection
working.
"""

from __future__ import annotations

import re
from concurrent.futures import ThreadPoolExecutor
from typing import Any

import httpx

from integrations.instana.client import InstanaClient, InstanaConfig
from tools.tool_decorator import tool

_INJECTED: tuple[str, ...] = ("base_url", "api_token")

_LOG_ERROR_KEYWORDS = ("error", "exception", "fail", "timeout", "oom", "panic")


# ---------------------------------------------------------------------------
# Availability / param extraction (tool-layer helpers)
# ---------------------------------------------------------------------------


def _instana_available(sources: dict[str, dict]) -> bool:
    inst = sources.get("instana") or {}
    return bool(inst.get("base_url") and inst.get("api_token"))


def _instana_extract_params(sources: dict[str, dict]) -> dict[str, Any]:
    inst = sources.get("instana") or {}
    params: dict[str, Any] = {
        "base_url": inst.get("base_url", ""),
        "api_token": inst.get("api_token", ""),
    }
    # Test/injection passthrough: a pre-built client short-circuits credential use.
    if inst.get("_client_override") is not None:
        params["_client_override"] = inst["_client_override"]
    return params


def _resolve_client(base_url: str, api_token: str, override: InstanaClient | None) -> InstanaClient:
    if override is not None:
        return override
    return InstanaClient(
        InstanaConfig.model_validate({"base_url": base_url, "api_token": api_token})
    )


def _error(exc: Exception) -> str:
    if isinstance(exc, httpx.HTTPStatusError):
        return f"HTTP {exc.response.status_code}: {exc.response.text[:200]}"
    return f"{type(exc).__name__}: {exc}"


def _safe(fn: Any, *args: Any, **kwargs: Any) -> list[dict[str, Any]]:
    """Call an error-facet client method, returning [] instead of raising.

    Error analysis fans out over several call-groups facets (messages, http status,
    endpoints). One facet failing — e.g. a tag a given tenant doesn't populate returns
    HTTP 400 — must not blank the others, so each facet is isolated here.
    """
    try:
        result = fn(*args, **kwargs)
        return result if isinstance(result, list) else []
    except Exception:
        return []


def _extract_event_id(event_id: str, event_url: str) -> str:
    """Return the event id, parsing it from an Instana event URL if needed.

    Instana event URLs carry the id as ``eventId=<id>`` (e.g.
    ``.../#/event;eventId=ABC123;...``).
    """
    if event_id:
        return event_id.strip()
    if not event_url:
        return ""
    match = re.search(r"eventId=([^;&/?\s]+)", event_url)
    if match:
        return match.group(1)
    return ""


_EVENT_FIELDS = ("eventId", "problem", "severity", "state", "type", "entityLabel", "start", "end")


def _compact_event(e: dict) -> dict:
    return {k: e.get(k) for k in _EVENT_FIELDS}


def _severity(e: dict[str, Any]) -> int:
    sv = e.get("severity")
    return sv if isinstance(sv, int) else -99


_NOISE_EVENT_TYPE = "change"


def _event_is_relevant(e: dict[str, Any], relevant_to: str) -> bool:
    """True if this event's entity plausibly belongs to ``relevant_to``.

    Instana's ``/api/events`` has no entity/service filter param, so callers that need
    per-service evidence (as opposed to an intentionally account-wide sweep) must filter
    client-side. ``entityLabel`` formats observed in practice are inconsistent — a bare
    service name (``"ratings"``), a namespaced service (``"robot-shop/be-gateway"``), or a
    namespaced pod with a deployment-hash suffix (``"robot-shop/cart-6c94fd9f66-hq749"``,
    or bracket-wrapped as ``"cart (robot-shop/cart-6c94fd9f66-hq749)"``) — so this is a
    case-insensitive substring match rather than an exact/prefix match, which is the only
    rule that holds across all three observed shapes without needing to parse K8s naming
    conventions. An event with no ``entityLabel`` at all (e.g. some account-level
    incidents) can't be ruled out either way — it's kept, not dropped, since the goal
    is excluding *confirmed*-unrelated entities, not maximizing precision at the cost
    of hiding evidence that simply wasn't labeled.
    """
    label = e.get("entityLabel")
    if not label:
        return True
    return relevant_to.lower() in str(label).lower()


def _rank_events(
    events: list[dict[str, Any]],
    *,
    min_severity: int,
    open_only: bool,
    max_events: int,
    include_changes: bool,
    relevant_to: str | None = None,
) -> dict[str, Any]:
    """Rank + compact Instana events for RCA, with totals.

    Drops ``type == "change"`` infra noise unless ``include_changes``. Keeps events at
    or above ``min_severity`` (and open-only when asked), ranked open-first then by
    severity then recency. Returns the same shape the events tool exposes.

    ``relevant_to``, when given, additionally drops events whose entity doesn't
    plausibly belong to that service (see ``_event_is_relevant``) — used for per-service
    evidence gathering; both ``instana_get_investigation_context`` and
    ``instana_get_events`` always pass it, since ``service_name`` is a required
    parameter on both tools.
    """
    total = len(events)
    open_count = sum(1 for e in events if e.get("state") == "open")
    by_severity: dict[str, int] = {}
    for e in events:
        sv = str(e.get("severity"))
        by_severity[sv] = by_severity.get(sv, 0) + 1
    kept = [
        e
        for e in events
        if _severity(e) >= min_severity
        and (include_changes or e.get("type") != _NOISE_EVENT_TYPE)
        and (not open_only or e.get("state") == "open")
        and (relevant_to is None or _event_is_relevant(e, relevant_to))
    ]
    kept.sort(
        key=lambda e: (e.get("state") == "open", _severity(e), e.get("start") or 0),
        reverse=True,
    )
    shown = [_compact_event(e) for e in kept[:max_events]]
    filt = f"severity>={min_severity}" + (", open-only" if open_only else ", open-first")
    if not include_changes:
        filt += ", excl-change"
    if relevant_to is not None:
        filt += f", relevant-to={relevant_to}"
    return {
        "totals": {"all": total, "open": open_count, "by_severity": by_severity},
        "filter": filt,
        "shown": len(shown),
        "omitted": max(0, len(kept) - len(shown)),
        "events": shown,
    }


# ---------------------------------------------------------------------------
# Ported tools
# ---------------------------------------------------------------------------


@tool(
    name="instana_get_events",
    display_name="Instana Events",
    source="instana",
    description=(
        "List significant Instana events/incidents/issues for a service in a window. Scoped "
        "to entities plausibly belonging to service_name the same way "
        "instana_get_investigation_context scopes its events (see _event_is_relevant) — this "
        "account is shared across multiple unrelated applications/tenants, so an unscoped sweep "
        "would surface other teams' incidents alongside anything actually relevant. Returns the "
        "highest severity / open events first (compact fields + eventId to drill into via "
        "instana_get_event_detail), plus totals so nothing is silently dropped. Infra "
        "'change'-type events (host online/offline noise) are excluded by default; set "
        "include_changes=true to include them. Lower min_severity or raise max_events to widen."
    ),
    use_cases=[
        "Finding active incidents or issues affecting a specific service or entity",
        "Checking whether an alert corresponds to an open Instana event for that service",
        "Reviewing recent state changes around the incident window for a service",
    ],
    tags=("events", "incidents", "instana"),
    requires=[],
    evidence_type="events",
    side_effect_level="read_only",
    injected_params=_INJECTED,
    is_available=_instana_available,
    extract_params=_instana_extract_params,
)
def instana_get_events(
    service_name: str,
    window_size_ms: int = 3_600_000,
    min_severity: int = 5,
    max_events: int = 50,
    open_only: bool = False,
    include_changes: bool = False,
    event_type_filters: list[str] | None = None,
    to_ms: int | None = None,
    base_url: str = "",
    api_token: str = "",
    _client_override: InstanaClient | None = None,
    **_kwargs: Any,
) -> dict:
    """Return ranked, compacted significant Instana events with full totals, scoped to service_name.

    ``service_name`` is required (not optional) — this account is shared across
    unrelated applications, so a real production incident showed the agent
    treating another application's DB-connectivity event as if it were the
    alerting service's own evidence purely because the unscoped sweep put it at
    the top by severity. Forcing scope at the call signature, not just via a
    description an agent can choose to ignore, closes that path entirely. Use
    instana_get_investigation_context for a specific alert's own evidence.
    """
    try:
        client = _resolve_client(base_url, api_token, _client_override)
        events = client.get_events(
            window_size_ms=window_size_ms, event_type_filters=event_type_filters, to_ms=to_ms
        )
        ranked = _rank_events(
            events,
            min_severity=min_severity,
            open_only=open_only,
            max_events=max_events,
            include_changes=include_changes,
            relevant_to=service_name,
        )
        scope = f"scoped to entities plausibly belonging to '{service_name}'"
        return {"source": "instana", "available": True, "scope": scope, **ranked}
    except Exception as exc:
        return {"source": "instana", "available": False, "error": _error(exc), "events": []}


@tool(
    name="instana_get_event_detail",
    display_name="Instana Event Detail",
    source="instana",
    description=(
        "Fetch full details of a specific Instana event by its event id. "
        "Provide event_id, or pass event_url (e.g. an event link containing "
        "'eventId=...') and the id is parsed from it."
    ),
    use_cases=["Retrieving the details of a known incident/event from its id or URL"],
    requires=[],
    evidence_type="events",
    side_effect_level="read_only",
    injected_params=_INJECTED,
    is_available=_instana_available,
    extract_params=_instana_extract_params,
)
def instana_get_event_detail(
    event_id: str = "",
    event_url: str = "",
    base_url: str = "",
    api_token: str = "",
    _client_override: InstanaClient | None = None,
    **_kwargs: Any,
) -> dict:
    """Return a single Instana event by id (or parsed from an event URL)."""
    eid = _extract_event_id(event_id, event_url)
    if not eid:
        return {
            "source": "instana",
            "available": False,
            "error": "No event id provided (pass event_id or an event_url containing eventId=...).",
            "event": {},
        }
    try:
        client = _resolve_client(base_url, api_token, _client_override)
        detail = client.get_event_detail(eid)
        return {"source": "instana", "available": True, "event_id": eid, "event": detail}
    except Exception as exc:
        return {
            "source": "instana",
            "available": False,
            "error": _error(exc),
            "event_id": eid,
            "event": {},
        }


@tool(
    name="instana_application_metrics",
    display_name="Instana Application Metrics",
    source="instana",
    description=(
        "Fetch golden-signal metrics (latency, error rate, throughput) for a service. "
        "service_name is required: without it, the underlying API blends latency/error-rate/"
        "throughput across every service on this shared multi-tenant account into one "
        "meaningless composite number, silently corrupting any 'confirm this alert against "
        "golden signals' check."
    ),
    use_cases=[
        "Checking latency/error-rate/throughput for a service during an incident",
        "Confirming a latency or error-rate alert against golden-signal metrics",
        "Comparing a service's metrics to its pre-incident baseline",
    ],
    tags=("metrics", "golden-signals", "latency", "instana"),
    requires=[],
    evidence_type="metrics",
    side_effect_level="read_only",
    injected_params=_INJECTED,
    is_available=_instana_available,
    extract_params=_instana_extract_params,
)
def instana_application_metrics(
    service_name: str,
    window_size_ms: int = 3_600_000,
    granularity_s: int = 60,
    to_ms: int | None = None,
    base_url: str = "",
    api_token: str = "",
    _client_override: InstanaClient | None = None,
    **_kwargs: Any,
) -> dict:
    """Return per-service golden-signal metrics (v2 API) as magnitude+trend summaries.

    ``service_name`` is required — without it the v2 metrics API has no
    ``tagFilterExpression`` and blends every service on this shared account
    into one composite number, which would silently corrupt any comparison
    against a specific service's alert threshold.
    """
    try:
        client = _resolve_client(base_url, api_token, _client_override)
        result = client.application_metrics(
            service_name=service_name,
            window_size_ms=window_size_ms,
            granularity_s=granularity_s,
            to_ms=to_ms,
        )
        return {
            "source": "instana",
            "available": True,
            "timeframe": result.get("timeframe"),
            "metrics": result.get("metrics", {}),
        }
    except Exception as exc:
        return {"source": "instana", "available": False, "error": _error(exc), "metrics": {}}


@tool(
    name="instana_infrastructure_health",
    display_name="Instana Infrastructure",
    source="instana",
    description="Query infrastructure entities (hosts/containers/pods) and their health/metrics.",
    use_cases=[
        "Checking host/container/pod health and saturation during an incident",
        "Confirming a host/infrastructure alert against CPU/memory/disk metrics",
        "Mapping an alerting host to its running containers/pods",
    ],
    tags=("infrastructure", "hosts", "saturation", "instana"),
    requires=["query"],
    evidence_type="topology",
    side_effect_level="read_only",
    injected_params=_INJECTED,
    is_available=_instana_available,
    extract_params=_instana_extract_params,
)
def instana_infrastructure_health(
    query: str,
    window_size_ms: int = 3_600_000,
    base_url: str = "",
    api_token: str = "",
    _client_override: InstanaClient | None = None,
    **_kwargs: Any,
) -> dict:
    """Return infrastructure entities matching a query."""
    try:
        client = _resolve_client(base_url, api_token, _client_override)
        snapshots = client.infrastructure_health(query=query, window_size_ms=window_size_ms)
        return {"source": "instana", "available": True, "infrastructure": snapshots}
    except Exception as exc:
        return {
            "source": "instana",
            "available": False,
            "error": _error(exc),
            "infrastructure": {},
        }


@tool(
    name="instana_traces",
    display_name="Instana Traces",
    source="instana",
    description=(
        "List the SLOWEST traces for a service (ordered by latency, descending) so the "
        "actual tail outliers are visible, not a random sample. Returns trace ids to drill "
        "into with instana_get_trace_detail. Set erroneous_only=true for error-rate incidents "
        "to get the actual failing traces (default returns the slowest by latency)."
    ),
    use_cases=[
        "Finding the slowest traces/endpoints and which trace to drill into",
        "Locating erroring calls behind a latency or error-rate alert",
        "Identifying the failing downstream service in a request path",
    ],
    tags=("traces", "latency", "errors", "instana"),
    requires=["service_name"],
    evidence_type="traces",
    side_effect_level="read_only",
    injected_params=_INJECTED,
    is_available=_instana_available,
    extract_params=_instana_extract_params,
)
def instana_traces(
    service_name: str,
    window_size_ms: int = 3_600_000,
    max_traces: int = 10,
    erroneous_only: bool = False,
    to_ms: int | None = None,
    base_url: str = "",
    api_token: str = "",
    _client_override: InstanaClient | None = None,
    **_kwargs: Any,
) -> dict:
    """Return the slowest (or, with erroneous_only, the erroring) traces for a service."""
    try:
        client = _resolve_client(base_url, api_token, _client_override)
        slowest = client.traces(
            service_name=service_name,
            window_size_ms=window_size_ms,
            max_traces=max_traces,
            erroneous_only=erroneous_only,
            to_ms=to_ms,
        )
        return {
            "source": "instana",
            "available": True,
            "count": len(slowest),
            "slowest_traces": slowest,
        }
    except Exception as exc:
        return {"source": "instana", "available": False, "error": _error(exc), "slowest_traces": []}


@tool(
    name="instana_get_trace_detail",
    display_name="Instana Trace Detail",
    source="instana",
    description=(
        "Drill into a single Instana trace by id (ids come from instana_traces) and return "
        "its spans ranked by duration, each with the downstream destination service/endpoint, "
        "self time, and an error count. Use it to name the exact slow or erroring downstream "
        "hop. For the actual exception text behind those errors, use instana_error_analysis."
    ),
    use_cases=["Drilling into one trace to find the slow/failing downstream call or service"],
    requires=["trace_id"],
    evidence_type="traces",
    side_effect_level="read_only",
    injected_params=_INJECTED,
    is_available=_instana_available,
    extract_params=_instana_extract_params,
)
def instana_get_trace_detail(
    trace_id: str = "",
    retrieval_size: int = 200,
    max_spans: int = 25,
    base_url: str = "",
    api_token: str = "",
    _client_override: InstanaClient | None = None,
    **_kwargs: Any,
) -> dict:
    """Return a compact, duration-ranked span summary for a single Instana trace.

    Each span carries the fields needed to localize the bottleneck: name, duration,
    self time, downstream destination service/endpoint, and an integer error count,
    plus a top-level ``error_span_count`` so erroring downstream hops are surfaced.
    The v2 trace-detail payload does not carry per-span exception text; for the real
    error/exception messages behind these errors, use ``instana_error_analysis``.
    """
    tid = trace_id.strip()
    if not tid:
        return {
            "source": "instana",
            "available": False,
            "error": "No trace id provided.",
            "slowest_spans": [],
        }
    try:
        client = _resolve_client(base_url, api_token, _client_override)
        spans = client.get_trace_detail(tid, retrieval_size=retrieval_size)
        summarized = []
        error_span_count = 0
        for sp in spans:
            dst = sp.get("destination") or {}
            ec = sp.get("errorCount")
            if isinstance(ec, (int, float)) and ec > 0:
                error_span_count += 1
            summarized.append(
                {
                    "name": sp.get("name"),
                    "duration_ms": sp.get("duration"),
                    "self_time_ms": sp.get("minSelfTime"),
                    "destination_service": (dst.get("service") or {}).get("label"),
                    "destination_endpoint": (dst.get("endpoint") or {}).get("label"),
                    "error_count": ec,
                }
            )
        summarized.sort(key=lambda s: s.get("duration_ms") or 0, reverse=True)
        return {
            "source": "instana",
            "available": True,
            "trace_id": tid,
            "span_count": len(spans),
            "error_span_count": error_span_count,
            "slowest_spans": summarized[:max_spans],
        }
    except Exception as exc:
        return {
            "source": "instana",
            "available": False,
            "error": _error(exc),
            "trace_id": tid,
            "slowest_spans": [],
        }


@tool(
    name="instana_resolve_aws_resource",
    display_name="Instana → AWS Resource",
    source="instana",
    description=(
        "Resolve which AWS account, region, and ARN any Instana-observed AWS resource belongs "
        "to — RDS and Aurora databases, EC2 and ECS compute, Lambda, load balancers, and other "
        "infrastructure — from its Instana snapshotId (found on infrastructure events under "
        "metrics[].snapshotId or snapshotId). Use this first for any AWS or database "
        "infrastructure incident, then pass the returned aws_account_id to aws_readonly_call to "
        "query that account."
    ),
    use_cases=[
        "Find which AWS account and region an Instana-observed resource lives in",
        "Map a database, compute instance, or infrastructure entity to its AWS account "
        "before querying CloudWatch or the AWS API",
    ],
    examples=[
        "Resolve the AWS account and region for an Aurora database from its snapshotId",
    ],
    tags=("aws", "account", "infrastructure", "database", "resource", "region"),
    requires=["snapshot_id"],
    evidence_type="topology",
    side_effect_level="read_only",
    injected_params=_INJECTED,
    is_available=_instana_available,
    extract_params=_instana_extract_params,
)
def instana_resolve_aws_resource(
    snapshot_id: str,
    base_url: str = "",
    api_token: str = "",
    _client_override: InstanaClient | None = None,
    **_kwargs: Any,
) -> dict:
    """Return {aws_account_id, region, arn, ...} for an Instana AWS entity snapshot."""
    sid = snapshot_id.strip()
    if not sid:
        return {"source": "instana", "available": False, "error": "No snapshot_id provided."}
    try:
        client = _resolve_client(base_url, api_token, _client_override)
        result = client.resolve_aws_resource(sid)
        account = result.get("aws_account_id")
        return {
            "source": "instana",
            "available": bool(account),
            "snapshot_id": sid,
            "aws_account_id": account,
            "region": result.get("region"),
            "arn": result.get("arn"),
            "resource_label": result.get("resource_label"),
            "plugin": result.get("plugin"),
            "error": None if account else "No aws_account_id found on this snapshot.",
        }
    except Exception as exc:
        return {"source": "instana", "available": False, "error": _error(exc), "snapshot_id": sid}


# ---------------------------------------------------------------------------
# A8 — RCA tools
# ---------------------------------------------------------------------------


@tool(
    name="instana_get_investigation_context",
    display_name="Instana investigation context",
    source="instana",
    evidence_type="events",
    tags=("events", "metrics", "traces", "context", "instana"),
    cost_tier="moderate",
    description=(
        "One-shot RCA context for a service: recent events, golden-signal metric summary, "
        "and slowest/erroring traces — fetched in parallel."
    ),
    use_cases=[
        "Starting an investigation on an Instana-monitored service",
        "Getting events + metrics + erroring traces in one call",
        "Drilling into a member service returned by instana_get_application_context",
    ],
    examples=[
        "For a service latency alert, fetch events + golden signals + slow traces at once.",
        "After application context returns be-orders, pull its full RCA bundle.",
    ],
    requires=["service_name"],
    input_schema={
        "type": "object",
        "properties": {
            "service_name": {"type": "string"},
            "window_size_ms": {"type": "integer", "default": 3_600_000},
            "max_events": {"type": "integer", "default": 20},
            "max_traces": {"type": "integer", "default": 5},
            "to_ms": {"type": "integer"},
        },
        "required": ["service_name"],
    },
    side_effect_level="read_only",
    injected_params=_INJECTED,
    is_available=_instana_available,
    extract_params=_instana_extract_params,
)
def instana_get_investigation_context(
    service_name: str,
    window_size_ms: int = 3_600_000,
    max_events: int = 20,
    max_traces: int = 5,
    to_ms: int | None = None,
    base_url: str = "",
    api_token: str = "",
    _client_override: InstanaClient | None = None,
    **_kwargs: Any,
) -> dict:
    """Fetch events + metric summary + slowest/erroring traces for a service in parallel."""
    try:
        client = _resolve_client(base_url, api_token, _client_override)

        def _events() -> list[dict[str, Any]]:
            raw = client.get_events(window_size_ms=window_size_ms, to_ms=to_ms)
            ranked = _rank_events(
                raw,
                min_severity=1,
                open_only=False,
                max_events=max_events,
                include_changes=False,
                relevant_to=service_name,
            )
            events_out: list[dict[str, Any]] = ranked["events"]
            return events_out

        def _metrics() -> dict[str, Any]:
            return client.application_metrics(
                service_name=service_name, window_size_ms=window_size_ms, to_ms=to_ms
            )

        def _traces() -> list[dict[str, Any]]:
            return client.traces(
                service_name=service_name,
                window_size_ms=window_size_ms,
                max_traces=max_traces,
                to_ms=to_ms,
            )

        def _errors() -> dict[str, list[dict[str, Any]]]:
            # Three RCA facets: exception messages (when apps emit them), HTTP status
            # codes, and erroring endpoints (for status-code failures with no message).
            return {
                "error_messages": _safe(
                    client.error_messages,
                    service_name=service_name, window_size_ms=window_size_ms, limit=max_traces,
                    to_ms=to_ms,
                ),
                "http_status": _safe(
                    client.error_http_status,
                    service_name=service_name, window_size_ms=window_size_ms, limit=max_traces,
                    to_ms=to_ms,
                ),
                "error_endpoints": _safe(
                    client.error_endpoints,
                    service_name=service_name, window_size_ms=window_size_ms, limit=max_traces,
                    to_ms=to_ms,
                ),
            }

        with ThreadPoolExecutor(max_workers=4) as pool:
            fut_events = pool.submit(_events)
            fut_metrics = pool.submit(_metrics)
            fut_traces = pool.submit(_traces)
            fut_errors = pool.submit(_errors)
            events = fut_events.result()
            metrics = fut_metrics.result()
            traces = fut_traces.result()
            errors = fut_errors.result()

        error_spans = [t for t in traces if t.get("erroneous")]
        return {
            "source": "instana",
            "available": True,
            "service_name": service_name,
            "events": events,
            "metrics": metrics.get("metrics", metrics),
            "slowest_traces": traces,
            "error_spans": error_spans,
            "error_messages": errors["error_messages"],
            "http_status": errors["http_status"],
            "error_endpoints": errors["error_endpoints"],
            "truncation_note": f"events<={max_events}, traces<={max_traces}",
        }
    except Exception as exc:
        return {
            "source": "instana",
            "available": False,
            "error": _error(exc),
            "service_name": service_name,
            "events": [],
            "metrics": {},
            "slowest_traces": [],
            "error_spans": [],
            "error_messages": [],
            "http_status": [],
            "error_endpoints": [],
        }


@tool(
    name="instana_error_analysis",
    display_name="Instana error analysis",
    source="instana",
    evidence_type="events",
    tags=("errors", "exceptions", "rca"),
    cost_tier="moderate",
    description=(
        "Explain WHY a service is erroring. Returns three ranked facets for erroring calls: "
        "exception messages (e.g. 'NOT_FOUND: National ID not found', Postgres '23505: "
        "duplicate key'), HTTP status codes (e.g. 500), and the erroring endpoints (e.g. "
        "'POST /payments'). Exception messages are empty for services that fail with a status "
        "code and no message — the HTTP status + endpoint facets name the cause in that case. "
        "service_name is required: this account is shared across multiple unrelated "
        "applications/tenants, and an account-wide 'which service is erroring most' sweep "
        "reads like it names a downstream dependency of your target service when it actually "
        "just ranks unrelated services by error volume."
    ),
    use_cases=[
        "Finding the real exception messages and failing endpoints for a service",
        "Diagnosing an error-rate alert down to specific 5xx endpoints",
    ],
    examples=[
        "For an error-rate alert on be-payments, surface exception messages + 5xx endpoints.",
    ],
    requires=[],
    input_schema={
        "type": "object",
        "properties": {
            "service_name": {"type": "string"},
            "window_size_ms": {"type": "integer", "default": 3_600_000},
            "limit": {"type": "integer", "default": 10},
            "to_ms": {"type": "integer"},
        },
        "required": ["service_name"],
    },
    side_effect_level="read_only",
    injected_params=_INJECTED,
    is_available=_instana_available,
    extract_params=_instana_extract_params,
)
def instana_error_analysis(
    service_name: str,
    window_size_ms: int = 3_600_000,
    limit: int = 10,
    to_ms: int | None = None,
    base_url: str = "",
    api_token: str = "",
    _client_override: InstanaClient | None = None,
    **_kwargs: Any,
) -> dict:
    """Return ranked error facets (messages, HTTP status, endpoints) for one service.

    ``service_name`` is required — not optional — for the same reason
    ``instana_get_events`` requires it: a real production incident showed the
    agent reading this tool's account-wide "top erroring services" facet
    (meant only for account-wide sweeps, not per-service RCA) as if it named a
    downstream dependency of the service under investigation, when it was
    really just the loudest unrelated service on a shared multi-tenant
    account. Removing the account-wide branch entirely — not just gating it
    behind a description — closes that path at the call signature.
    """
    try:
        client = _resolve_client(base_url, api_token, _client_override)
        svc = service_name.strip() or None
        # error_messages is the primary call: a hard failure (auth/connection) surfaces as
        # available=False via the outer except. The enrichment facets are best-effort so a
        # tenant-specific tag 400 can't blank the primary signal.
        messages = client.error_messages(service_name=svc, window_size_ms=window_size_ms, limit=limit, to_ms=to_ms)
        http_status = _safe(client.error_http_status, service_name=svc, window_size_ms=window_size_ms, limit=limit, to_ms=to_ms)
        endpoints = _safe(client.error_endpoints, service_name=svc, window_size_ms=window_size_ms, limit=limit, to_ms=to_ms)
        return {
            "source": "instana",
            "available": True,
            "service_name": svc,
            "error_messages": messages,
            "http_status": http_status,
            "error_endpoints": endpoints,
        }
    except Exception as exc:
        return {
            "source": "instana",
            "available": False,
            "error": _error(exc),
            "service_name": service_name.strip() or None,
            "error_messages": [],
            "http_status": [],
            "error_endpoints": [],
        }


@tool(
    name="instana_get_application_context",
    display_name="Instana application context",
    source="instana",
    evidence_type="topology",
    tags=("application", "services", "rca", "instana"),
    cost_tier="moderate",
    description=(
        "For an Instana Application Perspective alert (entity_type=application), resolve the "
        "application by name to its member services and which of them are erroring most. Call "
        "this FIRST for application-scoped alerts, then drill into the returned services with "
        "instana_get_investigation_context / instana_error_analysis. Do NOT pass an application "
        "name as service_name to the service tools."
    ),
    use_cases=[
        "Finding the real member services behind an Instana application-perspective alert",
        "Resolving which member service is erroring most for an application alert",
    ],
    examples=[
        "For an Application Perspective alert, resolve the app to its member services then drill in.",
    ],
    requires=["application"],
    input_schema={
        "type": "object",
        "properties": {
            "application": {"type": "string"},
            "window_size_ms": {"type": "integer", "default": 3_600_000},
            "to_ms": {"type": "integer"},
            "limit": {"type": "integer", "default": 10},
        },
        "required": ["application"],
    },
    side_effect_level="read_only",
    injected_params=_INJECTED,
    is_available=_instana_available,
    extract_params=_instana_extract_params,
)
def instana_get_application_context(
    application: str,
    window_size_ms: int = 3_600_000,
    to_ms: int | None = None,
    limit: int = 10,
    base_url: str = "",
    api_token: str = "",
    _client_override: InstanaClient | None = None,
    **_kwargs: Any,
) -> dict:
    """Resolve an Instana Application Perspective → member services + top erroring services."""
    try:
        client = _resolve_client(base_url, api_token, _client_override)
        out = client.application_context(application, window_size_ms=window_size_ms, to_ms=to_ms, limit=limit)
        return {"source": "instana", "available": True, **out}
    except Exception as exc:
        return {"source": "instana", "available": False, "error": _error(exc),
                "application": application, "services": [], "top_error_services": []}


@tool(
    name="instana_search_logs",
    display_name="Instana logs",
    source="instana",
    evidence_type="logs",
    tags=("logs", "observability"),
    cost_tier="moderate",
    description="Search Instana logs for errors/exceptions by service + time window.",
    use_cases=["Finding error messages/stack traces for a failing service"],
    requires=[],
    input_schema={
        "type": "object",
        "properties": {
            "query": {"type": "string"},
            "service_name": {"type": "string"},
            "window_size_ms": {"type": "integer", "default": 3_600_000},
            "limit": {"type": "integer", "default": 50},
        },
        "required": [],
    },
    side_effect_level="read_only",
    injected_params=_INJECTED,
    is_available=_instana_available,
    extract_params=_instana_extract_params,
)
def instana_search_logs(
    query: str = "",
    service_name: str = "",
    window_size_ms: int = 3_600_000,
    limit: int = 50,
    base_url: str = "",
    api_token: str = "",
    _client_override: InstanaClient | None = None,
    **_kwargs: Any,
) -> dict:
    """Search Instana logs, degrading gracefully when the log API is unavailable.

    Log Management is a separately-licensed Instana capability. On tenants without
    it (e.g. APM-only) every ``/api/log/...`` endpoint returns 404, so this tool
    returns a structured ``available: False`` rather than crashing the agent loop.
    When logs are unavailable, use ``instana_error_analysis`` for the real exception
    text behind a service's errors.
    """
    try:
        client = _resolve_client(base_url, api_token, _client_override)
        logs = client.search_logs(
            query=query,
            service_name=service_name,
            window_size_ms=window_size_ms,
            limit=limit,
        )
    except Exception as exc:
        detail = _error(exc)
        # Prefer the real status code; only fall back to a tight text match ("HTTP 404")
        # when there's no status, so a non-404 whose body mentions "not found" can't misfire.
        status = exc.response.status_code if isinstance(exc, httpx.HTTPStatusError) else None
        not_available = status == 404 or (status is None and "HTTP 404" in detail)
        return {
            "source": "instana_logs",
            "available": False,
            "retry": not not_available,
            "error": (
                "Instana Log Management is not enabled on this tenant — no logs available. "
                "Do not retry instana_search_logs; use instana_error_analysis for error detail."
                if not_available
                else detail
            ),
            "logs": [],
            "error_logs": [],
        }
    error_logs = [
        log
        for log in logs
        if any(k in (log.get("message", "") or "").lower() for k in _LOG_ERROR_KEYWORDS)
    ]
    return {
        "source": "instana_logs",
        "available": True,
        "logs": logs[:limit],
        "error_logs": error_logs[:30],
    }
