from app.agent.stages.resolve_integrations.node import resolve_integrations


def test_resolve_integrations_returns_preset_untouched():
    injected = {"instana": {"base_url": "https://x.instana.io", "api_token": "tok"}}
    out = resolve_integrations({"resolved_integrations": injected})
    assert out == injected


def test_astream_investigation_accepts_resolved_integrations_kwarg():
    import inspect

    from app.pipeline.runners import astream_investigation

    params = inspect.signature(astream_investigation).parameters
    assert "resolved_integrations" in params
