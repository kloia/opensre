# tests/tools/investigation/test_resolve_short_circuit.py
import inspect

from tools.investigation.stages.resolve_integrations.node import resolve_integrations
from tools.investigation.capability import astream_investigation


def test_resolve_integrations_returns_preset_untouched():
    injected = {"instana": {"base_url": "https://x.instana.io", "api_token": "tok"}}
    # The node short-circuits when resolved_integrations is already present and
    # returns it as a state update: {"resolved_integrations": <preset>}.
    assert resolve_integrations({"resolved_integrations": injected}) == {
        "resolved_integrations": injected
    }


def test_astream_investigation_accepts_resolved_integrations_kwarg():
    assert "resolved_integrations" in inspect.signature(astream_investigation).parameters
