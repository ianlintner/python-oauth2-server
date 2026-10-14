"""Optional OpenTelemetry tracing (oauth2_server.telemetry)."""

from __future__ import annotations

import pytest

from oauth2_server import telemetry


@pytest.fixture(autouse=True)
def _reset(monkeypatch):
    monkeypatch.delenv("OTEL_EXPORTER_OTLP_ENDPOINT", raising=False)
    monkeypatch.delenv("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT", raising=False)
    monkeypatch.delenv("OTEL_SDK_DISABLED", raising=False)
    monkeypatch.setattr(telemetry, "_configured", False)


def test_disabled_without_endpoint():
    assert telemetry.tracing_requested() is False
    assert telemetry.setup_tracing() is False


def test_sdk_disabled_flag_wins(monkeypatch):
    monkeypatch.setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "http://collector:4318")
    monkeypatch.setenv("OTEL_SDK_DISABLED", "true")
    assert telemetry.tracing_requested() is False


def test_instrument_app_noop_when_not_configured():
    from fastapi import FastAPI

    app = FastAPI()
    telemetry.instrument_app(app)  # must not raise or import opentelemetry
    assert not getattr(app, "_is_instrumented_by_opentelemetry", False)


class _FakeSpan:
    def __init__(self, attrs):
        self.attributes = dict(attrs)

    def is_recording(self):
        return True

    def set_attribute(self, k, v):
        self.attributes[k] = v


def test_strip_query_removes_codes_and_state():
    span = _FakeSpan(
        {
            "http.target": "/auth/callback/github?code=SECRET&state=XYZ",
            "http.url": "https://roauth2.example/auth/callback/github?code=SECRET&state=XYZ",
            "url.full": "https://roauth2.example/oauth/authorize?client_id=a&code_challenge=b",
            "url.query": "code=SECRET&state=XYZ",
        }
    )
    telemetry._strip_query(span, {"path": "/auth/callback/github"})
    joined = " ".join(str(v) for v in span.attributes.values())
    assert "SECRET" not in joined and "XYZ" not in joined and "code_challenge" not in joined
    assert span.attributes["http.target"] == "/auth/callback/github"
    assert span.attributes["http.url"] == "https://roauth2.example/auth/callback/github"


def test_end_to_end_spans_with_in_memory_exporter(monkeypatch):
    otel = pytest.importorskip("opentelemetry.sdk.trace")
    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor
    from opentelemetry.sdk.trace.export import SimpleSpanProcessor
    from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter

    exporter = InMemorySpanExporter()
    provider = otel.TracerProvider()
    provider.add_span_processor(SimpleSpanProcessor(exporter))

    app = FastAPI()

    @app.get("/health")
    def health():
        return {"ok": True}

    @app.get("/auth/callback/{p}")
    def cb(p: str):
        return {"p": p}

    FastAPIInstrumentor.instrument_app(
        app,
        excluded_urls=telemetry.EXCLUDED_URLS,
        server_request_hook=telemetry._strip_query,
        exclude_spans=["receive", "send"],
        tracer_provider=provider,
    )
    c = TestClient(app)
    c.get("/health")
    c.get("/auth/callback/github?code=SECRET&state=XYZ")
    spans = exporter.get_finished_spans()
    assert len(spans) == 1, [s.name for s in spans]  # /health excluded
    attrs = " ".join(str(v) for v in spans[0].attributes.values())
    assert "SECRET" not in attrs and "XYZ" not in attrs
