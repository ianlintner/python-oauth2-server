"""Optional OpenTelemetry tracing.

Enabled only when ``OTEL_EXPORTER_OTLP_ENDPOINT`` (or the traces-specific variant) is
set *and* the ``otel`` extra is installed; otherwise every function here is a no-op, so
the default install, the test suite and local dev are unaffected.

What gets traced:

* inbound FastAPI requests, except the noisy ``/health``, ``/ready`` and ``/metrics``;
* outbound ``httpx`` calls (social-login token/userinfo exchanges, CIMD/JWKS fetches);
* MongoDB / Cosmos commands via the pymongo instrumentor (``motor`` wraps pymongo).

Privacy: OAuth requests carry credentials. Header capture stays off (the default). Query
strings, which contain ``code``/``state`` on callbacks, are stripped from server spans by
``_strip_query``. Mongo statements are not recorded. The collector also scrubs
``url.query``/``http.target`` defensively.

Standard OTEL_* env vars configure the exporter (endpoint, headers, protocol). The OTLP/HTTP
exporter is used because it honours ``HTTP_PROXY``, which is how the ACA deployment reaches
the collector over a Tailscale sidecar without opening any inbound port.
"""

from __future__ import annotations

import logging
import os
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from fastapi import FastAPI

log = logging.getLogger(__name__)

EXCLUDED_URLS = "health,ready,metrics"
_configured = False


def tracing_requested() -> bool:
    return (
        bool(
            os.environ.get("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT")
            or os.environ.get("OTEL_EXPORTER_OTLP_ENDPOINT")
        )
        and os.environ.get("OTEL_SDK_DISABLED", "").lower() != "true"
    )


def _strip_query(span: Any, scope: dict) -> None:
    """Server request hook: replace query-bearing URL attributes with query-free values."""
    if span is None or not span.is_recording():
        return
    path = scope.get("path") or "/"
    attrs = getattr(span, "attributes", None) or {}
    if "url.query" in attrs:
        span.set_attribute("url.query", "[redacted]")
    if "http.target" in attrs:
        span.set_attribute("http.target", path)
    for key in ("http.url", "url.full"):
        value = attrs.get(key)
        if isinstance(value, str) and "?" in value:
            span.set_attribute(key, value.split("?", 1)[0])


def setup_tracing() -> bool:
    """Install the tracer provider and global (httpx/pymongo) instrumentation.

    Call once per worker process *before* the app's HTTP client is created.
    Returns True when tracing is active.
    """
    global _configured
    if _configured:
        return True
    if not tracing_requested():
        return False
    try:
        from opentelemetry import trace
        from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
        from opentelemetry.instrumentation.httpx import HTTPXClientInstrumentor
        from opentelemetry.instrumentation.pymongo import PymongoInstrumentor
        from opentelemetry.sdk.resources import Resource
        from opentelemetry.sdk.trace import TracerProvider
        from opentelemetry.sdk.trace.export import BatchSpanProcessor
    except ImportError:
        log.warning(
            "OTEL_EXPORTER_OTLP_ENDPOINT is set but the 'otel' extra is not installed; tracing disabled"
        )
        return False

    resource = Resource.create(
        {
            "service.name": os.environ.get("OTEL_SERVICE_NAME", "oauth2-server"),
            "service.namespace": "cat-herding",
        }
    )
    provider = TracerProvider(resource=resource)
    provider.add_span_processor(BatchSpanProcessor(OTLPSpanExporter()))
    trace.set_tracer_provider(provider)
    HTTPXClientInstrumentor().instrument()
    PymongoInstrumentor().instrument(capture_statement=False)
    _configured = True
    log.info("OpenTelemetry tracing enabled")
    return True


def instrument_app(app: FastAPI) -> None:
    """Attach request tracing to the FastAPI app (no-op unless setup_tracing succeeded)."""
    if not _configured:
        return
    from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor

    FastAPIInstrumentor.instrument_app(
        app,
        excluded_urls=EXCLUDED_URLS,
        server_request_hook=_strip_query,
        exclude_spans=["receive", "send"],
    )
