"""Worker-count resolution: the server runs a single worker unless state is shared."""

import pytest

from oauth2_server import __main__ as entry
from oauth2_server.__main__ import resolve_worker_count


def test_worker_count_defaults_to_one():
    assert resolve_worker_count({}) == 1


def test_worker_count_accepts_explicit_one():
    assert resolve_worker_count({"OAUTH2_WORKERS": "1"}) == 1


def test_worker_count_rejects_multi():
    with pytest.raises(SystemExit) as exc:
        resolve_worker_count({"OAUTH2_WORKERS": "4"})
    assert "OAUTH2_WORKERS" in str(exc.value)


@pytest.mark.parametrize("value", ["many", "0", "-2", "1.5"])
def test_worker_count_rejects_invalid(value):
    with pytest.raises(SystemExit) as exc:
        resolve_worker_count({"OAUTH2_WORKERS": value})
    assert "OAUTH2_WORKERS" in str(exc.value)


def test_conformance_mode_forces_single_worker():
    assert resolve_worker_count({"OAUTH2_WORKERS": "4"}, conformance=True) == 1


def test_main_passes_resolved_workers_to_uvicorn(monkeypatch):
    monkeypatch.setenv("OAUTH2_JWT_SECRET", "x" * 40)
    monkeypatch.delenv("OAUTH2_WORKERS", raising=False)
    monkeypatch.delenv("OAUTH2_CONFORMANCE_MODE", raising=False)
    captured: dict = {}
    monkeypatch.setattr(entry.uvicorn, "run", lambda *a, **kw: captured.update(kw))
    entry.main()
    assert captured["workers"] == 1
    assert captured["proxy_headers"] is False


def test_main_refuses_multi_worker_before_starting(monkeypatch):
    monkeypatch.setenv("OAUTH2_JWT_SECRET", "x" * 40)
    monkeypatch.setenv("OAUTH2_WORKERS", "4")
    monkeypatch.delenv("OAUTH2_CONFORMANCE_MODE", raising=False)
    ran: list = []
    monkeypatch.setattr(entry.uvicorn, "run", lambda *a, **kw: ran.append(kw))
    with pytest.raises(SystemExit):
        entry.main()
    assert ran == []
