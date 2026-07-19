import json
from datetime import datetime, timezone

from oauth2_server.models import Claims, Client, IntrospectionResponse


def test_client_is_public():
    c = _client(token_endpoint_auth_method="none")
    assert c.is_public() is True
    assert _client(token_endpoint_auth_method="client_secret_basic").is_public() is False


def test_client_redirect_uri_list_parses_json_string():
    c = _client(redirect_uris='["https://a.example/cb","https://b.example/cb"]')
    assert c.redirect_uri_list() == ["https://a.example/cb", "https://b.example/cb"]


def test_claims_aud_serializes_single_as_string():
    claims = Claims.new("user1", "client1", "read", 3600, "https://auth.example.com")
    data = claims.to_payload()
    assert data["aud"] == "client1"          # single aud -> bare string (Rust serde parity)
    assert data["iss"] == "https://auth.example.com"
    assert data["exp"] - data["iat"] == 3600
    assert len(data["jti"]) > 0


def test_claims_aud_serializes_multiple_as_list():
    claims = Claims.new("user1", "client1", "read", 3600, "https://auth.example.com")
    claims.aud = ["a", "b"]
    assert claims.to_payload()["aud"] == ["a", "b"]


def test_introspection_response_omits_none_fields():
    body = IntrospectionResponse(active=False).model_dump(exclude_none=True)
    assert body == {"active": False}


def _client(**overrides) -> Client:
    now = datetime.now(timezone.utc)
    base = dict(
        id="cid-1", client_id="client1", client_secret="s3cret",
        redirect_uris=json.dumps(["https://a.example/cb"]),
        grant_types=json.dumps(["authorization_code"]),
        scope="read", name="Test", created_at=now, updated_at=now,
    )
    base.update(overrides)
    return Client(**base)
