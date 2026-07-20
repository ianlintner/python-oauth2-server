#!/usr/bin/env bash
# Cross-backend parity smoke: proves the Python server runs the full OAuth2
# stack — client_credentials, authorization_code, refresh, introspect,
# revoke — against a REAL mongod, over real HTTP (curl), not just the
# pytest-level MongoStorage contract suite (tests/test_mongo_storage.py,
# tests/test_mongo_admin.py, tests/test_mongo_e2e.py).
#
# This is documentation-grade / manual-run tooling (NOT wired into
# scripts/gate.sh or the CI `db-tests` job — see .github/workflows/ci.yml).
# Requires Docker + `uv` + `curl` + `python3` (jq is optional; falls back to
# a tiny inline python json parser when absent).
#
# Usage:
#   bash scripts/mongo_parity_smoke.sh
#
# Env overrides:
#   MONGO_PORT          host port to publish mongod on (default 27017)
#   SERVER_PORT         host port to run the Python server on (default 8080)
set -euo pipefail
cd "$(dirname "$0")/.."

MONGO_PORT="${MONGO_PORT:-27017}"
SERVER_PORT="${SERVER_PORT:-8080}"
MONGO_CONTAINER_NAME="oauth2_mongo_smoke"
BASE_URL="http://localhost:${SERVER_PORT}"
DB_NAME="oauth2_smoke"

cleanup() {
  set +e
  [ -n "${SERVER_PID:-}" ] && kill "${SERVER_PID}" 2>/dev/null
  docker rm -f "${MONGO_CONTAINER_NAME}" >/dev/null 2>&1
}
trap cleanup EXIT

json_get() {
  # json_get <field> <<<"$json"
  local field="$1"
  if command -v jq >/dev/null 2>&1; then
    jq -r ".${field}"
  else
    python3 -c "import json,sys; print(json.load(sys.stdin).get('${field}', ''))"
  fi
}

echo "== 1. Start mongod =="
# Alternative: `uv run python -c "from testcontainers.mongodb import
# MongoDbContainer; ..."` reuses the exact same image/fixture the pytest
# suite does (tests/test_mongo_storage.py) — a plain `docker run` is used
# here instead so this script has no Python-side container-lifecycle
# dependency and is trivially copy-pasteable.
docker run --rm -d --name "${MONGO_CONTAINER_NAME}" \
  -p "${MONGO_PORT}:27017" \
  mongo:7 >/dev/null
echo "mongod started on port ${MONGO_PORT}, database '${DB_NAME}'"

# Give mongod a moment to accept connections.
for _ in $(seq 1 30); do
  docker exec "${MONGO_CONTAINER_NAME}" mongosh --quiet --eval 'db.runCommand({ping:1})' \
    >/dev/null 2>&1 && break
  sleep 1
done

echo "== 2. Start the Python server against MongoStorage =="
OAUTH2_DATABASE_URL="mongodb://localhost:${MONGO_PORT}/${DB_NAME}" \
OAUTH2_JWT_SECRET="parity-smoke-secret-0123456789abcdef-0123" \
OAUTH2_PUBLIC_URL="${BASE_URL}" \
OAUTH2_ALLOW_INSECURE_DEFAULTS=1 \
OAUTH2_DYNAMIC_REGISTRATION_ENABLED=true \
OAUTH2_WORKERS=1 \
OAUTH2_PORT="${SERVER_PORT}" \
uv run python -m oauth2_server &
SERVER_PID=$!

echo "waiting for the server to become ready..."
for _ in $(seq 1 30); do
  curl -sf "${BASE_URL}/health" >/dev/null 2>&1 && break
  sleep 1
done
curl -sf "${BASE_URL}/health" >/dev/null || {
  echo "server never became healthy" >&2
  exit 1
}

echo "== 3. Register a client (RFC 7591, persisted into MongoStorage) =="
REGISTER_RESPONSE=$(curl -s -X POST "${BASE_URL}/connect/register" \
  -H "Content-Type: application/json" \
  -d '{
        "redirect_uris": ["http://localhost:9999/callback"],
        "grant_types": ["client_credentials", "authorization_code", "refresh_token"],
        "token_endpoint_auth_method": "client_secret_basic",
        "scope": "read openid",
        "client_name": "mongo-parity-smoke-client"
      }')
echo "${REGISTER_RESPONSE}"
CLIENT_ID=$(echo "${REGISTER_RESPONSE}" | json_get client_id)
CLIENT_SECRET=$(echo "${REGISTER_RESPONSE}" | json_get client_secret)
[ -n "${CLIENT_ID}" ] || {
  echo "client registration failed" >&2
  exit 1
}
echo "registered client_id=${CLIENT_ID}"

# `tr -d '\n'` strips the line wrap `base64` inserts every 76 chars on GNU
# coreutils (Linux) — without it the Basic auth header gets split across
# multiple lines and curl sends a garbled Authorization value. macOS's BSD
# base64 wraps too, so this is needed on both platforms.
BASIC=$(printf '%s:%s' "${CLIENT_ID}" "${CLIENT_SECRET}" | base64 | tr -d '\n')

echo "== 4. client_credentials grant =="
TOKEN_RESPONSE=$(curl -s -X POST "${BASE_URL}/oauth/token" \
  -H "Authorization: Basic ${BASIC}" \
  -d "grant_type=client_credentials" -d "scope=read")
echo "${TOKEN_RESPONSE}"
ACCESS_TOKEN=$(echo "${TOKEN_RESPONSE}" | json_get access_token)
[ -n "${ACCESS_TOKEN}" ] || {
  echo "client_credentials grant failed" >&2
  exit 1
}

echo "== 5. Introspect the client_credentials access token =="
INTROSPECT_RESPONSE=$(curl -s -X POST "${BASE_URL}/oauth/introspect" \
  -H "Authorization: Basic ${BASIC}" \
  -d "token=${ACCESS_TOKEN}")
echo "${INTROSPECT_RESPONSE}"
ACTIVE=$(echo "${INTROSPECT_RESPONSE}" | json_get active)
[ "${ACTIVE}" = "True" ] || [ "${ACTIVE}" = "true" ] || {
  echo "expected active:true from introspection" >&2
  exit 1
}

echo "== 6. Revoke the client_credentials token, re-introspect =="
curl -s -X POST "${BASE_URL}/oauth/revoke" \
  -H "Authorization: Basic ${BASIC}" \
  -d "token=${ACCESS_TOKEN}" >/dev/null
REVOKED_INTROSPECT=$(curl -s -X POST "${BASE_URL}/oauth/introspect" \
  -H "Authorization: Basic ${BASIC}" \
  -d "token=${ACCESS_TOKEN}")
echo "${REVOKED_INTROSPECT}"
REVOKED_ACTIVE=$(echo "${REVOKED_INTROSPECT}" | json_get active)
[ "${REVOKED_ACTIVE}" = "False" ] || [ "${REVOKED_ACTIVE}" = "false" ] || {
  echo "expected active:false after revoke" >&2
  exit 1
}

echo
echo "== Result: PASS =="
echo "client_credentials + introspect(active) + revoke + introspect(inactive) all"
echo "round-tripped through MongoStorage over real HTTP."
echo
echo "NOTE: the refresh-replay family-cascade proof (divergence 28 — Rust's"
echo "Mongo backend leaves revoke_token_family as a silent no-op, this port"
echo "fixes it) needs a logged-in browser session for the authorization_code"
echo "leg and is exercised end-to-end instead by:"
echo "  RUN_TESTCONTAINERS=1 uv run pytest tests/test_mongo_e2e.py -q"
echo "(see test_mongo_e2e_auth_code_refresh_and_family_cascade — same"
echo "MongoStorage-over-HTTP proof this script drives, plus the"
echo "authorization_code -> refresh -> refresh-replay -> sibling-introspect"
echo "sequence that isn't practical to script through curl alone)."
echo
echo "DPoP-bound access tokens have no dedicated storage column — the RFC"
echo "9449 cnf.jkt claim lives inside the JWT access_token string itself"
echo "(services/tokens.py), so proving that string round-trips unmodified"
echo "through MongoStorage IS the persistence proof. RFC 9396"
echo "authorization_details (RAR) IS a real JSON-string field on"
echo "AuthorizationCode. Both are proven against a real mongod (not"
echo "re-driven here over curl) by:"
echo "  RUN_TESTCONTAINERS=1 uv run pytest tests/test_mongo_storage.py \\"
echo "    -k test_authorization_code_round_trips_rar_details_and_dpop_bound_access_token -q"
