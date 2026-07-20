#!/usr/bin/env bash
# Benchmark POST /oauth/token (client_credentials) and POST /oauth/introspect
# against a running oauth2-server instance.
#
# Prefers `oha` (or `wrk`) if installed; falls back to scripts/bench.py
# (asyncio+httpx closed-loop benchmark) otherwise.
#
# Usage:
#   BASE_URL=http://localhost:8080 CLIENT_ID=... CLIENT_SECRET=... scripts/bench.sh
set -euo pipefail
cd "$(dirname "$0")/.."

BASE_URL="${BASE_URL:-http://localhost:8080}"
CLIENT_ID="${CLIENT_ID:?set CLIENT_ID to a registered client}"
CLIENT_SECRET="${CLIENT_SECRET:?set CLIENT_SECRET to the client secret}"
CONCURRENCY="${CONCURRENCY:-64}"
DURATION="${DURATION:-15s}"
DURATION_SECS="${DURATION_SECS:-15}"

AUTH=$(printf '%s:%s' "$CLIENT_ID" "$CLIENT_SECRET" | base64)

echo "== Fetching an access token for the introspect benchmark =="
TOKEN=$(curl -s -X POST "$BASE_URL/oauth/token" \
  -H "Authorization: Basic $AUTH" \
  -d "grant_type=client_credentials" \
  -d "scope=read" | python3 -c 'import sys,json; print(json.load(sys.stdin)["access_token"])')
echo "Got token: ${TOKEN:0:12}..."

BODY_TOKEN_FILE=$(mktemp)
printf 'grant_type=client_credentials&scope=read' > "$BODY_TOKEN_FILE"

BODY_INTROSPECT_FILE=$(mktemp)
printf 'token=%s' "$TOKEN" > "$BODY_INTROSPECT_FILE"
trap 'rm -f "$BODY_TOKEN_FILE" "$BODY_INTROSPECT_FILE"' EXIT

run_oha() {
  local name="$1" body_file="$2"
  echo
  echo "== oha: $name =="
  oha -z "$DURATION" -c "$CONCURRENCY" -m POST \
    -H "Authorization: Basic $AUTH" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -d "@$body_file" \
    "$BASE_URL$name"
}

run_bench_py() {
  local name="$1" body_file="$2"
  echo
  echo "== bench.py fallback: $name =="
  uv run python scripts/bench.py "$BASE_URL$name" \
    --method POST \
    --body-file "$body_file" \
    --header "Authorization: Basic $AUTH" \
    --header "Content-Type: application/x-www-form-urlencoded" \
    --concurrency "$CONCURRENCY" \
    --duration "$DURATION_SECS"
}

if command -v oha >/dev/null 2>&1; then
  run_oha /oauth/token "$BODY_TOKEN_FILE"
  run_oha /oauth/introspect "$BODY_INTROSPECT_FILE"
elif command -v wrk >/dev/null 2>&1; then
  echo "== wrk: /oauth/token =="
  wrk -t4 -c"$CONCURRENCY" -d"$DURATION" -s /dev/stdin "$BASE_URL/oauth/token" <<EOF
wrk.method = "POST"
wrk.headers["Authorization"] = "Basic $AUTH"
wrk.headers["Content-Type"] = "application/x-www-form-urlencoded"
wrk.body = "grant_type=client_credentials&scope=read"
EOF
  echo "== wrk: /oauth/introspect =="
  wrk -t4 -c"$CONCURRENCY" -d"$DURATION" -s /dev/stdin "$BASE_URL/oauth/introspect" <<EOF
wrk.method = "POST"
wrk.headers["Authorization"] = "Basic $AUTH"
wrk.headers["Content-Type"] = "application/x-www-form-urlencoded"
wrk.body = "token=$TOKEN"
EOF
else
  echo "oha/wrk not found; using scripts/bench.py fallback"
  run_bench_py /oauth/token "$BODY_TOKEN_FILE"
  run_bench_py /oauth/introspect "$BODY_INTROSPECT_FILE"
fi
