#!/usr/bin/env bash
set -euo pipefail

BASE_URL="${SIGURSCAN_BACKEND_URL:-https://nudaclick-backend.vercel.app}"
API_KEY="${SIGURSCAN_ADMIN_API_KEY:-}"
TIMEOUT="${SIGURSCAN_SMOKE_TIMEOUT:-10}"

if [ -z "$API_KEY" ]; then
  if [ -f "/Users/vaduvageorge/AndroidStudioProjects/SigurScan/local.properties" ]; then
    API_KEY="$(awk -F= '/^SIGURSCAN_ADMIN_API_KEY=/{print $2}' "/Users/vaduvageorge/AndroidStudioProjects/SigurScan/local.properties" | tr -d '[:space:]')"
  fi
fi

if [ -z "$API_KEY" ]; then
  echo "ERR: missing SIGURSCAN_ADMIN_API_KEY"
  echo "Setează variabila de mediu sau păstreaz-o în local.properties"
  exit 1
fi

echo "[1/2] health check"
curl -sS --max-time "$TIMEOUT" -H "X-API-KEY: $API_KEY" "$BASE_URL/healthz" |
  jq -e '{status,version,config:{rate_limit_enabled,rate_limit_backend,admin_api_configured,api_key_required,play_integrity_mode}}' >/dev/null

echo "[2/2] dashboard html"
status=$(curl -sS --max-time "$TIMEOUT" -o /tmp/sigurscan-dashboard.html -w "%{http_code}" -H "X-API-KEY: $API_KEY" "$BASE_URL/v1/orchestration/dashboard")
if [ "$status" != "200" ]; then
  echo "ERR: dashboard returned $status"
  exit 1
fi

echo "Smoke OK"
echo "healthz: 200, dashboard: 200"
