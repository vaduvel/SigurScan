#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BACKEND_DIR="$ROOT_DIR/backend"

PROJECT_ID="${PROJECT_ID:-}"
REGION="${REGION:-europe-west1}"
SERVICE_NAME="${SERVICE_NAME:-sigurscan-api}"
IMAGE_NAME="${IMAGE_NAME:-sigurscan-api}"
TAG="${TAG:-$(git -C "$ROOT_DIR" rev-parse --short HEAD 2>/dev/null || date +%Y%m%d%H%M%S)}"
REPOSITORY="${REPOSITORY:-sigurscan}"
MIN_INSTANCES="${MIN_INSTANCES:-1}"
MAX_INSTANCES="${MAX_INSTANCES:-5}"
CONCURRENCY="${CONCURRENCY:-2}"
CPU_THROTTLING="${CPU_THROTTLING:-true}"
ORCHESTRATED_CLOUD_TASKS_ENABLED="${ORCHESTRATED_CLOUD_TASKS_ENABLED:-false}"
CLOUD_TASKS_PROJECT="${CLOUD_TASKS_PROJECT:-$PROJECT_ID}"
CLOUD_TASKS_LOCATION="${CLOUD_TASKS_LOCATION:-$REGION}"
CLOUD_TASKS_QUEUE="${CLOUD_TASKS_QUEUE:-sigurscan-orchestrated}"
CLOUD_TASKS_REQUEST_TIMEOUT_SECONDS="${CLOUD_TASKS_REQUEST_TIMEOUT_SECONDS:-4.0}"
ORCHESTRATED_CLOUD_TASKS_CONTINUE_DELAY_SECONDS="${ORCHESTRATED_CLOUD_TASKS_CONTINUE_DELAY_SECONDS:-3}"
OPENAPI_RO_API_KEY_SECRET="${OPENAPI_RO_API_KEY_SECRET-openapi-ro-api-key:latest}"
HUNTER_IO_API_KEY_SECRET="${HUNTER_IO_API_KEY_SECRET-hunter-io-api-key:latest}"
PLAY_INTEGRITY_CREDENTIALS_JSON_SECRET="${PLAY_INTEGRITY_CREDENTIALS_JSON_SECRET:-}"
ENV_VARS="${ENV_VARS:-REQUIRE_API_KEY=true,ENABLE_RATE_LIMIT=true,RATE_LIMIT_FAIL_CLOSED=true,PLAY_INTEGRITY_MODE=monitor,FAST_REPUTATION_MODE=true,FAST_REPUTATION_INCLUDE_URLHAUS=true,ENABLE_DEEP_REPUTATION_FALLBACK=true,OFFER_THREAT_ENRICHMENT_SHADOW=false,ENABLE_URL_REPUTATION=true,ENABLE_ASF_INVESTOR_ALERTS=true,ENABLE_PHISHING_DATABASE=true,ENABLE_SCAM_BLOCKLIST_NRD=true,ENABLE_PHISHDESTROY=true,ENABLE_DNS_REPUTATION=true,ENABLE_MISTRAL_SEMANTIC_PILLAR=true,ENABLE_MISTRAL_SHADOW_ADJUDICATION=false,ENABLE_OFFER_CLAIM_WEB_CHECK=false,OPENAPI_RO_MONTHLY_BUDGET=100,HUNTER_IO_MONTHLY_BUDGET=50,URLSCAN_VISIBILITY_DEFAULT=unlisted,GOOGLE_CLOUD_VISION_LOCATION=eu,ORCHESTRATED_CLOUD_TASKS_ENABLED=$ORCHESTRATED_CLOUD_TASKS_ENABLED,CLOUD_TASKS_PROJECT=$CLOUD_TASKS_PROJECT,CLOUD_TASKS_LOCATION=$CLOUD_TASKS_LOCATION,CLOUD_TASKS_QUEUE=$CLOUD_TASKS_QUEUE,CLOUD_TASKS_REQUEST_TIMEOUT_SECONDS=$CLOUD_TASKS_REQUEST_TIMEOUT_SECONDS,ORCHESTRATED_CLOUD_TASKS_CONTINUE_DELAY_SECONDS=$ORCHESTRATED_CLOUD_TASKS_CONTINUE_DELAY_SECONDS}"
SECRETS="${SECRETS:-SUPABASE_URL=supabase-url:latest,SUPABASE_SERVICE_ROLE_KEY=supabase-service-role-key:latest,GEMINI_API_KEY=gemini-api-key:latest,GOOGLE_CLOUD_VISION_API_KEY=google-cloud-vision-api-key:latest,GOOGLE_WEB_RISK_API_KEY=google-web-risk-api-key:latest,GOOGLE_SAFE_BROWSING_API_KEY=google-web-risk-api-key:latest,MISTRAL_API_KEY=mistral-api-key:latest,SIGURSCAN_URLSCAN_API_KEY=sigurscan-urlscan-api-key:latest,URLSCAN_API_KEY=sigurscan-urlscan-api-key:latest,NUDACLICK_URLSCAN_API_KEY=sigurscan-urlscan-api-key:latest,URLHAUS_AUTH_KEY=urlhaus-auth-key:latest,URLHAUS_API_KEY=urlhaus-auth-key:latest,ABUSECH_AUTH_KEY=urlhaus-auth-key:latest,UPSTASH_REDIS_REST_URL=upstash-redis-rest-url:latest,UPSTASH_REDIS_REST_TOKEN=upstash-redis-rest-token:latest,SIGURSCAN_ADMIN_API_KEYS=sigurscan-admin-api-keys:latest,SIGURSCAN_API_KEYS=sigurscan-api-keys:latest,NUDACLICK_API_KEYS=sigurscan-api-keys:latest,INVOICE_CACHE_HMAC_KEY=invoice-cache-hmac-key:latest,SIGURSCAN_INTERNAL_WORKER_TOKEN=sigurscan-internal-worker-token:latest}"

if [[ -n "$OPENAPI_RO_API_KEY_SECRET" ]]; then
  SECRETS="$SECRETS,OPENAPI_RO_API_KEY=$OPENAPI_RO_API_KEY_SECRET"
fi
if [[ -n "$HUNTER_IO_API_KEY_SECRET" ]]; then
  SECRETS="$SECRETS,HUNTER_IO_API_KEY=$HUNTER_IO_API_KEY_SECRET"
fi
if [[ -n "$PLAY_INTEGRITY_CREDENTIALS_JSON_SECRET" ]]; then
  SECRETS="$SECRETS,PLAY_INTEGRITY_CREDENTIALS_JSON=$PLAY_INTEGRITY_CREDENTIALS_JSON_SECRET"
fi

if [[ -z "$PROJECT_ID" ]]; then
  echo "PROJECT_ID is required. Example:"
  echo "  PROJECT_ID=my-gcp-project REGION=europe-west1 ./tools/deploy_cloud_run_backend.sh"
  exit 1
fi

if ! command -v gcloud >/dev/null 2>&1; then
  echo "gcloud CLI is required but was not found."
  echo "Install it from: https://cloud.google.com/sdk/docs/install"
  exit 1
fi

IMAGE="$REGION-docker.pkg.dev/$PROJECT_ID/$REPOSITORY/$IMAGE_NAME:$TAG"
CPU_THROTTLING_FLAG="--cpu-throttling"
CPU_THROTTLING_NORMALIZED="$(printf '%s' "$CPU_THROTTLING" | tr '[:upper:]' '[:lower:]')"
case "$CPU_THROTTLING_NORMALIZED" in
  0|false|no|off)
    CPU_THROTTLING_FLAG="--no-cpu-throttling"
    ;;
  1|true|yes|on)
    CPU_THROTTLING_FLAG="--cpu-throttling"
    ;;
  *)
    echo "CPU_THROTTLING must be true or false, got: $CPU_THROTTLING"
    exit 1
    ;;
esac

echo "Deploying SigurScan backend to Cloud Run"
echo "Project: $PROJECT_ID"
echo "Region:  $REGION"
echo "Service: $SERVICE_NAME"
echo "Image:   $IMAGE"
echo "Scaling: min-instances=$MIN_INSTANCES max-instances=$MAX_INSTANCES concurrency=$CONCURRENCY cpu-throttling=$CPU_THROTTLING"

gcloud artifacts repositories describe "$REPOSITORY" \
  --project "$PROJECT_ID" \
  --location "$REGION" >/dev/null 2>&1 || \
gcloud artifacts repositories create "$REPOSITORY" \
  --project "$PROJECT_ID" \
  --location "$REGION" \
  --repository-format docker \
  --description "SigurScan container images"

gcloud builds submit "$BACKEND_DIR" \
  --project "$PROJECT_ID" \
  --tag "$IMAGE"

gcloud run deploy "$SERVICE_NAME" \
  --project "$PROJECT_ID" \
  --region "$REGION" \
  --image "$IMAGE" \
  --platform managed \
  --allow-unauthenticated \
  --port 8080 \
  --cpu 1 \
  --memory 1Gi \
  --timeout 300 \
  --concurrency "$CONCURRENCY" \
  --min-instances "$MIN_INSTANCES" \
  --max-instances "$MAX_INSTANCES" \
  "$CPU_THROTTLING_FLAG" \
  --set-env-vars "$ENV_VARS" \
  --set-secrets "$SECRETS"

gcloud run services update-traffic "$SERVICE_NAME" \
  --project "$PROJECT_ID" \
  --region "$REGION" \
  --to-latest

echo "Cloud Run deployment finished."
