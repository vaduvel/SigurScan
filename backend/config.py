"""Static configuration and environment-derived settings for backend."""

import os
import re

URLSCAN_VISIBILITY_DEFAULT = os.getenv("URLSCAN_VISIBILITY_DEFAULT", "private").strip().lower() or "private"
URLSCAN_COUNTRY_DEFAULT = os.getenv("URLSCAN_COUNTRY_DEFAULT", "").strip().lower()
URLSCAN_CUSTOM_AGENT_DEFAULT = os.getenv("URLSCAN_CUSTOM_AGENT", "").strip()

EXPOSE_API_DOCS = os.getenv("EXPOSE_API_DOCS", "false").strip().lower() in {
    "1",
    "true",
    "yes",
    "on",
}

MAX_IMAGE_BYTES = 10 * 1024 * 1024
MAX_PDF_BYTES = 12 * 1024 * 1024
MAX_XML_BYTES = 2 * 1024 * 1024
MAX_TEXT_CHARS = int(os.getenv("MAX_TEXT_CHARS", "12000"))
MAX_URLS_PER_SCAN = int(os.getenv("MAX_URLS_PER_SCAN", "15"))
RISK_THRESHOLD = int(os.getenv("RISK_THRESHOLD", "50"))
PRIVACY_SAFE_MODE = (
    os.getenv("SIGURSCAN_SAFE_MODE")
    or os.getenv("NUDACLICK_SAFE_MODE")
    or "false"
).strip().lower() in {"1", "true", "yes", "on"}
ALLOWED_IMAGE_MIME_TYPES = {"image/jpeg", "image/png", "image/webp"}
ALLOWED_IMAGE_EXTS = {".jpg", ".jpeg", ".png", ".webp"}
ALLOWED_PDF_MIME_TYPES = {"application/pdf", "application/x-pdf"}
ALLOWED_PDF_EXTS = {".pdf"}
ALLOWED_XML_MIME_TYPES = {"application/xml", "text/xml", "application/octet-stream"}
ALLOWED_XML_EXTS = {".xml"}
ALLOWED_MOCK_OCR = os.getenv("ALLOW_MOCK_OCR", "false").strip().lower() in {
    "1",
    "true",
    "yes",
    "on",
}

# Plain-text URL extraction noise list:
# Some short Romanian tokens include a dot and can be wrongly matched as URLs by regex.
REQUIRE_API_KEY = os.getenv("REQUIRE_API_KEY", "false").strip().lower() in {"1", "true", "yes", "on"}
ALLOWED_API_KEYS = {
    key.strip()
    for key in (
        os.getenv("SIGURSCAN_API_KEYS")
        or os.getenv("NUDACLICK_API_KEYS")
        or ""
    ).split(",")
    if key.strip()
}

# Operator-only keys.
ADMIN_API_KEYS = {
    key.strip()
    for key in (os.getenv("SIGURSCAN_ADMIN_API_KEYS") or "").split(",")
    if key.strip()
}
INTERNAL_WORKER_TOKEN = (
    os.getenv("SIGURSCAN_INTERNAL_WORKER_TOKEN")
    or os.getenv("INTERNAL_WORKER_TOKEN")
    or ""
).strip()

ADMIN_ONLY_PATHS = {
    "/v1/orchestration/dashboard",
    "/v1/orchestration/telemetry",
    "/v1/feedback/summary",
    "/v1/adjudication/shadow",
    "/v1/adjudication/dashboard",
    "/v1/intel/ingest",
    "/v1/intel/moderate",
    "/v1/intel/moderation-queue",
    "/v1/intel/sources",
    "/v1/urechea/run",
    "/v1/campaign/active",
    "/v1/campaign/families",
    "/v1/campaign/match",
    "/v1/evaluation/feedback",
    "/v1/evaluation/run",
    "/v1/feedback/samples",
    "/v1/feedback/quality",
    "/v1/evaluation/feedback/trend",
    "/v1/evaluation/readiness",
}

PUBLIC_PATHS = {
    "/",
    "/health",
    "/healthz",
    "/health/security",
    "/privacy",
    "/privacy-policy",
    "/terms",
    "/terms-of-service",
    "/v1/voice/twilio/incoming",
    "/v1/voice/twilio/transcription",
}

# GET-only screenshot proxy consumed by image loaders (Coil) that cannot attach
# auth headers. Unguessable urlscan UUID in the path; rate limiting still applies.
_SCREENSHOT_PROXY_PATH_RE = re.compile(r"^/v1/sandbox/urlscan/[^/]+/screenshot$")

# Scan intake routes covered by Play Integrity once it leaves "off" mode.
_INTEGRITY_GUARDED_PREFIXES = ("/v1/scan/", "/v1/extract/", "/v1/audio/", "/v1/sandbox/urlscan")
PLAY_INTEGRITY_NONCE_PATH = "/v1/security/play-integrity/nonce"
CLIENT_INSTANCE_HEADER = "X-SigurScan-Client-Instance"
GENERIC_LOOKALIKE_TOKENS = {
    "account",
    "accounts",
    "app",
    "client",
    "cont",
    "eportal",
    "login",
    "online",
    "pay",
    "payment",
    "plata",
    "plati",
    "portal",
    "secure",
    "service",
    "servicii",
    "verify",
}
MISTRAL_SEMANTIC_SYSTEM_PROMPT = """
Ești pilonul semantic SigurScan pentru mesaje în limba română.
Nu ai voie să dai verdict final și nu ai voie să folosești etichete SIGUR/SUSPECT/PERICULOS.
Primești text redactat, domenii finale și context atlas/corpus. Întorci doar semantic_review structurat.
Reguli:
- Marchează high doar când claim-ul seamănă clar cu o familie scam sau cere acțiuni sensibile/social-engineering.
- Marchează benign doar când claim-ul seamănă cu un șablon legitim/marketing normal și nu cere date sensibile.
- Marketing language, CTA, reduceri, catalog, newsletter sau link sub buton nu sunt suficiente pentru high.
- Tratează ca high cererile de cod/OTP parțial sau complet, cod unic din aplicația bancară, captură/screenshot de cod QR eSIM, PIN/CVV/card, parole, seed phrase sau date de identitate.
- Tratează ca high pretextele de siguranță care cer login/autentificare într-un simulator, link extern, formular data: sau deeplink de aplicație.
- Tratează ca high transferurile către cont/beneficiar de siguranță, cont nou, IBAN migrat, transfer test, depozit rambursabil de colet sau taxă/token de eliberare pachet.
- Tratează ca high URL-urile cu userinfo spoofing de forma brand.ro@alt-domeniu și deeplink-urile/native/data URL care cer acțiuni sensibile.
- Textul educațional legitim de tip "nu comunica OTP/parola, sună canalul oficial" este benign doar dacă nu cere apoi login, transfer, cod, instalare sau contact prin canal neoficial.
- Separă intenția de textul descriptiv: un articol, ghid, status de tranzacție, control de audit sau factură care doar menționează OTP/card/IBAN/scam NU este cerere de acțiune.
- Marchează positive_action_request=true doar când utilizatorului i se cere să facă ceva: să introducă/dateze/trimită coduri, card, parolă, să plătească/transfere, să instaleze, să sune/continue apelul sau să apese un link pentru verificare.
- Rezolvă negațiile: "nu comunica OTP", "nu accesa linkuri", "IBAN-ul nu s-a schimbat", "fără plată/link/card" sunt protective/descriptive dacă nu există o cerere opusă după ele.
- Nu inventa branduri, domenii, provider hits sau fapte lipsă.
Răspunde strict JSON:
{
  "risk_class": "high|medium|benign|unknown",
  "claim_matches_known_scam_family": false,
  "matched_family": null,
  "matched_template": null,
  "reason_codes": ["semantic:..."],
  "social_engineering": {
    "intent": "credential_theft|payment_redirection|remote_access|investment_fraud|impersonation|recovery_scam|benign|unknown",
    "ask_present": false,
    "ask_type": ["transfer|otp|card|remote_install|gift_card|seed_phrase|callback|none"],
    "levers": ["authority|fear|urgency|scarcity|liking|reciprocity|social_proof|loss_aversion|sunk_cost|compassion|greed|secrecy"],
    "persona_targeting": "elderly|parent|jobseeker|investor|employee|bereaved|generic",
    "channel_coherence": "coherent|mismatch|unknown",
    "urgency_score": 0.0,
    "confidence": 0.0
  },
  "intent_analysis": {
    "positive_action_request": false,
    "is_protective_warning": false,
    "is_descriptive_or_status": false,
    "negation_scope_resolved": true,
    "invoice_or_payment_document": false,
    "payment_instruction_present": false,
    "payment_instruction_is_requested": false,
    "payment_instruction_is_descriptive": false,
    "describes_fraud_without_request": false,
    "confidence": 0.0
  }
}
""".strip()

_SOCIAL_ENGINEERING_PRESSURE_PATTERNS = (
    # authority / law-enforcement impersonation
    r"\b(parchet|procuror|comisar|poli[țt]i[ae]|politi[ae]|dosar\s+penal|mandat\s+de\s+aducere|"
    r"anchet[ăa]|ancheta|diicot|dna)\b",
    # secrecy / isolation
    r"\bnu\s+spune(?:ti|ți)?\s+nim[ăa]nui\b",
    r"\bnu\s+(?:discuta(?:ti|ți)?|spune(?:ti|ți)?)\b.{0,40}\b(nim[ăa]nui|familie|colegi|superiori)\b",
    r"\b(confiden[țt]ial|clasificat[ăa]?|[îi]ntre\s+noi)\b",
    # out-of-band callback / stay on the line
    r"\b(suna(?:ti|ți)?[-\s]?ne|suna(?:ti|ți)?\s+(?:urgent|acum|la)|reveni(?:ti|ți)\s+telefonic)\b",
    r"\br[ăa]m(?:a|â)ne(?:ti|ți)?\s+pe\s+(?:linie|fir)\b",
    # safe-account / move funds to a "protective" account
    r"\bcont(?:ul)?\s+(?:de\s+)?(?:siguran[țt][ăa]|protec[țt]ie|seif|temporar)\b",
    r"\b(transfera(?:ti|ți)?|muta(?:ti|ți)?|mut[ăa])\b.{0,60}\bcont(?:ul)?\s+(?:nou|sigur)\b",
    r"\bbeneficiar(?:ul)?\s+(?:de\s+)?(?:siguran[țt][ăa]|temporar)\b",
    r"\b(?:cod(?:ul)?\s+unic|cod(?:ul)?.{0,50}aplica[țt]ia\s+bancar[ăa]|cod(?:ul)?\s+qr.{0,40}esim)\b",
    # threat + coercion
    r"\b(arest|aresta(?:t|re)|re[țt]inere|re[țt]inut|dezactivat|clon[ăa])\b",
)

SOCIAL_ENGINEERING_INTENTS = {
    "credential_theft",
    "payment_redirection",
    "remote_access",
    "investment_fraud",
    "impersonation",
    "recovery_scam",
    "benign",
    "unknown",
}
SOCIAL_ENGINEERING_ASK_TYPES = {
    "transfer",
    "otp",
    "card",
    "remote_install",
    "gift_card",
    "seed_phrase",
    "callback",
    "none",
}
SOCIAL_ENGINEERING_LEVERS = {
    "authority",
    "fear",
    "urgency",
    "scarcity",
    "liking",
    "reciprocity",
    "social_proof",
    "loss_aversion",
    "sunk_cost",
    "compassion",
    "greed",
    "secrecy",
}

ENABLE_RATE_LIMIT = os.getenv("ENABLE_RATE_LIMIT", "true").strip().lower() in {"1", "true", "yes", "on"}
# Pilon DNS reputation (gratis, fără cheie). Free-first: OPT-IN, implicit OFF.
ENABLE_DNS_REPUTATION = os.getenv("ENABLE_DNS_REPUTATION", "false").strip().lower() in {"1", "true", "yes", "on"}
RATE_LIMIT_PER_MINUTE = int(os.getenv("RATE_LIMIT_PER_MINUTE", "60"))
RATE_LIMIT_WINDOW_SECONDS = 60

URLSCAN_API_KEY = (
    os.getenv("SIGURSCAN_URLSCAN_API_KEY")
    or os.getenv("NUDACLICK_URLSCAN_API_KEY")
    or os.getenv("URLSCAN_API_KEY")
    or ""
).strip()
URLSCAN_TIMEOUT_SECONDS = float(os.getenv("URLSCAN_TIMEOUT_SECONDS", "8.0"))

ENABLE_CLOUD_AI_EXPLANATION = os.getenv("ENABLE_CLOUD_AI_EXPLANATION", "true").strip().lower() in {
    "1",
    "true",
    "yes",
    "on",
}
AI_EXPLANATION_TIMEOUT_SECONDS = float(os.getenv("AI_EXPLANATION_TIMEOUT_SECONDS", "2.5"))
AI_OFFER_CLAIM_TIMEOUT_SECONDS = float(os.getenv("AI_OFFER_CLAIM_TIMEOUT_SECONDS", "5.0"))
ENABLE_MISTRAL_SEMANTIC_PILLAR = os.getenv("ENABLE_MISTRAL_SEMANTIC_PILLAR", "true").strip().lower() in {
    "1",
    "true",
    "yes",
    "on",
}
MISTRAL_SEMANTIC_API_KEY = os.getenv("MISTRAL_API_KEY", "").strip()
MISTRAL_SEMANTIC_MODEL = (
    os.getenv("MISTRAL_SEMANTIC_MODEL")
    or os.getenv("MISTRAL_MODEL")
    or "mistral-small-2503"
).strip()
MISTRAL_SEMANTIC_TIMEOUT_SECONDS = float(os.getenv("MISTRAL_SEMANTIC_TIMEOUT_SECONDS", "3.0"))

FAST_REPUTATION_MODE = os.getenv("FAST_REPUTATION_MODE", "true").strip().lower() in {"1", "true", "yes", "on"}
FAST_REPUTATION_INCLUDE_URLHAUS = os.getenv("FAST_REPUTATION_INCLUDE_URLHAUS", "false").strip().lower() in {
    "1",
    "true",
    "yes",
    "on",
}
ENABLE_DEEP_REPUTATION_FALLBACK = os.getenv("ENABLE_DEEP_REPUTATION_FALLBACK", "true").strip().lower() in {
    "1",
    "true",
    "yes",
    "on",
}
DOMAIN_SUSPICIOUS_AGE_DAYS = int(os.getenv("DOMAIN_SUSPICIOUS_AGE_DAYS", "30"))
DOMAIN_ESTABLISHED_AGE_DAYS = int(os.getenv("DOMAIN_ESTABLISHED_AGE_DAYS", "365"))

DEFAULT_ALLOWED_ORIGINS = (
    "https://sigurscan.ro,"
    "https://www.sigurscan.ro,"
    "https://sigurscan-backend.vercel.app"
)
ALLOWED_ORIGINS = [
    origin.strip()
    for origin in os.getenv("ALLOWED_ORIGINS", DEFAULT_ALLOWED_ORIGINS).split(",")
    if origin.strip()
]
if not ALLOWED_ORIGINS:
    ALLOWED_ORIGINS = DEFAULT_ALLOWED_ORIGINS.split(",")
ALLOWED_CORS_METHODS = ["GET", "POST", "OPTIONS"]
ALLOWED_CORS_HEADERS = [
    "Authorization",
    "Content-Type",
    "X-API-KEY",
    "X-Play-Integrity-Token",
    "X-SigurScan-Client-Instance",
]
SIGURSCAN_PUBLIC_API_BASE_URL = (
    os.getenv("SIGURSCAN_PUBLIC_API_BASE_URL", "https://api.sigurscan.com").strip().rstrip("/")
)

CLOUD_TASKS_PROJECT = (
    os.getenv("CLOUD_TASKS_PROJECT")
    or os.getenv("GOOGLE_CLOUD_PROJECT")
    or os.getenv("GCP_PROJECT")
    or ""
).strip()
CLOUD_TASKS_LOCATION = os.getenv("CLOUD_TASKS_LOCATION", "").strip()
CLOUD_TASKS_QUEUE = os.getenv("CLOUD_TASKS_QUEUE", "").strip()
ORCHESTRATED_CLOUD_TASKS_ENABLED = os.getenv(
    "ORCHESTRATED_CLOUD_TASKS_ENABLED",
    "false",
).strip().lower() in {"1", "true", "yes", "on"}
CLOUD_TASKS_METADATA_TOKEN_URL = os.getenv(
    "CLOUD_TASKS_METADATA_TOKEN_URL",
    "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token",
).strip()
CLOUD_TASKS_REQUEST_TIMEOUT_SECONDS = float(os.getenv("CLOUD_TASKS_REQUEST_TIMEOUT_SECONDS", "4.0"))
ORCHESTRATED_CLOUD_TASKS_CONTINUE_DELAY_SECONDS = int(
    os.getenv("ORCHESTRATED_CLOUD_TASKS_CONTINUE_DELAY_SECONDS", "3")
)
_LEGACY_SCREENSHOT_PROXY_HOSTS = {
    "nudaclick-backend.vercel.app",
    "sigurscan-backend.vercel.app",
}

ORCHESTRATED_JOB_TTL_SECONDS = int(os.getenv("ORCHESTRATED_JOB_TTL_SECONDS", "900"))
ORCHESTRATED_URLSCAN_PENDING_TIMEOUT_SECONDS = int(
    os.getenv("ORCHESTRATED_URLSCAN_PENDING_TIMEOUT_SECONDS", "120")
)
ORCHESTRATED_REQUIRED_PILLAR_TIMEOUT_SECONDS = int(
    os.getenv("ORCHESTRATED_REQUIRED_PILLAR_TIMEOUT_SECONDS", "90")
)
ORCHESTRATED_URLSCAN_SUBMIT_RESERVATION_TIMEOUT_SECONDS = int(
    os.getenv("ORCHESTRATED_URLSCAN_SUBMIT_RESERVATION_TIMEOUT_SECONDS", "30")
)
URLSCAN_SCREENSHOT_UNAVAILABLE_DETAILS = (
    "Raportul de verificare izolata este disponibil, dar captura paginii nu a fost publicata de provider. "
    "Verdictul final ramane bazat pe sursele de risc."
)
# Publish the verdict as soon as the required pillars are terminal, with
# is_final=false while the urlscan report is still pending.
ORCHESTRATED_EARLY_VERDICT = (
    os.getenv("ORCHESTRATED_EARLY_VERDICT", "true").strip().lower() in {"1", "true", "yes", "on"}
)
# Ship the first publishable verdict with the deterministic fallback
# explanation and attach the cloud explanation on a later poll.
ORCHESTRATED_DEFER_AI_EXPLANATION = (
    os.getenv("ORCHESTRATED_DEFER_AI_EXPLANATION", "true").strip().lower() in {"1", "true", "yes", "on"}
)
URLSCAN_PREVIEW_CACHE_TTL_SECONDS = int(os.getenv("URLSCAN_PREVIEW_CACHE_TTL_SECONDS", str(7 * 24 * 60 * 60)))
URLSCAN_PREVIEW_CACHE_MAX_ENTRIES = int(os.getenv("URLSCAN_PREVIEW_CACHE_MAX_ENTRIES", "512"))
FAST_PREVIEW_CACHE_MAX_ENTRIES = int(os.getenv("FAST_PREVIEW_CACHE_MAX_ENTRIES", "512"))
FAST_PREVIEW_SIGNED_URL_TTL_SECONDS = int(os.getenv("FAST_PREVIEW_SIGNED_URL_TTL_SECONDS", "900"))
ORCHESTRATED_REFRESH_LOCK_TTL_SECONDS = int(os.getenv("ORCHESTRATED_REFRESH_LOCK_TTL_SECONDS", "90"))

# URLSCAN/OA route internals
_ORCHESTRATED_STAGE_RANK = {
    "queued": 0,
    "resolved": 10,
    "urlhaus_ready": 15,
    "reputation_ready": 20,
    "semantic_ready": 25,
    "claim_ready": 28,
    "analysis_ready": 30,
    "urlscan_submitting": 35,
    "urlscan_submitted": 40,
    "done": 100,
}

_VERDICT_SEVERITY_RANK = {"SAFE": 0, "UNVERIFIED": 1, "SUSPECT": 2, "DANGEROUS": 3}
_FINAL_URL_UNRESOLVED_ERROR_MARKERS = (
    "nameresolutionerror",
    "failed to resolve",
    "temporary failure in name resolution",
    "nodename nor servname",
    "nxdomain",
)
_FINAL_URL_UNRESOLVED_SUSPICIOUS_DNS_VERDICTS = {
    "nxdomain",
    "registrar_suspended",
    "suspended_nameserver",
    "domain_suspended",
}
