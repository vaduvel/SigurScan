"""Monthly budget gates for paid enrichment providers.

Central choke point for per-call paid APIs (Google Vision OCR, Google Web
Risk, Mistral, Gemini, urlscan). Reuses ``services.provider_budget`` which is
backed by Supabase/Upstash with an in-memory fallback and fails closed on
store errors.

Safety contract: budget exhaustion only disables PAID ENRICHMENT. The verdict
gate treats missing provider data conservatively (a missing/pending provider
blocks SAFE and can never downgrade a DANGEROUS verdict), so running out of
budget can never make a scam look safe. See audit issue #82.
"""

from __future__ import annotations

from services.provider_budget import try_consume_monthly_budget

# Intentionally generous defaults so production behaviour only changes when an
# operator sets a lower limit via env. Setting a budget env var to 0 disables
# that provider entirely.
GOOGLE_VISION_MONTHLY_BUDGET_DEFAULT = 5000
WEB_RISK_MONTHLY_BUDGET_DEFAULT = 50000
MISTRAL_MONTHLY_BUDGET_DEFAULT = 20000
GEMINI_MONTHLY_BUDGET_DEFAULT = 20000
URLSCAN_MONTHLY_BUDGET_DEFAULT = 3000


def consume_google_vision() -> bool:
    """Consume one Google Vision OCR call from the monthly budget."""
    return try_consume_monthly_budget(
        "google_vision",
        env_name="GOOGLE_VISION_MONTHLY_BUDGET",
        default_limit=GOOGLE_VISION_MONTHLY_BUDGET_DEFAULT,
    )


def consume_web_risk() -> bool:
    """Consume one Google Web Risk URI lookup from the monthly budget."""
    return try_consume_monthly_budget(
        "google_web_risk",
        env_name="WEB_RISK_MONTHLY_BUDGET",
        default_limit=WEB_RISK_MONTHLY_BUDGET_DEFAULT,
    )


def consume_mistral() -> bool:
    """Consume one Mistral chat-completions call from the monthly budget."""
    return try_consume_monthly_budget(
        "mistral",
        env_name="MISTRAL_MONTHLY_BUDGET",
        default_limit=MISTRAL_MONTHLY_BUDGET_DEFAULT,
    )


def consume_gemini() -> bool:
    """Consume one Gemini generate-content call from the monthly budget."""
    return try_consume_monthly_budget(
        "gemini",
        env_name="GEMINI_MONTHLY_BUDGET",
        default_limit=GEMINI_MONTHLY_BUDGET_DEFAULT,
    )


def consume_urlscan() -> bool:
    """Consume one urlscan submission from the monthly budget.

    Note: not yet wired into the urlscan pipeline (follow-up in #82); exposed
    here so the submit path can adopt the same gate.
    """
    return try_consume_monthly_budget(
        "urlscan",
        env_name="URLSCAN_MONTHLY_BUDGET",
        default_limit=URLSCAN_MONTHLY_BUDGET_DEFAULT,
    )
