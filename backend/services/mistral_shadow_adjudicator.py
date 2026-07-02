import json
import os
import time
from typing import Any, Dict, Optional

import requests

from services.adjudication_validator import validate_and_guard
from services.telemetry import log_scan_event


MISTRAL_ENDPOINT = "https://api.mistral.ai/v1/chat/completions"
SHADOW_ENABLED = os.getenv("ENABLE_MISTRAL_SHADOW_ADJUDICATION", "false").strip().lower() in {
    "1",
    "true",
    "yes",
    "on",
}
MISTRAL_API_KEY = os.getenv("MISTRAL_API_KEY", "").strip()
MISTRAL_MODEL = (
    os.getenv("MISTRAL_ADJUDICATOR_MODEL")
    or os.getenv("MISTRAL_MODEL")
    or "mistral-small-2503"
).strip()
MISTRAL_TIMEOUT_SECONDS = float(os.getenv("MISTRAL_ADJUDICATOR_TIMEOUT_SECONDS", "2.5"))

_CACHE: Dict[str, Dict[str, Any]] = {}

ADJUDICATOR_SYSTEM = """
Ești un analist anti-scam pentru mesaje în limba română.
Primești doar un Evidence Bundle cu fapte verificate de SigurScan, nu ai voie să inventezi dovezi.
Decide eticheta doar pe baza faptelor, providerilor, URL-ului final, registry-ului, corpusului și semnalelor text.
Reguli dure:
- Provider malicious/phishing/malware înseamnă PERICULOS.
- Dacă destinația finală este oficială/delegată, providerii sunt curați și textul nu cere activ date/OTP/parolă/card/CVV/PIN, nu escalada la PERICULOS.
- Mențiunea pasivă de plată, abonament, factură sau card nu este cerere activă de date.
- Nu inventa motive. Folosește numai chei existente în evidence_used.
- Răspunde strict JSON.
Schema:
{
  "label": "SIGUR|SUSPECT|PERICULOS|NECUNOSCUT",
  "confidence": 0.0,
  "motiv_ro": "motiv scurt în română",
  "familie_scam": "id sau null",
  "sablon_legit": "id sau null",
  "evidence_used": ["chei din Evidence Bundle"]
}
""".strip()


def is_ambiguous(evidence: Dict[str, Any]) -> bool:
    gate = evidence.get("gate") if isinstance(evidence.get("gate"), dict) else {}
    label = str(gate.get("user_risk_label") or "").strip().upper()
    family_id = str(gate.get("detected_family_id") or "")
    provider_gate = gate.get("provider_gate") if isinstance(gate.get("provider_gate"), dict) else {}

    if label in {"NECUNOSCUT", "SUSPECT"}:
        return True
    if family_id.startswith("provider-gate-partial") or family_id in {
        "provider-gate-unofficial-inconclusive",
        "provider-gate-mismatch-or-sensitive",
        "provider-gate-legacy-high",
        "provider-gate-unverified",
    }:
        return True
    return bool(provider_gate.get("missing_required_pillars"))


def _call_mistral(evidence: Dict[str, Any]) -> Dict[str, Any]:
    response = requests.post(
        MISTRAL_ENDPOINT,
        headers={
            "Authorization": f"Bearer {MISTRAL_API_KEY}",
            "Content-Type": "application/json",
        },
        json={
            "model": MISTRAL_MODEL,
            "temperature": 0,
            "max_tokens": 450,
            "response_format": {"type": "json_object"},
            "messages": [
                {"role": "system", "content": ADJUDICATOR_SYSTEM},
                {"role": "user", "content": json.dumps(evidence, ensure_ascii=False, sort_keys=True)},
            ],
        },
        timeout=MISTRAL_TIMEOUT_SECONDS,
    )
    response.raise_for_status()
    payload = response.json()
    content = (
        payload.get("choices", [{}])[0]
        .get("message", {})
        .get("content", "")
        .strip()
    )
    parsed = json.loads(content)
    return parsed if isinstance(parsed, dict) else {}


def maybe_run_shadow_adjudication(
    *,
    scan_id: str,
    input_type: str,
    source_channel: Optional[str],
    evidence: Dict[str, Any],
) -> Optional[Dict[str, Any]]:
    """Run Mistral as a shadow analyst. Never changes the user-facing verdict."""

    if not SHADOW_ENABLED or not MISTRAL_API_KEY:
        return None
    if not is_ambiguous(evidence):
        return None

    evidence_hash = evidence.get("evidence_hash")
    gate = evidence.get("gate") if isinstance(evidence.get("gate"), dict) else {}
    started = time.monotonic()
    cache_hit = False
    fallback_reason = None
    raw_shadow: Optional[Dict[str, Any]] = None
    shadow: Optional[Dict[str, Any]] = None

    if isinstance(evidence_hash, str) and evidence_hash in _CACHE:
        raw_shadow = _CACHE[evidence_hash]
        cache_hit = True
    else:
        from services.paid_provider_budgets import consume_mistral

        if not consume_mistral():
            fallback_reason = "mistral_budget_exhausted"
        else:
            try:
                raw_shadow = _call_mistral(evidence)
                if isinstance(evidence_hash, str) and raw_shadow:
                    _CACHE[evidence_hash] = raw_shadow
            except Exception as exc:
                fallback_reason = f"mistral_error:{type(exc).__name__}"

    if raw_shadow is not None:
        shadow = validate_and_guard(raw_shadow, evidence)
        if shadow is None:
            fallback_reason = "validator_rejected"

    latency_ms = int((time.monotonic() - started) * 1000)
    hash_suffix = str(evidence_hash or "nohash").replace("sha256:", "")[:16]
    event = {
        "scan_id": f"{scan_id}:shadow:{hash_suffix}",
        "event_type": "adjudication_shadow",
        "input_type": input_type,
        "source_channel": source_channel,
        "risk_score": gate.get("risk_score") or 0,
        "risk_level": gate.get("risk_level"),
        "user_risk_label": gate.get("user_risk_label"),
        "detected_family_id": gate.get("detected_family_id"),
        "detected_family": None,
        "claimed_brand": (evidence.get("brand") or {}).get("claimed") if isinstance(evidence.get("brand"), dict) else None,
        "predicted_is_scam": str(gate.get("user_risk_label") or "").upper() == "DANGEROUS",
        "signal_ids": ["shadow:mistral_adjudicator"],
        "url_count": len(evidence.get("urls") or []),
        "urls": [],
        "redacted_text_snippet": (evidence.get("input") or {}).get("text_redacted", "")[:120]
        if isinstance(evidence.get("input"), dict)
        else "",
        "evidence": {
            "evidence_hash": evidence_hash,
            "gate": {
                "label": gate.get("user_risk_label"),
                "risk_level": gate.get("risk_level"),
                "risk_score": gate.get("risk_score"),
                "family_id": gate.get("detected_family_id"),
            },
            "shadow": shadow,
            "shadow_raw_label": raw_shadow.get("label") if isinstance(raw_shadow, dict) else None,
            "valid": shadow is not None,
            "fallback_reason": fallback_reason,
            "cache_hit": cache_hit,
            "latency_ms": latency_ms,
            "model": MISTRAL_MODEL,
        },
        "metadata": {
            "parent_scan_id": scan_id,
            "evidence_hash": evidence_hash,
        },
    }
    log_scan_event(event)
    return event
