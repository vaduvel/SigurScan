"""Semantic review adapter for Urechea audio transcripts.

This module never accepts or returns raw audio. Android sends only transcript
windows that were already redacted on-device. The backend keeps the Mistral key
server-side and returns semantic signals, not a final product verdict.
"""

from __future__ import annotations

from typing import Any, Dict, List

from starlette.concurrency import run_in_threadpool

from api_models import AudioSemanticReviewRequest
from config import (
    ENABLE_MISTRAL_SEMANTIC_PILLAR,
    MISTRAL_SEMANTIC_API_KEY,
    MISTRAL_SEMANTIC_MODEL,
    PRIVACY_SAFE_MODE,
)
from services.external_url_privacy import sanitize_external_text
from services.scan_analysis import _call_mistral_semantic_review, _normalize_mistral_semantic_review


_RISK_RANK = {
    "benign": 0,
    "unknown": 0,
    "none": 0,
    "medium": 1,
    "high": 2,
}


def _dedupe(values: List[str]) -> List[str]:
    out: List[str] = []
    seen: set[str] = set()
    for value in values:
        item = str(value or "").strip()
        if item and item not in seen:
            out.append(item)
            seen.add(item)
    return out


def _risk_class_for_local_verdict(verdict: str | None) -> str:
    normalized = str(verdict or "").strip().upper()
    if normalized == "DANGEROUS":
        return "high"
    if normalized == "SUSPECT":
        return "medium"
    return "unknown"


def _rank(value: str | None) -> int:
    return _RISK_RANK.get(str(value or "").strip().lower(), 0)


def _fallback_review(request: AudioSemanticReviewRequest, *, extra_reason: str | None = None) -> Dict[str, Any]:
    local_risk = _risk_class_for_local_verdict(request.local_verdict)
    reason_codes = _dedupe(
        list(request.local_reason_codes or [])
        + ["semantic:audio_local_fallback"]
        + ([extra_reason] if extra_reason else [])
    )
    return {
        "status": "done",
        "risk_class": local_risk,
        "claim_matches_known_scam_family": local_risk in {"high", "medium"},
        "matched_family": request.arc_family,
        "claim_matches_legit_template": False,
        "matched_template": None,
        "reason_codes": reason_codes,
        "completeness": True,
        "source": "audio_local_fallback",
    }


def _response(status: str, review: Dict[str, Any], local_risk: str) -> Dict[str, Any]:
    risk_class = str(review.get("risk_class") or "unknown").strip().lower()
    return {
        "status": status,
        "semantic_review": review,
        "reason_codes": list(review.get("reason_codes") or []),
        "escalates": _rank(risk_class) > _rank(local_risk),
        "model": MISTRAL_SEMANTIC_MODEL if status == "done" and review.get("source") == "mistral_semantic_pillar" else None,
        "privacy": {
            "raw_audio_received": False,
            "raw_audio_stored": False,
            "transcript_echoed": False,
            "input": "redacted_transcript_only",
        },
    }


async def review_redacted_audio_transcript(request: AudioSemanticReviewRequest) -> Dict[str, Any]:
    provider_safe_text = sanitize_external_text(request.transcript_redacted or "")[:2500]
    local_risk = _risk_class_for_local_verdict(request.local_verdict)
    fallback = _fallback_review(request)

    if not provider_safe_text.strip():
        review = _fallback_review(request, extra_reason="semantic:audio_empty_transcript")
        return _response("fallback", review, local_risk)

    if PRIVACY_SAFE_MODE or not ENABLE_MISTRAL_SEMANTIC_PILLAR or not bool(MISTRAL_SEMANTIC_API_KEY):
        review = _fallback_review(request, extra_reason="semantic:mistral_unavailable")
        return _response("fallback", review, local_risk)

    payload = {
        "redacted_text": provider_safe_text,
        "channel": request.channel or "call_live",
        "locale": request.locale or "ro-RO",
        "claimed_identity": request.claimed_identity,
        "atlas_semantic_review": fallback,
        "family": {
            "id": request.arc_family,
            "name": request.arc_family,
        },
        "audio_context": {
            "source": "urechea",
            "raw_audio_sent": False,
            "transcript_redacted_on_device": True,
        },
    }

    try:
        raw_review = await run_in_threadpool(_call_mistral_semantic_review, payload)
        normalized_review = _normalize_mistral_semantic_review(raw_review, fallback)
        return _response("done", normalized_review, local_risk)
    except Exception as exc:
        review = _fallback_review(request, extra_reason="semantic:mistral_fallback")
        review["mistral_status"] = "failed"
        review["mistral_error"] = type(exc).__name__
        return _response("fallback", review, local_risk)
