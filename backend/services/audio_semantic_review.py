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

_MAX_SEMANTIC_CONTEXT_CHARS = 2500
_MAX_SAMPLED_SEGMENTS = 5


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


def _fallback_review(
    request: AudioSemanticReviewRequest,
    *,
    extra_reason: str | None = None,
    coverage_reason: str | None = None,
) -> Dict[str, Any]:
    local_risk = _risk_class_for_local_verdict(request.local_verdict)
    reason_codes = _dedupe(
        list(request.local_reason_codes or [])
        + ["semantic:audio_local_fallback"]
        + ([extra_reason] if extra_reason else [])
        + ([coverage_reason] if coverage_reason else [])
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


def _response(
    status: str,
    review: Dict[str, Any],
    local_risk: str,
    coverage: Dict[str, Any],
) -> Dict[str, Any]:
    risk_class = str(review.get("risk_class") or "unknown").strip().lower()
    return {
        "status": status,
        "semantic_review": review,
        "reason_codes": list(review.get("reason_codes") or []),
        "escalates": _rank(risk_class) > _rank(local_risk),
        "model": MISTRAL_SEMANTIC_MODEL if status == "done" and review.get("source") == "mistral_semantic_pillar" else None,
        "coverage": coverage,
        "privacy": {
            "raw_audio_received": False,
            "raw_audio_stored": False,
            "transcript_echoed": False,
            "input": "redacted_transcript_only",
        },
    }


def _clip_both_ends(value: str, budget: int) -> str:
    text = str(value or "").strip()
    if len(text) <= budget:
        return text
    if budget < 12:
        return text[:budget]
    separator = " ... "
    remaining = budget - len(separator)
    prefix = (remaining + 1) // 2
    suffix = remaining - prefix
    return text[:prefix] + separator + text[-suffix:]


def _sample_semantic_context(value: str, max_chars: int = _MAX_SEMANTIC_CONTEXT_CHARS) -> str:
    text = str(value or "").strip()
    if len(text) <= max_chars:
        return text
    segments = [segment.strip() for segment in text.split("\n\n") if segment.strip()]
    if not segments:
        return _clip_both_ends(text, max_chars)
    if len(segments) > _MAX_SAMPLED_SEGMENTS:
        last_index = len(segments) - 1
        selected_indices = {
            round(position * last_index / (_MAX_SAMPLED_SEGMENTS - 1))
            for position in range(_MAX_SAMPLED_SEGMENTS)
        }
        segments = [segments[index] for index in sorted(selected_indices)]
    separator_cost = max(0, len(segments) - 1) * 2
    available = max(1, max_chars - separator_cost)
    remaining = available
    sampled: List[str] = []
    for index, segment in enumerate(segments):
        segments_left = len(segments) - index
        budget = max(1, remaining // segments_left)
        fragment = _clip_both_ends(segment, budget)
        sampled.append(fragment)
        remaining -= len(fragment)
    return "\n\n".join(sampled)[:max_chars]


def _coverage_metadata(request: AudioSemanticReviewRequest) -> Dict[str, Any]:
    raw = request.coverage.model_dump(exclude_none=True) if request.coverage is not None else {}
    status = str(raw.get("status") or "unknown").strip().lower()
    if status not in {"complete", "partial", "unknown"}:
        status = "unknown"
    coverage: Dict[str, Any] = {"status": status}
    for key in (
        "source_duration_ms",
        "planned_duration_ms",
        "decoded_duration_ms",
        "transcribed_duration_ms",
        "windows_planned",
        "windows_decoded",
        "windows_skipped_by_vad",
        "windows_transcribed",
        "windows_failed",
        "transcript_chars_total",
        "transcript_chars_sent",
    ):
        value = raw.get(key)
        if isinstance(value, int) and value >= 0:
            coverage[key] = value
    ratio = raw.get("source_coverage_ratio")
    if isinstance(ratio, (int, float)):
        coverage["source_coverage_ratio"] = max(0.0, min(1.0, float(ratio)))
    for key in ("transcript_truncated", "vad_fallback_used"):
        if isinstance(raw.get(key), bool):
            coverage[key] = raw[key]
    return coverage


def _coverage_reason(coverage: Dict[str, Any]) -> str | None:
    status = str(coverage.get("status") or "unknown")
    if status == "partial":
        return "semantic:audio_partial_coverage"
    if status == "unknown":
        return "semantic:audio_unknown_coverage"
    return None


def _append_reason(review: Dict[str, Any], reason: str | None) -> Dict[str, Any]:
    if not reason:
        return review
    enriched = dict(review)
    enriched["reason_codes"] = _dedupe(list(enriched.get("reason_codes") or []) + [reason])
    return enriched


async def review_redacted_audio_transcript(request: AudioSemanticReviewRequest) -> Dict[str, Any]:
    provider_safe_text = _sample_semantic_context(
        sanitize_external_text(request.transcript_redacted or ""),
        _MAX_SEMANTIC_CONTEXT_CHARS,
    )
    local_risk = _risk_class_for_local_verdict(request.local_verdict)
    coverage = _coverage_metadata(request)
    coverage_reason = _coverage_reason(coverage)
    fallback = _fallback_review(request, coverage_reason=coverage_reason)

    if not provider_safe_text.strip():
        review = _fallback_review(
            request,
            extra_reason="semantic:audio_empty_transcript",
            coverage_reason=coverage_reason,
        )
        return _response("fallback", review, local_risk, coverage)

    if PRIVACY_SAFE_MODE or not ENABLE_MISTRAL_SEMANTIC_PILLAR or not bool(MISTRAL_SEMANTIC_API_KEY):
        review = _fallback_review(
            request,
            extra_reason="semantic:mistral_unavailable",
            coverage_reason=coverage_reason,
        )
        return _response("fallback", review, local_risk, coverage)

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
            "coverage": coverage,
        },
    }

    try:
        raw_review = await run_in_threadpool(_call_mistral_semantic_review, payload)
        normalized_review = _append_reason(
            _normalize_mistral_semantic_review(raw_review, fallback),
            coverage_reason,
        )
        return _response("done", normalized_review, local_risk, coverage)
    except Exception as exc:
        review = _fallback_review(
            request,
            extra_reason="semantic:mistral_fallback",
            coverage_reason=coverage_reason,
        )
        review["mistral_status"] = "failed"
        review["mistral_error"] = type(exc).__name__
        return _response("fallback", review, local_risk, coverage)
