"""Privacy-safe canonical input contract for every SigurScan scan surface.

The envelope records what the user supplied and how it was extracted. It is
deliberately verdict-neutral: downstream engines may consume it later, but
creating the envelope must never change a user-facing decision.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any, Dict, Iterable, Mapping, Optional, Sequence

from core.url_intelligence import extract_urls
from services.external_url_privacy import prepare_external_urls, sanitize_external_text
from services.pre_redaction_evidence import pre_redaction_summary


ARTIFACT_ENVELOPE_SCHEMA = "sigurscan_artifact_envelope_v1"
MAX_ENVELOPE_TEXT_CHARS = 4000


def _normalized_text(value: Any) -> str:
    return sanitize_external_text(value)[:MAX_ENVELOPE_TEXT_CHARS]


def _safe_email_auth_summary(email_auth: Optional[Mapping[str, Any]]) -> Dict[str, Any]:
    if not isinstance(email_auth, Mapping) or not email_auth:
        return {"present": False}

    auth_status = email_auth.get("auth_status")
    auth_status = auth_status if isinstance(auth_status, Mapping) else {}
    return {
        "present": True,
        "auth_strength": str(email_auth.get("auth_strength") or "unknown"),
        "sender_auth_confidence": str(email_auth.get("sender_auth_confidence") or "unknown"),
        "spf": str(auth_status.get("spf") or "missing"),
        "dkim": str(auth_status.get("dkim") or "missing"),
        "dmarc": str(auth_status.get("dmarc") or "missing"),
    }


def _qr_url_count(qr_payloads: Sequence[Any]) -> int:
    urls = []
    for payload in qr_payloads:
        for url in extract_urls(str(payload or "")):
            if url not in urls:
                urls.append(url)
    return len(urls)


def _stable_hash(payload: Mapping[str, Any]) -> str:
    canonical = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return "sha256:" + hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def build_artifact_envelope(
    *,
    artifact_type: str,
    analysis_input_type: str,
    source_channel: str,
    redacted_text: str,
    external_urls: Iterable[str],
    qr_payloads: Optional[Sequence[Any]] = None,
    hidden_url_visibility: bool = False,
    has_html: bool = False,
    email_auth: Optional[Mapping[str, Any]] = None,
    compound_evidence: Optional[Mapping[str, Any]] = None,
    extraction_warning: Optional[str] = None,
    pre_redaction_evidence: Optional[Mapping[str, Any]] = None,
) -> Dict[str, Any]:
    """Build the canonical, persistable artifact contract.

    Raw QR payloads, raw e-mail identities, and extraction warning text are not
    persisted. URLs are passed through the same privacy policy as provider
    calls, so tokens and PII cannot leak through this new metadata surface.
    """

    qr_payloads = list(qr_payloads or [])
    safe_urls, _privacy = prepare_external_urls(str(url or "") for url in external_urls or [])
    normalized_artifact_type = str(artifact_type or "unknown").strip().lower() or "unknown"
    normalized_analysis_type = str(analysis_input_type or "unknown").strip().lower() or "unknown"
    normalized_channel = str(source_channel or "unknown").strip().lower() or "unknown"

    compound_evidence = compound_evidence if isinstance(compound_evidence, Mapping) else {}
    compound_summary = compound_evidence.get("summary")
    compound_summary = compound_summary if isinstance(compound_summary, Mapping) else {}
    compound_coverage = compound_evidence.get("coverage")
    compound_coverage = compound_coverage if isinstance(compound_coverage, Mapping) else {}
    envelope: Dict[str, Any] = {
        "schema": ARTIFACT_ENVELOPE_SCHEMA,
        "artifact_type": normalized_artifact_type,
        "analysis_input_type": normalized_analysis_type,
        "source_channel": normalized_channel,
        "provenance": {
            "artifact_type_preserved": True,
            "artifact_type": normalized_artifact_type,
            "analysis_input_type": normalized_analysis_type,
            "source_channel": normalized_channel,
        },
        "content": {
            "redacted_text": _normalized_text(redacted_text),
            "has_html": bool(has_html),
        },
        "urls": {
            "items": safe_urls,
            "count": len(safe_urls),
            "hidden_url_visibility": bool(hidden_url_visibility),
        },
        "qr": {
            "count": len(qr_payloads),
            "url_count": _qr_url_count(qr_payloads),
            "hidden_url_visibility": bool(hidden_url_visibility),
        },
        "email_auth": _safe_email_auth_summary(email_auth),
        "compound": {
            "present": bool(compound_evidence),
            "schema": str(compound_evidence.get("schema") or "") if compound_evidence else None,
            "attachment_count": int(compound_summary.get("attachment_count") or 0),
            "candidate_url_count": int(compound_summary.get("candidate_url_count") or 0),
            "candidate_qr_count": int(compound_summary.get("candidate_qr_count") or 0),
            "coverage_status": str(compound_coverage.get("status") or "not_applicable"),
        },
        "extraction": {
            "status": "warning" if extraction_warning else "complete",
            "has_warning": bool(extraction_warning),
        },
        "pre_redaction": pre_redaction_summary(pre_redaction_evidence),
    }
    envelope["envelope_hash"] = _stable_hash(envelope)
    return envelope
