"""Twilio protected-call proof-of-concept endpoints.

These routes do not capture native Android call audio. Twilio owns the call
leg, transcribes it, and sends transcript events here. We redact the transcript
before semantic review and never expose the transcript back through status.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import html
import json
import os
import time
from threading import Lock
from typing import Any, Dict, Mapping

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import Response

from api_models import AudioSemanticReviewRequest
from services.audio_semantic_review import review_redacted_audio_transcript
from services.pii_redactor import redact_pii

router = APIRouter()

_SESSION_LOCK = Lock()
_SESSIONS: Dict[str, Dict[str, Any]] = {}


def _public_base_url(request: Request) -> str:
    configured = os.getenv("TWILIO_PUBLIC_BASE_URL", "").strip().rstrip("/")
    if configured:
        return configured
    forwarded_proto = request.headers.get("x-forwarded-proto", "").split(",")[0].strip()
    forwarded_host = request.headers.get("x-forwarded-host", "").split(",")[0].strip()
    if forwarded_proto and forwarded_host:
        return f"{forwarded_proto}://{forwarded_host}".rstrip("/")
    return str(request.base_url).rstrip("/")


async def _form_params(request: Request) -> Dict[str, str]:
    form = await request.form()
    return {str(key): str(value) for key, value in form.multi_items()}


def _twilio_signature(url: str, params: Mapping[str, str], token: str) -> str:
    signed = url + "".join(f"{key}{params[key]}" for key in sorted(params))
    digest = hmac.new(token.encode("utf-8"), signed.encode("utf-8"), hashlib.sha1).digest()
    return base64.b64encode(digest).decode("ascii")


def _verify_twilio_signature(request: Request, params: Mapping[str, str]) -> None:
    token = os.getenv("TWILIO_AUTH_TOKEN", "").strip()
    if not token:
        allow_unsigned = os.getenv("TWILIO_ALLOW_UNSIGNED_WEBHOOKS", "").strip().lower()
        if allow_unsigned in {"1", "true", "yes", "on"}:
            return
        raise HTTPException(status_code=403, detail="Twilio signature verification is not configured.")
    received = request.headers.get("X-Twilio-Signature", "").strip()
    if not received:
        raise HTTPException(status_code=403, detail="Missing Twilio signature.")
    expected = _twilio_signature(str(request.url), params, token)
    if not hmac.compare_digest(received, expected):
        raise HTTPException(status_code=403, detail="Invalid Twilio signature.")


def _session_key(params: Mapping[str, str]) -> str:
    return str(params.get("CallSid") or params.get("call_sid") or "unknown").strip() or "unknown"


def _extract_transcription_data(params: Mapping[str, str]) -> Dict[str, Any]:
    raw = str(params.get("TranscriptionData") or params.get("transcription_data") or "").strip()
    data: Dict[str, Any] = {}
    if raw:
        try:
            parsed = json.loads(raw)
            if isinstance(parsed, dict):
                data = parsed
        except json.JSONDecodeError:
            data = {}
    transcript = (
        data.get("transcript")
        or data.get("Transcript")
        or data.get("text")
        or data.get("utterance")
        or params.get("Transcript")
        or params.get("transcript")
        or ""
    )
    data["transcript"] = str(transcript or "")
    data["is_final"] = bool(data.get("is_final") or data.get("final") or data.get("isFinal"))
    try:
        data["confidence"] = float(data.get("confidence") or data.get("Confidence") or 0.0)
    except (TypeError, ValueError):
        data["confidence"] = 0.0
    return data


def _verdict_for_risk_class(value: str | None) -> str:
    normalized = str(value or "").strip().lower()
    if normalized == "high":
        return "DANGEROUS"
    if normalized == "medium":
        return "SUSPECT"
    return "UNVERIFIED"


def _safe_session_status(call_sid: str) -> Dict[str, Any]:
    with _SESSION_LOCK:
        session = dict(_SESSIONS.get(call_sid) or {"call_sid": call_sid, "status": "unknown"})
    session.pop("last_transcript_redacted", None)
    session.pop("last_transcript_raw", None)
    session["privacy"] = {
        "raw_audio_received": False,
        "raw_audio_stored": False,
        "transcript_echoed": False,
        "stored_transcript": False,
    }
    return session


def _upsert_session(call_sid: str, updates: Dict[str, Any]) -> Dict[str, Any]:
    now = time.time()
    with _SESSION_LOCK:
        current = dict(_SESSIONS.get(call_sid) or {"call_sid": call_sid, "created_at": now, "chunks_received": 0})
        current.update(updates)
        current["updated_at"] = now
        _SESSIONS[call_sid] = current
        return dict(current)


@router.post("/v1/voice/twilio/incoming")
async def twilio_incoming_call(request: Request):
    params = await _form_params(request)
    _verify_twilio_signature(request, params)
    base_url = _public_base_url(request)
    callback_url = f"{base_url}/v1/voice/twilio/transcription"
    forward_to = os.getenv("TWILIO_PROTECTED_CALL_FORWARD_TO", "").strip()
    call_sid = _session_key(params)
    _upsert_session(
        call_sid,
        {
            "status": "started",
            "from_redacted": "[PHONE_REDACTED]" if params.get("From") else None,
            "latest_verdict": "UNVERIFIED",
            "latest_risk_class": "unknown",
            "reason_codes": ["twilio:protected_call_started"],
        },
    )

    dial_or_pause = (
        f'<Dial answerOnBridge="true" timeout="25">{html.escape(forward_to)}</Dial>'
        if forward_to
        else '<Pause length="600"/>'
    )
    twiml = f"""<?xml version="1.0" encoding="UTF-8"?>
<Response>
  <Say language="ro-RO">Apel protejat SigurScan. Conversația este analizată anti-fraudă cu acordul tău.</Say>
  <Start>
    <Transcription name="sigurscan-protected-call" statusCallbackUrl="{html.escape(callback_url)}" languageCode="ro-RO" track="both_tracks" partialResults="true" enableAutomaticPunctuation="true" profanityFilter="false" />
  </Start>
  {dial_or_pause}
</Response>"""
    return Response(content=twiml, media_type="application/xml")


@router.post("/v1/voice/twilio/transcription")
async def twilio_transcription_callback(request: Request):
    params = await _form_params(request)
    _verify_twilio_signature(request, params)
    call_sid = _session_key(params)
    event = str(params.get("TranscriptionEvent") or params.get("EventType") or "").strip()
    if event in {"transcription-started", "transcription_starts", "started"}:
        _upsert_session(call_sid, {"status": "transcribing", "reason_codes": ["twilio:transcription_started"]})
        return {"accepted": True, "call_sid": call_sid, "event": event}
    if event in {"transcription-stopped", "transcription_stopped", "stopped"}:
        _upsert_session(call_sid, {"status": "stopped", "reason_codes": ["twilio:transcription_stopped"]})
        return {"accepted": True, "call_sid": call_sid, "event": event}
    if event and event not in {"transcription-content", "transcription_content", "content"}:
        _upsert_session(call_sid, {"status": "event_ignored", "last_event": event})
        return {"accepted": True, "call_sid": call_sid, "event": event, "ignored": True}

    data = _extract_transcription_data(params)
    transcript_raw = str(data.get("transcript") or "").strip()
    if not transcript_raw:
        _upsert_session(call_sid, {"status": "waiting_for_transcript", "last_event": event or "content_empty"})
        return {"accepted": True, "call_sid": call_sid, "event": event or "content_empty", "latest_verdict": "UNVERIFIED"}

    transcript_redacted = redact_pii(transcript_raw)
    review = await review_redacted_audio_transcript(
        AudioSemanticReviewRequest(
            transcript_redacted=transcript_redacted,
            channel="twilio_protected_call",
            local_verdict="UNVERIFIED",
            local_reason_codes=["twilio:realtime_transcription"],
        )
    )
    semantic = dict(review.get("semantic_review") or {})
    risk_class = str(semantic.get("risk_class") or "unknown").strip().lower()
    verdict = _verdict_for_risk_class(risk_class)
    reason_codes = list(dict.fromkeys(list(semantic.get("reason_codes") or []) + list(review.get("reason_codes") or [])))
    session = _upsert_session(
        call_sid,
        {
            "status": "transcribing",
            "last_event": event or "transcription-content",
            "chunks_received": int((_SESSIONS.get(call_sid) or {}).get("chunks_received") or 0) + 1,
            "latest_verdict": verdict,
            "latest_risk_class": risk_class,
            "matched_family": semantic.get("matched_family"),
            "reason_codes": reason_codes,
            "semantic_status": review.get("status"),
            "semantic_source": semantic.get("source"),
            "escalates": bool(review.get("escalates")),
            "last_transcript_chars": len(transcript_raw),
            "last_transcript_final": bool(data.get("is_final")),
            "last_transcript_confidence": float(data.get("confidence") or 0.0),
        },
    )
    return {
        "accepted": True,
        "call_sid": call_sid,
        "latest_verdict": session.get("latest_verdict"),
        "latest_risk_class": session.get("latest_risk_class"),
        "matched_family": session.get("matched_family"),
        "privacy": _safe_session_status(call_sid)["privacy"],
    }


@router.get("/v1/voice/twilio/sessions/{call_sid}")
async def twilio_session_status(call_sid: str):
    return _safe_session_status(call_sid)
