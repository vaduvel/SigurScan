"""Circle verification routes (PR-6).

Signed protected<->verifier pairing, out-of-band verification pings, guardian
second opinion. Extracted from main.py; metadata-only, revocable, does not pass
through verdict_gate.
"""

from fastapi import APIRouter, HTTPException

from services.circle_verification import (
    CircleLink,
    VerificationPing,
    circle_store as _circle_store,
)
from services import supabase_store
from api_models import (
    CirclePairRequest,
    CirclePingRequest,
    CircleRespondRequest,
    CircleRevokeRequest,
    GuardianSecondOpinionRequest,
)

router = APIRouter()


@router.post("/v1/circle/pair")
async def circle_pair(payload: CirclePairRequest):
    """PR-6 — pairing semnat protejat↔verificator, consimțământ explicit, revocabil."""
    try:
        link = _circle_store.pair(
            protected_id=payload.protected_id,
            verifier_id=payload.verifier_id,
            consent=payload.consent,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    supabase_store.save_circle_link(link.to_dict())  # best-effort, no-op fără Supabase
    return link.to_dict()


@router.post("/v1/circle/ping")
async def circle_ping(payload: CirclePingRequest):
    """PR-6 — ping de verificare out-of-band (metadata-only). Timeout → PRECAUTIE."""
    try:
        ping = _circle_store.create_ping(payload.link_id, claim=payload.claim)
    except KeyError:
        persisted = supabase_store.load_circle_link(payload.link_id)
        if not persisted:
            raise HTTPException(status_code=404, detail="circle link not found")
        _circle_store.remember_link(CircleLink(**persisted))
        try:
            ping = _circle_store.create_ping(payload.link_id, claim=payload.claim)
        except KeyError:
            raise HTTPException(status_code=404, detail="circle link not found")
        except ValueError as exc:
            raise HTTPException(status_code=409, detail=str(exc))
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc))
    ping_payload = ping.to_dict()
    supabase_store.save_verification_ping(ping_payload)  # best-effort
    delivery = ping_payload.get("delivery")
    if isinstance(delivery, dict):
        supabase_store.save_circle_delivery_event({
            **delivery,
            "ping_id": ping.ping_id,
            "link_id": ping.link_id,
        })
    return ping_payload


@router.post("/v1/circle/respond")
async def circle_respond(payload: CircleRespondRequest):
    """PR-6 — răspunsul verificatorului (its_me/not_me/timeout). NEVERIFICAT pe timeout."""
    try:
        if payload.response == "timeout":
            result = _circle_store.resolve_timeout(payload.ping_id)
        else:
            result = _circle_store.respond(payload.ping_id, payload.response)
    except KeyError:
        persisted = supabase_store.load_verification_ping(payload.ping_id)
        if not persisted:
            raise HTTPException(status_code=404, detail="verification ping not found")
        _circle_store.remember_ping(VerificationPing(**persisted))
        if payload.response == "timeout":
            result = _circle_store.resolve_timeout(payload.ping_id)
        else:
            result = _circle_store.respond(payload.ping_id, payload.response)
    saved_ping = _circle_store.get_ping(payload.ping_id)
    if saved_ping is not None:
        supabase_store.update_verification_ping(  # best-effort
            saved_ping.ping_id, saved_ping.verifier_response or "", saved_ping.status)
    return result


@router.post("/v1/circle/revoke")
async def circle_revoke(payload: CircleRevokeRequest):
    """PR-6 — doar protejatul poate revoca relația din Cerc."""
    try:
        _circle_store.revoke(payload.link_id, by_user=payload.by_user)
    except KeyError:
        persisted = supabase_store.load_circle_link(payload.link_id)
        if not persisted:
            raise HTTPException(status_code=404, detail="circle link not found")
        _circle_store.remember_link(CircleLink(**persisted))
        try:
            _circle_store.revoke(payload.link_id, by_user=payload.by_user)
        except KeyError:
            raise HTTPException(status_code=404, detail="circle link not found")
        except PermissionError as exc:
            raise HTTPException(status_code=403, detail=str(exc))
    except PermissionError as exc:
        raise HTTPException(status_code=403, detail=str(exc))
    supabase_store.mark_circle_link_revoked(payload.link_id)  # best-effort
    link = _circle_store.get_link(payload.link_id)
    return link.to_dict()


@router.post("/v1/guardian/second-opinion")
async def guardian_second_opinion(payload: GuardianSecondOpinionRequest):
    """PR-6 — a doua opinie pentru protejat. Default metadata-only; full doar cu consimțământ."""
    so = _circle_store.second_opinion(
        case_id=payload.case_id,
        protected_id=payload.protected_id,
        guardian_id=payload.guardian_id,
        redacted_summary=payload.redacted_summary,
        share_level=payload.share_level,
        consent=payload.consent,
    )
    supabase_store.save_guardian_second_opinion(so.to_dict())  # best-effort
    return so.to_dict()
