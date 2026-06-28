"""Early-access waitlist intake for the marketing landing page.

Public endpoint (no API key required): the landing form posts an email here.
Storage is best-effort write-through to Supabase and a safe no-op when Supabase
is not configured, mirroring the community/push routes. Only a validated,
normalized email (plus a coarse source tag) is stored; no other PII is collected
or echoed back to the caller.
"""

import logging
import re
from typing import Optional

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from services import supabase_store

router = APIRouter()
logger = logging.getLogger("sigurscan.waitlist")

# Pragmatic email shape check (defense-in-depth before storage). Intentionally
# not a full RFC 5322 validator: we only need to reject obvious junk.
_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
_MAX_EMAIL_LEN = 254
_ALLOWED_SOURCES = {"landing", "web", "android", "ios", "unknown"}


class WaitlistSubscribeRequest(BaseModel):
    email: str
    source: Optional[str] = "landing"


@router.post("/v1/waitlist")
def waitlist_subscribe(payload: WaitlistSubscribeRequest):
    email = (payload.email or "").strip().lower()
    if not email or len(email) > _MAX_EMAIL_LEN or not _EMAIL_RE.fullmatch(email):
        raise HTTPException(status_code=400, detail="invalid email")

    source = (payload.source or "landing").strip().lower()
    if source not in _ALLOWED_SOURCES:
        source = "unknown"

    if not supabase_store.is_supabase_enabled():
        return {"status": "accepted", "stored": False, "note": "supabase not configured"}

    try:
        supabase_store._post_json(
            "waitlist_signups",
            {
                "email": email,
                "source": source,
                "last_seen_at": supabase_store._utc_iso(),
            },
            "resolution=merge-duplicates,return=minimal",
            params={"on_conflict": "email"},
        )
    except Exception as exc:  # pragma: no cover - defensive; _post_json is best-effort
        logger.warning(
            "waitlist_subscribe storage failed source=%s error=%s",
            source,
            exc.__class__.__name__,
        )
        raise HTTPException(status_code=503, detail="waitlist storage unavailable")

    return {"status": "ok", "stored": True}
