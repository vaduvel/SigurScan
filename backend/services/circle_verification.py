"""Cercul + Guardian second opinion (MoatOS §6, PR-6).

„Buton de întrerupere a izolării": scamul izolează victima („nu spune nimănui,
rămâi la telefon, acum"); Cercul rupe izolarea printr-o verificare out-of-band,
criptografică (un ping semnat, nu o parolă rostită care se poate clona).

Reguli pinuite:
- Cercul NU trece prin verdict_gate — protocol semnat, separat de lamă.
- Pairing: protejat + verificator, consimțământ EXPLICIT, revocabil.
- Ping: metadata-only, default_on_timeout = PRECAUTIE (NEVERIFICAT), latency 10s.
  Timeout / „not_me" → acțiune out-of-band (sună numărul real salvat).
- Verificatorul NU poate activa supraveghere; doar protejatul revocă.
- Second opinion: share_level implicit metadata_only; full doar cu consimțământ.
- Zero conținut brut server-side: doar redacted_summary structurat.
"""
from __future__ import annotations

import uuid
from dataclasses import asdict, dataclass, field
from time import time
from typing import Any, Dict, Optional

PING_LATENCY_TARGET_S = 10

_VALID_SHARE_LEVELS = ("metadata_only", "redacted_excerpt", "full_with_consent")

# Acțiune out-of-band: clientul completează tel: cu numărul REAL salvat
# (serverul nu stochează numere brute — doar tipul acțiunii).
_OUT_OF_BAND_ACTION: Dict[str, str] = {
    "type": "call_known_number",
    "channel": "out_of_band",
    "hint": "Sună persoana pe numărul pe care îl ai salvat tu, nu pe cel din apel.",
}


def ping_outcome(response: Optional[str]) -> Dict[str, Any]:
    """Mapează răspunsul verificatorului la un rezultat. Absența/timeout/necunoscut
    → PRECAUTIE (NEVERIFICAT): niciodată nu coboară riscul la CONFIRMED."""
    if response == "its_me":
        return {"status": "CONFIRMED", "verified": True}
    if response == "not_me":
        return {"status": "REJECTED", "verified": False,
                "recommended_action": dict(_OUT_OF_BAND_ACTION)}
    # timeout, None, sau orice altceva → PRECAUTIE + acțiune out-of-band
    return {"status": "PRECAUTIE", "verified": False,
            "recommended_action": dict(_OUT_OF_BAND_ACTION)}


def normalize_share_level(level: Optional[str], *, consent: bool) -> tuple[str, bool]:
    """Întoarce (share_level efectiv, downgraded?). Default metadata_only;
    full_with_consent fără consimțământ explicit → coboară la metadata_only."""
    chosen = level if level in _VALID_SHARE_LEVELS else "metadata_only"
    if chosen == "full_with_consent" and not consent:
        return "metadata_only", True
    return chosen, False


@dataclass
class CircleLink:
    link_id: str
    protected_user_id: str
    verifier_user_id: str
    consent: str
    revocable: bool = True
    active: bool = True
    created_at: float = field(default_factory=time)
    revoked_at: Optional[float] = None

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        # Invariant §6 explicit în contract: link-ul nu dă supraveghere.
        d["verifier_can_read_content"] = False
        d["verifier_can_surveil"] = False
        return d


@dataclass
class VerificationPing:
    ping_id: str
    link_id: str
    claim: str
    payload_class: str = "metadata_only"
    default_on_timeout: str = "PRECAUTIE"
    latency_target_s: int = PING_LATENCY_TARGET_S
    status: str = "pending"  # pending | resolved
    verifier_response: Optional[str] = None
    created_at: float = field(default_factory=time)
    resolved_at: Optional[float] = None

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["raw_stored"] = False
        return d


@dataclass
class GuardianSecondOpinion:
    request_id: str
    case_id: str
    protected_user_id: str
    guardian_user_id: str
    share_level: str
    redacted_summary: Dict[str, Any]
    share_downgraded: bool = False
    status: str = "pending"  # pending | answered | expired
    created_at: float = field(default_factory=time)
    resolved_at: Optional[float] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class CircleStore:
    """Store in-memory pentru Cercul. Persistarea în Supabase (§9) e opțională și
    se face la nivel de endpoint — logica determinist-auditabilă stă aici."""

    def __init__(self) -> None:
        self._links: Dict[str, CircleLink] = {}
        self._pings: Dict[str, VerificationPing] = {}
        self._opinions: Dict[str, GuardianSecondOpinion] = {}

    # ─── Pairing ───────────────────────────────────────────────────────────
    def pair(self, *, protected_id: str, verifier_id: str, consent: str = "explicit") -> CircleLink:
        if consent != "explicit":
            raise ValueError("circle pairing requires explicit consent")
        if not protected_id or not verifier_id:
            raise ValueError("protected_id and verifier_id are required")
        link = CircleLink(
            link_id="cl_" + uuid.uuid4().hex[:16],
            protected_user_id=protected_id,
            verifier_user_id=verifier_id,
            consent=consent,
        )
        self._links[link.link_id] = link
        return link

    def get_link(self, link_id: str) -> Optional[CircleLink]:
        return self._links.get(link_id)

    def revoke(self, link_id: str, *, by_user: str) -> bool:
        link = self._links.get(link_id)
        if link is None:
            raise KeyError(link_id)
        # Doar protejatul poate revoca — verificatorul nu controlează relația.
        if by_user != link.protected_user_id:
            raise PermissionError("only the protected user can revoke the circle link")
        link.active = False
        link.revoked_at = time()
        return True

    # ─── Ping / respond ──────────────────────────────────────────────────────
    def create_ping(self, link_id: str, *, claim: str = "caller_claims_to_be_verifier") -> VerificationPing:
        link = self._links.get(link_id)
        if link is None:
            raise KeyError(link_id)
        if not link.active:
            raise ValueError("circle link is revoked/inactive")
        ping = VerificationPing(
            ping_id="vp_" + uuid.uuid4().hex[:16],
            link_id=link_id,
            claim=claim,
        )
        self._pings[ping.ping_id] = ping
        return ping

    def get_ping(self, ping_id: str) -> Optional[VerificationPing]:
        return self._pings.get(ping_id)

    def respond(self, ping_id: str, response: str) -> Dict[str, Any]:
        ping = self._pings.get(ping_id)
        if ping is None:
            raise KeyError(ping_id)
        ping.verifier_response = response
        ping.status = "resolved"
        ping.resolved_at = time()
        return ping_outcome(response)

    def resolve_timeout(self, ping_id: str) -> Dict[str, Any]:
        ping = self._pings.get(ping_id)
        if ping is None:
            raise KeyError(ping_id)
        ping.verifier_response = "timeout"
        ping.status = "resolved"
        ping.resolved_at = time()
        return ping_outcome("timeout")

    # ─── Guardian second opinion ─────────────────────────────────────────────
    def second_opinion(
        self,
        *,
        case_id: str,
        protected_id: str,
        guardian_id: str,
        redacted_summary: Optional[Dict[str, Any]] = None,
        share_level: Optional[str] = None,
        consent: bool = False,
    ) -> GuardianSecondOpinion:
        level, downgraded = normalize_share_level(share_level, consent=consent)
        so = GuardianSecondOpinion(
            request_id="go_" + uuid.uuid4().hex[:16],
            case_id=case_id,
            protected_user_id=protected_id,
            guardian_user_id=guardian_id,
            share_level=level,
            share_downgraded=downgraded,
            redacted_summary=dict(redacted_summary or {}),
        )
        self._opinions[so.request_id] = so
        return so


# Singleton folosit de endpoint-uri (per-proces; persistarea durabilă = §9 Supabase).
circle_store = CircleStore()
