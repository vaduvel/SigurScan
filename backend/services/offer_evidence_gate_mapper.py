"""Offer EvidenceGate mapper — traduce faptele ofertei în Evidence Bundle v2 și
alimentează ACELAȘI verdict_gate.reduce_verdict. NU un motor de verdict paralel.

Mapare (vocabular existent al gate-ului):
  identity        <- emitent (ANAF) + brand (impersonare / activ / nume)
  request         <- cererea sensibilă (card / crypto / id_document / transfer) + canal
  semantic_review <- familie OP + coerență + impersonare
  providers       <- integritate document (IBAN/coerență); fără threat-intel web în PR2
  resolution      <- not_required (oferta nu cere rezolvare URL în PR2)

Filosofia verdictului (neclintită): DANGEROUS = COMBINAȚIE. Lipsă în registru =
SUSPECT, nu auto-DANGEROUS. CUI valid ≠ ofertă reală. ANAF checked=False = UNKNOWN
(nu coboară la SAFE, nu urcă la DANGEROUS). Niciodată „100% safe". Determinist:
aceleași fapte → același verdict.
"""
from __future__ import annotations

import hashlib
import json
import re
from typing import TYPE_CHECKING, Any, Dict, List, Optional

from services import offer_signals as S
from services.invoice_coherence import CoherenceResult
from services.invoice_readiness_gate import ReadinessGateResult, ReadinessState
from services.offer_entity_verifier import OfferEntityResult
from services.registry_verification.models import RegistryStatus, RegistryVerificationResult
from services.verdict_gate import verdict as reduce_verdict

if TYPE_CHECKING:
    from services.offer_parser import OfferFields

# Platforme oficiale: plata în platformă NU e canal greșit.
_OFFICIAL_PLATFORMS = {
    "OLX", "Booking", "Airbnb", "VRBO", "eMAG", "Eventim",
    "iaBilet", "Ticketmaster", "Facebook Marketplace", "Autovit",
}
_FAMILY_CONF_FLOOR = 0.35

# Context de tranzacție (plată / contract / credit / rezervare). Fără el, o cerere
# sensibilă (ex. CI/CNP singur) NU e pe canal greșit → rămâne SUSPECT, nu DANGEROUS.
# DANGEROUS apare DOAR în combinație: sensibil hard + context (canal greșit).
_PAYMENT_CONTEXT = re.compile(
    r"\b(plat[ăaiț]|pl[ăa]te[șs]?t?e?|avans|transfer|factur|proform|contract|credit|"
    r"[îi]mprumut|rezervar|garan[țt]i|depozit|abonament|iban|cont(?:ul)?\b)",
    re.IGNORECASE,
)


def _sensitive(fields: "OfferFields", signals: List[str]) -> str:
    if S.OFFER_REMOTE_ACCESS_REQUEST in signals:
        return "remote"
    if S.OFFER_ID_DOCUMENT_REQUEST in signals:
        return "id_document"
    if S.OFFER_CARD_CVV_OTP_REQUEST in signals:
        return "card"
    if S.OFFER_PAYMENT_METHOD_CRITICAL in signals or S.OFFER_HAS_CRYPTO_WALLET in signals:
        return "crypto"
    if (
        S.OFFER_PAYMENT_METHOD_HIGH_RISK in signals
        or S.OFFER_OFF_PLATFORM_PAYMENT in signals
        or fields.iban
        or fields.payment_beneficiary
        or fields.total is not None
    ):
        return "transfer"
    return "none"


def _channel(fields: "OfferFields", signals: List[str], sensitive: str, text: str) -> str:
    if S.OFFER_OFF_PLATFORM_PAYMENT in signals:
        return "whatsapp"
    if fields.platform_name in _OFFICIAL_PLATFORMS:
        return "platform"  # nu e în WRONG_CHANNELS
    # Bug#7: un preț (fields.total) NU e dovadă de canal greșit — o ofertă
    # legitimă (OP-03/OP-07) menționează aproape mereu un preț. Contextul de
    # tranzacție trebuie să vină din canal/cont de plată concret, nu din simplul
    # fapt că oferta are o sumă.
    has_context = bool(
        fields.iban
        or fields.payment_beneficiary
        or S.OFFER_PAYMENT_METHOD_HIGH_RISK in signals
        or S.OFFER_PAYMENT_METHOD_CRITICAL in signals
        or (text and _PAYMENT_CONTEXT.search(text))
    )
    # Off-rails DOAR cu context de tranzacție (plată/contract/credit/rezervare).
    # Altfel canal „unknown" → o cerere sensibilă singură rămâne SUSPECT.
    return "unofficial_site" if has_context else "unknown"


def _identity(entity: OfferEntityResult, *, readiness_ready: bool) -> tuple[str, str]:
    if entity.brand_impersonation:
        return "lookalike", "Brand pretins, dar CUI/IBAN/domeniu nealiniat"
    if entity.has_cui:
        if not entity.cui_checked:
            return "unknown", "ANAF indisponibil — emitent neverificat"
        if not entity.cui_exists and entity.claims_company:
            return "unrelated", "CUI inexistent în ANAF deși pretinde firmă"
        if entity.cui_exists and not entity.cui_active:
            return "unrelated", "Firmă inactivă în ANAF"
        if entity.cui_exists and entity.cui_active:
            if entity.name_matches is False:
                return "unrelated", "Numele emitentului nu corespunde denumirii ANAF"
            verified = entity.name_matches is True or (
                bool(entity.claimed_brand) and entity.brand_cui_matches and entity.brand_iban_matches
            )
            if verified and readiness_ready:
                return ("official" if entity.claimed_brand else "coherent"), "Emitent verificat și activ în ANAF"
            return "unknown", "Emitent activ, dar date insuficiente pentru un verdict sigur"
    return "unknown", "Emitent neidentificat"


def _registry_no_match_alert(
    registry_results: List[RegistryVerificationResult], entity: OfferEntityResult
) -> bool:
    """NO_MATCH dintr-un registru consultat, pentru o entitate care pretinde firmă,
    NEconfirmată de ANAF. Doar contribuie la semantic_review; DANGEROUS apare numai
    în combinație (plată + canal riscant), prin reduce_verdict. Dacă ANAF (sursă
    live, mai puternică) a confirmat firma, un snapshot incomplet nu o subminează.
    """
    anaf_confirmed = entity.has_cui and entity.cui_checked and entity.cui_exists
    if anaf_confirmed or not entity.claims_company:
        return False
    return any(
        r.checked and r.status == RegistryStatus.NO_MATCH for r in registry_results
    )


def _semantic_risk(
    signals: List[str],
    entity: OfferEntityResult,
    coherence: Optional[CoherenceResult],
    family_code: Optional[str],
    family_confidence: float,
    registry_no_match: bool = False,
    suppress_brand_impersonation: bool = False,
) -> str:
    high = (
        (entity.brand_impersonation and not suppress_brand_impersonation)
        or (entity.has_cui and entity.cui_checked and not entity.cui_exists and entity.claims_company)
        or (entity.has_cui and entity.cui_exists and not entity.cui_active)
        or (S.OFFER_IBAN_INVALID_STRUCTURE in signals and S.OFFER_PRICE_URGENCY in signals)
        or S.OFFER_PAYMENT_METHOD_CRITICAL in signals
        or (
            S.OFFER_UPFRONT_FEE_REQUEST in signals
            and (
                S.OFFER_OFF_PLATFORM_PAYMENT in signals
                or S.OFFER_GUARANTEED_PROFIT in signals
                or (family_code or "OP-00") in {"OP-08", "OP-09"}
            )
        )
        or registry_no_match
    )
    if high:
        return "high"
    medium = (
        (S.OFFER_FAMILY_CLASSIFIED in signals and (family_code or "OP-00") not in ("OP-00", "OP-08")
         and family_confidence >= _FAMILY_CONF_FLOOR)
        or (coherence is not None and not coherence.all_ok)
        or S.OFFER_PRICE_URGENCY in signals
        or S.OFFER_PAYMENT_METHOD_HIGH_RISK in signals
        or S.OFFER_GUARANTEED_PROFIT in signals
    )
    if medium:
        return "medium"
    return "low"


def _providers(signals: List[str], coherence: Optional[CoherenceResult]) -> Dict[str, Any]:
    suspicious = S.OFFER_IBAN_INVALID_STRUCTURE in signals or (
        coherence is not None and (not coherence.totals_match or not coherence.dates_plausible)
    )
    # Fără threat-intel web în PR2 → niciodată „malicious" aici (PR6 adaugă web).
    return {"verdict": "suspicious" if suspicious else "clean", "completeness": True, "hits": []}


def build_offer_bundle(
    fields: "OfferFields",
    *,
    signals: List[str],
    entity: OfferEntityResult,
    coherence: Optional[CoherenceResult],
    family_code: Optional[str],
    family_confidence: float = 0.0,
    readiness: Optional[ReadinessGateResult] = None,
    redacted_text: Optional[str] = None,
    registry_results: Optional[List[RegistryVerificationResult]] = None,
    cross_scan_knowledge: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Construiește Evidence Bundle v2 din faptele ofertei. Pur, determinist."""
    registry_results = list(registry_results or [])
    ready = readiness is not None and readiness.state == ReadinessState.READY
    text = redacted_text if redacted_text is not None else (fields.raw_text or "")
    sensitive = _sensitive(fields, signals)
    channel = _channel(fields, signals, sensitive, text)
    identity_status, identity_reason = _identity(entity, readiness_ready=ready)
    cross_scan_knowledge = dict(cross_scan_knowledge or {})
    never_asks = cross_scan_knowledge.get("brand_never_asks")
    violated_never_asks = []
    if isinstance(never_asks, dict):
        violated_never_asks = list(never_asks.get("violated_never_asks") or [])
    payment_destinations = cross_scan_knowledge.get("payment_destinations")
    official_payment_match = any(
        isinstance(item, dict)
        and item.get("matched") is True
        and item.get("brand_matches") is True
        and item.get("can_contribute_to_safe") is True
        for item in (payment_destinations if isinstance(payment_destinations, list) else [])
    )
    fraud_flags = set(cross_scan_knowledge.get("fraud_flags") or [])
    destination_mismatch = "PAYMENT_DESTINATION_BRAND_MISMATCH" in fraud_flags
    unknown_destination = "UNKNOWN_PAYMENT_DESTINATION" in fraud_flags
    semantic = _semantic_risk(
        signals, entity, coherence, family_code, family_confidence,
        registry_no_match=_registry_no_match_alert(registry_results, entity),
        suppress_brand_impersonation=official_payment_match and not destination_mismatch,
    )
    if violated_never_asks or destination_mismatch:
        identity_status = "lookalike"
        identity_reason = "Brand pretins, dar cererea de plată/date contrazice politica oficială"
    elif official_payment_match and identity_status == "lookalike":
        identity_status = "unknown"
        identity_reason = "Brand pretins cu destinație de plată oficială, dar fără proveniență completă"
    elif unknown_destination and identity_status == "official":
        identity_status = "unknown"
        identity_reason = "IBAN valid, dar destinația de plată nu este confirmată pentru brand"

    bundle: Dict[str, Any] = {
        "schema": "sigurscan_evidence_bundle_v2",
        "input": {"type": "offer", "redacted_text": str(text)[:4000]},
        "resolution": {"status": "not_required", "completeness": True},
        "providers": _providers(signals, coherence),
        "identity": {
            "status": identity_status,
            "claimed_brand": entity.claimed_brand or "Nespecificat",
            "reason": identity_reason,
            "tld_suspicious": False,
            "completeness": True,
        },
        "request": {"sensitive": sensitive, "channel": channel, "completeness": True},
        "semantic_review": {"status": "done", "risk_class": semantic, "completeness": True},
        "context": {
            "offer_family": family_code or "OP-00",
            "offer_signals": list(signals),
            # Dovezi registru: context, nu verdict. MATCH nu înseamnă „sigur";
            # NO_MATCH/indisponibil nu înseamnă fraudă. Sortat = determinist.
            "registry": [
                r.to_bundle_dict()
                for r in sorted(registry_results, key=lambda r: r.source_id)
            ],
            "cross_scan_knowledge": cross_scan_knowledge,
        },
    }
    if violated_never_asks:
        bundle["identity"]["violated_never_asks"] = violated_never_asks
    canonical = json.dumps(bundle, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    bundle["evidence_hash"] = "sha256:" + hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    return bundle


def evaluate_offer_verdict(
    fields: "OfferFields",
    *,
    signals: List[str],
    entity: OfferEntityResult,
    coherence: Optional[CoherenceResult],
    family_code: Optional[str],
    family_confidence: float = 0.0,
    readiness: Optional[ReadinessGateResult] = None,
    redacted_text: Optional[str] = None,
    registry_results: Optional[List[RegistryVerificationResult]] = None,
    cross_scan_knowledge: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Bundle ofertă → reduce_verdict (gate-ul unic). Întoarce {bundle, gate}."""
    bundle = build_offer_bundle(
        fields,
        signals=signals,
        entity=entity,
        coherence=coherence,
        family_code=family_code,
        family_confidence=family_confidence,
        readiness=readiness,
        redacted_text=redacted_text,
        registry_results=registry_results,
        cross_scan_knowledge=cross_scan_knowledge,
    )
    return {"bundle": bundle, "gate": reduce_verdict(bundle)}
