"""Radarul — hot-cache local pentru CallScreening (MoatOS §7, PR-5).

Construiește payload-ul pe care device-ul îl sincronizează (delta) și îl
folosește OFFLINE în onScreenCall (zero network pe device în timpul apelului).

Reguli de aur:
- Produce DOAR date (avertismente de campanie + reputație numere pe buckets).
  Verdictul rămâne la verdict_gate; aici nu se decide nimic.
- ZERO număr de telefon brut server-side: reputația trece prin hash-urile primite
  de la device (HMAC client-side) + prefixe HMAC din campanii; bucket în loc de count.
- Spoofing pe mobil trece prin definiție → preemptiv DOAR pe campanii cunoscute
  (cold-start orb, asumat onest).
"""
from __future__ import annotations

import os
import re
import time
from typing import Any, Dict, List, Optional

HOT_CACHE_TTL_MINUTES = int(os.getenv("RADAR_HOT_CACHE_TTL_MINUTES", "60"))
_SHA256_HEX_RE = re.compile(r"^[0-9a-f]{64}$", re.IGNORECASE)

# Avertismente RO per arc-family (text scurt, acționabil, fără jargon).
_FAMILY_WARNINGS: Dict[str, Dict[str, str]] = {
    "CONV_BANK_SAFE_ACCOUNT": {
        "title": "Apeluri care pretind banca/BNR/Poliția",
        "body": "Nu muta banii într-un cont „sigur”. Închide și sună banca la numărul de pe card.",
    },
    "CONV_COURIER_TAX_CARD": {
        "title": "Curier fals care cere o taxă",
        "body": "Curierii reali nu cer date de card prin SMS/apel. Verifică în aplicația oficială a curierului.",
    },
    "CONV_INVESTMENT_DEEPFAKE": {
        "title": "Investiție „garantată” cu o personalitate cunoscută",
        "body": "Personalitățile publice nu recomandă investiții prin apel/reclamă. Nu depune bani.",
    },
    "CONV_TECH_SUPPORT_REMOTE": {
        "title": "Suport tehnic fals (Microsoft/Google)",
        "body": "Nu instala AnyDesk/TeamViewer la cererea unui apel. Companiile reale nu sună așa.",
    },
    "CONV_FAMILY_NEW_PHONE": {
        "title": "Apel: sunt copilul tău, am alt număr",
        "body": "Sună persoana la numărul vechi salvat înainte să trimiți bani.",
    },
    "CONV_WHATSAPP_TAKEOVER": {
        "title": "Cont WhatsApp compromis",
        "body": "Nu trimite coduri primite prin SMS. Activează verificarea în doi pași.",
    },
}
_DEFAULT_WARNING = {
    "title": "Apel de la un număr semnalat",
    "body": "Numărul a fost raportat în campanii recente. Nu oferi date sau bani; verifică pe canal oficial.",
}


def hot_warning_for_family(family: Optional[str]) -> Dict[str, str]:
    return dict(_FAMILY_WARNINGS.get(family or "", _DEFAULT_WARNING))


def reputation_bucket(report_count: int) -> str:
    """Buckets non-PII (nu expunem count exact)."""
    try:
        n = int(report_count)
    except (TypeError, ValueError):
        n = 0
    if n <= 0:
        return "0"
    if n <= 4:
        return "1-4"
    if n <= 24:
        return "5-24"
    if n <= 99:
        return "25-99"
    return "100+"


def reputation_status(report_count: int, risk_level: Optional[str] = None) -> str:
    """Conservative status for offline call screening.

    Community reports normally warn only. Blocking is reserved for explicit
    server-side block status or high-volume/high-risk phone reports.
    """
    normalized_risk = str(risk_level or "").strip().lower()
    if normalized_risk in {"blocked", "dangerous_blocked"}:
        return "blocked"
    try:
        n = int(report_count)
    except (TypeError, ValueError):
        n = 0
    if n >= 100:
        return "blocked"
    if n >= 25 and normalized_risk in {"high", "critical", "dangerous"}:
        return "blocked"
    return "reported"


def _now_iso() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def build_hot_cache(
    campaign_store: Any,
    *,
    reports: Optional[List[Dict[str, Any]]] = None,
    number_reputation_items: Optional[List[Dict[str, Any]]] = None,
    since: Optional[float] = None,
) -> Dict[str, Any]:
    """Asamblează payload-ul hot-cache.

    `campaign_store` = CampaignStore (folosim .active(since)).
    `reports` = listă de rapoarte comunitare deja hash-uite client-side
                ({hash, report_count, family}). Server-ul NU vede numărul brut.
    """
    now = time.time()
    since_ts = since if since is not None else (now - 7 * 86400)

    active = campaign_store.active(since=since_ts) if campaign_store is not None else []
    hot_campaigns: List[Dict[str, Any]] = []
    for intel in active:
        warning = hot_warning_for_family(intel.family)
        iocs = intel.iocs if isinstance(intel.iocs, dict) else {}
        hot_campaigns.append(
            {
                "campaign_id": intel.intel_id,
                "family": intel.family,
                "warning_title": warning["title"],
                "warning_body": warning["body"],
                "regions": list(intel.regions_hint or ["RO"]),
                "phone_hash_prefixes": list(iocs.get("phone_hash_prefixes") or []),
                "confidence": intel.evidence_quality,
            }
        )

    number_reputation: List[Dict[str, Any]] = []
    seen_phone_hashes: set[str] = set()
    for r in reports or []:
        if str(r.get("target_type") or "").strip().lower() != "phone":
            continue
        phone_hash = str(r.get("hash") or "").strip().lower()
        if not _SHA256_HEX_RE.fullmatch(phone_hash):
            continue
        seen_phone_hashes.add(phone_hash)
        number_reputation.append(
            {
                "phone_hash": phone_hash,
                "status": reputation_status(r.get("report_count", 0), r.get("risk_level")),
                "family": r.get("family"),
                "bucket_count": reputation_bucket(r.get("report_count", 0)),
            }
        )
    for item in number_reputation_items or []:
        phone_hash = str(item.get("phone_hash") or item.get("target_hash") or "").strip().lower()
        if not _SHA256_HEX_RE.fullmatch(phone_hash) or phone_hash in seen_phone_hashes:
            continue
        status = str(item.get("status") or "reported").strip().lower()
        if status not in {"reported", "blocked", "dangerous", "high_confidence"}:
            status = "reported"
        seen_phone_hashes.add(phone_hash)
        number_reputation.append(
            {
                "phone_hash": phone_hash,
                "status": status,
                "family": item.get("family"),
                "bucket_count": item.get("bucket_count") or reputation_bucket(item.get("report_count", 0)),
            }
        )

    return {
        "generated_at": _now_iso(),
        "ttl_minutes": HOT_CACHE_TTL_MINUTES,
        "hot_campaigns": hot_campaigns,
        "number_reputation": number_reputation,
    }
