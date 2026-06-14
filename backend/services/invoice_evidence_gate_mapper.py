"""InvoiceTruth — fuziunea pilonilor facturii într-un EvidenceBundle pentru
ACELAȘI verdict_gate (un singur judecător), simetric cu offer_evidence_gate_mapper.

NU e un motor de verdict paralel. Pilonii (issuer/ANAF, payment-destination/IBAN,
coherence, channel, fraud-signals) sunt deja calculați în scan_invoice; aici doar
îi traducem în secțiunile de bundle și chemăm `reduce_verdict`. Un singur creier.
"""
from __future__ import annotations

import hashlib
import json
import re
from typing import Any, Dict, Optional, Tuple

from services.verdict_gate import verdict as reduce_verdict


def _provider_section(result) -> Dict[str, Any]:
    anaf = result.anaf_cui_check if result else None
    iban_result = result.iban_valid if result else None
    coherence = result.coherence if result else None

    anaf_status, anaf_reasons = "clean", []
    if anaf:
        if anaf.get("checked") is False:
            anaf_status, _ = "unknown", anaf_reasons.append("ANAF temporar indisponibil")
        elif not anaf.get("exists"):
            anaf_status, _ = "unknown", anaf_reasons.append("CUI negăsit în registru")
        elif not anaf.get("activ"):
            anaf_status, _ = "malicious", anaf_reasons.append("Firmă inactivă")

    iban_status, iban_reasons = "clean", []
    if iban_result and not iban_result.valid_structure:
        iban_status = "suspicious"
        iban_reasons.append("IBAN invalid MOD-97")

    coherence_status, coherence_reasons = "clean", []
    if coherence:
        if not coherence.totals_match:
            coherence_status = "suspicious"
            coherence_reasons.append("Totalul nu corespunde cu subtotal+TVA")
        if not coherence.dates_plausible:
            coherence_status = "suspicious"
            coherence_reasons.append("Date incoerente (scadența înaintea emiterii)")

    section = {
        "verdict": "malicious" if anaf_status == "malicious"
        else "suspicious" if "suspicious" in (iban_status, coherence_status) else "clean",
        "anaf": {"status": anaf_status, "verdict": anaf_status, "reasons": anaf_reasons, "completeness": anaf is not None},
        "iban": {"status": iban_status, "verdict": iban_status, "reasons": iban_reasons, "completeness": iban_result is not None},
        "coherence": {"status": coherence_status, "verdict": coherence_status, "reasons": coherence_reasons, "completeness": coherence is not None},
    }
    if anaf_reasons:
        section.setdefault("reasons", []).extend(anaf_reasons)
    return section


def build_invoice_bundle(result, redacted_text: str = "") -> Dict[str, Any]:
    """Construiește bundle-ul v2 din pilonii facturii. Pur (fără rețea)."""
    brand_match = result.brand_match if result else None
    fields = result.fields if result else None
    readiness = result.readiness if result else None
    coherence = result.coherence if result else None

    readiness_blocks_safe = (readiness and readiness.blocks_safe_verdict) or False
    impersonation_risk = (brand_match and brand_match.impersonation_risk) or False
    cui_matches = (brand_match and brand_match.cui_matches) or False
    iban_matches = (brand_match and brand_match.iban_matches) or False
    claimed_brand = (result.brand if result else None) or "Nespecificat"

    # Piloni de semnale de fraudă (din scan_invoice) — intră ca SEMNALE, gate-ul decide.
    fraud_flags = list(result.fraud_flags) if result else []
    beneficiary_mismatch_flag = "BENEFICIARY_PERSON_MISMATCH" in fraud_flags
    weak_fraud_flag = any(
        f in fraud_flags
        for f in ("FOREIGN_IBAN", "ACCOUNT_CHANGE_LANGUAGE", "IBAN_CHANGED_VS_HISTORY")
    )
    strong_fraud_combo = ("FOREIGN_IBAN" in fraud_flags) and ("ACCOUNT_CHANGE_LANGUAGE" in fraud_flags)

    provider_section = _provider_section(result)
    # Registru negativ = dovadă externă HARD (ca un provider „malicious"): IBAN
    # raportat anterior ca fraudă → verdict_gate Rule 1 → PERICULOS determinist.
    if "REPORTED_FRAUD_IBAN" in fraud_flags:
        provider_section["verdict"] = "malicious"
        provider_section["negative_iban_registry"] = {
            "status": "malicious", "verdict": "malicious", "severity": "high",
            "consulted": True, "reasons": ["IBAN raportat ca fraudă"],
        }

    # Identity (issuer/destination): brand match + destinație nealiniată.
    if beneficiary_mismatch_flag:
        identity_status = "lookalike"
        identity_reason = "Beneficiarul plății nu corespunde firmei emitente"
    elif impersonation_risk:
        identity_status = "lookalike"
        identity_reason = "CUI/IBAN nealiniat cu brandul declarat"
    elif cui_matches and iban_matches:
        identity_status = "official"
        identity_reason = "Brand confirmat prin CUI și IBAN"
    elif claimed_brand != "Nespecificat":
        identity_status = "unknown"
        identity_reason = "Brand declarat dar neverificat complet"
    else:
        identity_status = "unknown"
        identity_reason = "Brand nedeclarat"

    identity_section = {
        "status": identity_status,
        "claimed_brand": claimed_brand,
        "domain_reputation": "established" if (brand_match and brand_match.domain_matches) else "unknown",
        "reason": identity_reason,
        # Completeness = am putut evalua. Un semnal de fraudă clar ÎNSEAMNĂ că am
        # evaluat (și am găsit o problemă) — altfel Rule 4 „insufficient_evidence"
        # ar înghiți semnalul de destinație la UNVERIFIED pe facturi fără brand.
        "completeness": (brand_match is not None) or beneficiary_mismatch_flag or weak_fraud_flag,
    }

    request_section = {"sensitive": "transfer", "channel": "invoice", "completeness": True}

    # Semantic: nivelurile „medium" (readiness/fraudă slabă) se aplică întâi, iar
    # „high" (impersonare/beneficiar/combo BEC) se setează ULTIMUL ca să câștige —
    # un semnal de fraudă clar nu trebuie coborât de „date insuficiente".
    semantic_risk, semantic_reasons = "low", []
    if readiness_blocks_safe:
        semantic_risk = "medium"
        semantic_reasons.append("Date insuficiente")
    if weak_fraud_flag:
        semantic_risk = "medium"
        semantic_reasons.append("Semnal de fraudă pe destinația plății")
    if impersonation_risk or beneficiary_mismatch_flag or strong_fraud_combo:
        semantic_risk = "high"
        semantic_reasons.append("Impersonation risk detected")
    if coherence and not coherence.all_ok:
        semantic_reasons.append("Document incoherent")

    semantic_section = {
        "status": "done",
        "risk_class": semantic_risk,
        "reasons": semantic_reasons,
        "completeness": readiness is not None,
    }

    bundle = {
        "schema": "sigurscan_evidence_bundle_v2",
        "input": {"type": "invoice", "redacted_text": str(redacted_text or "")[:4000]},
        "resolution": {"status": "not_required", "completeness": True},
        "providers": provider_section,
        "identity": identity_section,
        "request": request_section,
        "semantic_review": semantic_section,
        "context": {
            "urgency": bool(re.search(r"\b(urgent|azi|acum|24\s*de\s*ore|ultima|expir[ăa])\b", str(redacted_text or ""), re.IGNORECASE)),
            "passive_payment": bool(re.search(r"\b(plata abonamentului|se va efectua automat plata|factur[ăa])\b", str(redacted_text or ""), re.IGNORECASE)),
            "apk_or_remote_mention": False,
        },
    }
    canonical = json.dumps(bundle, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    bundle["evidence_hash"] = "sha256:" + hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    return bundle


def evaluate_invoice_verdict(result, redacted_text: str = "") -> Tuple[Dict[str, Any], Dict[str, Any]]:
    """Fuziune → ACELAȘI verdict_gate. Întoarce (bundle, gate_result)."""
    bundle = build_invoice_bundle(result, redacted_text)
    return bundle, reduce_verdict(bundle)
