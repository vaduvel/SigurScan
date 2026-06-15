from __future__ import annotations

import hmac
import os
import re
import time
from typing import Any, List, Optional, TYPE_CHECKING
from dataclasses import dataclass, field
from services.invoice_parser import parse_invoice, InvoiceFields
from services.iban_validator import validate_iban, IbanResult
from services.invoice_coherence import CoherenceResult, check_coherence
from services.invoice_readiness_gate import evaluate_readiness, ReadinessGateResult
from services.brand_registry import detect_claimed_brand, match_brand, BrandMatchResult
from services.anaf_cui import check_cui

if TYPE_CHECKING:
    from services.offer_parser import OfferFields
    from services.offer_entity_verifier import OfferEntityResult


CACHE_TTL = 43200  # 12 hours
_cui_cache: dict[str, tuple[float, dict]] = {}
_verdict_cache: dict[str, tuple[float, "InvoiceScanResult"]] = {}

def _cache_hmac_key() -> bytes:
    key = os.getenv("INVOICE_CACHE_HMAC_KEY")
    if not key:
        raise RuntimeError("INVOICE_CACHE_HMAC_KEY must be configured from Secret Manager/env")
    return key.encode()


def _hmac_digest(data: str) -> str:
    return hmac.new(_cache_hmac_key(), data.encode(), "sha256").hexdigest()


def _cache_key(fields) -> str:
    raw = fields.raw_text or f"{fields.cui}|{fields.iban}|{fields.total}|{fields.data_emitere}|{fields.nr_factura}"
    return _hmac_digest(raw)


def _cui_cache_key(cui: str) -> str:
    return "cui:" + _hmac_digest(cui)


def _get_cached_cui(cui: str) -> dict | None:
    key = _cui_cache_key(cui)
    entry = _cui_cache.get(key)
    if entry and (time.time() - entry[0]) < CACHE_TTL:
        return entry[1]
    if entry:
        del _cui_cache[key]
    return None


def _set_cached_cui(cui: str, data: dict):
    key = _cui_cache_key(cui)
    _cui_cache[key] = (time.time(), data)


def _get_cached_verdict(fields) -> InvoiceScanResult | None:
    key = _cache_key(fields)
    entry = _verdict_cache.get(key)
    if entry and (time.time() - entry[0]) < CACHE_TTL:
        cached = entry[1]
        cached._from_cache = True
        return cached
    if entry:
        del _verdict_cache[key]
    return None


def _set_cached_verdict(fields, result: "InvoiceScanResult"):
    key = _cache_key(fields)
    result._from_cache = False
    _verdict_cache[key] = (time.time(), result)


@dataclass
class InvoiceScanResult:
    raw_text: str
    fields: InvoiceFields
    readiness: ReadinessGateResult
    coherence: CoherenceResult
    iban_valid: Optional[IbanResult] = None
    brand: Optional[str] = None
    brand_match: Optional[BrandMatchResult] = None
    anaf_cui_check: Optional[dict] = None
    payment_destination: Optional[dict] = None
    error: Optional[str] = None
    warnings: list = field(default_factory=list)
    fraud_flags: list[str] = field(default_factory=list)
    from_cache: bool = False


_DIACRITICS = str.maketrans("ăâîșşțţ", "aaisstt")
_COMPANY_MARKERS = re.compile(
    r"\b(s\.?\s?r\.?\s?l|s\.?\s?a|s\.?\s?c|p\.?\s?f\.?\s?a|i\.?\s?i|s\.?\s?n\.?\s?c|"
    r"societate|societatea|asociat|fundat|regia|intreprindere|cooperativa|cabinet|"
    r"sucursala|gmbh|ltd|llc|inc|s\.?p\.?a)\b",
    re.IGNORECASE,
)
_ACCOUNT_CHANGE_RE = re.compile(
    r"(am\s+schimbat\s+(contul|banca|iban)|cont(ul)?\s+(nou|s-?a\s+schimbat|modificat|actualizat)|"
    r"noul\s+(nostru\s+)?(cont|iban)|iban[-\s]*(ul)?\s*(nou|s-?a\s+(schimbat|modificat))|"
    r"schimbare\s+(de\s+)?cont\s+bancar|date(le)?\s+bancare\s+(au\s+fost\s+)?(modificat|actualizat|schimbat)|"
    r"changed\s+(our\s+)?(bank\s+account|account\s+details|iban)|new\s+(bank\s+)?account)",
    re.IGNORECASE,
)
_PRESSURE_RE = re.compile(
    r"(astazi|imediat|in\s*24\s*(de\s*)?ore|ultima\s+zi|chiar\s+acum|de\s+urgenta|"
    r"altfel\s+(se\s+)?(suspend|debrans|deconect|pierde|anuleaz|sista)|debransare|"
    r"deconectare|executare\s+silita|poprire|pierdeti\s+comanda|risc(ati)?\s+(suspendare|debransare)|"
    r"evita(?:ti)?\s+(?:suspendarea|deconectarea|debransarea|penalizarile|blocarea))",
    re.IGNORECASE,
)
_NAME_STOPWORDS = {"sc", "srl", "sa", "pfa", "ii", "snc", "de", "si"}


def _txt_norm(text: str) -> str:
    return (text or "").lower().translate(_DIACRITICS)


def _foreign_ibans(all_ibans: list[str]) -> list[str]:
    output: list[str] = []
    for raw in all_ibans or []:
        norm = "".join(ch for ch in str(raw or "").upper() if ch.isalnum())
        if len(norm) >= 4 and norm[:2] != "RO" and validate_iban(norm).valid_structure:
            output.append(norm)
    return output


def _name_tokens(name: str) -> set[str]:
    cleaned = _COMPANY_MARKERS.sub(" ", _txt_norm(name))
    return {token for token in re.findall(r"[a-z]{2,}", cleaned) if token not in _NAME_STOPWORDS}


def _beneficiary_is_person(name: Optional[str]) -> bool:
    if not name or _COMPANY_MARKERS.search(name):
        return False
    tokens = re.findall(r"[A-Za-zĂÂÎȘŞȚŢăâîșşțţ]{2,}", name.strip())
    return 2 <= len(tokens) <= 4


def _beneficiary_mismatch(beneficiary: Optional[str], issuer: Optional[str]) -> bool:
    if not _beneficiary_is_person(beneficiary):
        return False
    beneficiary_tokens = _name_tokens(beneficiary or "")
    issuer_tokens = _name_tokens(issuer or "")
    if beneficiary_tokens and issuer_tokens and len(beneficiary_tokens & issuer_tokens) >= min(
        2, len(beneficiary_tokens), len(issuer_tokens)
    ):
        return False
    return True


def _anaf_identity_matches_invoice(anaf: Optional[dict], issuer: Optional[str]) -> bool:
    if not anaf or anaf.get("checked") is False or not anaf.get("exists") or not anaf.get("activ"):
        return False
    anaf_tokens = _name_tokens(str(anaf.get("denumire") or ""))
    issuer_tokens = _name_tokens(issuer or "")
    if not anaf_tokens or not issuer_tokens:
        return False
    return bool(anaf_tokens & issuer_tokens)


def _fields_to_coherence(fields: InvoiceFields) -> CoherenceResult:
    return check_coherence(
        subtotal=fields.subtotal,
        tva=fields.tva,
        total=fields.total,
        data_emitere=fields.data_emitere,
        scadenta=fields.scadenta,
    )


def _has_no_extractable_data(fields: InvoiceFields) -> bool:
    return not any([fields.cui, fields.iban, fields.emitent, fields.total is not None, fields.data_emitere])


async def scan_invoice(ocr_text: str, links: Optional[list[str]] = None) -> InvoiceScanResult:
    fields = parse_invoice(ocr_text)
    coherence = _fields_to_coherence(fields)
    if _has_no_extractable_data(fields):
        error = "Nu am putut extrage niciun câmp din document."
        return InvoiceScanResult(
            raw_text=ocr_text, fields=fields, error=error,
            readiness=evaluate_readiness(fields), coherence=coherence,
        )

    cached = _get_cached_verdict(fields)
    if cached is not None:
        return cached

    all_links = links or []
    warnings: list[str] = []
    readiness = evaluate_readiness(fields)

    iban_valid = validate_iban(fields.iban) if fields.iban else None
    if fields.iban and iban_valid and not iban_valid.valid_structure:
        warnings.append("IBAN invalid structure")

    claimed_brand = detect_claimed_brand(fields.emitent, ocr_text, all_links)
    brand_match_result: Optional[BrandMatchResult] = None
    anaf_check = None

    if claimed_brand:
        brand_match_result = match_brand(
            emitent=fields.emitent,
            text=ocr_text,
            links=all_links,
            cui=fields.cui,
            validated_iban=iban_valid,
            iban_raw=fields.iban,
        )
        if brand_match_result.impersonation_risk:
            reasons = []
            if not brand_match_result.domain_matches:
                reasons.append("domeniul nu corespunde brandului")
            if not brand_match_result.cui_matches:
                reasons.append("CUI-ul nu corespunde brandului")
            if not brand_match_result.iban_matches:
                reasons.append("IBAN-ul nu corespunde brandului")
            warnings.append(
                f"Potential impersonation of {claimed_brand}: "
                + "; ".join(reasons)
            )

    cui_check = None
    if fields.cui:
        cached_cui = _get_cached_cui(fields.cui)
        if cached_cui:
            cui_check = cached_cui
        else:
            raw_cui_check = await check_cui(fields.cui)
            cui_check = {
                "exists": raw_cui_check.exists,
                "checked": raw_cui_check.checked,
                "denumire": raw_cui_check.denumire,
                "activ": raw_cui_check.activ,
                "platitor_tva": raw_cui_check.platitor_tva,
            }
            # Bug#3: cacheaza DOAR rezultate verificate. checked=False (ANAF
            # indisponibil) NU se cacheaza, ca sa nu otraveasca verdictul 12h.
            if cui_check.get("checked"):
                _set_cached_cui(fields.cui, cui_check)
        anaf_check = cui_check
        # Bug#4: distinge "ANAF indisponibil" de "CUI inexistent".
        if not cui_check.get("checked"):
            warnings.append(
                f"Nu am putut verifica CUI {fields.cui} la ANAF acum (serviciul indisponibil)"
            )
        elif not cui_check["exists"]:
            warnings.append(f"CUI {fields.cui} inexistent în registrul ANAF (not found)")
        elif not cui_check["activ"]:
            warnings.append(f"Company {cui_check['denumire']} is inactive")

    fraud_flags: list[str] = []
    candidate_ibans = list(getattr(fields, "all_ibans", []) or [])
    if fields.iban:
        candidate_ibans.append(fields.iban)
    try:
        from services.negative_iban_registry import reported_fraud_ibans

        if reported_fraud_ibans(candidate_ibans):
            fraud_flags.append("REPORTED_FRAUD_IBAN")
            warnings.append("IBAN-ul de plată a fost raportat anterior ca fraudă.")
    except Exception:
        pass

    if _beneficiary_mismatch(getattr(fields, "payment_beneficiary", None), fields.emitent):
        fraud_flags.append("BENEFICIARY_PERSON_MISMATCH")
        warnings.append(
            "Beneficiarul plății pare o persoană fizică, nu firma emitentă. "
            "Confirmă direct cu furnizorul înainte de plată."
        )

    if _foreign_ibans(candidate_ibans):
        fraud_flags.append("FOREIGN_IBAN")
        warnings.append("IBAN-ul de plată nu este românesc; verifică destinația pe un canal oficial.")

    payment_destination = None
    if fields.iban:
        try:
            from services.payment_destination_registry import match_payment_destination

            payment_destination = match_payment_destination(
                fields.iban,
                claimed_brand=claimed_brand,
                cui=fields.cui,
            )
            if payment_destination.get("matched") and payment_destination.get("brand_matches") is False:
                fraud_flags.append("PAYMENT_DESTINATION_BRAND_MISMATCH")
                warnings.append("IBAN-ul este oficial pentru alt furnizor, nu pentru emitentul declarat.")
            elif payment_destination.get("matched") is False and iban_valid and iban_valid.valid_structure:
                if payment_destination.get("registry_has_brand_destinations") is True:
                    fraud_flags.append("UNKNOWN_PAYMENT_DESTINATION")
                    warnings.append(
                        "IBAN-ul este valid, dar nu apare între destinațiile oficiale cunoscute "
                        "pentru acest furnizor."
                    )
        except Exception:
            payment_destination = None

    normalized_text = _txt_norm(ocr_text)
    if _ACCOUNT_CHANGE_RE.search(normalized_text):
        fraud_flags.append("ACCOUNT_CHANGE_LANGUAGE")
        warnings.append("Textul anunță cont bancar/IBAN schimbat; confirmă pe un canal separat.")
    if _PRESSURE_RE.search(normalized_text):
        fraud_flags.append("PAYMENT_PRESSURE")
    if len(set(candidate_ibans)) >= 2:
        fraud_flags.append("MULTIPLE_IBANS")

    try:
        from services.offer_signals import CARD_CVV_OTP

        if CARD_CVV_OTP.search(ocr_text or ""):
            fraud_flags.append("SENSITIVE_DATA_REQUESTED")
            warnings.append("Factura cere date de card/CVV/OTP; nu completa și nu plăti.")
    except Exception:
        pass

    try:
        from services import vendor_memory

        if fields.cui and fields.iban:
            if vendor_memory.iban_changed_for_cui(fields.cui, fields.iban):
                fraud_flags.append("IBAN_CHANGED_VS_HISTORY")
                warnings.append("IBAN-ul diferă de istoricul curat al acestei firme.")
            hard_flags = {
                "REPORTED_FRAUD_IBAN",
                "BENEFICIARY_PERSON_MISMATCH",
                "FOREIGN_IBAN",
                "IBAN_CHANGED_VS_HISTORY",
                "ACCOUNT_CHANGE_LANGUAGE",
                "SENSITIVE_DATA_REQUESTED",
                "UNKNOWN_PAYMENT_DESTINATION",
            }
            if not (hard_flags & set(fraud_flags)):
                vendor_memory.remember_invoice_iban(fields.cui, fields.iban)
    except Exception:
        pass

    result = InvoiceScanResult(
        raw_text=ocr_text,
        fields=fields,
        readiness=readiness,
        coherence=coherence,
        iban_valid=iban_valid,
        brand=claimed_brand,
        brand_match=brand_match_result,
        anaf_cui_check=anaf_check,
        payment_destination=payment_destination,
        warnings=warnings,
        fraud_flags=fraud_flags,
    )
    _set_cached_verdict(fields, result)
    return result


@dataclass
class OfferScanResult:
    raw_text: str
    fields: "OfferFields"
    readiness: ReadinessGateResult
    coherence: CoherenceResult
    iban_valid: Optional[IbanResult]
    entity: "OfferEntityResult"
    family_code: str
    family_name: str
    family_confidence: float
    signals: List[str]
    bundle: dict
    gate: dict
    error: Optional[str] = None
    warnings: list = field(default_factory=list)
    # Dovezi din registre publice (PR4): context structurat, nu verdict.
    registry: list = field(default_factory=list)


async def scan_offer(
    ocr_text: str,
    links: Optional[List[str]] = None,
    qr_payloads: Optional[List[str]] = None,
) -> OfferScanResult:
    from services.offer_parser import parse_offer
    from services.invoice_readiness_gate import evaluate_offer_readiness
    from services.offer_signals import derive_offer_signals
    from services.family_classifier import classify_offer_family
    from services.payment_method_classifier import classify_payment_method
    from services.offer_entity_verifier import verify_offer_entity
    from services.offer_evidence_gate_mapper import evaluate_offer_verdict
    from services.registry_verification import verify_offer_registries
    from services.cross_scan_knowledge import evaluate_cross_scan_knowledge

    fields = parse_offer(ocr_text, links=links, qr_payloads=qr_payloads, input_type="offer")
    coherence = check_coherence(
        subtotal=fields.subtotal, tva=fields.tva, total=fields.total,
        data_emitere=fields.data_emitere, scadenta=fields.scadenta,
    )
    iban_valid = validate_iban(fields.iban) if fields.iban else None
    payment = classify_payment_method(
        fields.raw_text,
        iban_is_trezorerie=bool(iban_valid and iban_valid.is_trezorerie),
        has_qr=bool(fields.qr_payloads),
    )
    family_code, family_name, family_conf = classify_offer_family(fields.raw_text)
    readiness = evaluate_offer_readiness(fields)
    entity = await verify_offer_entity(fields, links=fields.urls)
    signals = derive_offer_signals(
        fields, iban_result=iban_valid, coherence=coherence, payment=payment,
        family_code=family_code, readiness=readiness,
    )
    # Registre publice: snapshot-uri locale/stubs oneste — zero apeluri live.
    registry_results = verify_offer_registries(fields, family_code)
    cross_scan_knowledge = evaluate_cross_scan_knowledge(
        text=fields.raw_text or ocr_text,
        claimed_brand=entity.claimed_brand or fields.claimed_brand or fields.emitent,
        cui=fields.cui,
        source_channel="offer",
    )
    out = evaluate_offer_verdict(
        fields, signals=signals, entity=entity, coherence=coherence,
        family_code=family_code, family_confidence=family_conf, readiness=readiness,
        redacted_text=ocr_text, registry_results=registry_results,
        cross_scan_knowledge=cross_scan_knowledge,
    )
    return OfferScanResult(
        raw_text=ocr_text,
        fields=fields,
        readiness=readiness,
        coherence=coherence,
        iban_valid=iban_valid,
        entity=entity,
        family_code=family_code,
        family_name=family_name,
        family_confidence=family_conf,
        signals=signals,
        bundle=out["bundle"],
        gate=out["gate"],
        warnings=list(entity.warnings),
        registry=registry_results,
    )


# ─────────────────────────────────────────────────────────────────────────────
# Bug#5 — ruta factură prin verdict_gate (Decizia A).
# Maparea InvoiceScanResult -> Evidence Bundle v2 + reduce_verdict. Sursă unică
# de adevăr, refolosită de /v1/scan/invoice ȘI de fast-lane-ul orchestrat.
# ─────────────────────────────────────────────────────────────────────────────
_UNTRUSTED_INTAKE = {"whatsapp", "sms", "phone", "social_dm", "messenger", "telegram", "unknown"}


def _intake_trusted(source_channel: Optional[str]) -> bool:
    return str(source_channel or "").strip().lower() not in _UNTRUSTED_INTAKE


def build_invoice_evidence_bundle(
    result: "InvoiceScanResult",
    redacted_text: str = "",
    source_channel: Optional[str] = None,
) -> dict:
    import hashlib
    import json
    import re

    anaf = result.anaf_cui_check
    iban_result = result.iban_valid
    coherence = result.coherence
    brand_match = result.brand_match
    readiness = result.readiness
    readiness_blocks_safe = bool(readiness and readiness.blocks_safe_verdict)
    impersonation_risk = bool(brand_match and brand_match.impersonation_risk)
    cui_matches = bool(brand_match and brand_match.cui_matches)
    iban_matches = bool(brand_match and brand_match.iban_matches)
    claimed_brand = result.brand or "Nespecificat"
    fraud_flags = list(getattr(result, "fraud_flags", []) or [])
    beneficiary_mismatch = "BENEFICIARY_PERSON_MISMATCH" in fraud_flags
    destination_mismatch = "PAYMENT_DESTINATION_BRAND_MISMATCH" in fraud_flags
    unknown_destination = "UNKNOWN_PAYMENT_DESTINATION" in fraud_flags
    payment_destination = getattr(result, "payment_destination", None) or {}
    never_asks_result = {
        "brand_ids": [],
        "violated_never_asks": [],
        "source_channel": str(source_channel or "").strip().lower(),
        "source_refs": [],
    }
    try:
        from services.brand_never_asks import evaluate_brand_never_asks

        never_asks_result = evaluate_brand_never_asks(
            claimed_brand=result.brand,
            text=redacted_text or result.raw_text,
            source_channel=source_channel,
            fraud_flags=fraud_flags,
            payment_destination=payment_destination,
            include_text_candidates=not _intake_trusted(source_channel),
        )
    except Exception:
        pass
    violated_never_asks = list(never_asks_result.get("violated_never_asks") or [])
    destination_trusted = bool(
        payment_destination.get("matched")
        and (payment_destination.get("brand_matches") is True or payment_destination.get("cui_matches") is True)
        and payment_destination.get("can_contribute_to_safe") is True
        and payment_destination.get("trust_tier") in {"T0_PARTNER_SIGNED", "T1_PUBLIC_OFFICIAL", "T2_OFFICIAL_DOCUMENT_CHAIN"}
    )
    destination_required = bool(
        getattr(result.fields, "iban", None)
        and payment_destination.get("registry_has_brand_destinations") is True
    )
    anaf_identity_match = _anaf_identity_matches_invoice(anaf, getattr(result.fields, "emitent", None))
    hard_or_contextual_flags = {
        flag for flag in fraud_flags
        if flag not in {"UNKNOWN_PAYMENT_DESTINATION"}
    }
    coherent_generic_invoice_identity = bool(
        not destination_required
        and not hard_or_contextual_flags
        and _intake_trusted(source_channel)
        and anaf_identity_match
        and iban_result
        and iban_result.valid_structure
        and coherence
        and coherence.all_ok
        and readiness
        and not readiness.blocks_safe_verdict
    )
    benign_unknown_destination = bool(unknown_destination and coherent_generic_invoice_identity)
    weak_fraud_flag = any(
        flag in fraud_flags
        for flag in ("FOREIGN_IBAN", "ACCOUNT_CHANGE_LANGUAGE", "IBAN_CHANGED_VS_HISTORY")
    ) or (
        unknown_destination and not benign_unknown_destination
    )
    sensitive_requested = "SENSITIVE_DATA_REQUESTED" in fraud_flags
    strong_bec_combo = "FOREIGN_IBAN" in fraud_flags and "ACCOUNT_CHANGE_LANGUAGE" in fraud_flags

    anaf_status = "clean"
    anaf_reasons: list = []
    if anaf:
        if anaf.get("checked") is False:
            anaf_status = "unknown"
            anaf_reasons.append("ANAF temporar indisponibil")
        elif not anaf.get("exists"):
            anaf_status = "unknown"
            anaf_reasons.append("CUI negăsit în registru")
        elif not anaf.get("activ"):
            anaf_status = "malicious"
            anaf_reasons.append("Firmă inactivă")

    iban_status = "clean"
    iban_reasons: list = []
    if iban_result and not iban_result.valid_structure:
        iban_status = "suspicious"
        iban_reasons.append("IBAN invalid MOD-97")

    coherence_status = "clean"
    coherence_reasons: list = []
    if coherence:
        if not coherence.totals_match:
            coherence_status = "suspicious"
            coherence_reasons.append("Totalul nu corespunde cu subtotal+TVA")
        if not coherence.dates_plausible:
            coherence_status = "suspicious"
            coherence_reasons.append("Date incoerente (scadența înaintea emiterii)")

    provider_section = {
        "verdict": "malicious" if anaf_status == "malicious" else "suspicious" if "suspicious" in (iban_status, coherence_status) else "clean",
        "anaf": {"status": anaf_status, "verdict": anaf_status, "reasons": anaf_reasons, "completeness": anaf is not None},
        "iban": {"status": iban_status, "verdict": iban_status, "reasons": iban_reasons, "completeness": iban_result is not None},
        "coherence": {"status": coherence_status, "verdict": coherence_status, "reasons": coherence_reasons, "completeness": coherence is not None},
    }
    if anaf_reasons:
        provider_section.setdefault("reasons", []).extend(anaf_reasons)
    if "REPORTED_FRAUD_IBAN" in fraud_flags:
        provider_section["verdict"] = "malicious"
        provider_section["negative_iban_registry"] = {
            "status": "malicious",
            "verdict": "malicious",
            "severity": "high",
            "consulted": True,
            "reasons": ["IBAN raportat ca fraudă"],
        }
    if payment_destination:
        if destination_mismatch:
            provider_section["payment_destination"] = {
                "status": "suspicious",
                "verdict": "suspicious",
                "trust_tier": payment_destination.get("trust_tier"),
                "brand_id": payment_destination.get("brand_id"),
                "matched": True,
                "brand_matches": False,
                "reasons": ["IBAN oficial pentru alt furnizor"],
                "iban_masked_for_client": payment_destination.get("iban_masked_for_client"),
            }
        elif destination_trusted:
            provider_section["payment_destination"] = {
                "status": "clean",
                "verdict": "clean",
                "trust_tier": payment_destination.get("trust_tier"),
                "brand_id": payment_destination.get("brand_id"),
                "matched": True,
                "brand_matches": True,
                "iban_masked_for_client": payment_destination.get("iban_masked_for_client"),
            }
        elif destination_required or (unknown_destination and not benign_unknown_destination):
            provider_section["payment_destination"] = {
                "status": "unknown",
                "verdict": "unknown",
                "trust_tier": payment_destination.get("trust_tier"),
                "matched": False,
                "brand_matches": None,
                "reasons": ["IBAN valid structural, dar neconfirmat ca destinație oficială"],
            }

    if beneficiary_mismatch:
        identity_status = "lookalike"
        identity_reason = "Beneficiarul plății nu corespunde firmei emitente"
    elif destination_mismatch:
        identity_status = "lookalike"
        identity_reason = "Destinația de plată aparține altui furnizor"
    elif impersonation_risk:
        identity_status = "lookalike"
        identity_reason = "CUI/IBAN nealiniat cu brandul declarat"
    elif destination_trusted and payment_destination.get("cui_matches") is True:
        identity_status = "official"
        identity_reason = "CUI și destinație de plată confirmate oficial"
    elif cui_matches and iban_matches and (not destination_required or destination_trusted):
        identity_status = "official"
        identity_reason = "Brand confirmat prin CUI și destinație de plată oficială"
    elif cui_matches and destination_required and not destination_trusted:
        identity_status = "unknown"
        identity_reason = "IBAN valid, dar nu este confirmat în registry-ul oficial al furnizorului"
    elif coherent_generic_invoice_identity:
        identity_status = "coherent"
        identity_reason = "CUI activ la ANAF, numele emitentului se potrivește, IBAN valid și document coerent"
    elif claimed_brand != "Nespecificat":
        identity_status = "unknown"
        identity_reason = "Brand declarat dar neverificat complet"
    else:
        identity_status = "unknown"
        identity_reason = "Brand nedeclarat"

    if not _intake_trusted(source_channel) and identity_status == "official":
        identity_status = "unknown"
        identity_reason = "Canal neoficial; proveniență neconfirmată"

    identity_section = {
        "status": identity_status,
        "claimed_brand": claimed_brand,
        "domain_reputation": "established" if (brand_match and brand_match.domain_matches) else "unknown",
        "reason": identity_reason,
        "completeness": (
            brand_match is not None
            or beneficiary_mismatch
            or weak_fraud_flag
            or sensitive_requested
            or "REPORTED_FRAUD_IBAN" in fraud_flags
            or destination_required
            or destination_mismatch
            or unknown_destination
            or destination_trusted
            or coherent_generic_invoice_identity
            or bool(violated_never_asks)
        ),
        "violated_never_asks": violated_never_asks,
    }
    if never_asks_result.get("source_refs"):
        identity_section["never_asks_source_refs"] = never_asks_result.get("source_refs")

    request_section = {
        "sensitive": "card" if sensitive_requested else "transfer",
        "channel": never_asks_result.get("source_channel") if violated_never_asks else "invoice",
        "completeness": True,
    }

    semantic_risk = "low"
    semantic_reasons: list = []
    if readiness_blocks_safe:
        semantic_risk = "medium"
        semantic_reasons.append("Date insuficiente")
    if weak_fraud_flag:
        semantic_risk = "medium"
        semantic_reasons.append("Semnal de fraudă pe destinația plății")
    if impersonation_risk or beneficiary_mismatch or destination_mismatch or strong_bec_combo or sensitive_requested:
        semantic_risk = "high"
        semantic_reasons.append("Impersonation risk detected")
    if violated_never_asks:
        semantic_risk = "high"
        semantic_reasons.append("Brand never-asks policy violated")
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


def evaluate_invoice_verdict(
    result: "InvoiceScanResult",
    redacted_text: str = "",
    source_channel: Optional[str] = None,
) -> dict:
    """Factură -> bundle v2 -> reduce_verdict (gate unic). {bundle, gate}."""
    from services.verdict_gate import verdict as reduce_verdict

    bundle = build_invoice_evidence_bundle(result, redacted_text, source_channel=source_channel)
    return {"bundle": bundle, "gate": reduce_verdict(bundle)}
