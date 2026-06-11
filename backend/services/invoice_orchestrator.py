from __future__ import annotations

import hashlib
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


def _cache_key(fields) -> str:
    raw = f"{fields.cui}|{fields.iban}|{fields.total}|{fields.data_emitere}|{fields.nr_factura}"
    return hashlib.sha256(raw.encode()).hexdigest()


def _cui_cache_key(cui: str) -> str:
    return "cui:" + hashlib.sha256(cui.encode()).hexdigest()


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
    error: Optional[str] = None
    warnings: list = field(default_factory=list)
    from_cache: bool = False


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
            _set_cached_cui(fields.cui, cui_check)
        anaf_check = cui_check
        if not cui_check["exists"]:
            warnings.append(f"CUI {fields.cui} not found in ANAF registry")
        elif not cui_check["activ"]:
            warnings.append(f"Company {cui_check['denumire']} is inactive")

    result = InvoiceScanResult(
        raw_text=ocr_text,
        fields=fields,
        readiness=readiness,
        coherence=coherence,
        iban_valid=iban_valid,
        brand=claimed_brand,
        brand_match=brand_match_result,
        anaf_cui_check=anaf_check,
        warnings=warnings,
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


async def scan_offer(
    ocr_text: str,
    links: Optional[List[str]] = None,
    qr_payloads: Optional[List[str]] = None,
) -> OfferScanResult:
    from services.offer_parser import parse_offer
    from services.offer_readiness import evaluate_offer_readiness
    from services.offer_signals import derive_offer_signals
    from services.family_classifier import classify_offer_family
    from services.payment_method_classifier import classify_payment_method
    from services.offer_entity_verifier import verify_offer_entity
    from services.offer_evidence_gate_mapper import evaluate_offer_verdict

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
    out = evaluate_offer_verdict(
        fields, signals=signals, entity=entity, coherence=coherence,
        family_code=family_code, family_confidence=family_conf, readiness=readiness,
        redacted_text=ocr_text,
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
    )
