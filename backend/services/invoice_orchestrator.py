from __future__ import annotations

import hmac
import os
import re
import time
from typing import Any, List, Optional, TYPE_CHECKING
from dataclasses import dataclass, field, replace
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


def _cache_key(fields, links: Optional[list[str]] = None) -> str:
    raw = fields.raw_text or f"{fields.cui}|{fields.iban}|{fields.total}|{fields.data_emitere}|{fields.nr_factura}"
    normalized_links = sorted(
        {
            str(link or "").strip().lower()
            for link in links or []
            if str(link or "").strip()
        }
    )
    if normalized_links:
        raw = raw + "|links:" + "|".join(normalized_links)
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


def _get_cached_verdict(fields, links: Optional[list[str]] = None) -> InvoiceScanResult | None:
    key = _cache_key(fields, links)
    entry = _verdict_cache.get(key)
    if entry and (time.time() - entry[0]) < CACHE_TTL:
        cached = entry[1]
        return replace(cached, from_cache=True)
    if entry:
        del _verdict_cache[key]
    return None


def _set_cached_verdict(fields, result: "InvoiceScanResult", links: Optional[list[str]] = None):
    key = _cache_key(fields, links)
    _verdict_cache[key] = (time.time(), replace(result, from_cache=False))


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
    beneficiary_name_check: Optional[dict] = None
    official_document_check: Optional[dict] = None
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
B2B_HIGH_RISK_FLAGS = {
    "BEC_REPLY_TO_ACCOUNT_CHANGE",
    "CEO_CONFIDENTIAL_PAYMENT",
    "PHISHING_LINK_IN_INVOICE_EMAIL",
    "INVOICE_ATTACHMENT_EXECUTABLE",
    "REMOTE_ACCESS_REQUEST",
    "OSIM_TRADEMARK_FEE_UNOFFICIAL_SENDER",
    "LEGAL_DEMAND_PAYMENT_TO_NEW_IBAN",
    "SAAS_LICENSE_AUDIT_URGENT_PAYMENT",
    "PO_OR_OVERPAYMENT_RETURN_REQUEST",
    "PAYROLL_OR_EMPLOYEE_DATA_REQUEST_VIA_INVOICE_THREAD",
    "URGENT_PAYMENT_OVERRIDE_NO_TICKET",
    "EFACTURA_OFFICIAL_DOCUMENT_MISMATCH",
    "PAYMENT_DIVERSION_HOLD_INSTRUCTIONS",
    "IP_OFFICE_PAYMENT_REQUEST_UNOFFICIAL_CHANNEL",
}
B2B_MEDIUM_RISK_FLAGS = {
    "REPLY_TO_MISMATCH",
    "FREE_EMAIL_FOR_COMPANY_INVOICE",
    "EFACTURA_CLAIM_WITHOUT_DOCUMENT",
    "EFACTURA_OFFICIAL_DOCUMENT_UNREADABLE",
    "PAYMENT_LINK_UNKNOWN_PSP",
    "DOMAIN_RENEWAL_INVOICE_NO_EXISTING_VENDOR",
    "GRANT_CONSULTING_FEE_BEFORE_CONTRACT",
    "NEW_VENDOR_PUBLIC_PROCUREMENT_FEE",
    "OFFICIAL_REGISTRY_CLAIM_BUT_NO_PROVENANCE",
}


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


def _detect_textual_b2b_flags(text: str, *, claimed_vendor: Optional[str] = None) -> tuple[list[str], list[str]]:
    flags: list[str] = []
    warnings: list[str] = []
    try:
        from services.b2b_invoice_signals import evaluate_b2b_invoice_signals

        b2b_result = evaluate_b2b_invoice_signals(text or "", claimed_vendor=claimed_vendor)
        flags.extend(b2b_result.flags)
        warnings.extend(b2b_result.warnings)
    except Exception:
        pass
    try:
        from services.offer_signals import CARD_CVV_OTP

        if CARD_CVV_OTP.search(text or "") and "SENSITIVE_DATA_REQUESTED" not in flags:
            flags.append("SENSITIVE_DATA_REQUESTED")
            warnings.append("Factura cere date de card/CVV/OTP; nu completa și nu plăti.")
    except Exception:
        pass
    return flags, warnings


def _build_beneficiary_name_check(
    *,
    fields: InvoiceFields,
    iban_valid: Optional[IbanResult],
    anaf_check: Optional[dict],
    payment_destination: Optional[dict],
    fraud_flags: list[str],
) -> Optional[dict]:
    """Manual SANB/BNDS guidance for valid-but-unconfirmed payment destinations."""
    if not fields.iban or not iban_valid or not iban_valid.valid_structure:
        return None

    hard_stop_flags = {
        "REPORTED_FRAUD_IBAN",
        "BENEFICIARY_PERSON_MISMATCH",
        "PAYMENT_DESTINATION_BRAND_MISMATCH",
        "SENSITIVE_DATA_REQUESTED",
    }
    if hard_stop_flags & set(fraud_flags):
        return None

    destination_confirmed = bool(
        payment_destination
        and payment_destination.get("matched")
        and (payment_destination.get("brand_matches") is True or payment_destination.get("cui_matches") is True)
        and payment_destination.get("can_contribute_to_safe") is True
    )
    if destination_confirmed:
        return None

    sanb_participant = None
    try:
        from services.sanb_registry import lookup_sanb_participant

        sanb_participant = lookup_sanb_participant(iban_valid.bank_code)
    except Exception:
        sanb_participant = None

    expected_name = (
        str(anaf_check.get("denumire")).strip()
        if anaf_check and anaf_check.get("checked") and anaf_check.get("exists") and anaf_check.get("denumire")
        else (fields.emitent or fields.payment_beneficiary or "")
    ).strip()
    iban_masked = fields.iban[:4] + "..." + fields.iban[-4:] if len(fields.iban) > 8 else fields.iban
    reasons: list[str] = []
    if payment_destination and payment_destination.get("registry_has_brand_destinations") is True:
        reasons.append("IBAN-ul nu apare între destinațiile oficiale cunoscute pentru acest furnizor.")
    else:
        reasons.append("Nu avem o sursă publică suficientă care să confirme proprietarul IBAN-ului.")
    if sanb_participant:
        reasons.append(
            "Banca beneficiarului apare în lista Transfond SANB; afișarea depinde și de banca din care plătești."
        )
    else:
        reasons.append(
            "Nu am confirmat banca beneficiarului în lista Transfond SANB, deci banca ta poate să nu afișeze numele."
        )

    return {
        "recommended": True,
        "method": "bank_app_beneficiary_name_check",
        "local_service_hint": "SANB/BNDS dacă ambele bănci îl oferă",
        "title": "Verifică numele beneficiarului în aplicația băncii",
        "reason": " ".join(reasons),
        "expected_beneficiary": expected_name or None,
        "iban_masked_for_client": iban_masked,
        "bank_code": iban_valid.bank_code,
        "bank": iban_valid.bank_name,
        "sanb": {
            "payee_bank_participant": sanb_participant is not None,
            "participant_name": sanb_participant.institution if sanb_participant else None,
            "bic": sanb_participant.bic if sanb_participant else None,
            "source": sanb_participant.source_url if sanb_participant else "https://www.transfond.ro/",
            "source_accessed_at": sanb_participant.source_accessed_at if sanb_participant else None,
            "requires_payer_bank_participation": True,
        },
        "steps": [
            "În aplicația băncii, începe o plată nouă către IBAN-ul de pe factură.",
            "Înainte să autorizezi plata, verifică numele beneficiarului afișat de bancă.",
            "Continuă doar dacă numele afișat seamănă clar cu firma emitentă de pe factură.",
            "Dacă banca nu afișează numele, banca ta sau banca beneficiarului poate să nu ofere SANB; confirmă direct cu furnizorul pe un canal oficial.",
            "Dacă numele afișat nu se potrivește, oprește plata.",
        ],
        "privacy_note": "SigurScan nu îți cere acces la banca ta, parolă, OTP, PIN sau captură de ecran.",
    }


def with_official_document_check(result: InvoiceScanResult, check: Optional[dict]) -> InvoiceScanResult:
    if not check or check.get("provided") is not True:
        return result

    fraud_flags = list(result.fraud_flags or [])
    warnings = list(result.warnings or [])
    risk_flag = check.get("risk_flag")
    if check.get("status") == "parse_error" and not risk_flag:
        risk_flag = "EFACTURA_OFFICIAL_DOCUMENT_UNREADABLE"
    if risk_flag and risk_flag not in fraud_flags:
        fraud_flags.append(str(risk_flag))
    if check.get("status") == "mismatch":
        warning = (
            "Factura scanată diferă de documentul oficial atașat. "
            "Nu plăti până nu verifici sursa documentului."
        )
        if warning not in warnings:
            warnings.append(warning)
    elif check.get("status") == "parse_error":
        warning = (
            "XML-ul e-Factura atașat nu a putut fi citit. "
            "Nu îl folosim ca dovadă oficială; confirmă documentul în SPV/e-Factura."
        )
        if warning not in warnings:
            warnings.append(warning)
    return replace(
        result,
        official_document_check=check,
        fraud_flags=fraud_flags,
        warnings=warnings,
    )


async def scan_invoice(ocr_text: str, links: Optional[list[str]] = None) -> InvoiceScanResult:
    fields = parse_invoice(ocr_text)
    coherence = _fields_to_coherence(fields)
    if _has_no_extractable_data(fields):
        fraud_flags, warnings = _detect_textual_b2b_flags(ocr_text, claimed_vendor=fields.emitent)
        error = "Nu am putut extrage niciun câmp din document."
        return InvoiceScanResult(
            raw_text=ocr_text, fields=fields, error=error,
            readiness=evaluate_readiness(fields), coherence=coherence,
            warnings=warnings, fraud_flags=fraud_flags,
        )

    all_links = links or []
    cached = _get_cached_verdict(fields, all_links)
    if cached is not None:
        return cached

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
            if brand_match_result.domain_matches is False:
                reasons.append("domeniul nu corespunde brandului")
            if brand_match_result.cui_matches is False:
                reasons.append("CUI-ul nu corespunde brandului")
            if brand_match_result.iban_matches is False:
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
                "source": getattr(raw_cui_check, "source", None) or "anaf",
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
                issuer_name=fields.emitent,
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

    textual_flags, textual_warnings = _detect_textual_b2b_flags(ocr_text, claimed_vendor=fields.emitent)
    for flag in textual_flags:
        if flag not in fraud_flags:
            fraud_flags.append(flag)
    for warning in textual_warnings:
        if warning not in warnings:
            warnings.append(warning)

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
                "REPLY_TO_MISMATCH",
                "BEC_REPLY_TO_ACCOUNT_CHANGE",
                "CEO_CONFIDENTIAL_PAYMENT",
                "PAYMENT_LINK_UNKNOWN_PSP",
                "PHISHING_LINK_IN_INVOICE_EMAIL",
                "INVOICE_ATTACHMENT_EXECUTABLE",
                "REMOTE_ACCESS_REQUEST",
                *B2B_HIGH_RISK_FLAGS,
                *B2B_MEDIUM_RISK_FLAGS,
            }
            # Do not promote the first plausible invoice into trusted vendor
            # memory. Seed this store only from explicit confirmation channels
            # such as e-Factura/XML, bank import, signed contract, or user
            # approval after an official callback.
            if not (hard_flags & set(fraud_flags)):
                pass
    except Exception:
        pass

    beneficiary_name_check = _build_beneficiary_name_check(
        fields=fields,
        iban_valid=iban_valid,
        anaf_check=anaf_check,
        payment_destination=payment_destination,
        fraud_flags=fraud_flags,
    )

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
        beneficiary_name_check=beneficiary_name_check,
        warnings=warnings,
        fraud_flags=fraud_flags,
    )
    _set_cached_verdict(fields, result, all_links)
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
    official_document_mismatch = "EFACTURA_OFFICIAL_DOCUMENT_MISMATCH" in fraud_flags
    payment_destination = getattr(result, "payment_destination", None) or {}
    official_document_check = getattr(result, "official_document_check", None) or None
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
        claimed_brand == "Nespecificat"
        and not destination_required
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
        for flag in (
            "FOREIGN_IBAN",
            "ACCOUNT_CHANGE_LANGUAGE",
            "IBAN_CHANGED_VS_HISTORY",
            *B2B_MEDIUM_RISK_FLAGS,
        )
    ) or (
        unknown_destination and not benign_unknown_destination
    )
    sensitive_requested = "SENSITIVE_DATA_REQUESTED" in fraud_flags
    remote_access_requested = "REMOTE_ACCESS_REQUEST" in fraud_flags
    strong_bec_combo = "FOREIGN_IBAN" in fraud_flags and "ACCOUNT_CHANGE_LANGUAGE" in fraud_flags
    b2b_high_risk = bool(B2B_HIGH_RISK_FLAGS & set(fraud_flags)) or (
        "REPLY_TO_MISMATCH" in fraud_flags
        and ("ACCOUNT_CHANGE_LANGUAGE" in fraud_flags or "IBAN_CHANGED_VS_HISTORY" in fraud_flags)
    ) or (
        "PAYMENT_LINK_UNKNOWN_PSP" in fraud_flags and sensitive_requested
    )

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
        "anaf": {
            "status": anaf_status,
            "verdict": anaf_status,
            "reasons": anaf_reasons,
            "completeness": anaf is not None,
            "source": anaf.get("source") if isinstance(anaf, dict) else None,
        },
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
                "cui_matches": payment_destination.get("cui_matches"),
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
    if official_document_check:
        official_status = official_document_check.get("status")
        provider_section["official_document"] = {
            "status": "suspicious" if official_status == "mismatch" else "clean" if official_status == "match" else "unknown",
            "verdict": "suspicious" if official_status == "mismatch" else "clean" if official_status == "match" else "unknown",
            "provided": True,
            "risk_flag": official_document_check.get("risk_flag"),
            "matched_fields": official_document_check.get("matched_fields") or [],
            "mismatches": official_document_check.get("mismatches") or [],
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
    elif destination_trusted and (
        payment_destination.get("brand_matches") is True
        or payment_destination.get("cui_matches") is True
    ):
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
            or b2b_high_risk
            or official_document_mismatch
        ),
        "violated_never_asks": violated_never_asks,
    }
    if never_asks_result.get("source_refs"):
        identity_section["never_asks_source_refs"] = never_asks_result.get("source_refs")

    request_section = {
        "sensitive": "remote" if remote_access_requested else "card" if sensitive_requested else "transfer",
        "channel": (
            never_asks_result.get("source_channel")
            if violated_never_asks
            else "reply"
            if "REPLY_TO_MISMATCH" in fraud_flags or "BEC_REPLY_TO_ACCOUNT_CHANGE" in fraud_flags
            else "unofficial_site"
            if "PAYMENT_LINK_UNKNOWN_PSP" in fraud_flags or "PHISHING_LINK_IN_INVOICE_EMAIL" in fraud_flags
            else "invoice"
        ),
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
    if (
        impersonation_risk
        or beneficiary_mismatch
        or destination_mismatch
        or strong_bec_combo
        or sensitive_requested
        or remote_access_requested
        or b2b_high_risk
        or official_document_mismatch
    ):
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
            "apk_or_remote_mention": remote_access_requested,
            "b2b_invoice_signals": [flag for flag in fraud_flags if flag in B2B_HIGH_RISK_FLAGS or flag in B2B_MEDIUM_RISK_FLAGS],
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
