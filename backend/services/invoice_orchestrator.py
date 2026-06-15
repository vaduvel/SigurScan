from __future__ import annotations

import hmac
import os
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
    # Cheie pe textul documentului: același document → cache hit; text diferit
    # (ex. „cont schimbat", alt beneficiar/IBAN) → recalculează. Evită coliziuni
    # între facturi diferite care întâmplător au aceleași câmpuri extrase.
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
    error: Optional[str] = None
    warnings: list = field(default_factory=list)
    fraud_flags: list = field(default_factory=list)
    from_cache: bool = False


# ─── Detectori de semnale de fraudă (titular/IBAN/limbaj) ────────────────────
# Pur detectori de SEMNAL (bool/listă) — NU dau verdict. Verdictul rămâne la
# verdict_gate (un singur judecător); semnalele intră în bundle ca toate celelalte.
import re as _re

_DIACRITICS = str.maketrans("ăâîșşțţ", "aaisstt")
_COMPANY_MARKERS = _re.compile(
    r"\b(s\.?\s?r\.?\s?l|s\.?\s?a|s\.?\s?c|p\.?\s?f\.?\s?a|i\.?\s?i|s\.?\s?n\.?\s?c|"
    r"societate|societatea|asociat|fundat|regia|intreprindere|cooperativa|cabinet|"
    r"sucursala|gmbh|ltd|llc|inc|s\.?p\.?a)\b",
    _re.IGNORECASE,
)
_ACCOUNT_CHANGE_RE = _re.compile(
    r"(am\s+schimbat\s+(contul|banca|iban)|cont(ul)?\s+(nou|s-?a\s+schimbat|modificat|actualizat)|"
    r"noul\s+(nostru\s+)?(cont|iban)|iban[-\s]*(ul)?\s*(nou|s-?a\s+(schimbat|modificat))|"
    r"schimbare\s+(de\s+)?cont\s+bancar|date(le)?\s+bancare\s+(au\s+fost\s+)?(modificat|actualizat|schimbat)|"
    r"changed\s+(our\s+)?(bank\s+account|account\s+details|iban)|new\s+(bank\s+)?account)",
    _re.IGNORECASE,
)
_PRESSURE_RE = _re.compile(
    r"(astazi|imediat|in\s*24\s*(de\s*)?ore|ultima\s+zi|chiar\s+acum|de\s+urgenta|"
    r"altfel\s+(se\s+)?(suspend|debrans|deconect|pierde|anuleaz|sista)|debransare|"
    r"deconectare|executare\s+silita|poprire|pierdeti\s+comanda|risc(ati)?\s+(suspendare|debransare))",
    _re.IGNORECASE,
)
_NAME_STOPWORDS = {"sc", "srl", "sa", "pfa", "ii", "snc", "de", "si"}


def _txt_norm(text: str) -> str:
    return (text or "").lower().translate(_DIACRITICS)


def _foreign_ibans(all_ibans: list[str]) -> list[str]:
    """IBAN-uri valide dar non-RO (red flag pe factură RO). Folosește validatorul."""
    out: list[str] = []
    for raw in all_ibans or []:
        norm = "".join(ch for ch in str(raw).upper() if ch.isalnum())
        if len(norm) >= 4 and norm[:2] != "RO" and validate_iban(raw).valid_structure:
            out.append(norm)
    return out


def _name_tokens(name: str) -> set:
    cleaned = _COMPANY_MARKERS.sub(" ", _txt_norm(name))
    return {t for t in _re.findall(r"[a-z]{2,}", cleaned) if t not in _NAME_STOPWORDS}


def _beneficiary_is_person(name: Optional[str]) -> bool:
    if not name or _COMPANY_MARKERS.search(name):
        return False
    tokens = _re.findall(r"[A-Za-zĂÂÎȘŞȚŢăâîșşțţ]{2,}", name.strip())
    return 2 <= len(tokens) <= 4


def _beneficiary_mismatch(beneficiary: Optional[str], issuer: Optional[str]) -> bool:
    """Beneficiar persoană fizică ce NU se suprapune cu emitentul-firmă.
    Tratează corect PFA (nume comun emitent↔beneficiar → fără mismatch)."""
    if not _beneficiary_is_person(beneficiary):
        return False
    ta, tb = _name_tokens(beneficiary or ""), _name_tokens(issuer or "")
    if ta and tb and len(ta & tb) >= min(2, len(ta), len(tb)):
        return False
    return True


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

    # ─── Semnale de fraudă „firmă reală + IBAN fals/complice" (prevenție) ─────
    # Doar SEMNALE — verdictul îl dă verdict_gate. Țintă: titular persoană fizică ≠
    # firmă, IBAN străin pe factură RO, limbaj „cont schimbat" (BEC), multi-IBAN.
    fraud_flags: list[str] = []
    issuer_name = fields.emitent
    # Registru negativ: dacă vreun IBAN al facturii a fost raportat ca fraudă →
    # semnal HARD (prinde „firmă reală + IBAN complice" de la victima #2).
    from services.negative_iban_registry import reported_fraud_ibans
    candidate_ibans = list(fields.all_ibans or [])
    if fields.iban:
        candidate_ibans.append(fields.iban)
    if reported_fraud_ibans(candidate_ibans):
        fraud_flags.append("REPORTED_FRAUD_IBAN")
        warnings.append(
            "IBAN-ul de plată a fost raportat anterior ca fraudă. NU plăti și "
            "raportează incidentul."
        )
    if _beneficiary_mismatch(fields.payment_beneficiary, issuer_name):
        fraud_flags.append("BENEFICIARY_PERSON_MISMATCH")
        warnings.append(
            "Beneficiarul plății pare o persoană fizică, nu firma emitentă — "
            "semn de cont de complice. Confirmă direct cu firma înainte să plătești."
        )
    foreign = _foreign_ibans(fields.all_ibans)
    if foreign:
        fraud_flags.append("FOREIGN_IBAN")
        warnings.append(
            "IBAN-ul de plată nu este românesc pe o factură RO — verifică pe un "
            "canal oficial al furnizorului înainte de plată."
        )
    if _ACCOUNT_CHANGE_RE.search(_txt_norm(ocr_text)):
        fraud_flags.append("ACCOUNT_CHANGE_LANGUAGE")
        warnings.append(
            "Mesajul anunță «cont nou / cont schimbat» — tactica #1 de fraudă (BEC). "
            "Sună furnizorul pe un număr cunoscut și confirmă noul cont."
        )
    if _PRESSURE_RE.search(_txt_norm(ocr_text)):
        fraud_flags.append("PAYMENT_PRESSURE")
    if len(fields.all_ibans or []) >= 2:
        fraud_flags.append("MULTIPLE_IBANS")
    # Cerere de date sensibile pe o factură (card/CVV/OTP) — nicio firmă reală nu
    # cere asta în factură. Detector PARTAJAT cu ruta ofertă (zero cod nou).
    # Ancorat pe corpusul RO (RO_SCN_016/F22 utility-bill: «confirmă card», CARD_DATA_REQUEST).
    try:
        from services.offer_signals import CARD_CVV_OTP
        if CARD_CVV_OTP.search(ocr_text or ""):
            fraud_flags.append("SENSITIVE_DATA_REQUESTED")
            warnings.append(
                "Factura cere date de card/CVV/OTP — nicio firmă reală nu cere asta "
                "într-o factură. NU completa și NU plăti."
            )
    except Exception:
        pass

    # Vendor memory: IBAN schimbat față de istoricul curat al firmei (semnal BEC #1).
    from services import vendor_memory
    if fields.cui and fields.iban:
        if vendor_memory.iban_changed_for_cui(fields.cui, fields.iban):
            fraud_flags.append("IBAN_CHANGED_VS_HISTORY")
            warnings.append(
                "IBAN-ul diferă de cel folosit anterior pentru această firmă — "
                "confirmă telefonic noul cont înainte de plată (tactică BEC)."
            )
        # Anti-poisoning: memorăm DOAR din scanări fără semnale de fraudă tari.
        _hard = ("REPORTED_FRAUD_IBAN", "BENEFICIARY_PERSON_MISMATCH",
                 "FOREIGN_IBAN", "IBAN_CHANGED_VS_HISTORY", "ACCOUNT_CHANGE_LANGUAGE")
        if not any(f in fraud_flags for f in _hard):
            vendor_memory.remember_invoice_iban(fields.cui, fields.iban)

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
    out = evaluate_offer_verdict(
        fields, signals=signals, entity=entity, coherence=coherence,
        family_code=family_code, family_confidence=family_conf, readiness=readiness,
        redacted_text=ocr_text, registry_results=registry_results,
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
