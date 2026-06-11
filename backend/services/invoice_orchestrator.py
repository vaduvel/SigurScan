from typing import Optional
from dataclasses import dataclass, field
from services.invoice_parser import parse_invoice, InvoiceFields
from services.iban_validator import validate_iban, IbanResult
from services.invoice_coherence import CoherenceResult, check_coherence
from services.invoice_readiness_gate import evaluate_readiness, ReadinessGateResult
from services.brand_registry import detect_claimed_brand, match_brand, BrandMatchResult
from services.anaf_cui import check_cui


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

    if fields.cui:
        cui_check = await check_cui(fields.cui)
        anaf_check = {
            "exists": cui_check.exists,
            "denumire": cui_check.denumire,
            "activ": cui_check.activ,
            "platitor_tva": cui_check.platitor_tva,
        }
        if not cui_check.exists:
            warnings.append(f"CUI {fields.cui} not found in ANAF registry")
        elif not cui_check.activ:
            warnings.append(f"Company {cui_check.denumire} is inactive (since {cui_check.data_inactivare})")

    return InvoiceScanResult(
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
