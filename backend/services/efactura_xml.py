from __future__ import annotations

import re
from typing import Any, Iterable, Optional

import defusedxml.ElementTree as ET

from services.invoice_parser import (
    IBAN_PATTERN,
    InvoiceFields,
    _extract_all_ibans,
    _normalize_cui,
    _parse_ro_amount,
)


class EFacturaXmlError(ValueError):
    pass


def _local_name(tag: str) -> str:
    if "}" in tag:
        return tag.rsplit("}", 1)[1]
    return tag


def _children_named(node: ET.Element, name: str) -> list[ET.Element]:
    return [child for child in list(node) if _local_name(child.tag) == name]


def _descendants_named(node: ET.Element, name: str) -> list[ET.Element]:
    return [child for child in node.iter() if _local_name(child.tag) == name]


def _first_text(nodes: Iterable[ET.Element]) -> Optional[str]:
    for node in nodes:
        value = (node.text or "").strip()
        if value:
            return value
    return None


def _first_descendant_text(node: ET.Element, *names: str) -> Optional[str]:
    wanted = set(names)
    return _first_text(child for child in node.iter() if _local_name(child.tag) in wanted)


def _first_section(root: ET.Element, name: str) -> Optional[ET.Element]:
    for child in root.iter():
        if _local_name(child.tag) == name:
            return child
    return None


def _require_supported_ubl_document(root: ET.Element) -> str:
    document_type = _local_name(root.tag)
    if document_type not in {"Invoice", "CreditNote"}:
        raise EFacturaXmlError(
            "XML-ul atașat nu pare să fie e-Factura UBL Invoice/CreditNote."
        )
    return document_type


def _format_xml_date(value: Optional[str]) -> Optional[str]:
    if not value:
        return None
    text = value.strip()
    match = re.fullmatch(r"(\d{4})-(\d{2})-(\d{2})", text)
    if match:
        return f"{match.group(3)}.{match.group(2)}.{match.group(1)}"
    return text


def _extract_party_name_and_cui(section: Optional[ET.Element]) -> tuple[Optional[str], Optional[str]]:
    if section is None:
        return None, None

    name = None
    party_name = _first_section(section, "PartyName")
    if party_name is not None:
        name = _first_descendant_text(party_name, "Name")
    if not name:
        legal_entity = _first_section(section, "PartyLegalEntity")
        if legal_entity is not None:
            name = _first_descendant_text(legal_entity, "RegistrationName")

    cui = None
    for section_name in ("PartyTaxScheme", "PartyLegalEntity", "PartyIdentification"):
        party_section = _first_section(section, section_name)
        if party_section is None:
            continue
        raw_cui = _first_descendant_text(party_section, "CompanyID", "ID", "EndpointID")
        if raw_cui:
            digits = _normalize_cui(raw_cui)
            if 2 <= len(digits) <= 10:
                cui = digits
                break
    return name, cui


def _extract_supplier(root: ET.Element) -> tuple[Optional[str], Optional[str]]:
    return _extract_party_name_and_cui(_first_section(root, "AccountingSupplierParty"))


def _extract_customer(root: ET.Element) -> tuple[Optional[str], Optional[str]]:
    return _extract_party_name_and_cui(_first_section(root, "AccountingCustomerParty"))


def _extract_payment_details(root: ET.Element) -> tuple[Optional[str], list[str], Optional[str]]:
    primary_iban = None
    beneficiary = None
    for account in _descendants_named(root, "PayeeFinancialAccount"):
        raw_iban = _first_descendant_text(account, "ID")
        account_name = _first_descendant_text(account, "Name")
        if account_name and not beneficiary:
            beneficiary = account_name.strip()
        if raw_iban:
            match = IBAN_PATTERN.search(raw_iban.replace(" ", ""))
            if match and not primary_iban:
                primary_iban = match.group(0).upper()

    if not beneficiary:
        payee_party = _first_section(root, "PayeeParty")
        beneficiary, _ = _extract_party_name_and_cui(payee_party)

    raw_xml_text = ET.tostring(root, encoding="unicode", method="text")
    all_ibans = _extract_all_ibans(raw_xml_text)
    if not primary_iban:
        primary_iban = next((iban for iban in all_ibans if iban.startswith("RO")), None)
        if not primary_iban and all_ibans:
            primary_iban = all_ibans[0]
    return primary_iban, all_ibans, beneficiary


def _extract_document_currency(root: ET.Element) -> Optional[str]:
    currency = _first_text(_descendants_named(root, "DocumentCurrencyCode"))
    return currency.upper() if currency else None


def _extract_payable_amount(root: ET.Element) -> tuple[Optional[float], Optional[str]]:
    amount_nodes: list[ET.Element] = []
    monetary_total = _first_section(root, "LegalMonetaryTotal")
    if monetary_total is not None:
        amount_nodes.extend(_descendants_named(monetary_total, "PayableAmount"))
    amount_nodes.extend(_descendants_named(root, "PayableAmount"))

    for node in amount_nodes:
        amount = _parse_ro_amount((node.text or "").strip())
        if amount is None:
            continue
        currency = None
        for key, value in node.attrib.items():
            if _local_name(key) == "currencyID" and value:
                currency = value.upper()
                break
        return amount, currency or _extract_document_currency(root)
    return None, _extract_document_currency(root)


def parse_efactura_xml(xml_bytes: bytes) -> InvoiceFields:
    if not xml_bytes:
        raise EFacturaXmlError("XML-ul oficial este gol.")
    head = xml_bytes[:512].decode("utf-8", errors="ignore").lower()
    if "<!doctype" in head or "<!entity" in head:
        raise EFacturaXmlError("XML-ul conține DOCTYPE/ENTITY și nu poate fi procesat sigur.")
    try:
        root = ET.fromstring(xml_bytes)
    except ET.ParseError as exc:
        raise EFacturaXmlError("XML-ul oficial nu este valid.") from exc

    document_type = _require_supported_ubl_document(root)
    emitent, cui = _extract_supplier(root)
    customer_name, customer_cui = _extract_customer(root)
    total, currency = _extract_payable_amount(root)
    invoice_id = _first_text(_children_named(root, "ID")) or _first_descendant_text(root, "ID")
    issue_date = _format_xml_date(_first_text(_children_named(root, "IssueDate")))
    due_date = _format_xml_date(_first_text(_children_named(root, "DueDate")))
    iban, all_ibans, beneficiary = _extract_payment_details(root)

    return InvoiceFields(
        emitent=emitent,
        cui=cui,
        nr_factura=invoice_id,
        data_emitere=issue_date,
        scadenta=due_date,
        total=total,
        currency=currency,
        invoice_profile=f"ubl_{document_type.lower()}",
        iban=iban,
        all_ibans=all_ibans or ([iban] if iban else []),
        payment_beneficiary=beneficiary,
        raw_text=ET.tostring(root, encoding="unicode", method="text"),
        lines=[
            {
                "role": "customer",
                "name": customer_name,
                "cui": customer_cui,
            }
        ] if customer_name or customer_cui else [],
    )


def _norm_text(value: Optional[str]) -> Optional[str]:
    if value is None:
        return None
    return re.sub(r"\s+", " ", str(value).strip()).upper() or None


def _norm_date(value: Optional[str]) -> Optional[str]:
    if not value:
        return None
    text = value.strip()
    match = re.fullmatch(r"(\d{4})-(\d{2})-(\d{2})", text)
    if match:
        return f"{match.group(3)}.{match.group(2)}.{match.group(1)}"
    return text


def _field_dict(fields: InvoiceFields) -> dict[str, Any]:
    return {
        "emitent": fields.emitent,
        "cui": fields.cui,
        "nr_factura": fields.nr_factura,
        "data_emitere": fields.data_emitere,
        "scadenta": fields.scadenta,
        "iban": fields.iban,
        "all_ibans": fields.all_ibans,
        "payment_beneficiary": fields.payment_beneficiary,
        "total": fields.total,
        "currency": fields.currency,
        "invoice_profile": fields.invoice_profile,
    }


def compare_invoice_to_official_xml(invoice: InvoiceFields, official: InvoiceFields) -> dict[str, Any]:
    comparisons = {
        "cui": ("high", lambda left, right: _normalize_cui(str(left)) == _normalize_cui(str(right))),
        "iban": ("high", lambda left, right: _norm_text(left) == _norm_text(right)),
        "total": ("high", lambda left, right: abs(float(left) - float(right)) <= 0.01),
        "nr_factura": ("medium", lambda left, right: _norm_text(left) == _norm_text(right)),
        "data_emitere": ("medium", lambda left, right: _norm_date(str(left)) == _norm_date(str(right))),
        "scadenta": ("medium", lambda left, right: _norm_date(str(left)) == _norm_date(str(right))),
    }
    mismatches: list[dict[str, Any]] = []
    matched_fields: list[str] = []
    missing_official_fields: list[str] = []

    for field, (severity, comparator) in comparisons.items():
        invoice_value = getattr(invoice, field, None)
        official_value = getattr(official, field, None)
        if official_value in (None, ""):
            missing_official_fields.append(field)
            continue
        if invoice_value in (None, ""):
            continue
        try:
            if field == "iban":
                official_ibans = {
                    _norm_text(value)
                    for value in ([official.iban] + list(getattr(official, "all_ibans", []) or []))
                    if value
                }
                matches = _norm_text(invoice_value) in official_ibans
            else:
                matches = comparator(invoice_value, official_value)
        except Exception:
            matches = False
        if matches:
            matched_fields.append(field)
        else:
            mismatches.append(
                {
                    "field": field,
                    "invoice_value": invoice_value,
                    "official_value": official_value,
                    "severity": severity,
                }
            )

    has_high_mismatch = any(item["severity"] == "high" for item in mismatches)
    status = "mismatch" if mismatches else "match" if matched_fields else "insufficient_data"
    return {
        "provided": True,
        "source_kind": "user_uploaded_efactura_xml",
        "verification_scope": "consistency_check",
        "requires_spv_confirmation": True,
        "can_confirm_payment_destination": False,
        "trust_tier": "T3_USER_LOCAL_TRUSTED",
        "status": status,
        "risk_flag": "EFACTURA_OFFICIAL_DOCUMENT_MISMATCH" if has_high_mismatch else None,
        "mismatches": mismatches,
        "matched_fields": matched_fields,
        "missing_official_fields": missing_official_fields,
        "official_fields": _field_dict(official),
    }
