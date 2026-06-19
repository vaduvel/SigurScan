from __future__ import annotations

from typing import Any, Dict, Iterable, Optional


OFFICIAL_SOURCE_CHANNELS = {
    "official_portal",
    "vendor_portal",
    "spv",
    "efactura",
    "bank_import",
}


HARD_CONFLICT_FLAGS = {
    "REPORTED_FRAUD_IBAN": "REPORTED_NEGATIVE_CORROBORATED",
    "QR_PRINTED_IBAN_MISMATCH": "VISIBLE_VS_QR_PAYMENT_HIJACK",
    "DOCUMENT_LAYER_IBAN_CONFLICT": "VISIBLE_VS_TEXT_LAYER_PAYMENT_HIJACK",
    "EFACTURA_OFFICIAL_DOCUMENT_MISMATCH": "OFFICIAL_DOCUMENT_FIELD_MISMATCH",
    "PAYMENT_DESTINATION_BRAND_MISMATCH": "PRIMARY_PAYMENT_DESTINATION_BELONGS_ELSEWHERE",
    "BENEFICIARY_PERSON_MISMATCH": "CONFIRMED_PERSONAL_PAYEE_INCOMPATIBLE_WITH_ISSUER",
    "SENSITIVE_DATA_REQUESTED": "SENSITIVE_CAPTURE_ON_WRONG_CHANNEL",
    "REMOTE_ACCESS_REQUEST": "SENSITIVE_CAPTURE_ON_WRONG_CHANNEL",
    "FAKE_EFACTURA_RECONCILIATION_PAYMENT": "CLAIMED_PUBLIC_AUTHORITY_PAYMENT_CONTRADICTION",
    "CEO_CONFIDENTIAL_PAYMENT": "PAYMENT_CONTROL_BYPASS",
    "PAYROLL_OR_EMPLOYEE_DATA_REQUEST_VIA_INVOICE_THREAD": "HIGH_RISK_B2B_PAYMENT_PATTERN",
    "BEC_REPLY_TO_ACCOUNT_CHANGE": "BEC_ACCOUNT_CHANGE_COMBO",
    "BEC_EXCLUSIVE_NEW_IBAN_WITH_OLD_DETAILS_SUPPRESSION": "BEC_ACCOUNT_CHANGE_COMBO",
    "BEC_INVOICE_THREAD_IBAN_CHANGE": "BEC_ACCOUNT_CHANGE_COMBO",
    "UNDISCLOSED_INTERMEDIARY_BENEFICIARY": "UNDISCLOSED_PAYMENT_INTERMEDIARY",
    "TAX_AUTHORITY_SENSITIVE_DATA_REQUEST": "SENSITIVE_CAPTURE_ON_WRONG_CHANNEL",
    "COURIER_OTP_OR_WHATSAPP_CODE_REQUEST": "SENSITIVE_CAPTURE_ON_WRONG_CHANNEL",
}

TEXT_ONLY_PAYMENT_PATTERN_FLAGS = {
    "COURIER_CUSTOMS_OR_ADDRESS_FEE_PAYMENT",
    "DOMAIN_RENEWAL_INVOICE_NO_EXISTING_VENDOR",
    "GRANT_CONSULTING_FEE_BEFORE_CONTRACT",
    "IP_OFFICE_PAYMENT_REQUEST_UNOFFICIAL_CHANNEL",
    "LEGAL_DEMAND_PAYMENT_TO_NEW_IBAN",
    "NEW_VENDOR_PUBLIC_PROCUREMENT_FEE",
    "OFFICIAL_REGISTRY_CLAIM_BUT_NO_PROVENANCE",
    "OSIM_TRADEMARK_FEE_UNOFFICIAL_SENDER",
    "PAYMENT_DIVERSION_HOLD_INSTRUCTIONS",
    "PO_OR_OVERPAYMENT_RETURN_REQUEST",
    "REGULATED_FINANCE_ADVANCE_FEE_OR_ID_REQUEST",
    "SAAS_LICENSE_AUDIT_URGENT_PAYMENT",
    "TAX_AUTHORITY_APPROVES_UPDATED_IBAN",
    "TAX_AUTHORITY_PAYMENT_REQUEST_UNOFFICIAL_CHANNEL",
    "URGENT_PAYMENT_OVERRIDE_NO_TICKET",
}

_SOFT_SEMANTIC_DANGEROUS_REASONS = {
    "HIGH_RISK_B2B_PAYMENT_PATTERN",
    "identity_spoof",
    "scam_family_match",
    "semantic_high_risk_match",
    "semantic_high_value_request",
}

_DECISIVE_GENERIC_DANGEROUS_PREFIXES = (
    "never_asks_violated:",
    "provider_malicious",
    "reported_fraud_iban",
    "sensitive_wrong_channel",
    "urlhaus_malicious",
    "urlscan_malicious",
    "webrisk_malicious",
)


def evaluate_invoice_truth_v4(
    result: Any,
    *,
    source_channel: Optional[str] = None,
    sanb_attestation: Optional[str] = None,
) -> Dict[str, Any]:
    fields = getattr(result, "fields", None)
    anaf = getattr(result, "anaf_cui_check", None) or {}
    iban_valid = getattr(result, "iban_valid", None)
    coherence = getattr(result, "coherence", None)
    readiness = getattr(result, "readiness", None)
    payment_destination = getattr(result, "payment_destination", None) or {}
    official_document_check = getattr(result, "official_document_check", None) or {}
    beneficiary_name_check = getattr(result, "beneficiary_name_check", None)
    fraud_flags = list(getattr(result, "fraud_flags", []) or [])
    # The user's SANB / Verification-of-Payee answer, if they performed the guided
    # bank-app check. May be passed explicitly or carried on the scan result.
    sanb_attestation = sanb_attestation or getattr(result, "sanb_attestation", None)

    verified_items: list[dict] = []
    unconfirmed_items: list[dict] = []
    hard_conflicts = _hard_conflicts_from_flags(fraud_flags)

    issuer_state = _issuer_state(anaf)
    if issuer_state == "CONFIRMED":
        verified_items.append(_item("ISSUER_CONFIRMED", "Firma este verificată"))
    elif issuer_state == "INACTIVE":
        unconfirmed_items.append(_item("ISSUER_INACTIVE", "Firma apare inactivă; verifică pe canalul oficial"))
    elif issuer_state == "CONTRADICTED":
        unconfirmed_items.append(_item("ISSUER_NOT_CONFIRMED", "Firma nu a putut fi confirmată"))
    else:
        unconfirmed_items.append(_item("ISSUER_NOT_FULLY_CONFIRMED", "Firma nu a putut fi confirmată complet"))

    if iban_valid is not None:
        if getattr(iban_valid, "valid_structure", False):
            verified_items.append(_item("IBAN_STRUCTURE_VALID", "IBAN-ul are format valid"))
        else:
            unconfirmed_items.append(_item("IBAN_STRUCTURE_INVALID", "IBAN-ul nu are format valid"))

    if coherence is not None and getattr(coherence, "all_ok", False):
        verified_items.append(_item("DOCUMENT_COHERENT", "Suma și datele facturii sunt coerente"))
    elif coherence is not None:
        unconfirmed_items.append(_item("DOCUMENT_NOT_FULLY_COHERENT", "Datele facturii nu sunt complet coerente"))

    destination_state = _payment_destination_state(payment_destination, official_document_check, sanb_attestation)
    if destination_state in {"OFFICIAL_REGISTRY_MATCH", "OFFICIAL_DOCUMENT_MATCH", "LOCAL_APPROVED_MATCH", "BANK_MATCH"}:
        verified_items.append(_item("PAYMENT_DESTINATION_CONFIRMED", "Contul de plată este confirmat"))
    elif destination_state == "REPORTED_NEGATIVE":
        hard_conflicts.append(_conflict("REPORTED_NEGATIVE_CORROBORATED", "IBAN raportat în fraude"))
    elif destination_state == "MISMATCH":
        hard_conflicts.append(_conflict("PRIMARY_PAYMENT_DESTINATION_BELONGS_ELSEWHERE", "Contul de plată indică altă entitate"))
    elif destination_state == "INVALID_STRUCTURE":
        unconfirmed_items.append(_item("PAYMENT_IBAN_INVALID", "Contul de plată nu are format valid"))
    elif getattr(fields, "iban", None):
        unconfirmed_items.append(_item("PAYMENT_BENEFICIARY_UNCONFIRMED", "Beneficiarul plății nu este confirmat automat"))

    obligation_state = _invoice_obligation_state(
        source_channel=source_channel,
        official_document_check=official_document_check,
    )
    if obligation_state == "CONFIRMED":
        verified_items.append(_item("INVOICE_OBLIGATION_CONFIRMED", "Factura este confirmată într-o sursă potrivită"))
    else:
        unconfirmed_items.append(_item("INVOICE_OBLIGATION_UNCONFIRMED", "Nu putem confirma automat că datorezi această factură"))

    channel_state = _channel_state(source_channel, fraud_flags)
    if channel_state == "TRUSTED":
        verified_items.append(_item("CHANNEL_TRUSTED", "Factura vine dintr-un canal verificat"))
    elif channel_state == "CHANGED":
        unconfirmed_items.append(_item("CHANNEL_OR_PAYMENT_CHANGED", "Canalul sau datele de plată par schimbate"))

    if any(flag in TEXT_ONLY_PAYMENT_PATTERN_FLAGS for flag in fraud_flags):
        unconfirmed_items.append(
            _item("HIGH_RISK_PAYMENT_PATTERN_REQUIRES_VERIFICATION", "Tiparul de plată trebuie verificat înainte de autorizare")
        )

    if readiness is not None and getattr(readiness, "blocks_safe_verdict", False):
        unconfirmed_items.append(_item("INSUFFICIENT_DATA", "Documentul nu are suficiente date citibile"))

    hard_conflicts = _dedupe_by_code(hard_conflicts)
    verified_items = _dedupe_by_code(verified_items)
    unconfirmed_items = _dedupe_by_code(unconfirmed_items)

    if hard_conflicts:
        verdict = "NU_PLATI"
        decision_status = "DO_NOT_PAY"
        safe_to_pay = False
        primary_reason = hard_conflicts[0]["code"]
        display = {
            "title": "Nu plăti",
            "message": (
                "Am găsit o contradicție clară în datele facturii sau ale plății. "
                "Contactează furnizorul pe canalul oficial."
            ),
            "tone": "danger",
        }
        next_action = {
            "type": "CONTACT_SUPPLIER_OFFICIAL_CHANNEL",
            "title": "Contactează furnizorul pe canalul oficial",
            "requires_authorization": False,
        }
    else:
        safe_requirements_met = (
            issuer_state == "CONFIRMED"
            and obligation_state == "CONFIRMED"
            and destination_state in {"OFFICIAL_REGISTRY_MATCH", "OFFICIAL_DOCUMENT_MATCH", "LOCAL_APPROVED_MATCH", "BANK_MATCH"}
            and channel_state in {"TRUSTED", "NEUTRAL"}
            and not any(item["code"] in {"INSUFFICIENT_DATA", "DOCUMENT_NOT_FULLY_COHERENT"} for item in unconfirmed_items)
        )
        if safe_requirements_met:
            verdict = "DATE_CONFIRMATE"
            decision_status = "OK"
            safe_to_pay = True
            primary_reason = "ALL_REQUIRED_PROOFS_CONFIRMED"
            display = {
                "title": "Date confirmate",
                "message": (
                    "Factura și datele de plată sunt confirmate. "
                    "Verifică suma înainte de autorizare."
                ),
                "tone": "safe",
            }
            next_action = {
                "type": "REVIEW_AMOUNT_THEN_PAY",
                "title": "Verifică suma înainte de plată",
                "requires_authorization": False,
            }
            unconfirmed_items = []
        else:
            verdict = "VERIFY_BEFORE_PAYING"
            decision_status = "ACTION_REQUIRED"
            safe_to_pay = False
            primary_reason = _primary_missing_reason(unconfirmed_items, destination_state, obligation_state, issuer_state)
            display = {
                "title": "Verifică înainte să plătești",
                "message": (
                    "Factura nu pare fraudă, dar nu putem confirma automat contul de plată "
                    "sau că datorezi suma. Verifică înainte să plătești."
                ),
                "tone": "pending",
            }
            next_action = _next_action(primary_reason, beneficiary_name_check)

    return {
        "schema": "sigurscan_invoice_truth_v4",
        "ruleset_version": "invoice-truth-v4.0",
        "verdict": verdict,
        "decision_status": decision_status,
        "safe_to_pay": safe_to_pay,
        "primary_reason_code": primary_reason,
        "policy_profile": _policy_profile(fields, source_channel=source_channel),
        "display": display,
        "verified_items": verified_items,
        "unconfirmed_items": unconfirmed_items,
        "hard_conflicts": hard_conflicts,
        "proofs": {
            "issuer_identity": {"state": issuer_state, "source": "company_registry"},
            "invoice_obligation": {"state": obligation_state, "source": _obligation_source(source_channel, official_document_check)},
            "payment_destination": {
                "state": destination_state,
                "trust_tier": payment_destination.get("trust_tier"),
                "iban_masked": (
                    payment_destination.get("iban_masked_for_client")
                    or _mask_iban(getattr(fields, "iban", None))
                ),
            },
            "channel_change": {"state": channel_state},
        },
        "assurance": {
            "required": ["issuer_identity", "invoice_obligation", "payment_destination", "channel_change"],
            "missing_requirements": [item["code"] for item in unconfirmed_items],
        },
        "next_action": next_action,
    }


def gate_from_invoice_truth(truth: Dict[str, Any], fallback_gate: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    fallback_gate = dict(fallback_gate or {})
    verdict = str(truth.get("verdict") or "")
    fallback_label = str(fallback_gate.get("label") or "").upper()
    if (
        fallback_label == "DANGEROUS"
        and verdict != "DATE_CONFIRMATE"
        and not _truth_is_inactive_only(truth)
        and _generic_dangerous_can_override_invoice(fallback_gate)
    ):
        return {**fallback_gate, "is_final": True}
    if verdict == "NU_PLATI":
        return {
            **fallback_gate,
            "label": "DANGEROUS",
            "risk_level": "high",
            "risk_score": max(90, int(fallback_gate.get("risk_score") or 0)),
            "reason_codes": [truth.get("primary_reason_code") or "invoice_hard_conflict"],
            "confidence": 95,
            "is_final": True,
        }
    if verdict == "DATE_CONFIRMATE":
        return {
            **fallback_gate,
            "label": "SAFE",
            "risk_level": "low",
            "risk_score": min(int(fallback_gate.get("risk_score") or 10), 10),
            "reason_codes": ["invoice_truth_confirmed"],
            "confidence": 92,
            "is_final": True,
        }
    if verdict == "VERIFY_BEFORE_PAYING" and fallback_label in {"SAFE", "SUSPECT", "UNVERIFIED"}:
        return {**fallback_gate, "is_final": True}
    return {
        **fallback_gate,
        "label": "SUSPECT",
        "risk_level": "medium",
        "risk_score": max(int(fallback_gate.get("risk_score") or 35), 35),
        "reason_codes": [truth.get("primary_reason_code") or "value_request_needs_verification"],
        "confidence": 82,
        "is_final": True,
    }


def _item(code: str, label: str) -> Dict[str, str]:
    return {"code": code, "label": label}


def _conflict(code: str, label: str) -> Dict[str, str]:
    return {"code": code, "label": label}


def _dedupe_by_code(items: Iterable[Dict[str, Any]]) -> list[Dict[str, Any]]:
    seen: set[str] = set()
    output: list[Dict[str, Any]] = []
    for item in items:
        code = str(item.get("code") or "")
        if not code or code in seen:
            continue
        seen.add(code)
        output.append(dict(item))
    return output


def _hard_conflicts_from_flags(flags: list[str]) -> list[dict]:
    conflicts: list[dict] = []
    for flag in flags:
        code = HARD_CONFLICT_FLAGS.get(flag)
        if code:
            conflicts.append(_conflict(code, _hard_conflict_label(code)))
    if (
        "IBAN_CHANGED_VS_HISTORY" in flags
        and "REPLY_TO_MISMATCH" in flags
        and ("ACCOUNT_CHANGE_LANGUAGE" in flags or "PAYMENT_PRESSURE" in flags)
    ):
        conflicts.append(_conflict("BEC_ACCOUNT_CHANGE_COMBO", "IBAN nou, canal schimbat și presiune de plată"))
    if (
        "ACCOUNT_CHANGE_LANGUAGE" in flags
        and ("IBAN_CHANGED_VS_HISTORY" in flags or "REPLY_TO_MISMATCH" in flags or "PAYMENT_DESTINATION_BRAND_MISMATCH" in flags)
    ):
        conflicts.append(_conflict("BEC_ACCOUNT_CHANGE_COMBO", "Cont bancar schimbat pe canal sau istoric neobișnuit"))
    if "ACCOUNT_CHANGE_LANGUAGE" in flags and "FOREIGN_IBAN" in flags and "PAYMENT_PRESSURE" in flags:
        conflicts.append(_conflict("BEC_ACCOUNT_CHANGE_COMBO", "Cont bancar schimbat, IBAN străin și presiune de plată"))
    return conflicts


def _hard_conflict_label(code: str) -> str:
    labels = {
        "REPORTED_NEGATIVE_CORROBORATED": "IBAN raportat în fraude",
        "VISIBLE_VS_QR_PAYMENT_HIJACK": "IBAN-ul din QR diferă de cel tipărit",
        "VISIBLE_VS_TEXT_LAYER_PAYMENT_HIJACK": "Documentul conține instrucțiuni de plată contradictorii",
        "OFFICIAL_DOCUMENT_FIELD_MISMATCH": "Documentul oficial contrazice factura scanată",
        "PRIMARY_PAYMENT_DESTINATION_BELONGS_ELSEWHERE": "Contul de plată indică altă entitate",
        "CONFIRMED_PERSONAL_PAYEE_INCOMPATIBLE_WITH_ISSUER": "Beneficiar persoană fizică pentru factură de firmă",
        "SENSITIVE_CAPTURE_ON_WRONG_CHANNEL": "Factura cere date sensibile sau acces la distanță",
        "CLAIMED_PUBLIC_AUTHORITY_PAYMENT_CONTRADICTION": "Pretext e-Factura/SPV cu plată neconfirmată",
        "HIGH_RISK_B2B_PAYMENT_PATTERN": "Tipar B2B cunoscut de fraudă la plată",
        "BEC_ACCOUNT_CHANGE_COMBO": "Schimbare de cont cu semnale de deturnare plată",
        "UNDISCLOSED_PAYMENT_INTERMEDIARY": "Beneficiar intermediar neconfirmat pentru plata facturii",
        "PAYMENT_CONTROL_BYPASS": "Instrucțiune de plată care ocolește verificarea normală",
    }
    return labels.get(code, code.replace("_", " ").lower())


def _generic_dangerous_can_override_invoice(fallback_gate: Dict[str, Any]) -> bool:
    reasons = [str(code or "") for code in (fallback_gate.get("reason_codes") or []) if str(code or "")]
    if not reasons:
        return False
    return any(
        reason in _DECISIVE_GENERIC_DANGEROUS_PREFIXES
        or any(reason.startswith(prefix) for prefix in _DECISIVE_GENERIC_DANGEROUS_PREFIXES)
        for reason in reasons
        if reason not in _SOFT_SEMANTIC_DANGEROUS_REASONS
    )


def _truth_is_inactive_only(truth: Dict[str, Any]) -> bool:
    hard_conflicts = truth.get("hard_conflicts") if isinstance(truth, dict) else []
    if hard_conflicts:
        return False
    primary = str(truth.get("primary_reason_code") or "")
    if primary != "ISSUER_INACTIVE":
        return False
    unconfirmed = truth.get("unconfirmed_items") or []
    codes = {
        str(item.get("code") or "")
        for item in unconfirmed
        if isinstance(item, dict)
    }
    return "ISSUER_INACTIVE" in codes


def _issuer_state(anaf: Dict[str, Any]) -> str:
    if not anaf:
        return "UNKNOWN"
    if anaf.get("checked") is False:
        return "UNKNOWN"
    if not anaf.get("exists"):
        return "CONTRADICTED"
    if anaf.get("activ") is False:
        return "INACTIVE"
    return "CONFIRMED"


def _payment_destination_state(
    payment_destination: Dict[str, Any],
    official_document_check: Dict[str, Any],
    sanb_attestation: Optional[str] = None,
) -> str:
    if official_document_check and official_document_check.get("status") == "mismatch":
        return "MISMATCH"
    # User-assist SANB / Verification-of-Payee result (free VoP substitute): the
    # user checked the beneficiary name in their own bank app and reported back.
    # A hard official contradiction above still wins; below, the user's answer
    # decides. "match" -> BANK_MATCH reaches SAFE only through the Safe Eligibility
    # Gate (issuer + obligation must also be confirmed) -> anti-poisoning.
    attestation = str(sanb_attestation or "").strip().lower()
    if attestation == "no_match":
        return "MISMATCH"
    if attestation in {"match", "close_match"}:
        return "BANK_MATCH"
    if official_document_check and official_document_check.get("can_confirm_payment_destination") is True:
        if official_document_check.get("status") == "match" and not official_document_check.get("risk_flag"):
            return "OFFICIAL_DOCUMENT_MATCH"
    if payment_destination.get("matched") and payment_destination.get("can_contribute_to_safe") is True:
        return "OFFICIAL_REGISTRY_MATCH"
    if payment_destination.get("brand_matches") is False or payment_destination.get("cui_matches") is False:
        return "MISMATCH"
    trust_tier = str(payment_destination.get("trust_tier") or "")
    if trust_tier == "missing":
        return "UNKNOWN"
    if trust_tier == "T4_STRUCTURALLY_VALID_UNKNOWN" or payment_destination.get("matched") is False:
        return "UNCONFIRMED_VALID"
    return "UNKNOWN"


def _invoice_obligation_state(*, source_channel: Optional[str], official_document_check: Dict[str, Any]) -> str:
    source = str(source_channel or "").strip().lower()
    if source in OFFICIAL_SOURCE_CHANNELS:
        return "CONFIRMED"
    if official_document_check and official_document_check.get("can_confirm_payment_destination") is True:
        if official_document_check.get("status") == "match" and not official_document_check.get("risk_flag"):
            return "CONFIRMED"
    if official_document_check and official_document_check.get("status") == "mismatch":
        return "CONTRADICTED"
    return "PLAUSIBLE"


def _channel_state(source_channel: Optional[str], fraud_flags: list[str]) -> str:
    source = str(source_channel or "").strip().lower()
    if source in OFFICIAL_SOURCE_CHANNELS:
        return "TRUSTED"
    if any(flag in fraud_flags for flag in ("REPLY_TO_MISMATCH", "ACCOUNT_CHANGE_LANGUAGE", "IBAN_CHANGED_VS_HISTORY")):
        return "CHANGED"
    return "NEUTRAL"


def _primary_missing_reason(
    unconfirmed_items: list[dict],
    destination_state: str,
    obligation_state: str,
    issuer_state: str,
) -> str:
    codes = {item.get("code") for item in unconfirmed_items}
    if issuer_state == "INACTIVE":
        return "ISSUER_INACTIVE"
    if "INSUFFICIENT_DATA" in codes:
        return "INSUFFICIENT_DATA"
    if destination_state in {"UNCONFIRMED_VALID", "UNKNOWN"}:
        return "UNCONFIRMED_DESTINATION"
    if obligation_state != "CONFIRMED":
        return "UNEXPECTED_OBLIGATION"
    if "CHANNEL_OR_PAYMENT_CHANGED" in codes:
        return "CHANGED_IBAN_OR_CHANNEL"
    return "VERIFY_BEFORE_PAYING"


def _next_action(primary_reason: str, beneficiary_name_check: Optional[dict]) -> Dict[str, Any]:
    if primary_reason == "UNCONFIRMED_DESTINATION":
        return {
            "type": "VERIFY_BENEFICIARY_IN_BANK",
            "title": "Verifică numele beneficiarului în aplicația băncii",
            "requires_authorization": False,
            "available": bool(beneficiary_name_check),
        }
    if primary_reason == "UNEXPECTED_OBLIGATION":
        return {
            "type": "VERIFY_IN_SUPPLIER_PORTAL",
            "title": "Verifică factura în portalul furnizorului",
            "requires_authorization": False,
        }
    if primary_reason in {"ISSUER_INACTIVE", "CHANGED_IBAN_OR_CHANNEL"}:
        return {
            "type": "CALL_SUPPLIER_KNOWN_NUMBER",
            "title": "Sună furnizorul pe numărul cunoscut",
            "requires_authorization": False,
        }
    return {
        "type": "UPLOAD_COMPLETE_DOCUMENT",
        "title": "Încarcă documentul complet sau verifică în portal",
        "requires_authorization": False,
    }


def _policy_profile(fields: Any, *, source_channel: Optional[str]) -> str:
    try:
        amount = float(getattr(fields, "total", None) or 0)
    except (TypeError, ValueError):
        amount = 0.0
    if amount >= 5000:
        return "high_value_payment"
    if str(source_channel or "").strip().lower() in OFFICIAL_SOURCE_CHANNELS:
        return "consumer_or_vendor_portal"
    if getattr(fields, "cui", None):
        return "b2b_or_invoice_with_issuer"
    return "unknown_invoice"


def _obligation_source(source_channel: Optional[str], official_document_check: Dict[str, Any]) -> str:
    source = str(source_channel or "").strip().lower()
    if source in OFFICIAL_SOURCE_CHANNELS:
        return source
    if official_document_check and official_document_check.get("provided"):
        return "user_provided_document_consistency_check"
    return "scanned_document_only"


def _mask_iban(value: Optional[str]) -> Optional[str]:
    text = "".join(ch for ch in str(value or "").upper() if ch.isalnum())
    if not text:
        return None
    if len(text) <= 8:
        return text
    return f"{text[:4]}...{text[-4:]}"
