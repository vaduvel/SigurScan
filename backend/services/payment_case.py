"""Deterministic cross-artifact reducer for a payment investigation.

The module does not scan content and does not replace any existing engine. It
normalizes the privacy-safe facts produced by those engines, detects conflicts
between artifacts, and applies a monotonic case verdict.
"""

from __future__ import annotations

import copy
from decimal import Decimal, InvalidOperation
import hashlib
import hmac
import os
import re
import unicodedata
import urllib.parse
from typing import Any, Iterable, Mapping, Sequence

from services.pre_redaction_evidence import sanitize_pre_redaction_evidence


PAYMENT_CASE_FACTS_SCHEMA = "sigurscan_payment_case_facts_v1"
PAYMENT_CASE_ARTIFACT_SCHEMA = "sigurscan_payment_case_artifact_v1"
PAYMENT_CASE_RESULT_SCHEMA = "sigurscan_payment_case_result_v1"

_VERDICT_RANK = {"SAFE": 0, "UNVERIFIED": 1, "SUSPECT": 2, "DANGEROUS": 3}
_VERDICT_ALIASES = {
    "SIGUR": "SAFE",
    "NEVERIFICAT": "UNVERIFIED",
    "VERIFICA": "SUSPECT",
    "VERIFICĂ": "SUSPECT",
    "SUSPECT": "SUSPECT",
    "PERICULOS": "DANGEROUS",
}
_LEGAL_FORM_TOKENS = {
    "sa",
    "srl",
    "srld",
    "pfa",
    "ii",
    "if",
    "ifn",
    "snc",
    "scs",
    "sca",
    "sc",
    "societate",
    "comerciala",
}
_PAYMENT_ACTIONS = {
    "transfer_money",
    "pay_fee",
    "pay_invoice",
    "send_money",
    "buy_gift_card",
    "pay_crypto",
}
_ACCOUNT_CHANGE_SIGNALS = {
    "account_change_language",
    "changed_iban_or_channel",
    "iban_changed_vs_history",
    "bec_reply_to_account_change",
    "bec_account_change_combo",
}
_FINAL_PAYMENT_REQUEST_REASONS = {
    "value_request_needs_verification",
    "semantic_high_value_request",
    "identity_spoof_value_request",
    "changed_iban_or_channel",
    "bec_account_change_combo",
}


def _dedupe(values: Iterable[str]) -> list[str]:
    output: list[str] = []
    for value in values:
        normalized = str(value or "").strip()
        if normalized and normalized not in output:
            output.append(normalized)
    return output


def _normalized_verdict(value: Any) -> str:
    candidate = str(value or "UNVERIFIED").strip().upper()
    candidate = _VERDICT_ALIASES.get(candidate, candidate)
    return candidate if candidate in _VERDICT_RANK else "UNVERIFIED"


def _entity_core(value: Any) -> str | None:
    folded = unicodedata.normalize("NFKD", str(value or ""))
    folded = "".join(ch for ch in folded if not unicodedata.combining(ch)).lower()
    # Preserve word boundaries while collapsing punctuation inside legal forms:
    # "S.A." -> "sa" and "S.R.L.-D" -> "srld".
    tokens = [
        token
        for part in re.split(r"\s+", folded)
        if (token := re.sub(r"[^a-z0-9]", "", part))
        and token not in _LEGAL_FORM_TOKENS
    ]
    return " ".join(tokens) or None


def _hmac_key() -> bytes:
    value = os.getenv("INVOICE_CACHE_HMAC_KEY", "").strip()
    if not value:
        raise RuntimeError("INVOICE_CACHE_HMAC_KEY must be configured for Payment Case fingerprints")
    return value.encode("utf-8")


def _payment_destination_fingerprint(value: Any) -> str:
    normalized = re.sub(r"\s+", "", str(value or "")).upper()
    digest = hmac.new(_hmac_key(), normalized.encode("utf-8"), hashlib.sha256).hexdigest()
    return "hmac-sha256:" + digest


def _entity_fingerprint(value: Any) -> str | None:
    core = _entity_core(value)
    if not core:
        return None
    digest = hmac.new(
        _hmac_key(),
        ("payment-case-entity:" + core).encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
    return "hmac-sha256:" + digest


def client_owner_fingerprint(client_instance_id: str) -> str:
    """Bind private case records to an installation without storing its raw ID."""

    normalized = str(client_instance_id or "").strip()
    if not normalized:
        raise ValueError("client_instance_id is required")
    digest = hmac.new(
        _hmac_key(),
        ("payment-case-owner:" + normalized).encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
    return "hmac-sha256:" + digest


def _normalized_amount(value: Any) -> str | None:
    raw = str(value or "").strip().replace(" ", "")
    if not raw:
        return None
    if "," in raw and "." in raw:
        if raw.rfind(",") > raw.rfind("."):
            raw = raw.replace(".", "").replace(",", ".")
        else:
            raw = raw.replace(",", "")
    else:
        raw = raw.replace(",", ".")
    try:
        amount = Decimal(raw)
    except (InvalidOperation, ValueError):
        return None
    if amount < 0:
        return None
    return format(amount.quantize(Decimal("0.01")), "f")


def build_payment_case_facts(
    *,
    artifact_type: str,
    pre_redaction_evidence: Mapping[str, Any] | None = None,
    entity_name: str | None = None,
    cui: str | None = None,
    amount: Any = None,
    currency: str | None = None,
    requested_actions: Sequence[str] | None = None,
    signals: Sequence[str] | None = None,
    domains: Sequence[str] | None = None,
    evidence_provenance: str = "unknown",
) -> dict[str, Any]:
    """Build persistable facts without retaining raw payment identifiers."""

    evidence = sanitize_pre_redaction_evidence(pre_redaction_evidence)
    identifiers = evidence.get("identifiers", {}) if evidence else {}
    payment = evidence.get("payment", {}) if evidence else {}
    raw_ibans = identifiers.get("ibans") if isinstance(identifiers, Mapping) else []
    raw_ibans = raw_ibans if isinstance(raw_ibans, list) else []
    fingerprints = _dedupe(
        _payment_destination_fingerprint(entry.get("value") if isinstance(entry, Mapping) else entry)
        for entry in raw_ibans
        if (entry.get("value") if isinstance(entry, Mapping) else entry)
    )

    raw_cuis = identifiers.get("cuis") if isinstance(identifiers, Mapping) else []
    raw_cuis = raw_cuis if isinstance(raw_cuis, list) else []
    normalized_cui = "".join(ch for ch in str(cui or (raw_cuis[0] if raw_cuis else "")) if ch.isdigit())
    actions = _dedupe(str(value or "").strip().lower() for value in requested_actions or [])
    normalized_signals = _dedupe(str(value or "").strip().lower() for value in signals or [])
    normalized_currency = str(currency or "").strip().upper() or None
    beneficiary = payment.get("beneficiary") if isinstance(payment, Mapping) else None
    entity_value = entity_name or beneficiary
    entity_core = _entity_core(entity_value)

    return {
        "schema": PAYMENT_CASE_FACTS_SCHEMA,
        "artifact_type": str(artifact_type or "unknown").strip().lower() or "unknown",
        "entity": {
            "name_fingerprint": _entity_fingerprint(entity_value),
            "name_token_count": len(entity_core.split()) if entity_core else 0,
            "cui": normalized_cui or None,
        },
        "payment": {
            "requested": bool(set(actions) & _PAYMENT_ACTIONS),
            "destination_fingerprints": fingerprints,
            "amount": _normalized_amount(amount),
            "currency": normalized_currency,
        },
        "requested_actions": actions,
        "signals": normalized_signals,
        "domains": _dedupe(str(value or "").strip().lower() for value in domains or []),
        "provenance": str(evidence_provenance or "unknown").strip().lower() or "unknown",
        "privacy": {
            "raw_payment_destination_persisted": False,
            "raw_artifact_text_persisted": False,
        },
    }


def build_payment_case_facts_from_scan(
    *,
    artifact_type: str,
    analysis_input_type: str,
    raw_text: str,
    pre_redaction_evidence: Mapping[str, Any] | None = None,
    action_asset: Mapping[str, Any] | None = None,
    urls: Sequence[str] | None = None,
) -> dict[str, Any]:
    """Project ephemeral scanner inputs into the persistable case contract."""

    from services.offer_parser import parse_offer

    scan_urls = [str(value) for value in urls or [] if str(value).strip()]
    parse_mode = "invoice" if str(analysis_input_type).lower() == "invoice" else "offer"
    fields = parse_offer(str(raw_text or ""), links=scan_urls, input_type=parse_mode)
    domains: list[str] = []
    for url in scan_urls:
        hostname = (urllib.parse.urlparse(url).hostname or "").strip(".").lower()
        if hostname and hostname not in domains:
            domains.append(hostname)

    return build_payment_case_facts(
        artifact_type=artifact_type,
        pre_redaction_evidence=pre_redaction_evidence,
        entity_name=fields.issuer_name or fields.emitent or fields.payment_beneficiary,
        cui=fields.cui,
        amount=fields.total,
        currency=fields.currency,
        requested_actions=(
            ["pay_invoice"]
            if parse_mode == "invoice" and (fields.iban or fields.total is not None)
            else []
        ),
        # Action & Asset remains shadow-only. Final gate reasons enrich these
        # facts immediately before the server registers an attachable artifact.
        signals=[],
        domains=domains,
        evidence_provenance="server_extracted",
    )


def enrich_payment_case_facts_with_final_gate(
    facts: Mapping[str, Any],
    reason_codes: Sequence[str] | None,
) -> dict[str, Any]:
    """Apply only final, user-facing gate evidence to persistable case facts."""

    enriched = copy.deepcopy(dict(facts))
    normalized_reasons = _dedupe(str(value or "").strip().lower() for value in reason_codes or [])
    signals = _dedupe([*(enriched.get("signals") or []), *normalized_reasons])
    enriched["signals"] = signals
    payment = enriched.get("payment") if isinstance(enriched.get("payment"), Mapping) else {}
    payment = dict(payment)
    if set(normalized_reasons) & _FINAL_PAYMENT_REQUEST_REASONS:
        payment["requested"] = True
    enriched["payment"] = payment
    return enriched


def build_case_artifact(
    *,
    artifact_ref: str,
    artifact_type: str,
    verdict: str,
    is_final: bool,
    reason_codes: Sequence[str] | None = None,
    facts: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    return {
        "schema": PAYMENT_CASE_ARTIFACT_SCHEMA,
        "artifact_ref": str(artifact_ref or "").strip(),
        "artifact_type": str(artifact_type or "unknown").strip().lower() or "unknown",
        "verdict": _normalized_verdict(verdict),
        "is_final": bool(is_final),
        "reason_codes": _dedupe(str(value or "") for value in reason_codes or []),
        "facts": dict(facts) if isinstance(facts, Mapping) else {},
    }


def _amount_contradiction(artifacts: Sequence[Mapping[str, Any]]) -> dict[str, Any] | None:
    amounts_by_currency: dict[str, set[Decimal]] = {}
    refs_by_currency: dict[str, list[str]] = {}
    for artifact in artifacts:
        facts = artifact.get("facts") if isinstance(artifact.get("facts"), Mapping) else {}
        payment = facts.get("payment") if isinstance(facts.get("payment"), Mapping) else {}
        amount_raw = payment.get("amount")
        currency = str(payment.get("currency") or "").upper()
        if not amount_raw or not currency:
            continue
        try:
            amount = Decimal(str(amount_raw))
        except InvalidOperation:
            continue
        amounts_by_currency.setdefault(currency, set()).add(amount)
        refs_by_currency.setdefault(currency, []).append(str(artifact.get("artifact_ref") or ""))
    if len(amounts_by_currency) > 1:
        return {
            "code": "AMOUNT_CONTRADICTION",
            "severity": "verify",
            "artifact_refs": _dedupe(ref for refs in refs_by_currency.values() for ref in refs),
            "message": "Moneda cerută nu este aceeași în toate documentele. Verifică totalul înainte de plată.",
        }
    for currency, values in amounts_by_currency.items():
        if len(values) > 1:
            return {
                "code": "AMOUNT_CONTRADICTION",
                "severity": "verify",
                "artifact_refs": _dedupe(refs_by_currency[currency]),
                "message": "Suma cerută nu este aceeași în toate documentele. Verifică totalul înainte de plată.",
            }
    return None


def _entity_contradiction(artifacts: Sequence[Mapping[str, Any]]) -> dict[str, Any] | None:
    cuis: dict[str, list[str]] = {}
    names: dict[str, list[str]] = {}
    for artifact in artifacts:
        facts = artifact.get("facts") if isinstance(artifact.get("facts"), Mapping) else {}
        entity = facts.get("entity") if isinstance(facts.get("entity"), Mapping) else {}
        ref = str(artifact.get("artifact_ref") or "")
        cui = str(entity.get("cui") or "")
        name = str(entity.get("name_fingerprint") or "")
        name_token_count = int(entity.get("name_token_count") or 0)
        if cui:
            cuis.setdefault(cui, []).append(ref)
        if name and name_token_count >= 2:
            names.setdefault(name, []).append(ref)
    if len(cuis) > 1:
        return {
            "code": "ENTITY_CONTRADICTION",
            "severity": "verify",
            "artifact_refs": _dedupe(ref for refs in cuis.values() for ref in refs),
            "message": "Firma identificată nu este aceeași în toate artefactele. Confirmă emitentul înainte de plată.",
        }
    # Names alone are weaker than CUI. Flag only clearly different multi-token
    # legal names; short brands and aliases remain unconfirmed, not contradicted.
    if not cuis and len(names) > 1:
        return {
            "code": "ENTITY_CONTRADICTION",
            "severity": "verify",
            "artifact_refs": _dedupe(ref for refs in names.values() for ref in refs),
            "message": "Numele firmei diferă între documente. Confirmă cine solicită plata.",
        }
    return None


def _destination_contradiction(artifacts: Sequence[Mapping[str, Any]]) -> dict[str, Any] | None:
    destinations: dict[str, list[str]] = {}
    signals: set[str] = set()
    for artifact in artifacts:
        facts = artifact.get("facts") if isinstance(artifact.get("facts"), Mapping) else {}
        payment = facts.get("payment") if isinstance(facts.get("payment"), Mapping) else {}
        signals.update(str(value or "").lower() for value in facts.get("signals") or [])
        if payment.get("requested") is not True:
            continue
        for fingerprint in payment.get("destination_fingerprints") or []:
            destinations.setdefault(str(fingerprint), []).append(str(artifact.get("artifact_ref") or ""))
    if len(destinations) <= 1:
        return None
    hard = bool(signals & _ACCOUNT_CHANGE_SIGNALS)
    return {
        "code": "PAYMENT_DESTINATION_CONTRADICTION",
        "severity": "danger" if hard else "verify",
        "artifact_refs": _dedupe(ref for refs in destinations.values() for ref in refs),
        "message": (
            "Mesajul schimbă contul de plată față de document. Nu transfera bani până nu confirmi direct cu firma."
            if hard
            else "Documentele indică destinații de plată diferite. Confirmă beneficiarul în aplicația băncii."
        ),
    }


def reduce_payment_case(artifacts: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    normalized = [
        build_case_artifact(
            artifact_ref=str(item.get("artifact_ref") or ""),
            artifact_type=str(item.get("artifact_type") or "unknown"),
            verdict=str(item.get("verdict") or "UNVERIFIED"),
            is_final=item.get("is_final") is True,
            reason_codes=item.get("reason_codes") if isinstance(item.get("reason_codes"), list) else [],
            facts=item.get("facts") if isinstance(item.get("facts"), Mapping) else {},
        )
        for item in artifacts
        if isinstance(item, Mapping)
    ]
    if not normalized:
        return {
            "schema": PAYMENT_CASE_RESULT_SCHEMA,
            "verdict": "UNVERIFIED",
            "artifact_count": 0,
            "reason_codes": ["payment_case_empty"],
            "contradictions": [],
            "message": "Adaugă factura, mesajul sau oferta pentru a verifica plata.",
        }

    verdict = max((item["verdict"] for item in normalized), key=lambda item: _VERDICT_RANK[item])
    reason_codes = _dedupe(code for item in normalized for code in item.get("reason_codes") or [])
    if any(item.get("is_final") is not True for item in normalized) and _VERDICT_RANK[verdict] < _VERDICT_RANK["SUSPECT"]:
        verdict = "UNVERIFIED"
        reason_codes.append("payment_case_incomplete")

    contradictions = [
        item
        for item in (
            _destination_contradiction(normalized),
            _entity_contradiction(normalized),
            _amount_contradiction(normalized),
        )
        if item is not None
    ]
    if any(item["severity"] == "danger" for item in contradictions):
        verdict = "DANGEROUS"
        reason_codes.append("cross_artifact_payment_destination_changed")
    elif contradictions and _VERDICT_RANK[verdict] < _VERDICT_RANK["SUSPECT"]:
        verdict = "SUSPECT"
        code_map = {
            "PAYMENT_DESTINATION_CONTRADICTION": "cross_artifact_payment_destination_mismatch",
            "ENTITY_CONTRADICTION": "cross_artifact_entity_mismatch",
            "AMOUNT_CONTRADICTION": "cross_artifact_amount_mismatch",
        }
        reason_codes.extend(code_map[item["code"]] for item in contradictions if item["code"] in code_map)

    message = {
        "SAFE": "Documentele verificate sunt coerente și nu am găsit contradicții de plată.",
        "UNVERIFIED": "Nu avem încă suficiente dovezi finale pentru întreaga cerere de plată.",
        "SUSPECT": "Am găsit informații care trebuie confirmate înainte de plată.",
        "DANGEROUS": "Nu continua plata. Cel puțin o dovadă sau o contradicție indică fraudă.",
    }[verdict]
    if contradictions:
        message = contradictions[0]["message"]

    return {
        "schema": PAYMENT_CASE_RESULT_SCHEMA,
        "verdict": verdict,
        "artifact_count": len(normalized),
        "reason_codes": _dedupe(reason_codes),
        "contradictions": contradictions,
        "message": message,
    }
