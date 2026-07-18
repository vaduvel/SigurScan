"""Shadow-only protected-action policy over the canonical Action & Asset contract."""

from __future__ import annotations

from typing import Any, Dict, Mapping, Optional

from services.action_asset import (
    build_action_asset_contract,
    normalize_action_asset_contract,
)


PROTECTED_ACTION_SHADOW_SCHEMA = "sigurscan_protected_action_shadow_v1"

_RISKY_CHANNELS = {"phone", "sms", "whatsapp", "social", "email", "audio"}
_TRUSTED_IDENTITIES = {"official", "delegated", "coherent", "official_match"}
_BAD_IDENTITIES = {"lookalike", "unrelated", "mismatch", "spoofed"}
_LABEL_RANK = {"SAFE": 0, "UNVERIFIED": 1, "SUSPECT": 2, "DANGEROUS": 3}


def _payment_destination_from_bundle(
    decision_bundle: Optional[Mapping[str, Any]],
) -> Optional[Mapping[str, Any]]:
    bundle = decision_bundle if isinstance(decision_bundle, Mapping) else {}
    providers = bundle.get("providers") if isinstance(bundle.get("providers"), Mapping) else {}
    direct = providers.get("payment_destination")
    if isinstance(direct, Mapping):
        return direct
    context = bundle.get("context") if isinstance(bundle.get("context"), Mapping) else {}
    cross_scan = context.get("cross_scan_knowledge")
    cross_scan = cross_scan if isinstance(cross_scan, Mapping) else {}
    destinations = cross_scan.get("payment_destinations")
    if isinstance(destinations, list):
        return next((item for item in destinations if isinstance(item, Mapping)), None)
    return None


def _payment_trust(payment_destination: Optional[Mapping[str, Any]]) -> str:
    payment = payment_destination if isinstance(payment_destination, Mapping) else {}
    if payment.get("brand_matches") is False and payment.get("cui_matches") is not True:
        return "mismatched"
    if payment.get("matched") is True and payment.get("can_contribute_to_safe") is True:
        return "confirmed"
    if payment.get("matched") is True:
        return "partially_confirmed"
    explicit = str(payment.get("trust") or "").strip().lower()
    if explicit in {"confirmed", "partially_confirmed", "mismatched", "changed", "unknown"}:
        return explicit
    return "unknown"


def evaluate_protected_action_shadow(
    contract: Any,
    *,
    decision_bundle: Optional[Mapping[str, Any]] = None,
    identity_status: Optional[str] = None,
    payment_destination: Optional[Mapping[str, Any]] = None,
    actual_label: Optional[str] = None,
) -> Dict[str, Any]:
    """Project a verdict floor for measurement without applying it."""

    normalized = normalize_action_asset_contract(contract)
    bundle = decision_bundle if isinstance(decision_bundle, Mapping) else {}
    identity = bundle.get("identity") if isinstance(bundle.get("identity"), Mapping) else {}
    resolved_identity = str(identity_status or identity.get("status") or "unknown").strip().lower()
    payment_destination = payment_destination or _payment_destination_from_bundle(bundle)
    payment_trust = _payment_trust(payment_destination)
    destination = dict(normalized.get("destination") or {})
    if payment_trust != "unknown":
        destination["trust"] = payment_trust
    destination.setdefault("type", "unknown")
    destination.setdefault("changed", False)
    normalized["destination"] = destination

    protected = set(normalized["protected_actions"])
    requested_actions = set(normalized["requested_actions"])
    compositions = set(normalized["composition_rules"])
    assets = set(normalized["requested_assets"])
    positive = normalized["positive_request"] is True
    proof_required = bool(positive and (protected or "guided_banking" in compositions))
    identity_confirmed = resolved_identity in _TRUSTED_IDENTITIES
    identity_mismatched = resolved_identity in _BAD_IDENTITIES
    money_related = bool(
        protected.intersection(
            {
                "transfer_money",
                "change_payment_destination",
                "pay_to_receive",
                "transfer_alternative_value",
                "scan_payment_qr",
            }
        )
        or assets.intersection({"money", "iban", "crypto", "gift_card", "payment_qr"})
    )
    if not proof_required:
        proof_status = "not_required"
    elif money_related:
        proof_status = (
            "satisfied"
            if identity_confirmed
            and destination.get("trust") == "confirmed"
            and not destination.get("changed")
            else "blocked"
        )
    else:
        proof_status = (
            "satisfied"
            if identity_confirmed and normalized["channel"] not in _RISKY_CHANNELS
            else "blocked"
        )

    candidate: Optional[str] = None
    reasons: list[str] = []
    if proof_required and identity_mismatched:
        candidate = "DANGEROUS"
        reasons.append("protected_action_identity_mismatch")
    elif (
        positive
        and requested_actions.intersection(
            {"share_code", "share_credentials", "share_card_data"}
        )
        and normalized["channel"] in _RISKY_CHANNELS
    ):
        candidate = "DANGEROUS"
        reasons.append("protected_authentication_secret_wrong_channel")
    elif positive and "guided_banking" in compositions and normalized["channel"] in {
        "phone",
        "audio",
    }:
        candidate = "DANGEROUS"
        reasons.append("guided_banking_during_call")
    elif positive and "remote_access_install" in compositions and (
        normalized["claimed_actor"] == "bank"
        or assets.intersection({"money", "bank_account"})
    ):
        candidate = "DANGEROUS"
        reasons.append("remote_access_with_banking_context")
    elif (
        positive
        and "transfer_to_changed_destination" in compositions
        and destination.get("trust") != "confirmed"
    ):
        candidate = "DANGEROUS"
        reasons.append("transfer_to_changed_unconfirmed_destination")
    elif proof_required and proof_status == "blocked":
        candidate = "SUSPECT"
        reasons.append("protected_action_requires_proof")

    actual = str(actual_label or "").strip().upper() or None
    would_raise = bool(
        candidate
        and actual in _LABEL_RANK
        and _LABEL_RANK[candidate] > _LABEL_RANK[actual]
    )
    return {
        "schema": PROTECTED_ACTION_SHADOW_SCHEMA,
        "shadow_only": True,
        "contract": normalized,
        "proof_before_safe": {
            "required": proof_required,
            "status": proof_status,
            "identity_trust": (
                "confirmed"
                if identity_confirmed
                else "mismatched"
                if identity_mismatched
                else "unknown"
            ),
            "destination_trust": str(destination.get("trust") or "unknown"),
        },
        "candidate_min_label": candidate,
        "reason_codes": reasons,
        "actual_label": actual,
        "would_raise_actual": would_raise,
        "applied_to_verdict": False,
        "raw_text_persisted": False,
    }


def build_action_asset_shadow(
    raw_text: str,
    *,
    source_channel: Optional[str] = None,
    pre_redaction_summary: Optional[Mapping[str, Any]] = None,
) -> Dict[str, Any]:
    return evaluate_protected_action_shadow(
        build_action_asset_contract(
            raw_text,
            source_channel=source_channel,
            pre_redaction_summary=pre_redaction_summary,
        )
    )
