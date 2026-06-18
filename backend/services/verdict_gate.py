from __future__ import annotations

from typing import Any, Dict, List


INTERNAL_LABELS = {"DANGEROUS", "SUSPECT", "UNVERIFIED", "SAFE"}
USER_LABELS = {"DANGEROUS", "SUSPECT", "UNVERIFIED", "SAFE"}

HARD_SENSITIVE_REQUESTS = {"card", "cvv", "otp", "password", "pin", "banking_pin", "cnp", "iban", "crypto", "remote", "apk", "id_document"}
MONEY_OR_VALUE_REQUESTS = {"transfer"}
WRONG_CHANNELS = {"reply", "whatsapp", "unofficial_site", "phone", "sms", "telegram", "messenger", "social_dm"}
BAD_IDENTITY = {"lookalike", "unrelated"}
TRUSTED_IDENTITY = {"official", "delegated", "coherent", "official_match"}
PROVIDER_MALICIOUS = {"malicious", "phishing", "malware", "dangerous", "blacklisted"}
PROVIDER_SUSPICIOUS = {"suspicious"}
PROVIDER_CLEAN = {"clean", "no_match", "safe"}
PROVIDER_ERROR = {"error"}
PROVIDER_PENDING = {"pending", "running", "queued", "scanning"}
INCOMPLETE_RESOLUTION = {"failed", "partial", "pending", "unknown", ""}
ESTABLISHED_DOMAIN_AGE_DAYS = 365
CAMPAIGN_MATCH_HIGH_CONFIDENCE_THRESHOLD = 0.82
PUBLIC_NAVIGATION_INPUT_TYPES = {
    "qr",
    "qr_scan",
    "android_qr_scan",
    "url",
    "url_scan",
    "android_url_scan",
    "manual_url_scan",
}
PUBLIC_URL_TEXT_INPUT_TYPES = {"android_native", "text", "visible_text", "share_text"}


def _section(bundle: Dict[str, Any], name: str) -> Dict[str, Any]:
    value = bundle.get(name)
    return value if isinstance(value, dict) else {}


def _norm(value: Any) -> str:
    return str(value or "").strip().lower()


def _bool(value: Any) -> bool:
    return bool(value) if value is not None else False


def _result(
    label: str,
    reason_codes: List[str],
    *,
    confidence: int | None = None,
    is_final: bool | None = None,
) -> Dict[str, Any]:
    label = label if label in INTERNAL_LABELS else "UNVERIFIED"
    risk_level = {
        "SAFE": "low",
        "UNVERIFIED": "info",
        "SUSPECT": "medium",
        "DANGEROUS": "high",
    }[label]
    risk_score = {
        "SAFE": 10,
        "UNVERIFIED": 25,
        "SUSPECT": 55,
        "DANGEROUS": 90,
    }[label]
    return {
        "label": label,
        "risk_level": risk_level,
        "risk_score": risk_score,
        "reason_codes": reason_codes,
        "confidence": confidence if confidence is not None else (60 if label == "UNVERIFIED" else 80),
        "is_final": (label != "UNVERIFIED") if is_final is None else is_final,
    }


def _providers_verdict(providers: Dict[str, Any]) -> str:
    value = _norm(providers.get("verdict"))
    if value:
        return value

    saw_clean = False
    saw_suspicious = False
    saw_pending = False
    saw_error = False
    for key, raw in providers.items():
        if key in {"hits", "completeness"} or not isinstance(raw, dict):
            continue
        source_status = _norm(raw.get("status") or raw.get("verdict"))
        severity = _norm(raw.get("severity"))
        if source_status in PROVIDER_MALICIOUS or severity == "high":
            return "malicious"
        if source_status in PROVIDER_SUSPICIOUS:
            saw_suspicious = True
        if source_status in PROVIDER_PENDING:
            saw_pending = True
        elif source_status in PROVIDER_ERROR:
            saw_error = True
        elif source_status in PROVIDER_CLEAN:
            saw_clean = True

    if saw_pending:
        return "pending"
    if saw_suspicious:
        return "suspicious"
    if saw_error and not saw_clean:
        return "error"
    if saw_clean and not saw_error:
        return "clean"
    return "unknown"


def _required_completeness(bundle: Dict[str, Any]) -> bool:
    required_sections = ("resolution", "providers", "identity", "request", "semantic_review")
    for name in required_sections:
        section = _section(bundle, name)
        if section.get("completeness") is False:
            return False
    return True


def _semantic_risk(semantic: Dict[str, Any]) -> str:
    for key in ("risk_class", "severity", "confidence_class"):
        value = _norm(semantic.get(key))
        if value in {"high", "medium", "low", "benign"}:
            return value
    if _bool(semantic.get("claim_matches_known_scam_family")):
        return "high"
    if _bool(semantic.get("claim_matches_legit_template")):
        return "benign"
    return "unknown"


def _is_safety_education_semantic(semantic: Dict[str, Any]) -> bool:
    matched_template = _norm(semantic.get("matched_template"))
    reason_codes = semantic.get("reason_codes") if isinstance(semantic.get("reason_codes"), list) else []
    return matched_template == "safety_education" or "semantic:safety_education_scope" in {
        _norm(code) for code in reason_codes
    }


def _domain_age_days(identity: Dict[str, Any]) -> int | None:
    try:
        value = identity.get("domain_age_days")
        return int(value) if value is not None else None
    except (TypeError, ValueError):
        return None


def _domain_is_established(identity: Dict[str, Any]) -> bool:
    reputation = _norm(identity.get("domain_reputation"))
    age_days = _domain_age_days(identity)
    return reputation == "established" or (
        age_days is not None and age_days >= ESTABLISHED_DOMAIN_AGE_DAYS
    )


def _domain_is_young(identity: Dict[str, Any]) -> bool:
    age_days = _domain_age_days(identity)
    return age_days is not None and age_days < 30


def _looks_like_bare_public_url_text(value: Any) -> bool:
    text = str(value or "").strip()
    if not text:
        return False
    lowered = text.lower()
    for prefix in ("link:", "url:"):
        if lowered.startswith(prefix):
            text = text[len(prefix):].strip()
            lowered = text.lower()
            break
    if not text or any(char.isspace() for char in text):
        return False
    return lowered.startswith(("https://", "http://", "hxxps://", "hxxp://", "www."))


def _has_impersonated_brand(identity: Dict[str, Any]) -> bool:
    status = _norm(identity.get("status"))
    return status in {"lookalike", "unrelated", "mismatch"}


def _has_positive_provenance(identity: Dict[str, Any], provenance: Dict[str, Any]) -> bool:
    """SAFE requires positive provenance match.
    
    A message can prove it comes from the claimed entity via:
    - TRUSTED_IDENTITY status (official/delegated/coherent/official_match) from BTR
    - provenance.official_domain_match == True
    - provenance.official_email_match == True
    - provenance.official_shortcode_match == True
    - provenance.official_phone_match == True
    """
    identity_status = _norm(identity.get("status"))
    if identity_status in TRUSTED_IDENTITY:
        return True
    if _bool(provenance.get("official_domain_match")):
        return True
    if _bool(provenance.get("official_email_match")):
        return True
    if _bool(provenance.get("official_shortcode_match")):
        return True
    if _bool(provenance.get("official_phone_match")):
        return True
    return False


def _has_trusted_payment_destination(providers: Dict[str, Any]) -> bool:
    payment = providers.get("payment_destination")
    if not isinstance(payment, dict):
        return False
    status = _norm(payment.get("status") or payment.get("verdict"))
    trust_tier = _norm(payment.get("trust_tier"))
    return (
        status in PROVIDER_CLEAN
        and _bool(payment.get("matched"))
        and (
            _bool(payment.get("brand_matches"))
            or _bool(payment.get("cui_matches"))
        )
        and trust_tier
        in {
            "t0_partner_signed",
            "t1_public_official",
            "t2_official_document_chain",
        }
    )


def _has_checked_payment_destination(providers: Dict[str, Any]) -> bool:
    payment = providers.get("payment_destination")
    if not isinstance(payment, dict):
        return False
    return any(
        key in payment
        for key in (
            "matched",
            "brand_matches",
            "cui_matches",
            "registry_has_brand_destinations",
            "trust_tier",
            "can_contribute_to_safe",
        )
    )


def _is_clean_coherent_invoice_without_registry_destination(
    *,
    identity_status: str,
    channel: str,
    semantic_risk: str,
    providers: Dict[str, Any],
) -> bool:
    if identity_status != "coherent" or channel != "invoice" or semantic_risk not in {"low", "benign"}:
        return False
    payment = providers.get("payment_destination")
    if isinstance(payment, dict):
        payment_status = _norm(payment.get("status") or payment.get("verdict"))
        if payment_status in PROVIDER_MALICIOUS or payment_status in PROVIDER_SUSPICIOUS:
            return False
        if _bool(payment.get("registry_has_brand_destinations")):
            return False
    return True


def _is_low_risk_public_navigation(
    *,
    bundle: Dict[str, Any],
    identity: Dict[str, Any],
    identity_status: str,
    provider_verdict: str,
    sensitive: str,
    semantic_risk: str,
    tld_suspicious: bool,
) -> bool:
    input_section = _section(bundle, "input")
    input_type = _norm(input_section.get("type"))
    claimed_brand = _norm(identity.get("claimed_brand"))
    is_public_navigation_input = input_type in PUBLIC_NAVIGATION_INPUT_TYPES
    is_android_bare_url_input = (
        input_type in PUBLIC_URL_TEXT_INPUT_TYPES
        and _looks_like_bare_public_url_text(input_section.get("redacted_text"))
    )
    if not (is_public_navigation_input or is_android_bare_url_input):
        return False
    if claimed_brand and claimed_brand not in {"none", "unknown", "nespecificat"}:
        return False
    if identity_status != "unknown":
        return False
    if provider_verdict not in PROVIDER_CLEAN:
        return False
    if sensitive != "none":
        return False
    if semantic_risk not in {"unknown", "low", "benign"}:
        return False
    if tld_suspicious or not _domain_is_established(identity):
        return False
    if _bool(identity.get("brand_token_mismatch")):
        return False
    if _bool(identity.get("host_unreachable")):
        return False
    context = _section(bundle, "context")
    if _bool(context.get("apk_or_remote_mention")):
        return False
    return True


def _campaign_match_high_enough(campaign: Dict[str, Any]) -> bool:
    """Campaign fingerprint match solo -> max SUSPECT."""
    status = _norm(campaign.get("status"))
    if status != "match":
        return False
    try:
        confidence = float(campaign.get("confidence") or 0.0)
    except (TypeError, ValueError):
        confidence = 0.0
    return confidence >= CAMPAIGN_MATCH_HIGH_CONFIDENCE_THRESHOLD


def _has_violated_never_asks(identity: Dict[str, Any]) -> List[str]:
    return identity.get("violated_never_asks") or []


def _has_violated_never_does(identity: Dict[str, Any]) -> List[str]:
    return identity.get("violated_never_does") or []


def verdict(bundle: Dict[str, Any]) -> Dict[str, Any]:
    """EvidenceGate unic — 4 stări.

    Determinist, auditabil. AI/LLM/conversație = medium maximum, nu pot produce
    singure DANGEROUS sau SAFE.

    safe_requires: positive_provenance_match
    default_when_no_signal: UNVERIFIED
    """
    resolution = _section(bundle, "resolution")
    providers = _section(bundle, "providers")
    identity = _section(bundle, "identity")
    request = _section(bundle, "request")
    semantic = _section(bundle, "semantic_review")
    provenance = _section(bundle, "provenance")
    campaign = _section(bundle, "campaign_match")
    community = _section(bundle, "community")

    provider_verdict = _providers_verdict(providers)
    identity_status = _norm(identity.get("status") or "unknown")
    resolution_status = _norm(resolution.get("status") or "unknown")
    sensitive = _norm(request.get("sensitive") or "none")
    channel = _norm(request.get("channel") or "unknown")
    semantic_status = _norm(semantic.get("status") or "pending")
    semantic_risk = _semantic_risk(semantic)
    tld_suspicious = _bool(identity.get("tld_suspicious"))
    hard_sensitive = sensitive in HARD_SENSITIVE_REQUESTS
    value_sensitive = sensitive in MONEY_OR_VALUE_REQUESTS
    wrong_channel = channel in WRONG_CHANNELS
    has_provenance = _has_positive_provenance(identity, provenance)
    campaign_high = _campaign_match_high_enough(campaign)
    try:
        community_reports = int(community.get("reports") or 0)
    except (TypeError, ValueError):
        community_reports = 0
    violated_never_asks = _has_violated_never_asks(identity)
    violated_never_does = _has_violated_never_does(identity)
    provider_is_error = provider_verdict in PROVIDER_ERROR

    # ─── Rule 1: Hard external evidence wins ────────────────────────────────
    if provider_verdict in PROVIDER_MALICIOUS:
        return _result("DANGEROUS", ["provider_malicious"], confidence=95)

    # ─── Rule 1b: Safety education is not an action request ─────────────────
    if _is_safety_education_semantic(semantic) and not hard_sensitive and not value_sensitive:
        if has_provenance and provider_verdict in PROVIDER_CLEAN:
            return _result("SAFE", ["positive_provenance_clean", "safety_education_not_action_request"], confidence=92)
        return _result("UNVERIFIED", ["safety_education_not_action_request"], confidence=0, is_final=True)

    # ─── Rule 2: BTR mismatch + sensitive request ───────────────────────────
    if identity_status in BAD_IDENTITY and (hard_sensitive or value_sensitive or tld_suspicious):
        return _result("DANGEROUS", ["identity_spoof"], confidence=90)

    # ─── Rule 2b: Determinist combo ────────────────────────────────────────
    if (
        _domain_is_young(identity)
        and identity.get("ssl_invalid")
        and _has_impersonated_brand(identity)
    ):
        return _result(
            "DANGEROUS",
            ["young_domain_invalid_ssl_impersonation"],
            confidence=92,
        )

    # ─── Rule 2c: Person manifest "never_does" violated ────────────────────
    if violated_never_does:
        reason_codes = [f"never_does_violated:{v}" for v in violated_never_does]
        return _result("DANGEROUS", reason_codes, confidence=94)

    # ─── Rule 2d: BTR "never_asks" violated on wrong channel ───────────────
    if violated_never_asks and wrong_channel:
        reason_codes = [f"never_asks_violated:{v}" for v in violated_never_asks]
        return _result("DANGEROUS", reason_codes, confidence=92)

    # ─── Rule 2e: Whitelist violation in combo with sensitive ──────────────
    # (whitelist official domain violated would come via identity_status mismatch)

    # ─── Rule 3: Sensitive on wrong channel ─────────────────────────────────
    if hard_sensitive and wrong_channel:
        return _result("DANGEROUS", ["sensitive_wrong_channel"], confidence=90)
    if value_sensitive and wrong_channel and semantic_risk == "high":
        return _result(
            "DANGEROUS",
            ["semantic_high_value_request"],
            confidence=88,
        )
    if identity_status in BAD_IDENTITY and value_sensitive and (
        semantic_risk == "high" or tld_suspicious
    ):
        return _result(
            "DANGEROUS",
            ["identity_spoof_value_request"],
            confidence=88,
        )

    # ─── Rule 4: Incomplete evidence → UNVERIFIED ──────────────────────────
    if (
        resolution_status in INCOMPLETE_RESOLUTION
        or provider_verdict in PROVIDER_PENDING
        or semantic_status != "done"
        or not _required_completeness(bundle)
    ):
        return _result("UNVERIFIED", ["insufficient_evidence"], confidence=0)

    # ─── Rule 5: Provider error blocks SAFE but allows SUSPECT ─────────────
    # Moved after all DANGEROUS checks but before SAFE.
    if provider_is_error:
        if has_provenance:
            return _result("UNVERIFIED", ["provider_error"], confidence=0, is_final=True)
        return _result("SUSPECT", ["provider_error"], confidence=55)

    # ─── Rule 7: Campaign fingerprint match solo → max SUSPECT ────────────
    if campaign_high and not has_provenance:
        return _result("SUSPECT", ["campaign_match_only"], confidence=68)

    # ─── Rule 8: Semantic high + sensitive combo ───────────────────────────
    if semantic_risk == "high" and (hard_sensitive or value_sensitive or identity_status in BAD_IDENTITY):
        return _result("DANGEROUS", ["semantic_high_risk_match"], confidence=86)

    # ─── Rule 6: Weighted provider warning → SUSPECT, not DANGEROUS ────────
    if provider_verdict in PROVIDER_SUSPICIOUS:
        return _result("SUSPECT", ["provider_suspicious"], confidence=70)

    # ─── Rule 8b: Raport comunitar singular → max SUSPECT ──────────────────
    # Doar dacă e singurul semnal (fără proveniență pozitivă). Niciodată DANGEROUS solo.
    if community_reports >= 1 and not has_provenance:
        return _result("SUSPECT", ["community_report_only"], confidence=64)

    # ─── Rule 8c: Money transfer needs confirmed destination ───────────────
    if (
        value_sensitive
        and has_provenance
        and not _has_trusted_payment_destination(providers)
        and not _is_clean_coherent_invoice_without_registry_destination(
            identity_status=identity_status,
            channel=channel,
            semantic_risk=semantic_risk,
            providers=providers,
        )
    ):
        return _result("SUSPECT", ["value_request_needs_verification"], confidence=70)

    # ─── Rule 9: SAFE via positive provenance ──────────────────────────────
    # SAFE requires BTR match + zero sensitive + provider clean + URL final
    if (
        has_provenance
        and provider_verdict in PROVIDER_CLEAN
        and not (hard_sensitive and wrong_channel)
        and not violated_never_asks
    ):
        return _result("SAFE", ["positive_provenance_clean"], confidence=92)

    # ─── Rule 9b: Public navigation QR/URL clean → SAFE ───────────────────
    # A QR/menu/catalog link is not an invoice, bank login, or identity claim.
    # If it is a direct public-navigation scan, all providers are clean, the
    # domain is established, and there is no sensitive ask, do not punish it for
    # lacking a brand registry entry.
    if _is_low_risk_public_navigation(
        bundle=bundle,
        identity=identity,
        identity_status=identity_status,
        provider_verdict=provider_verdict,
        sensitive=sensitive,
        semantic_risk=semantic_risk,
        tld_suspicious=tld_suspicious,
    ):
        input_type = _norm(_section(bundle, "input").get("type"))
        reason = "clean_public_navigation_qr" if "qr" in input_type else "clean_public_navigation_url"
        return _result("SAFE", [reason], confidence=88)

    # ─── Rule 9c: Brand-token lookalike → SUSPECT (never SAFE/UNVERIFIED) ──
    if _bool(identity.get("brand_token_mismatch")) and provider_verdict in PROVIDER_CLEAN:
        return _result("SUSPECT", ["brand_token_lookalike"], confidence=75)

    # ─── Rule 10: Unknown provenance + clean → UNVERIFIED (NOT SAFE) ──────
    if identity_status == "unknown" and provider_verdict in PROVIDER_CLEAN and sensitive == "none":
        if _domain_is_established(identity) and not tld_suspicious:
            return _result("UNVERIFIED", ["unknown_but_clean_established"], confidence=0)
        return _result("UNVERIFIED", ["unknown_but_clean"], confidence=0)

    # ─── Rule 11: Value transfer without decisive evidence → SUSPECT ──────
    if value_sensitive and not has_provenance:
        return _result("SUSPECT", ["value_request_needs_verification"], confidence=70)

    # ─── Rule 11b: Bad identity (lookalike/unrelated) without sensitive → SUSPECT ──
    if identity_status in BAD_IDENTITY and provider_verdict in PROVIDER_CLEAN:
        return _result("SUSPECT", ["lookalike_identity_no_sensitive"], confidence=65)

    # ─── Rule 12: Residual ────────────────────────────────────────────────
    return _result("UNVERIFIED", ["residual"], confidence=60, is_final=True)
