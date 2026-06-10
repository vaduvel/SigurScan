from __future__ import annotations

from typing import Any, Dict, List


USER_LABELS = {"SIGUR", "SUSPECT", "PERICULOS"}
INTERNAL_LABELS = USER_LABELS | {"PENDING"}

HARD_SENSITIVE_REQUESTS = {"card", "otp", "password", "crypto", "remote"}
MONEY_OR_VALUE_REQUESTS = {"transfer"}
WRONG_CHANNELS = {"reply", "whatsapp", "unofficial_site", "phone"}
BAD_IDENTITY = {"lookalike", "unrelated"}
TRUSTED_IDENTITY = {"official", "delegated", "coherent"}
PROVIDER_MALICIOUS = {"malicious", "phishing", "malware", "dangerous", "blacklisted"}
PROVIDER_CLEAN = {"clean", "no_match", "safe"}
PENDING_VALUES = {"pending", "running", "queued", "scanning"}
INCOMPLETE_RESOLUTION = {"failed", "partial", "pending", "unknown", ""}
ESTABLISHED_DOMAIN_AGE_DAYS = 365


def _section(bundle: Dict[str, Any], name: str) -> Dict[str, Any]:
    value = bundle.get(name)
    return value if isinstance(value, dict) else {}


def _norm(value: Any) -> str:
    return str(value or "").strip().lower()


def _bool(value: Any) -> bool:
    return bool(value) if value is not None else False


def _result(label: str, reason_codes: List[str], *, confidence: int | None = None) -> Dict[str, Any]:
    label = label if label in INTERNAL_LABELS else "SUSPECT"
    risk_level = {
        "SIGUR": "low",
        "SUSPECT": "medium",
        "PERICULOS": "high",
        "PENDING": "pending",
    }[label]
    risk_score = {
        "SIGUR": 10,
        "SUSPECT": 55,
        "PERICULOS": 90,
        "PENDING": 0,
    }[label]
    return {
        "label": label,
        "risk_level": risk_level,
        "risk_score": risk_score,
        "reason_codes": reason_codes,
        "confidence": confidence if confidence is not None else (0 if label == "PENDING" else 80),
        "is_final": label != "PENDING",
    }


def _providers_verdict(providers: Dict[str, Any]) -> str:
    value = _norm(providers.get("verdict"))
    if value:
        return value

    # Backward-compatible adapter for provider summaries that have per-source
    # entries but no normalized aggregate verdict yet.
    saw_clean = False
    saw_pending = False
    saw_unknown = False
    for key, raw in providers.items():
        if key in {"hits", "completeness"} or not isinstance(raw, dict):
            continue
        source_status = _norm(raw.get("status") or raw.get("verdict"))
        severity = _norm(raw.get("severity"))
        if source_status in PROVIDER_MALICIOUS or severity == "high":
            return "malicious"
        if source_status in PENDING_VALUES:
            saw_pending = True
        elif source_status in PROVIDER_CLEAN:
            saw_clean = True
        else:
            saw_unknown = True
    if saw_pending:
        return "pending"
    if saw_clean and not saw_unknown:
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


def _cert_is_young(identity: Dict[str, Any]) -> bool:
    raw = identity.get("ssl_invalid")
    return bool(raw)


def _has_impersonated_brand(identity: Dict[str, Any]) -> bool:
    status = _norm(identity.get("status"))
    return status in {"lookalike", "unrelated"}


def verdict(bundle: Dict[str, Any]) -> Dict[str, Any]:
    """Pure SigurScan verdict reducer.

    This function is deliberately boring: no network, no file I/O, no regex over
    raw text, and no dependency on legacy scores. It only reads the normalized
    Evidence Bundle v2 produced by the pillars.
    """

    resolution = _section(bundle, "resolution")
    providers = _section(bundle, "providers")
    identity = _section(bundle, "identity")
    request = _section(bundle, "request")
    semantic = _section(bundle, "semantic_review")

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

    # 1. Hard external evidence wins.
    if provider_verdict in PROVIDER_MALICIOUS:
        return _result("PERICULOS", ["provider_malicious"], confidence=95)

    # 2. Clear impersonation plus dangerous request or suspicious TLD.
    if identity_status in BAD_IDENTITY and (tld_suspicious or hard_sensitive):
        return _result("PERICULOS", ["identity_spoof"], confidence=90)

    # 2a. RDAP 404: domain does not exist in registry → immediate hard danger.
    if identity.get("rdap_inexistent"):
        return _result("PERICULOS", ["domain_not_found"], confidence=95)

    # 2b. Deterministic combo: young domain (<30d) + invalid SSL + impersonated
    # brand → PERICULOS without any urlscan/LLM (FN=0 guard).
    if (
        _domain_is_young(identity)
        and identity.get("ssl_invalid")
        and _has_impersonated_brand(identity)
    ):
        return _result("PERICULOS", ["young_domain_invalid_ssl_impersonation"], confidence=92)

    # 3. Sensitive credential/card/remote/crypto asks on wrong channels are hard
    # danger. Money-transfer asks are contextual and need semantic severity.
    if hard_sensitive and wrong_channel:
        return _result("PERICULOS", ["sensitive_wrong_channel"], confidence=90)
    if value_sensitive and wrong_channel and semantic_risk == "high":
        return _result("PERICULOS", ["semantic_high_value_request"], confidence=88)
    if identity_status in BAD_IDENTITY and value_sensitive and (semantic_risk == "high" or tld_suspicious):
        return _result("PERICULOS", ["identity_spoof_value_request"], confidence=88)

    # 4. Missing required evidence is not guilt. It is internal pending.
    if (
        resolution_status in INCOMPLETE_RESOLUTION
        or provider_verdict in PENDING_VALUES
        or semantic_status != "done"
        or not _required_completeness(bundle)
    ):
        return _result("PENDING", ["insufficient_evidence"], confidence=0)

    # 5. Golden false-positive guard: official/delegated + clean providers +
    # no hard sensitive ask on wrong channel is safe. Context words cannot undo it.
    if (
        identity_status in TRUSTED_IDENTITY
        and provider_verdict in PROVIDER_CLEAN
        and not (hard_sensitive and wrong_channel)
    ):
        return _result("SIGUR", ["official_clean"], confidence=92)

    # Clean providers + an established destination domain + no sensitive ask is
    # safe enough even when the brand is not in our manual registry. This is the
    # general false-positive guard for legitimate small businesses and event
    # campaigns such as hipo.ro.
    if (
        identity_status == "unknown"
        and provider_verdict in PROVIDER_CLEAN
        and sensitive == "none"
        and not tld_suspicious
        and _domain_is_established(identity)
    ):
        return _result("SIGUR", ["clean_established_domain"], confidence=86)

    # Semantic similarity is a structured evidence pillar, not free-form text.
    if semantic_risk == "high" and (hard_sensitive or value_sensitive or identity_status in BAD_IDENTITY):
        return _result("PERICULOS", ["semantic_high_risk_match"], confidence=86)

    # 6. Zero-day posture: unknown but clean and no sensitive ask stays suspect-low,
    # not safe and not red-alert.
    if identity_status == "unknown" and provider_verdict in PROVIDER_CLEAN and sensitive == "none":
        return _result("SUSPECT", ["unknown_but_clean"], confidence=62)

    # Value transfer without decisive technical/provider evidence is suspicious,
    # not automatically dangerous. This preserves the product posture for small
    # merchants/charity/family cases while still warning the user.
    if value_sensitive:
        return _result("SUSPECT", ["value_request_needs_verification"], confidence=70)

    # 7. Residual uncertainty.
    return _result("SUSPECT", ["residual"], confidence=65)
