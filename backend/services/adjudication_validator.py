from typing import Any, Dict, Iterable, Optional, Set


VALID_LABELS = {"SAFE", "SUSPECT", "DANGEROUS", "UNVERIFIED", "NECUNOSCUT"}
MALICIOUS_WORDS = {"malicious", "malware", "phishing", "dangerous", "blacklisted"}


def _normalize(value: Any) -> str:
    return str(value or "").strip().lower()


def _iter_provider_values(evidence: Dict[str, Any]) -> Iterable[str]:
    providers = evidence.get("providers") if isinstance(evidence.get("providers"), dict) else {}
    for details in providers.values():
        if not isinstance(details, dict):
            continue
        for key in ("status", "verdict", "severity", "details"):
            value = details.get(key)
            if value is not None:
                yield _normalize(value)


def any_hard_provider_malicious(evidence: Dict[str, Any]) -> bool:
    for value in _iter_provider_values(evidence):
        if any(word in value for word in MALICIOUS_WORDS):
            return True
    return False


def has_threat_evidence(evidence: Dict[str, Any]) -> bool:
    if any_hard_provider_malicious(evidence):
        return True

    brand = evidence.get("brand") if isinstance(evidence.get("brand"), dict) else {}
    text = evidence.get("text_signals") if isinstance(evidence.get("text_signals"), dict) else {}
    urls = evidence.get("urls") if isinstance(evidence.get("urls"), list) else []

    unofficial_destination = bool(urls) and not bool(brand.get("official_destination"))
    active_sensitive = bool(
        text.get("direct_sensitive_request")
        or text.get("sensitive_url_path")
        or text.get("brand_warning_triggered")
        or text.get("apk_or_remote_access")
    )
    if unofficial_destination and (active_sensitive or brand.get("mismatch")):
        return True

    gate = evidence.get("gate") if isinstance(evidence.get("gate"), dict) else {}
    gate_family = _normalize(gate.get("detected_family_id"))
    return gate_family in {
        "provider-gate-bad-provider",
        "provider-gate-decisive-structural-danger",
        "provider-gate-sensitive-unofficial-form",
        "provider-gate-lookalike-domain",
        "provider-gate-no-url-social-danger",
    }


def _flatten_keys(value: Any, prefix: str = "") -> Set[str]:
    keys: Set[str] = set()
    if isinstance(value, dict):
        for key, child in value.items():
            path = f"{prefix}.{key}" if prefix else str(key)
            keys.add(path)
            keys.update(_flatten_keys(child, path))
    elif isinstance(value, list):
        for idx, child in enumerate(value[:20]):
            path = f"{prefix}.{idx}" if prefix else str(idx)
            keys.add(path)
            keys.update(_flatten_keys(child, path))
    return keys


def _evidence_key_allowed(requested_key: str, allowed_keys: Set[str]) -> bool:
    key = str(requested_key or "").strip()
    if not key:
        return False
    if key in allowed_keys:
        return True
    return any(existing.startswith(f"{key}.") or key.startswith(f"{existing}.") for existing in allowed_keys)


def validate_and_guard(llm: Optional[Dict[str, Any]], evidence: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Validate shadow adjudication and apply non-negotiable safety guards."""

    if not isinstance(llm, dict):
        return None

    label = str(llm.get("label") or "").strip().upper()
    if label not in VALID_LABELS:
        return None

    try:
        confidence = float(llm.get("confidence"))
    except Exception:
        return None
    if confidence < 0.0 or confidence > 1.0:
        return None

    guarded = dict(llm)
    guarded["label"] = label
    guarded["confidence"] = confidence

    if any_hard_provider_malicious(evidence):
        guarded["label"] = "DANGEROUS"
        guarded["motiv_ro"] = "Sursă semnalată ca malițioasă de un furnizor de securitate."
        return guarded

    if label == "DANGEROUS" and not has_threat_evidence(evidence):
        return None

    used = guarded.get("evidence_used") or []
    if not isinstance(used, list):
        return None
    allowed_keys = _flatten_keys(evidence)
    for key in used:
        if not _evidence_key_allowed(str(key), allowed_keys):
            return None

    return guarded
