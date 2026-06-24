from __future__ import annotations

import re
from email.utils import parseaddr
from typing import Any, Dict

import tldextract

from core.url_intelligence import _dedupe_preserve_order

EMAIL_AUTH_STATUS_FAILS = {"fail", "softfail", "permerror"}
EMAIL_AUTH_STATUS_UNKNOWN = {"neutral", "none", "policy", "unknown", "temperror", "deferred", "error"}
EMAIL_AUTH_STATUS_BEST = {"pass", "bestguesspass"}

_AUTH_RESULT_RE = re.compile(r"\b(spf|dkim|dmarc)\s*=\s*([a-z]+)", re.IGNORECASE)
_DKIM_SIGNATURE_DOMAIN_RE = re.compile(r"\bd=([^;\\s]+)", re.IGNORECASE)
_DKIM_SIGNATURE_SELECTOR_RE = re.compile(r"\bs=([^;\\s]+)", re.IGNORECASE)


def _get_registrable_domain(extracted: "tldextract.ExtractResult") -> str:
    domain = getattr(extracted, "top_domain_under_public_suffix", "")
    if isinstance(domain, str) and domain.strip():
        return domain.strip().lower()
    return ""


def _extract_domain(raw_address: str | None) -> str | None:
    if not raw_address:
        return None
    parsed = parseaddr(raw_address)[1]
    if "@" not in parsed:
        return None
    return parsed.split("@", 1)[1].strip().lower()


def _extract_domain_root(raw_domain: str | None) -> str | None:
    if not raw_domain:
        return None

    normalized = str(raw_domain).strip().lower().strip(".")
    if not normalized:
        return None

    extracted = tldextract.extract(normalized)
    registrable_domain = _get_registrable_domain(extracted)
    if registrable_domain:
        return registrable_domain

    return normalized


def _coerce_int(raw_value: Any, default: int = 0) -> int:
    try:
        return int(raw_value)
    except Exception:
        return default


def _is_domain_aligned(
    left_domain: str | None,
    right_domain: str | None,
    alignment_mode: str | None = "r",
) -> bool | None:
    mode = (alignment_mode or "r").lower().strip()
    if mode not in {"r", "s", "strict", "relaxed"}:
        mode = "r"

    if not left_domain or not right_domain:
        return None

    left = str(left_domain).strip().lower().strip(".")
    right = str(right_domain).strip().lower().strip(".")
    if not left or not right:
        return None

    if left == right:
        return True

    if mode in {"s", "strict"}:
        return False

    return _extract_domain_root(left) == _extract_domain_root(right)


def _normalize_auth_status(raw_status: str) -> str:
    status = (raw_status or "").lower().strip()
    if status in EMAIL_AUTH_STATUS_BEST:
        return "pass"
    if status in EMAIL_AUTH_STATUS_FAILS:
        return "fail"
    if status in EMAIL_AUTH_STATUS_UNKNOWN:
        return "unknown"
    return "unknown"


def _parse_auth_statuses(header_value: str, auth_results: Dict[str, str]) -> None:
    for match in _AUTH_RESULT_RE.finditer(header_value or ""):
        mechanism = match.group(1).lower()
        normalized = _normalize_auth_status(match.group(2))
        current = auth_results.get(mechanism, "missing")
        if normalized == "fail":
            auth_results[mechanism] = "fail"
        elif normalized == "pass" and current != "fail":
            auth_results[mechanism] = "pass"
        elif mechanism not in auth_results:
            auth_results[mechanism] = normalized


def _parse_dkim_signature_fields(signature: str) -> Dict[str, str]:
    parsed: Dict[str, str] = {}
    if not signature:
        return parsed

    domain_match = _DKIM_SIGNATURE_DOMAIN_RE.search(signature)
    selector_match = _DKIM_SIGNATURE_SELECTOR_RE.search(signature)
    if domain_match:
        parsed["domain"] = domain_match.group(1).strip().lower()
    if selector_match:
        parsed["selector"] = selector_match.group(1).strip().lower()
    return parsed


def _normalize_dns_text(value: str | None) -> str | None:
    if not value:
        return None
    normalized = value.strip().lower()
    return normalized or None


def _extract_spf_all_mechanism(spf_record: str | None) -> str | None:
    if not spf_record:
        return None
    normalized = spf_record.lower()
    match = re.search(r"([+\-~?])all", normalized)
    if match:
        return match.group(1)
    if " all" in normalized and normalized.split()[-1].endswith("all"):
        return "all"
    return None


def _dmarc_policy_action_label(dmarc_policy: Dict[str, Any] | None) -> str:
    if not isinstance(dmarc_policy, dict):
        return "none"
    return _normalize_dns_text(dmarc_policy.get("p")) or "none"


def _build_auth_action_plan(email_ctx: Dict[str, Any]) -> Dict[str, Any]:
    dns_checks = email_ctx.get("dns_checks", {}) or {}
    if not isinstance(dns_checks, dict):
        dns_checks = {}

    dmarc_policy = dns_checks.get("dmarc_policy")
    dmarc_action = _dmarc_policy_action_label(dmarc_policy)
    spf_record = dns_checks.get("spf_record") or ""
    spf_all = _extract_spf_all_mechanism(spf_record)

    auth_status = email_ctx.get("auth_status", {})
    if not isinstance(auth_status, dict):
        auth_status = {}

    dns_spf_present = bool(dns_checks.get("spf_record"))
    dns_dkim_present = bool(dns_checks.get("dkim_dns"))
    dns_dmarc_present = bool(dns_checks.get("dmarc_policy"))
    dmarc_pct = _coerce_int(dmarc_policy.get("pct", 100), 100) if isinstance(dmarc_policy, dict) else 100

    dkim_signature_domain = dns_checks.get("dkim_signature_domain")
    return_path_domain = dns_checks.get("return_path_domain")
    spf_alignment_mode = str(dns_checks.get("spf_alignment_mode", "r")).lower() or "r"
    dkim_alignment_mode = str(dns_checks.get("dkim_alignment_mode", "r")).lower() or "r"
    spf_aligned = dns_checks.get("spf_aligned")
    dkim_aligned = dns_checks.get("dkim_aligned")
    if not isinstance(spf_aligned, bool) and dns_checks.get("from_domain") and return_path_domain:
        spf_aligned = _is_domain_aligned(
            dns_checks.get("from_domain"),
            return_path_domain,
            spf_alignment_mode,
        )
    if not isinstance(dkim_aligned, bool) and dns_checks.get("from_domain") and dkim_signature_domain:
        dkim_aligned = _is_domain_aligned(
            dns_checks.get("from_domain"),
            dkim_signature_domain,
            dkim_alignment_mode,
        )

    spf_aligned = bool(spf_aligned) if isinstance(spf_aligned, bool) else None
    dkim_aligned = bool(dkim_aligned) if isinstance(dkim_aligned, bool) else None

    fails = {k: v for k, v in auth_status.items() if v == "fail"}
    has_any_fail = bool(fails)
    has_partial_or_missing = any(v in {"missing", "unknown"} for v in auth_status.values())

    action = "monitor"
    severity = "low"
    score = 0
    reasons = []

    if has_any_fail:
        action = "reject"
        severity = "high"
        score += 42
        reasons.append("Autentificare SPF/DKIM/DMARC incompletă sau invalidă — risc de phishing.")
        reasons.extend([
            f"{mechanism.upper()}={status}"
            for mechanism, status in sorted(fails.items())
        ])

    if dmarc_action == "reject":
        if has_any_fail:
            reasons.append("DMARC='reject' combinat cu autentificare eșuată: blocare recomandată.")
        elif has_partial_or_missing:
            action = "reject"
            severity = "high"
            score += 32
            reasons.append("DMARC='reject' fără dovezi complete de autentificare: tratează mesajul ca potențial spoof.")
        elif action == "monitor":
            action = "monitor"
            reasons.append("DMARC='reject' detectat și mesajul pare aliniat; păstrezi monitorizare activă.")

    elif dmarc_action == "quarantine":
        if has_any_fail or has_partial_or_missing:
            action = "quarantine"
            severity = "medium" if severity != "high" else severity
            score += 20
            reasons.append("DMARC='quarantine' + autentificare incompletă: mesaj nesigur.")

    if not dns_spf_present:
        score += 6
        reasons.append("SPF DNS indisponibil: nu putem confirma politicile expeditorului.")

    if auth_status.get("spf") == "pass" and spf_aligned is False:
        score += 10
        reasons.append("SPF pass fără aliniere DMARC (SPF/From diferite).")
    if email_ctx.get("has_dkim_signature") and auth_status.get("dkim") == "pass" and dkim_aligned is False:
        score += 10
        reasons.append("DKIM pass fără aliniere DMARC (semnătură din alt domeniu).")
    if not dns_dkim_present and email_ctx.get("has_dkim_signature"):
        score += 6
        reasons.append("Semnătură DKIM prezentă fără înregistrare DNS validă.")
    if not dns_dmarc_present:
        score += 6
        reasons.append("DMARC DNS lipsă: nu există politică de aliniere verificabilă.")

    if dmarc_action == "reject" and not has_any_fail and (spf_aligned is False or dkim_aligned is False):
        action = "reject"
        severity = "high"
        score += 18
        reasons.append("DMARC='reject' + mecanisme non-aliniate: risc ridicat de phishing.")

    if spf_all == "-" and "fail" not in (auth_status.get("spf"),):
        score -= 4
        reasons.append("SPF strict (-all) detectat: cadru de autentificare mai rigid.")

    if not has_any_fail and not has_partial_or_missing and action == "monitor":
        action = "monitor"
        severity = "low"
        score = max(score, 0)

    if not dmarc_action and has_partial_or_missing:
        severity = "medium" if severity == "low" else severity
        score += 10
        reasons.append("DMARC absent + autentificare incompletă: risc moderat pentru e-mail nevalidat.")

    return {
        "dmarc_policy": dmarc_action,
        "spf_all": spf_all,
        "spf_dns_present": dns_spf_present,
        "dkim_dns_present": dns_dkim_present,
        "dmarc_dns_present": dns_dmarc_present,
        "dmarc_pct": dmarc_pct,
        "action": action,
        "severity": severity,
        "risk_score_delta": max(score, 0),
        "policy_context": {
            "adkim": str(dmarc_policy.get("adkim")) if isinstance(dmarc_policy, dict) else None,
            "aspf": str(dmarc_policy.get("aspf")) if isinstance(dmarc_policy, dict) else None,
            "provider": email_ctx.get("from_domain"),
            "pct": dmarc_pct,
            "spf_alignment_mode": spf_alignment_mode,
            "dkim_alignment_mode": dkim_alignment_mode,
            "spf_aligned": spf_aligned,
            "dkim_aligned": dkim_aligned,
        },
        "reasons": _dedupe_preserve_order(reasons),
    }
