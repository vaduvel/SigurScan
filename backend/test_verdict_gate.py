import json
from pathlib import Path

from services.verdict_gate import verdict


ROOT = Path(__file__).resolve().parent
TESTSET_PATH = ROOT / "data" / "verdict_testset_ro.jsonl"
FIRE_CASES = {"FAN-01", "FAN-02", "YOXO-01", "COM-01"}


def _load_cases():
    with TESTSET_PATH.open("r", encoding="utf-8") as handle:
        return [json.loads(line) for line in handle if line.strip()]


def _semantic_review_from_case(case: dict) -> dict:
    family = str(case.get("family") or "").lower()
    input_text = str(case.get("input") or "").lower()
    high_markers = (
        "bancar/",
        "taxe/",
        "amenzi/",
        "vishing/bnr",
        "romance",
        "investitii/",
        "remote/",
        "malware/",
        "takeover/",
        "job/task",
        "loterie",
        "sextortion",
        "suport-tehnic",
        "abonament/",
        "utilitati/",
        "ceo-fraud",
    )
    medium_markers = (
        "urgenta/",
        "ceo-fraud/furnizor",
        "caritate-falsa",
        "magazin-fals",
        "job/like",
        "vishing/banca",
        "sim-swap",
    )
    legit = family.startswith("guard/") or any(
        token in family for token in ("legit",)
    )
    risk_class = "benign" if legit else "unknown"
    if any(marker in family for marker in high_markers):
        risk_class = "high"
    elif any(marker in family for marker in medium_markers):
        risk_class = "medium"
    if family == "ceo-fraud/furnizor":
        risk_class = "medium"

    return {
        "status": "done",
        "claim_matches_known_scam_family": risk_class in {"high", "medium"},
        "matched_family": case.get("family") if risk_class in {"high", "medium"} else None,
        "claim_matches_legit_template": legit,
        "matched_template": case.get("family") if legit else None,
        "reason_codes": [f"semantic:{risk_class}", f"family:{family or 'unknown'}"],
        "risk_class": risk_class,
        "completeness": True,
        "notes": input_text[:0],
    }


def _bundle_v2_from_case(case: dict) -> dict:
    compact = case["bundle"]
    sensitive = compact["sensitive"]
    if sensitive == "card" and "transfer" in str(case.get("input") or "").lower():
        sensitive = "transfer"
    community_reports = case.get("community_reports", 0)
    bundle = {
        "schema": "sigurscan_evidence_bundle_v2",
        "input": {
            "type": case.get("channel") or "unknown",
            "redacted_text": case.get("input") or "",
        },
        "resolution": {
            "final_url": "https://example.invalid/",
            "status": compact["resolution"],
            "completeness": compact["resolution"] == "resolved",
        },
        "providers": {
            "verdict": compact["providers"],
            "hits": [],
            "completeness": compact["providers"] not in {"pending"},
        },
        "identity": {
            "claimed_brand": case.get("brand") or None,
            "status": compact["identity"],
            "tld_suspicious": bool(compact["tld_susp"]),
            "completeness": True,
        },
        "request": {
            "sensitive": sensitive,
            "channel": compact["req_channel"],
            "completeness": True,
        },
        "context": {
            "urgency": False,
            "passive_payment": False,
            "apk_or_remote_mention": False,
        },
        "semantic_review": _semantic_review_from_case(case),
    }
    if community_reports:
        bundle["community"] = {"reports": community_reports}
    return bundle


def test_verdict_gate_matches_all_manual_romania_contract_cases():
    failures = []
    for case in _load_cases():
        result = verdict(_bundle_v2_from_case(case))
        if result["label"] != case["label"]:
            failures.append(
                {
                    "id": case["id"],
                    "expected": case["label"],
                    "actual": result["label"],
                    "reason_codes": result.get("reason_codes", []),
                    "motiv": case.get("motiv"),
                }
            )

    assert not failures


def test_verdict_gate_fire_cases_are_exact():
    cases = {case["id"]: case for case in _load_cases()}
    missing = FIRE_CASES - set(cases)
    assert not missing

    for case_id in FIRE_CASES:
        result = verdict(_bundle_v2_from_case(cases[case_id]))
        assert result["label"] == cases[case_id]["label"]


def test_context_words_cannot_override_official_clean_evidence():
    bundle = {
        "schema": "sigurscan_evidence_bundle_v2",
        "input": {
            "type": "sms",
            "redacted_text": "FAN: urgent, taxa, cod, PIN, plata. Detalii pe awb.fan.ro",
        },
        "resolution": {"status": "resolved", "completeness": True},
        "providers": {"verdict": "clean", "hits": [], "completeness": True},
        "identity": {
            "claimed_brand": "FAN Courier",
            "status": "delegated",
            "tld_suspicious": False,
            "completeness": True,
        },
        "request": {"sensitive": "none", "channel": "official", "completeness": True},
        "context": {
            "urgency": True,
            "passive_payment": True,
            "apk_or_remote_mention": False,
        },
        "semantic_review": {
            "status": "done",
            "claim_matches_known_scam_family": False,
            "matched_family": None,
            "claim_matches_legit_template": True,
            "matched_template": "official_courier_pin",
            "reason_codes": ["semantic:benign"],
            "risk_class": "benign",
            "completeness": True,
        },
    }

    assert verdict(bundle)["label"] == "SAFE"


def test_visual_preview_metadata_cannot_change_verdict():
    case = next(case for case in _load_cases() if case["id"] == "FAN-01")
    bundle = _bundle_v2_from_case(case)
    expected = verdict(bundle)
    bundle["preview"] = {
        "status": "ready",
        "source": "precapture_worker",
        "visual_only": True,
        "verdict_role": "none",
        "screenshot_url": "https://signed.example/preview.png",
        "page_title": "A deliberately misleading visual title",
    }

    assert verdict(bundle) == expected


def test_unknown_clean_established_domain_is_unverified_without_registry():
    """Breaking change: no longer SAFE without positive provenance."""
    bundle = {
        "schema": "sigurscan_evidence_bundle_v2",
        "input": {
            "type": "sms",
            "redacted_text": "Hipo iti recomanda evenimentul Angajatori de TOP. Inscrie-te https://www.hipo.ro/ADT_TM",
        },
        "resolution": {"status": "resolved", "completeness": True, "final_url": "https://www.hipo.ro/ADT_TM"},
        "providers": {"verdict": "clean", "hits": ["google_web_risk", "phishing_database", "urlhaus"], "completeness": True},
        "identity": {
            "claimed_brand": None,
            "status": "unknown",
            "tld_suspicious": False,
            "domain_age_days": 2400,
            "domain_reputation": "established",
            "completeness": True,
        },
        "request": {"sensitive": "none", "channel": "official", "completeness": True},
        "context": {
            "urgency": False,
            "passive_payment": False,
            "apk_or_remote_mention": False,
        },
        "semantic_review": {
            "status": "done",
            "claim_matches_known_scam_family": False,
            "matched_family": None,
            "claim_matches_legit_template": False,
            "matched_template": None,
            "reason_codes": ["semantic:unknown"],
            "risk_class": "unknown",
            "completeness": True,
        },
    }

    result = verdict(bundle)

    # Breaking change: unknown + clean + established domain is no longer SAFE
    assert result["label"] == "UNVERIFIED", f"Expected UNVERIFIED got {result['label']}"
    assert result["reason_codes"] == ["unknown_but_clean_established"]


def test_clean_established_qr_menu_without_sensitive_request_is_safe():
    bundle = {
        "schema": "sigurscan_evidence_bundle_v2",
        "input": {
            "type": "qr_scan",
            "redacted_text": "https://www.smart-menu.ro/qr/vbiwmbouhu",
        },
        "resolution": {"status": "resolved", "completeness": True, "final_url": "https://www.smart-menu.ro/qr/vbiwmbouhu"},
        "providers": {
            "verdict": "clean",
            "hits": ["google_web_risk", "phishing_database", "urlhaus", "urlscan", "infra_dns"],
            "completeness": True,
        },
        "identity": {
            "claimed_brand": None,
            "status": "unknown",
            "tld_suspicious": False,
            "domain_age_days": 2193,
            "domain_reputation": "established",
            "completeness": True,
        },
        "request": {"sensitive": "none", "channel": "unofficial_site", "completeness": True},
        "context": {
            "urgency": False,
            "passive_payment": False,
            "apk_or_remote_mention": False,
        },
        "semantic_review": {
            "status": "done",
            "claim_matches_known_scam_family": False,
            "matched_family": None,
            "claim_matches_legit_template": False,
            "matched_template": None,
            "reason_codes": ["semantic:unknown"],
            "risk_class": "unknown",
            "completeness": True,
        },
    }

    result = verdict(bundle)

    assert result["label"] == "SAFE"
    assert result["reason_codes"] == ["clean_public_navigation_qr"]


def test_clean_established_qr_with_card_request_is_not_safe():
    bundle = {
        "schema": "sigurscan_evidence_bundle_v2",
        "input": {
            "type": "qr_scan",
            "redacted_text": "Meniu digital. Pentru acces introdu cardul: https://restaurant.example/card",
        },
        "resolution": {"status": "resolved", "completeness": True, "final_url": "https://restaurant.example/card"},
        "providers": {"verdict": "clean", "hits": ["google_web_risk", "urlscan"], "completeness": True},
        "identity": {
            "claimed_brand": None,
            "status": "unknown",
            "tld_suspicious": False,
            "domain_age_days": 1200,
            "domain_reputation": "established",
            "completeness": True,
        },
        "request": {"sensitive": "card", "channel": "unofficial_site", "completeness": True},
        "context": {"urgency": False, "passive_payment": False, "apk_or_remote_mention": False},
        "semantic_review": {
            "status": "done",
            "claim_matches_known_scam_family": False,
            "matched_family": None,
            "claim_matches_legit_template": False,
            "matched_template": None,
            "reason_codes": ["semantic:unknown"],
            "risk_class": "unknown",
            "completeness": True,
        },
    }

    result = verdict(bundle)

    assert result["label"] != "SAFE"


def test_unknown_clean_new_domain_stays_unverified_without_registry():
    bundle = {
        "schema": "sigurscan_evidence_bundle_v2",
        "input": {
            "type": "sms",
            "redacted_text": "Inscrie-te la campanie pe https://promo-nou.example",
        },
        "resolution": {"status": "resolved", "completeness": True, "final_url": "https://promo-nou.example"},
        "providers": {"verdict": "clean", "hits": ["google_web_risk", "phishing_database", "urlhaus"], "completeness": True},
        "identity": {
            "claimed_brand": None,
            "status": "unknown",
            "tld_suspicious": False,
            "domain_age_days": 20,
            "domain_reputation": "new",
            "completeness": True,
        },
        "request": {"sensitive": "none", "channel": "official", "completeness": True},
        "context": {
            "urgency": False,
            "passive_payment": False,
            "apk_or_remote_mention": False,
        },
        "semantic_review": {
            "status": "done",
            "claim_matches_known_scam_family": False,
            "matched_family": None,
            "claim_matches_legit_template": False,
            "matched_template": None,
            "reason_codes": ["semantic:unknown"],
            "risk_class": "unknown",
            "completeness": True,
        },
    }

    result = verdict(bundle)

    # Breaking change: even with established domain, UNVERIFIED not SAFE
    assert result["label"] == "UNVERIFIED"


def test_unknown_clean_established_marketing_domain_ignores_semantic_false_positive():
    bundle = {
        "schema": "sigurscan_evidence_bundle_v2",
        "input": {
            "type": "sms",
            "redacted_text": "SALE pana la -50%! Pantofi de top la jumatate de pret. https://snrs.it/0BJIIOV #MODIVOclub",
        },
        "resolution": {
            "status": "resolved",
            "completeness": True,
            "final_url": "https://epantofi.ro/c/epantofi/omnibus_discount",
        },
        "providers": {
            "verdict": "clean",
            "hits": ["google_web_risk", "phishing_database", "urlhaus", "urlscan"],
            "completeness": True,
        },
        "identity": {
            "claimed_brand": None,
            "status": "unknown",
            "tld_suspicious": False,
            "domain_age_days": 5522,
            "domain_reputation": "established",
            "completeness": True,
        },
        "request": {"sensitive": "none", "channel": "official", "completeness": True},
        "context": {
            "urgency": True,
            "passive_payment": False,
            "apk_or_remote_mention": False,
        },
        "semantic_review": {
            "status": "done",
            "claim_matches_known_scam_family": True,
            "matched_family": "marketing_false_positive",
            "claim_matches_legit_template": False,
            "matched_template": None,
            "reason_codes": ["semantic:high"],
            "risk_class": "high",
            "completeness": True,
        },
    }

    result = verdict(bundle)

    # Breaking change: unknown + clean → UNVERIFIED, even with established domain
    assert result["label"] == "UNVERIFIED"
    assert result["reason_codes"] == ["unknown_but_clean_established"]


def test_established_domain_cannot_override_brand_mismatch_and_card_request():
    bundle = {
        "schema": "sigurscan_evidence_bundle_v2",
        "input": {
            "type": "sms",
            "redacted_text": (
                "DHL: coletul dvs. este reținut la vamă. Achitați taxa de 12,40 RON "
                "pentru livrare: https://www.tipografia-arteum.ro/dhl/plata — "
                "actualizați datele cardului în 24h."
            ),
        },
        "resolution": {
            "status": "resolved",
            "completeness": True,
            "final_url": "https://www.tipografia-arteum.ro/dhl/plata",
        },
        "providers": {"verdict": "clean", "hits": ["google_web_risk", "phishing_database", "urlhaus"], "completeness": True},
        "identity": {
            "claimed_brand": "DHL",
            "status": "unrelated",
            "tld_suspicious": False,
            "domain_age_days": 2800,
            "domain_reputation": "established",
            "completeness": True,
        },
        "request": {"sensitive": "card", "channel": "unofficial_site", "completeness": True},
        "context": {"urgency": True, "passive_payment": False, "apk_or_remote_mention": False},
        "semantic_review": {
            "status": "done",
            "claim_matches_known_scam_family": True,
            "matched_family": "delivery_phishing",
            "claim_matches_legit_template": False,
            "matched_template": None,
            "reason_codes": ["semantic:high"],
            "risk_class": "high",
            "completeness": True,
        },
    }

    result = verdict(bundle)

    assert result["label"] == "DANGEROUS"
    assert result["reason_codes"][0] in {"identity_spoof", "sensitive_wrong_channel"}


def test_homoglyph_identity_spoof_stays_dangerous_even_with_clean_providers():
    bundle = {
        "schema": "sigurscan_evidence_bundle_v2",
        "input": {
            "type": "sms",
            "redacted_text": "ING Home'Bank: autentificare suspectă detectată. Confirmați identitatea: https://ıng-home.ro/verificare",
        },
        "resolution": {"status": "resolved", "completeness": True, "final_url": "https://xn--ng-home-qqa.ro/verificare"},
        "providers": {"verdict": "clean", "hits": ["google_web_risk", "phishing_database", "urlhaus"], "completeness": True},
        "identity": {
            "claimed_brand": "ING",
            "status": "lookalike",
            "tld_suspicious": True,
            "domain_age_days": 3,
            "domain_reputation": "new",
            "completeness": True,
        },
        "request": {"sensitive": "none", "channel": "unofficial_site", "completeness": True},
        "context": {"urgency": False, "passive_payment": False, "apk_or_remote_mention": False},
        "semantic_review": {
            "status": "done",
            "claim_matches_known_scam_family": True,
            "matched_family": "banking_login_phishing",
            "claim_matches_legit_template": False,
            "matched_template": None,
            "reason_codes": ["semantic:high", "idn:homoglyph"],
            "risk_class": "high",
            "completeness": True,
        },
    }

    result = verdict(bundle)

    assert result["label"] == "DANGEROUS"
    assert result["reason_codes"] == ["identity_spoof"]


def test_delegated_deeplink_clean_young_domain_can_be_safe():
    bundle = {
        "schema": "sigurscan_evidence_bundle_v2",
        "input": {
            "type": "sms",
            "redacted_text": "Vodafone: factura ta pe luna mai este disponibilă. Vizualizează: https://vfro.page.link/8Hk2",
        },
        "resolution": {"status": "resolved", "completeness": True, "final_url": "https://vfro.page.link/8Hk2"},
        "providers": {"verdict": "clean", "hits": ["google_web_risk", "phishing_database", "urlhaus"], "completeness": True},
        "identity": {
            "claimed_brand": "Vodafone România",
            "status": "delegated",
            "tld_suspicious": False,
            "domain_age_days": 22,
            "domain_reputation": "new",
            "completeness": True,
        },
        "request": {"sensitive": "none", "channel": "official", "completeness": True},
        "context": {"urgency": False, "passive_payment": True, "apk_or_remote_mention": False},
        "semantic_review": {
            "status": "done",
            "claim_matches_known_scam_family": False,
            "matched_family": None,
            "claim_matches_legit_template": True,
            "matched_template": "official_invoice_notice",
            "reason_codes": ["semantic:benign"],
            "risk_class": "benign",
            "completeness": True,
        },
    }

    result = verdict(bundle)

    assert result["label"] == "SAFE"
    assert result["reason_codes"] == ["positive_provenance_clean"]
