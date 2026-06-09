import sys
import os
import json
import asyncio
import time
import urllib.parse
import pytest
from fastapi.testclient import TestClient
from pathlib import Path
from bs4 import BeautifulSoup

# Add current directory to path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from services.pii_redactor import redact_pii
from services.adjudication_validator import validate_and_guard
from services.evidence_bundle import build_evidence_bundle
from services.mistral_shadow_adjudicator import is_ambiguous
from services.redirect_resolver import (
    get_domain_info,
    is_known_shortener,
    _is_scan_target_blocked,
    _extract_soft_redirect,
    KNOWN_SHORTENERS,
    query_rotld_whois,
    check_domain_age,
    check_mx_records,
    resolve_redirects_safely,
)
from services.scam_atlas import ScamAtlasEngine
from services.offer_claim_verifier import verify_offer_claim
from services import offer_claim_verifier
from services.telemetry import (
    build_feedback_evaluation_rows,
    run_feedback_threshold_sweep,
    summarize_feedback_records,
    summarize_feedback_trend,
)
from services import redirect_resolver, scam_atlas, supabase_store, url_reputation
from services.tier1_classifier import Tier1Classifier
from services import google_web_risk
from eval.evaluate import run_threshold_sweep
from email import policy
from email.message import EmailMessage
import main as app_main
from main import (
    _build_ai_explanation,
    _collect_signal_ids,
    _collect_click_targets_from_html,
    _dedupe_preserve_order,
    _extract_email_auth_context,
    _safe_mode_url_entry,
    _is_domain_aligned,
    _user_risk_level_label,
    _user_risk_level_text,
    _user_recommended_action,
    _normalise_obfuscated_text,
    extract_urls,
    _build_scan_response,
    _apply_provider_gate_verdict,
    _project_provider_gate_verdict,
)


@pytest.fixture(autouse=True)
def _disable_live_mistral_semantic_pillar_by_default(monkeypatch):
    monkeypatch.setattr(app_main, "MISTRAL_SEMANTIC_API_KEY", "")


def test_pii_redaction():
    print("Testing PII Redactor...")
    
    # 1. Test Email Redaction
    text = "Trimite-mi detalii la adresa popescu.ion@gmail.com, te rog."
    redacted = redact_pii(text)
    assert "[EMAIL_REDACTED]" in redacted
    assert "popescu.ion" not in redacted
    print("  - Email: PASS")

    # 2. Test Romanian Phone Redaction
    text = "Suna-ma la +40 722 123 456 sau pe 0733123456 sau 021-222-3333."
    redacted = redact_pii(text)
    assert "[PHONE_REDACTED]" in redacted
    print("  - Phone: PASS")

    # 3. Test IBAN Redaction
    text = "Contul meu nou este RO89BTRL0130120234567800. Trimite banii acolo."
    redacted = redact_pii(text)
    assert "[IBAN_REDACTED]" in redacted
    assert "RO89BTRL" not in redacted
    print("  - IBAN: PASS")

    # 4. Test OTP Redaction
    text = "Codul tau de verificare WhatsApp este 492-385. Nu il da nimănui."
    redacted = redact_pii(text)
    assert "[OTP_REDACTED]" in redacted
    assert "492-385" not in redacted
    print("  - OTP: PASS")


def test_extract_urls_keeps_link_when_phone_period_is_adjacent_to_https():
    text = (
        "Dispozitivul dvs. (cod 8HXDX) nu a putut fi reparat. "
        "Informatii la 0371237475. https://idroid.ro/verificare-status "
        "Se percepe taxa de magazinaj la depasirea a 10 zile."
    )

    assert extract_urls(text) == ["https://idroid.ro/verificare-status"]

    print("PII Redactor Tests: ALL PASS\n")


def test_extract_urls_does_not_join_sentence_boundary_into_fake_domain():
    text = (
        "Bună, mama. Sunt eu. am făcut accident și scriu de pe numărul acesta temporar. "
        "Te rog nu mă suna acum, nu pot vorbi. Am nevoie urgent de 1800 lei până seara."
    )

    assert extract_urls(text) == []


def test_extract_urls_keeps_obfuscated_plain_domain_with_spaced_dot():
    assert extract_urls("Vezi oferta pe emag . ro azi") == ["https://emag.ro/"]


def test_detection_helpers():
    print("Testing URL and email helper utilities...")

    obf_text = "Click hxxp://anaf-spv[.]info/plata\nNu uita: www.posta-romana[.]ro?token=1"
    normalized = _normalise_obfuscated_text(obf_text)
    assert "http://" in normalized
    assert "anaf-spv.info" in normalized
    assert "posta-romana.ro" in normalized

    urls = extract_urls(obf_text)
    assert "http://anaf-spv.info/plata" in urls
    assert any(url.startswith("https://www.posta-romana.ro") for url in urls), urls
    assert any("/?token=1" in url for url in urls), urls

    unique = _dedupe_preserve_order(["x", "y", "x", "z", "y"])
    assert unique == ["x", "y", "z"]

    msg = EmailMessage()
    msg["From"] = "Scam <attacker@phish.example>"
    msg["Reply-To"] = "contact@safe.example"
    msg["Authentication-Results"] = "spf=pass; dkim=none; dmarc=pass"
    msg["Received-SPF"] = "pass"
    msg["DKIM-Signature"] = "v=1;"

    email_ctx = _extract_email_auth_context(msg)
    assert email_ctx["from_domain"] == "phish.example"
    assert email_ctx["reply_to_domain"] == "safe.example"
    assert any(
        "dkim" in reason.lower() or "reply-to" in reason.lower()
        for reason in email_ctx["auth_fail_reasons"]
    )
    print("  - Detection helpers: PASS\n")


def test_offer_claim_verifier_confirms_yoxo_buyback_on_official_destination(monkeypatch):
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    monkeypatch.setattr(
        "services.offer_claim_verifier._fetch_page_text",
        lambda url: "yoxo buyback evaluare online telefon plata in cont transport gratuit",
    )

    text = (
        "Ai un telefon sau o tableta pe care nu le mai folosesti? "
        "Acum le poti transforma rapid in bani cu serviciul de buy-back YOXO. "
        "Afla cat valoreaza dispozitivul tau: buyback.yoxo.ro"
    )
    result = verify_offer_claim(
        text,
        {"claimed_brand": "YOXO"},
        [{"final_url": "https://buyback.yoxo.ro", "final_hostname": "buyback.yoxo.ro"}],
        brand_registry={"YOXO": ["yoxo.ro", "buyback.yoxo.ro", "orange.ro"]},
    )

    assert result["provider"] == "ai_offer_web_check"
    assert result["status"] == "confirmed"
    assert result["official_source_found"] is True
    assert result["evidence_urls"]
    assert result["knowledge_target"] == "buyback YOXO"


def test_offer_claim_verifier_prefers_fast_official_fetch_before_gemini(monkeypatch):
    monkeypatch.setenv("GEMINI_API_KEY", "test-gemini-key")
    monkeypatch.setattr(
        "services.offer_claim_verifier._fetch_page_text",
        lambda url: "yoxo buyback evaluare online telefon plata in cont transport gratuit",
    )
    monkeypatch.setattr(
        "services.offer_claim_verifier._verify_with_gemini_search",
        lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("Gemini must not run when official evidence confirms the claim")),
    )

    text = (
        "Ai un telefon sau o tableta pe care nu le mai folosesti? "
        "Acum le poti transforma rapid in bani cu serviciul de buy-back YOXO. "
        "Afla cat valoreaza dispozitivul tau: buyback.yoxo.ro"
    )
    result = verify_offer_claim(
        text,
        {"claimed_brand": "YOXO"},
        [{"final_url": "https://buyback.yoxo.ro", "final_hostname": "buyback.yoxo.ro"}],
        brand_registry={"YOXO": ["yoxo.ro", "buyback.yoxo.ro", "orange.ro"]},
    )

    assert result["status"] == "confirmed"
    assert result["method"] == "official_page_fetch"
    assert result["official_source_found"] is True


def test_offer_claim_gemini_grounding_is_bounded_for_25_flash(monkeypatch):
    captured = {}

    class FakeResponse:
        def raise_for_status(self):
            return None

        def json(self):
            return {
                "candidates": [
                    {
                        "content": {
                            "parts": [
                                {
                                    "text": json.dumps(
                                        {
                                            "status": "confirmed",
                                            "summary": "Confirmat pe surse oficiale.",
                                            "evidence_urls": ["https://example.com/offer"],
                                            "official_source_found": True,
                                            "confidence": 80,
                                        }
                                    )
                                }
                            ]
                        }
                    }
                ]
            }

    def fake_post(url, *, params, json, timeout):
        captured["url"] = url
        captured["params"] = params
        captured["json"] = json
        captured["timeout"] = timeout
        return FakeResponse()

    monkeypatch.setenv("GEMINI_API_KEY", "test-gemini-key")
    monkeypatch.setenv("OFFER_CLAIM_GEMINI_MODEL", "gemini-2.5-flash")
    monkeypatch.setenv("OFFER_CLAIM_GEMINI_TIMEOUT_SECONDS", "4.0")
    monkeypatch.setattr(offer_claim_verifier.requests, "post", fake_post)
    monkeypatch.setattr(offer_claim_verifier, "OFFER_CLAIM_GEMINI_TIMEOUT_SECONDS", 4.0)

    result = offer_claim_verifier._verify_with_gemini_search(
        text="Oferta test https://example.com",
        claimed_brand="Example",
        official_domains=["example.com"],
        final_urls=["https://example.com"],
        query="Oferta test Example",
        claim_target={"claim_type": "test"},
    )

    assert result["status"] == "confirmed"
    assert "gemini-2.5-flash:generateContent" in captured["url"]
    assert captured["params"] == {"key": "test-gemini-key"}
    assert captured["timeout"] == 4.0
    assert captured["json"]["tools"] == [{"google_search": {}}]
    assert captured["json"]["generationConfig"]["maxOutputTokens"] == 512


def test_offer_claim_gemini_grounding_falls_back_to_web_risk_key(monkeypatch):
    calls = []

    class FakeResponse:
        def __init__(self, ok):
            self.ok = ok

        def raise_for_status(self):
            if not self.ok:
                raise RuntimeError("RESOURCE_EXHAUSTED")

        def json(self):
            return {
                "candidates": [
                    {
                        "content": {
                            "parts": [
                                {
                                    "text": json.dumps(
                                        {
                                            "status": "confirmed",
                                            "summary": "Confirmat cu cheia fallback.",
                                            "evidence_urls": ["https://example.com/offer"],
                                            "official_source_found": True,
                                            "confidence": 75,
                                        }
                                    )
                                }
                            ]
                        }
                    }
                ]
            }

    def fake_post(url, *, params, json, timeout):
        calls.append(params["key"])
        return FakeResponse(ok=params["key"] == "working-web-risk-key")

    monkeypatch.setenv("GEMINI_API_KEY", "quota-hit-gemini-key")
    monkeypatch.setenv("GOOGLE_WEB_RISK_API_KEY", "working-web-risk-key")
    monkeypatch.setattr(offer_claim_verifier.requests, "post", fake_post)

    result = offer_claim_verifier._verify_with_gemini_search(
        text="Oferta test https://example.com",
        claimed_brand="Example",
        official_domains=["example.com"],
        final_urls=["https://example.com"],
        query="Oferta test Example",
        claim_target={"claim_type": "test"},
    )

    assert calls == ["quota-hit-gemini-key", "working-web-risk-key"]
    assert result["status"] == "confirmed"
    assert result["method"] == "gemini_google_search"


def test_offer_claim_gemini_grounding_accepts_non_json_text_with_official_url(monkeypatch):
    class FakeResponse:
        def raise_for_status(self):
            return None

        def json(self):
            return {
                "candidates": [
                    {
                        "content": {
                            "parts": [
                                {"text": "Da, hipo.ro există și pagina oficială este https://www.hipo.ro/ADT_TM."}
                            ]
                        }
                    }
                ]
            }

    monkeypatch.setattr(offer_claim_verifier.requests, "post", lambda *args, **kwargs: FakeResponse())

    monkeypatch.setenv("GEMINI_API_KEY", "working-gemini-key")
    monkeypatch.delenv("GOOGLE_WEB_RISK_API_KEY", raising=False)

    result = offer_claim_verifier._verify_with_gemini_search(
        text="Hipo iti recomanda evenimentul Angajatori de TOP. https://www.hipo.ro/ADT_TM",
        claimed_brand="Hipo",
        official_domains=["hipo.ro"],
        final_urls=["https://www.hipo.ro/ADT_TM"],
        query="Hipo Angajatori de TOP",
        claim_target={"claim_type": "event"},
    )

    assert result["status"] == "confirmed"
    assert result["official_source_found"] is True
    assert result["evidence_urls"] == ["https://www.hipo.ro/ADT_TM"]


def test_offer_claim_gemini_grounding_uses_minimal_thinking_for_35_flash(monkeypatch):
    captured = {}

    class FakeResponse:
        def raise_for_status(self):
            return None

        def json(self):
            return {
                "candidates": [
                    {
                        "content": {
                            "parts": [
                                {
                                    "text": json.dumps(
                                        {
                                            "status": "inconclusive",
                                            "summary": "Nu este concludent.",
                                            "evidence_urls": [],
                                            "official_source_found": False,
                                            "confidence": 10,
                                        }
                                    )
                                }
                            ]
                        }
                    }
                ]
            }

    def fake_post(url, *, params, json, timeout):
        captured["url"] = url
        return FakeResponse()

    monkeypatch.setenv("GEMINI_API_KEY", "test-gemini-key")
    monkeypatch.setenv("OFFER_CLAIM_GEMINI_MODEL", "gemini-3.5-flash")
    monkeypatch.setattr(offer_claim_verifier.requests, "post", fake_post)
    monkeypatch.setattr(offer_claim_verifier, "OFFER_CLAIM_GEMINI_TIMEOUT_SECONDS", 5.0)

    result = offer_claim_verifier._verify_with_gemini_search(
        text="Oferta test https://example.com",
        claimed_brand="Example",
        official_domains=["example.com"],
        final_urls=["https://example.com"],
        query="Oferta test Example",
        claim_target={"claim_type": "test"},
    )

    assert result["status"] == "inconclusive"
    assert "gemini-3.5-flash:generateContent" in captured["url"]


def test_offer_claim_verifier_uses_runtime_knowledge_sources_for_yoxo(monkeypatch):
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    checked_urls = []

    def fake_fetch(url):
        checked_urls.append(url)
        if "newsroom.orange.ro" in url:
            return "program buyback yoxo evaluare online telefon plata in cont"
        return ""

    monkeypatch.setattr("services.offer_claim_verifier._fetch_page_text", fake_fetch)

    text = (
        "Ai un telefon sau o tableta pe care nu le mai folosesti? "
        "Acum le poti transforma rapid in bani cu serviciul de buy-back YOXO. "
        "Afla cat valoreaza dispozitivul tau: buyback.yoxo.ro"
    )
    result = verify_offer_claim(
        text,
        {"claimed_brand": "YOXO"},
        [{"final_url": "https://buyback.yoxo.ro", "final_hostname": "buyback.yoxo.ro"}],
        brand_registry={"YOXO": ["yoxo.ro", "buyback.yoxo.ro", "orange.ro"]},
    )

    assert result["status"] == "confirmed"
    assert result["knowledge_target"] == "buyback YOXO"
    assert any("newsroom.orange.ro" in url for url in checked_urls)


def test_offer_claim_verifier_matches_idroid_runtime_target_without_claimed_brand(monkeypatch):
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    monkeypatch.setattr(
        "services.offer_claim_verifier._fetch_page_text",
        lambda url: "status reparatie dispozitiv cod service informatii magazinaj",
    )

    text = (
        "Dispozitivul dvs. (cod 8HXDX) nu a putut fi reparat. "
        "Informatii la 0371237475. https://idroid.ro/verificare-status "
        "Se percepe taxa de magazinaj la depasirea a 10 zile."
    )
    result = verify_offer_claim(
        text,
        {"claimed_brand": "Nespecificat"},
        [{"final_url": "https://idroid.ro/verificare-status", "final_hostname": "idroid.ro"}],
        brand_registry={"iDroid": ["idroid.ro"]},
    )

    assert result["status"] == "confirmed"
    assert result["knowledge_target"] == "service status iDroid"


def test_attach_offer_claim_verification_carries_knowledge_target_into_external_summary():
    analysis = {"evidence": {}}
    offer_claim = {
        "provider": "ai_offer_web_check",
        "status": "confirmed",
        "verdict": "confirmed",
        "severity": "low",
        "summary": "Oferta a fost confirmată pe sursă oficială.",
        "details": "Oferta a fost confirmată pe sursă oficială.",
        "confidence": 88,
        "claimed_brand": "YOXO",
        "official_domains": ["yoxo.ro", "buyback.yoxo.ro"],
        "evidence_urls": ["https://buyback.yoxo.ro/"],
        "method": "test",
        "official_source_found": True,
        "knowledge_target": "buyback YOXO",
    }

    app_main._attach_offer_claim_verification(analysis, offer_claim)

    summary = analysis["evidence"]["external_intel_summary"]["ai_offer_web_check"]
    assert summary["knowledge_target"] == "buyback YOXO"


def test_provider_gate_keeps_official_destination_partial_until_all_pillars_complete():
    analysis = {
        "claimed_brand": "YOXO",
        "risk_level": "medium",
        "risk_score": 72,
        "detected_family": "Text marketing suspect",
        "evidence": {
            "external_intel_summary": {
                "google_web_risk": {"status": "clean", "verdict": "clean", "consulted": True},
                "virustotal": {"status": "clean", "verdict": "clean", "consulted": True},
            }
        },
    }
    resolved_urls = [
        {
            "url": "https://buyback.yoxo.ro",
            "final_url": "https://buyback.yoxo.ro",
            "hostname": "buyback.yoxo.ro",
            "final_hostname": "buyback.yoxo.ro",
            "registered_domain": "yoxo.ro",
            "final_registered_domain": "yoxo.ro",
        }
    ]

    result = _apply_provider_gate_verdict(analysis, resolved_urls)

    assert result["risk_level"] == "pending"
    assert result["risk_score"] == 0
    assert result["detected_family_id"] == "provider-gate-pending"
    assert result["evidence"]["verdict_gate"]["label"] == "PENDING"
    assert result["evidence"]["provider_gate"]["consulted_count"] == 2
    assert result["evidence"]["provider_gate"]["official_destination"] is True
    assert result["evidence"]["provider_gate"]["urlscan_consulted"] is False


def test_provider_gate_marks_yoxo_official_clean_pillars_as_low_risk():
    analysis = {
        "claimed_brand": "YOXO",
        "risk_level": "medium",
        "risk_score": 72,
        "detected_family": "Text marketing suspect",
        "evidence": {
            "offer_claim_verification": {"status": "confirmed"},
            "external_intel_summary": {
                "google_web_risk": {"status": "clean", "verdict": "clean", "consulted": True},
                "virustotal": {"status": "clean", "verdict": "clean", "consulted": True},
                "urlscan": {"status": "clean", "verdict": "clean", "consulted": True},
            },
        },
    }
    resolved_urls = [
        {
            "url": "https://buyback.yoxo.ro",
            "final_url": "https://buyback.yoxo.ro",
            "hostname": "buyback.yoxo.ro",
            "final_hostname": "buyback.yoxo.ro",
            "registered_domain": "yoxo.ro",
            "final_registered_domain": "yoxo.ro",
        }
    ]

    result = _apply_provider_gate_verdict(analysis, resolved_urls)

    assert result["risk_level"] == "low"
    assert result["risk_score"] == 10
    assert result["detected_family_id"] == "provider-gate-official-clean"


def test_provider_gate_marks_clean_first_party_domain_claim_as_low_risk():
    analysis = {
        "claimed_brand": "Nespecificat",
        "risk_level": "medium",
        "risk_score": 55,
        "detected_family": "Necunoscut",
        "evidence": {
            "external_intel_summary": {
                "google_web_risk": {"status": "clean", "verdict": "clean", "consulted": True},
                "virustotal": {"status": "clean", "verdict": "clean", "consulted": True},
                "urlscan": {"status": "clean", "verdict": "clean", "consulted": True},
            },
            "semantic_review": {
                "status": "done",
                "risk_class": "unknown",
                "claim_matches_known_scam_family": False,
                "claim_matches_legit_template": False,
                "completeness": True,
            },
        },
    }
    resolved_urls = [
        {
            "url": "https://www.hipo.ro/ADT_TM",
            "final_url": "https://www.hipo.ro/locuri-de-munca/angajatoridetop/timisoara",
            "hostname": "www.hipo.ro",
            "final_hostname": "www.hipo.ro",
            "registered_domain": "hipo.ro",
            "final_registered_domain": "hipo.ro",
        }
    ]

    result = _apply_provider_gate_verdict(
        analysis,
        resolved_urls,
        raw_text="Hipo iti recomanda evenimentul Angajatori de TOP. Inscrie-te https://www.hipo.ro/ADT_TM",
    )

    assert result["risk_level"] == "low"
    assert result["evidence"]["verdict_gate"]["label"] == "SIGUR"
    assert result["evidence"]["decision_bundle"]["identity"]["status"] == "coherent"


def test_provider_gate_does_not_trust_brand_like_compound_domain_claim():
    analysis = {
        "claimed_brand": "Nespecificat",
        "risk_level": "medium",
        "risk_score": 55,
        "detected_family": "Necunoscut",
        "evidence": {
            "external_intel_summary": {
                "google_web_risk": {"status": "clean", "verdict": "clean", "consulted": True},
                "virustotal": {"status": "clean", "verdict": "clean", "consulted": True},
                "urlscan": {"status": "clean", "verdict": "clean", "consulted": True},
            },
            "semantic_review": {
                "status": "done",
                "risk_class": "unknown",
                "claim_matches_known_scam_family": False,
                "claim_matches_legit_template": False,
                "completeness": True,
            },
        },
    }
    resolved_urls = [
        {
            "url": "https://fancurier-relivrare.com/plata",
            "final_url": "https://fancurier-relivrare.com/plata",
            "hostname": "fancurier-relivrare.com",
            "final_hostname": "fancurier-relivrare.com",
            "registered_domain": "fancurier-relivrare.com",
            "final_registered_domain": "fancurier-relivrare.com",
        }
    ]

    result = _apply_provider_gate_verdict(
        analysis,
        resolved_urls,
        raw_text="FAN Courier: coletul are taxa de livrare. Reprogrameaza la https://fancurier-relivrare.com/plata",
    )

    assert result["evidence"]["verdict_gate"]["label"] != "SIGUR"
    assert result["evidence"]["decision_bundle"]["identity"]["status"] == "unknown"


def test_provider_gate_marks_clean_shortener_to_named_first_party_domain_as_low_risk():
    analysis = {
        "claimed_brand": "Nespecificat",
        "risk_level": "medium",
        "risk_score": 55,
        "detected_family": "Necunoscut",
        "evidence": {
            "external_intel_summary": {
                "google_web_risk": {"status": "clean", "verdict": "clean", "consulted": True},
                "virustotal": {"status": "clean", "verdict": "clean", "consulted": True},
                "urlscan": {"status": "clean", "verdict": "clean", "consulted": True},
            },
            "semantic_review": {
                "status": "done",
                "risk_class": "unknown",
                "claim_matches_known_scam_family": False,
                "claim_matches_legit_template": False,
                "completeness": True,
            },
        },
    }
    resolved_urls = [
        {
            "url": "https://bit.ly/38EsUAf",
            "final_url": "https://www.cetelem.ro/credite/promo-pp-sms-nsqe",
            "hostname": "bit.ly",
            "final_hostname": "www.cetelem.ro",
            "registered_domain": "bit.ly",
            "final_registered_domain": "cetelem.ro",
        }
    ]

    result = _apply_provider_gate_verdict(
        analysis,
        resolved_urls,
        raw_text="La Cetelem ai chiar azi un credit cu dobanda fixa. Intra pe bit.ly/38EsUAf",
    )

    assert result["evidence"]["verdict_gate"]["label"] == "SIGUR"
    assert result["evidence"]["decision_bundle"]["identity"]["status"] == "coherent"


def test_provider_gate_exposes_established_domain_as_positive_context():
    analysis = {
        "claimed_brand": "Nespecificat",
        "risk_level": "medium",
        "risk_score": 55,
        "detected_family": "Necunoscut",
        "evidence": {
            "external_intel_summary": {
                "google_web_risk": {"status": "clean", "verdict": "clean", "consulted": True},
                "virustotal": {"status": "clean", "verdict": "clean", "consulted": True},
                "urlscan": {"status": "clean", "verdict": "clean", "consulted": True},
            },
            "semantic_review": {
                "status": "done",
                "risk_class": "unknown",
                "claim_matches_known_scam_family": False,
                "claim_matches_legit_template": False,
                "completeness": True,
            },
        },
    }
    resolved_urls = [
        {
            "url": "https://www.hipo.ro/ADT_TM",
            "final_url": "https://www.hipo.ro/locuri-de-munca/angajatoridetop/timisoara",
            "hostname": "www.hipo.ro",
            "final_hostname": "www.hipo.ro",
            "registered_domain": "hipo.ro",
            "final_registered_domain": "hipo.ro",
            "domain_age_days": 2400,
            "domain_created_date": "2019-11-05",
        }
    ]

    result = _apply_provider_gate_verdict(
        analysis,
        resolved_urls,
        raw_text="Hipo iti recomanda evenimentul Angajatori de TOP. Inscrie-te https://www.hipo.ro/ADT_TM",
    )

    identity = result["evidence"]["decision_bundle"]["identity"]
    summary = result["evidence"]["external_intel_summary"]
    assert result["evidence"]["verdict_gate"]["label"] == "SIGUR"
    assert identity["status"] == "coherent"
    assert identity["domain_age_days"] == 2400
    assert identity["domain_reputation"] == "established"
    assert summary["infra_domain_age"]["status"] == "clean"
    assert summary["infra_domain_age"]["verdict"] == "established_domain"


def test_provider_gate_banking_safety_warning_with_phone_and_otp_is_not_high_risk():
    text = (
        "Banca Transilvania: am blocat tranzacția de 1.250 RON la card. "
        "Dacă NU recunoașteți, apelați 0264 308 028. "
        "Nu comunicați NICIODATĂ codul OTP sau PIN-ul."
    )
    analysis = {
        "claimed_brand": "Banca Transilvania",
        "risk_level": "medium",
        "risk_score": 55,
        "detected_family": "Avertizare securitate",
        "detected_family_id": "bank_safety_warning",
        "reasons": [],
        "evidence": {
            "external_intel_summary": {},
            "semantic_review": {
                "status": "done",
                "claim_matches_known_scam_family": False,
                "matched_family": None,
                "claim_matches_legit_template": True,
                "matched_template": "bank_security_warning",
                "reason_codes": ["semantic:benign_safety_warning"],
                "risk_class": "benign",
                "completeness": True,
            },
        },
    }

    result = _apply_provider_gate_verdict(analysis, [], raw_text=text)

    assert result["risk_level"] != "high"
    provider_gate = result["evidence"]["provider_gate"]
    decision_bundle = result["evidence"]["decision_bundle"]
    assert provider_gate["direct_sensitive_request"] is False
    assert decision_bundle["request"]["sensitive"] == "none"
    assert result["evidence"]["verdict_gate"]["label"] in {"SIGUR", "SUSPECT"}


def test_provider_gate_multi_url_official_lure_does_not_mask_phishing_link():
    text = (
        "eMAG: comanda #4471 a fost livrată. Detalii: https://www.emag.ro — "
        "Dacă NU ai comandat, anulează aici: https://bit.ly/emag-anulare"
    )
    analysis = {
        "claimed_brand": "eMAG",
        "risk_level": "medium",
        "risk_score": 60,
        "detected_family": "Curier/eMAG phishing",
        "detected_family_id": "emag_cancel_phishing",
        "reasons": [],
        "evidence": {
            "external_intel_summary": {
                "google_web_risk": {"status": "clean", "verdict": "clean", "consulted": True},
                "virustotal": {"status": "clean", "verdict": "clean", "consulted": True},
                "urlhaus": {"status": "clean", "verdict": "clean", "consulted": True},
            },
            "semantic_review": {
                "status": "done",
                "claim_matches_known_scam_family": True,
                "matched_family": "delivery_order_cancellation_phishing",
                "claim_matches_legit_template": False,
                "matched_template": None,
                "reason_codes": ["semantic:high"],
                "risk_class": "high",
                "completeness": True,
            },
            "url_lexical": {
                "reasons": ["typosquatting / lookalike domain detected"],
            },
        },
    }
    resolved_urls = [
        {
            "url": "https://www.emag.ro",
            "final_url": "https://www.emag.ro",
            "hostname": "www.emag.ro",
            "final_hostname": "www.emag.ro",
            "registered_domain": "emag.ro",
            "final_registered_domain": "emag.ro",
            "success": True,
            "domain_age_days": 7000,
        },
        {
            "url": "https://bit.ly/emag-anulare",
            "final_url": "https://emag-comenzi-retur.top/anulare",
            "hostname": "bit.ly",
            "final_hostname": "emag-comenzi-retur.top",
            "registered_domain": "bit.ly",
            "final_registered_domain": "emag-comenzi-retur.top",
            "success": True,
            "domain_age_days": 2,
        },
    ]

    pillars = {
        "final_url": {"status": "ok", "required": True},
        "google_web_risk": {"status": "ok", "required": True},
        "virustotal": {"status": "ok", "required": True},
        "urlscan": {"status": "pending", "required": False},
        "claim_verifier": {"status": "ok", "required": True},
        "semantic_review": {"status": "ok", "required": True},
    }

    result = _apply_provider_gate_verdict(analysis, resolved_urls, raw_text=text, pillars=pillars)

    assert result["risk_level"] == "high"
    assert result["evidence"]["verdict_gate"]["label"] == "PERICULOS"
    assert result["evidence"]["decision_bundle"]["identity"]["status"] in {"lookalike", "unrelated"}
    assert result["evidence"]["provider_gate"]["official_destination"] is False


def test_provider_gate_does_not_mark_new_first_party_domain_as_low_risk():
    analysis = {
        "claimed_brand": "Nespecificat",
        "risk_level": "medium",
        "risk_score": 55,
        "detected_family": "Necunoscut",
        "evidence": {
            "external_intel_summary": {
                "google_web_risk": {"status": "clean", "verdict": "clean", "consulted": True},
                "virustotal": {"status": "clean", "verdict": "clean", "consulted": True},
                "urlscan": {"status": "clean", "verdict": "clean", "consulted": True},
            },
            "semantic_review": {
                "status": "done",
                "risk_class": "unknown",
                "claim_matches_known_scam_family": False,
                "claim_matches_legit_template": False,
                "completeness": True,
            },
        },
    }
    resolved_urls = [
        {
            "url": "https://promohelpnet.ro/campanie",
            "final_url": "https://promohelpnet.ro/campanie",
            "hostname": "promohelpnet.ro",
            "final_hostname": "promohelpnet.ro",
            "registered_domain": "promohelpnet.ro",
            "final_registered_domain": "promohelpnet.ro",
            "domain_age_days": 20,
            "domain_created_date": "2026-05-19",
        }
    ]

    result = _apply_provider_gate_verdict(
        analysis,
        resolved_urls,
        raw_text="Promo Helpnet: inscrie-te pe promohelpnet.ro/campanie",
    )

    assert result["evidence"]["verdict_gate"]["label"] == "SUSPECT"
    assert result["evidence"]["decision_bundle"]["identity"]["status"] == "unknown"


def test_provider_gate_does_not_mark_url_only_unknown_clean_domain_as_low_risk():
    analysis = {
        "claimed_brand": "Nespecificat",
        "risk_level": "medium",
        "risk_score": 55,
        "detected_family": "Necunoscut",
        "evidence": {
            "external_intel_summary": {
                "google_web_risk": {"status": "clean", "verdict": "clean", "consulted": True},
                "virustotal": {"status": "clean", "verdict": "clean", "consulted": True},
                "urlscan": {"status": "clean", "verdict": "clean", "consulted": True},
            },
            "semantic_review": {
                "status": "done",
                "risk_class": "unknown",
                "claim_matches_known_scam_family": False,
                "claim_matches_legit_template": False,
                "completeness": True,
            },
        },
    }
    resolved_urls = [
        {
            "url": "https://www.hipo.ro/ADT_TM",
            "final_url": "https://www.hipo.ro/ADT_TM",
            "hostname": "www.hipo.ro",
            "final_hostname": "www.hipo.ro",
            "registered_domain": "hipo.ro",
            "final_registered_domain": "hipo.ro",
        }
    ]

    result = _apply_provider_gate_verdict(
        analysis,
        resolved_urls,
        raw_text="Inscrie-te aici: https://www.hipo.ro/ADT_TM",
    )

    assert result["evidence"]["verdict_gate"]["label"] == "SUSPECT"
    assert result["evidence"]["decision_bundle"]["identity"]["status"] == "unknown"


def test_rdap_domain_age_uses_valid_url_without_literal_braces(monkeypatch):
    from services import redirect_resolver

    captured = {}

    class FakeResponse:
        status_code = 200

        def json(self):
            return {
                "events": [
                    {
                        "eventAction": "registration",
                        "eventDate": "1997-09-15T04:00:00Z",
                    }
                ]
            }

    def fake_get(url, **kwargs):
        captured["url"] = url
        return FakeResponse()

    monkeypatch.setattr(redirect_resolver.requests, "get", fake_get)

    age_days, created_date = redirect_resolver.check_domain_age("google.com")

    assert captured["url"] == "https://rdap.org/domain/google.com"
    assert not captured["url"].startswith("{")
    assert not captured["url"].endswith("}")
    assert created_date == "1997-09-15"
    assert age_days is not None and age_days > 365 * 20


def test_mx_lookup_uses_valid_cloudflare_doh_url_without_literal_braces(monkeypatch):
    from services import redirect_resolver

    captured = {}

    class FakeResponse:
        status_code = 200

        def json(self):
            return {"Answer": [{"type": 15, "data": "10 smtp.google.com."}]}

    def fake_get(url, **kwargs):
        captured["url"] = url
        return FakeResponse()

    monkeypatch.setattr(redirect_resolver.requests, "get", fake_get)

    has_mx = redirect_resolver.check_mx_records("gmail.com")

    assert captured["url"] == "https://cloudflare-dns.com/dns-query?name=gmail.com&type=MX"
    assert not captured["url"].startswith("{")
    assert not captured["url"].endswith("}")
    assert has_mx is True


def test_tier1_classifier_recognizes_real_marketing_and_official_notices():
    classifier = Tier1Classifier.load_default()

    modivo = classifier.classify(
        "SALE pana la -50%! Pantofi de top le poti cumpara chiar si la jumatate de pret. "
        "https://snrs.it/0BJIIOV #MODIVOclub StopSMS http://oot.gg/nXy7lQfd"
    )
    orange = classifier.classify(
        "In data de 07-06-2026 s-a emis factura ta Orange in valoare de 32.32 lei. "
        "Descarca factura aici https://orange.ro/r/KK5IMyT"
    )
    scam = classifier.classify(
        "FanCourier: taxa vamala neachitata 3.50 RON. Introdu datele cardului aici https://fancurier-relivrare.com/plata"
    )

    assert modivo["label"] == "legit_marketing"
    assert modivo["confidence"] >= 0.5
    assert orange["label"] == "official_notice"
    assert orange["confidence"] >= 0.5
    assert scam["label"] == "scam_like"
    assert scam["confidence"] >= 0.5


def test_tier1_classifier_calibrates_semantic_false_positive_without_touching_hard_signals():
    review = {
        "status": "done",
        "claim_matches_known_scam_family": True,
        "matched_family": "F06",
        "claim_matches_legit_template": False,
        "matched_template": None,
        "reason_codes": ["semantic:high", "semantic:atlas_high_preserved"],
        "risk_class": "high",
        "completeness": True,
        "source": "mistral_semantic_pillar",
    }
    classifier_result = {
        "label": "legit_marketing",
        "confidence": 0.82,
        "source": "tier1_local_classifier",
    }

    calibrated = app_main._calibrate_semantic_review_with_tier1(
        review,
        classifier_result,
        raw_text="SALE pana la -50%! Pantofi de top la jumatate de pret. https://snrs.it/0BJIIOV",
    )

    assert calibrated["risk_class"] == "benign"
    assert calibrated["claim_matches_known_scam_family"] is False
    assert calibrated["claim_matches_legit_template"] is True
    assert calibrated["matched_template"] == "legit_marketing"
    assert "semantic:tier1_legit_override" in calibrated["reason_codes"]

    sensitive = app_main._calibrate_semantic_review_with_tier1(
        review,
        classifier_result,
        raw_text="SALE pana la -50%! Introdu datele cardului pentru confirmare.",
    )

    assert sensitive["risk_class"] == "high"


def test_provider_gate_projection_is_pure_and_matches_apply():
    analysis = {
        "claimed_brand": "YOXO",
        "risk_level": "medium",
        "risk_score": 72,
        "detected_family": "Text marketing suspect",
        "evidence": {
            "offer_claim_verification": {"status": "confirmed"},
            "external_intel_summary": {
                "google_web_risk": {"status": "clean", "verdict": "clean", "consulted": True},
                "virustotal": {"status": "clean", "verdict": "clean", "consulted": True},
                "urlscan": {"status": "clean", "verdict": "clean", "consulted": True},
            },
        },
    }
    original = json.loads(json.dumps(analysis))
    resolved_urls = [
        {
            "url": "https://buyback.yoxo.ro",
            "final_url": "https://buyback.yoxo.ro",
            "hostname": "buyback.yoxo.ro",
            "final_hostname": "buyback.yoxo.ro",
            "registered_domain": "yoxo.ro",
            "final_registered_domain": "yoxo.ro",
        }
    ]

    projection = _project_provider_gate_verdict(analysis, resolved_urls)
    applied = _apply_provider_gate_verdict(json.loads(json.dumps(analysis)), resolved_urls)

    assert analysis == original
    assert projection["risk_level"] == applied["risk_level"]
    assert projection["risk_score"] == applied["risk_score"]
    assert projection["detected_family_id"] == applied["detected_family_id"]
    assert projection["provider_gate"]["official_destination"] is True


def test_provider_gate_virustotal_malicious_is_decisive_provider_risk():
    analysis = {
        "claimed_brand": "Nespecificat",
        "risk_level": "low",
        "risk_score": 5,
        "detected_family": "Necunoscut",
        "evidence": {
            "external_intel_summary": {
                "google_web_risk": {"status": "clean", "verdict": "clean", "consulted": True},
                "virustotal": {
                    "status": "malicious",
                    "verdict": "malicious",
                    "severity": "high",
                    "consulted": True,
                    "details": "5 engines malicious",
                },
            },
        },
    }
    resolved_urls = [
        {
            "url": "https://malware-example.test/login",
            "final_url": "https://malware-example.test/login",
            "hostname": "malware-example.test",
            "final_hostname": "malware-example.test",
            "registered_domain": "malware-example.test",
            "final_registered_domain": "malware-example.test",
        }
    ]

    result = _apply_provider_gate_verdict(analysis, resolved_urls)

    assert result["risk_level"] == "high"
    assert result["risk_score"] == 90
    assert result["detected_family_id"] == "provider-gate-bad-provider"
    assert result["evidence"]["provider_gate"]["virustotal_consulted"] is True


def test_provider_gate_web_risk_malicious_is_decisive_provider_risk_when_other_providers_clean():
    analysis = {
        "claimed_brand": "Nespecificat",
        "risk_level": "low",
        "risk_score": 5,
        "detected_family": "Necunoscut",
        "evidence": {
            "external_intel_summary": {
                "google_web_risk": {
                    "status": "malicious",
                    "verdict": "malicious",
                    "consulted": True,
                    "risk_score": 100,
                    "threat_type": "SOCIAL_ENGINEERING",
                },
                "virustotal": {"status": "clean", "verdict": "clean", "consulted": True},
                "urlscan": {"status": "clean", "verdict": "clean", "consulted": True},
                "urlhaus": {"status": "clean", "verdict": "clean", "consulted": True},
            }
        },
    }
    resolved_urls = [
        {
            "url": "https://web-risk-only.example/login",
            "final_url": "https://web-risk-only.example/login",
            "hostname": "web-risk-only.example",
            "final_hostname": "web-risk-only.example",
            "registered_domain": "web-risk-only.example",
            "final_registered_domain": "web-risk-only.example",
        }
    ]

    result = _apply_provider_gate_verdict(analysis, resolved_urls)

    assert result["risk_level"] == "high"
    assert result["risk_score"] == 90
    assert result["detected_family_id"] == "provider-gate-bad-provider"
    provider_gate = result["evidence"]["provider_gate"]
    assert provider_gate["reason"] == "provider_malicious"
    assert provider_gate["web_risk_consulted"] is True
    assert provider_gate["virustotal_consulted"] is True
    assert provider_gate["urlscan_consulted"] is True
    assert "google_web_risk" in provider_gate["consulted_sources"]


def test_scam_atlas_text_only_social_fraud_escalates_to_high_risk():
    local_engine = ScamAtlasEngine()
    samples = [
        "Transcriere apel: apelantul plânge, spune că este nepotul, că a lovit pe cineva cu mașina și că avocatul cere 12.000 lei cash. Cere să nu fie sunată poliția.",
        "Transcriere apel: persoana spune că lucrează la banca mea, că am un credit aprobat fraudulos și că trebuie să confirm datele de acces în aplicația bancară.",
        "Transcriere apel: consultantul promite profit garantat la Hidroelectrica și îmi cere să instalez AnyDesk ca să mă ajute să cumpăr acțiuni.",
    ]

    for text in samples:
        result = local_engine.analyze(text, urls=[])
        assert result["risk_level"] in {"high", "critical"}
        assert result["risk_score"] >= 75
        assert "fraudă socială" in " ".join(result["reasons"])


def test_legitimate_otp_safety_message_does_not_create_circular_brand_warning():
    text = (
        "BT: codul tău de autentificare este 532424. Nu îl comunica nimănui, "
        "nici măcar unei persoane care pretinde că este de la bancă. Dacă nu ai "
        "inițiat tu operațiunea, ignoră mesajul și verifică aplicația oficială."
    )
    local_engine = ScamAtlasEngine()
    analysis = local_engine.analyze(text, urls=[])
    analysis["claimed_brand"] = "BT"

    final = _apply_provider_gate_verdict(analysis, [], raw_text=text)

    assert final["risk_level"] != "high"
    assert final["evidence"]["provider_gate"]["brand_warning"]["triggered"] is False
    assert final["evidence"]["provider_gate"]["direct_sensitive_request"] is False


def test_fan_tracking_subdomain_is_an_official_destination():
    local_engine = ScamAtlasEngine()
    urls = [
        {
            "url": "https://awb.fan.ro/hJ90LuI0605A8",
            "hostname": "awb.fan.ro",
            "registered_domain": "fan.ro",
            "final_url": "https://awb.fan.ro/hJ90LuI0605A8",
            "final_hostname": "awb.fan.ro",
            "final_registered_domain": "fan.ro",
            "success": True,
        }
    ]

    mismatch, domain = local_engine.check_brand_mismatch("FAN Courier", urls)

    assert mismatch is False
    assert domain is None


def test_provider_gate_brand_mismatch_sensitive_payment_is_high_risk():
    analysis = {
        "claimed_brand": "Poșta Română",
        "risk_level": "high",
        "risk_score": 75,
        "detected_family": "delivery_phishing / Poșta Română",
        "detected_family_id": "RO_SCN_002_POSTA_PHISHING",
        "reasons": [
            "Mismatch de Domeniu: Pretinde a fi de la Poșta Română, dar link-ul duce către un domeniu neoficial",
            "Pretext de livrare a unui colet sau taxe vamale neachitate",
        ],
        "evidence": {
            "has_domain_mismatch": True,
            "offer_claim_verification": {"status": "not_found"},
            "external_intel_summary": {
                "google_web_risk": {"status": "clean", "verdict": "clean", "consulted": True},
                "urlscan": {"status": "clean", "verdict": "clean", "consulted": True},
            },
        },
    }
    resolved_urls = [
        {
            "url": "https://conflict-posta.test/pay",
            "final_url": "https://conflict-posta.test/pay",
            "hostname": "conflict-posta.test",
            "final_hostname": "conflict-posta.test",
            "registered_domain": "conflict-posta.test",
            "final_registered_domain": "conflict-posta.test",
        }
    ]

    result = _apply_provider_gate_verdict(
        analysis,
        resolved_urls,
        raw_text="Poșta: plătește 5 lei pentru relivrare colet.",
    )

    assert result["risk_level"] == "high"
    assert result["risk_score"] >= 88
    assert result["detected_family_id"] == "provider-gate-decisive-structural-danger"


def test_provider_gate_keeps_text_only_social_fraud_high_risk():
    local_engine = ScamAtlasEngine()
    analysis = local_engine.analyze(
        "Bună, mama. Sunt eu. am făcut accident și scriu de pe numărul acesta temporar. "
        "Te rog nu mă suna acum. Am nevoie urgent de 1800 lei și îți trimit IBAN-ul unui prieten.",
        urls=[],
    )

    result = _apply_provider_gate_verdict(analysis, [], raw_text="am făcut accident urgent bani IBAN prieten")

    assert result["risk_level"] == "high"
    assert result["risk_score"] >= 85
    assert result["detected_family_id"] == analysis["evidence"]["scam_family"]["id"]
    assert result["evidence"]["provider_gate"]["detected_family_id"] == "provider-gate-semantic-high-risk"


def test_provider_gate_text_only_accident_money_transfer_without_iban_is_high_risk():
    text = (
        "Buna ziua, nepotul dvs a avut accident si are nevoie urgent de 4500 lei pentru operatie. "
        "Trimiteti banii acum prin transfer."
    )
    local_engine = ScamAtlasEngine()
    analysis = local_engine.analyze(text, urls=[])

    result = _apply_provider_gate_verdict(analysis, [], raw_text=text)

    assert result["risk_level"] == "high"
    assert result["risk_score"] >= 85
    assert result["detected_family_id"] == "F14"
    assert result["evidence"]["decision_bundle"]["request"]["sensitive"] == "transfer"
    assert result["evidence"]["provider_gate"]["detected_family_id"] == "provider-gate-semantic-high-risk"


def test_provider_gate_official_safety_education_does_not_trigger_false_positive():
    analysis = {
        "claimed_brand": "Bolt",
        "risk_level": "high",
        "risk_score": 65,
        "detected_family": "Marketing",
        "detected_family_id": "marketing",
        "reasons": [
            "Solicitare date personale sensibile (CNP, IBAN sau identificare)",
            "Solicitare date sensibile (card, CVC, PIN, cod de securitate)",
        ],
        "evidence": {
            "has_domain_mismatch": False,
            "offer_claim_verification": {"status": "confirmed"},
            "external_intel_summary": {
                "google_web_risk": {"status": "clean", "verdict": "clean", "consulted": True},
                "urlscan": {"status": "clean", "verdict": "clean", "consulted": True},
                "virustotal": {"status": "clean", "verdict": "clean", "consulted": True},
            },
        },
    }
    resolved_urls = [
        {
            "url": "https://bolt.eu/ro-ro/food/promo-test",
            "final_url": "https://bolt.eu/ro-ro/food/promo-test",
            "hostname": "bolt.eu",
            "final_hostname": "bolt.eu",
            "registered_domain": "bolt.eu",
            "final_registered_domain": "bolt.eu",
        }
    ]

    result = _apply_provider_gate_verdict(
        analysis,
        resolved_urls,
        raw_text="Ai o ofertă Bolt. Nu îți cerem CNP, PIN, CVV sau coduri SMS.",
    )

    assert result["risk_level"] == "low"
    assert result["detected_family_id"] == "provider-gate-official-clean"


def test_provider_gate_sensitive_url_path_on_unofficial_domain_is_high_risk():
    analysis = {
        "claimed_brand": "Nespecificat",
        "risk_level": "low",
        "risk_score": 15,
        "detected_family": "Necunoscut",
        "detected_family_id": "unknown",
        "reasons": ["Verificare externă curată."],
        "evidence": {
            "has_domain_mismatch": False,
            "offer_claim_verification": {"status": "not_found"},
            "external_intel_summary": {
                "google_web_risk": {"status": "clean", "verdict": "clean", "consulted": True},
                "urlscan": {"status": "clean", "verdict": "clean", "consulted": True},
            },
        },
    }
    resolved_urls = [
        {
            "url": "https://vama-pachet.test/card",
            "final_url": "https://vama-pachet.test/card",
            "hostname": "vama-pachet.test",
            "final_hostname": "vama-pachet.test",
            "registered_domain": "vama-pachet.test",
            "final_registered_domain": "vama-pachet.test",
        }
    ]

    result = _apply_provider_gate_verdict(analysis, resolved_urls)

    assert result["risk_level"] == "high"
    assert result["detected_family_id"] == "provider-gate-sensitive-wrong-channel"


def test_provider_gate_can_mark_official_destination_clean_without_virustotal():
    analysis = {
        "claimed_brand": "eMAG",
        "risk_level": "medium",
        "risk_score": 60,
        "detected_family": "Ofertă verificată",
        "evidence": {
            "offer_claim_verification": {"status": "confirmed"},
            "external_intel_summary": {
                "google_web_risk": {"status": "clean", "verdict": "clean", "consulted": True},
                "urlscan": {"status": "clean", "verdict": "clean", "consulted": True},
            },
        },
    }
    resolved_urls = [
        {
            "url": "https://www.emag.ro/order/tracking",
            "final_url": "https://www.emag.ro/order/tracking",
            "hostname": "www.emag.ro",
            "final_hostname": "www.emag.ro",
            "registered_domain": "emag.ro",
            "final_registered_domain": "emag.ro",
        }
    ]

    result = _apply_provider_gate_verdict(analysis, resolved_urls)

    assert result["risk_level"] == "low"
    assert result["detected_family_id"] == "provider-gate-official-clean"
    assert "VirusTotal" not in result["evidence"]["provider_gate"]["missing_required_pillars"]
    assert result["evidence"]["provider_gate"]["official_destination"] is True


def test_provider_gate_yoxo_onelink_subscription_notice_is_low_risk():
    analysis = {
        "claimed_brand": "YOXO",
        "risk_level": "critical",
        "risk_score": 91,
        "detected_family": "Marketing sau abonament telecom",
        "detected_family_id": "telecom-subscription-notice",
        "reasons": ["Mesajul menționează cardul în contextul unei plăți automate de abonament."],
        "evidence": {
            "has_domain_mismatch": False,
            "offer_claim_verification": {"status": "inconclusive"},
            "external_intel_summary": {
                "google_web_risk": {"status": "clean", "verdict": "clean", "consulted": True},
                "virustotal": {"status": "clean", "verdict": "clean", "consulted": True},
                "urlscan": {"status": "clean", "verdict": "No malicious classification", "consulted": True},
            },
        },
    }
    resolved_urls = [
        {
            "url": "https://yoxo.onelink.me/f8ly/ijiwsfwu",
            "final_url": "https://apps.apple.com/us/app/yoxo-voce-internet-roaming/id1481946568",
            "hostname": "yoxo.onelink.me",
            "final_hostname": "apps.apple.com",
            "registered_domain": "onelink.me",
            "final_registered_domain": "apple.com",
        }
    ]
    raw_text = (
        "In 24 de ore se va efectua automat plata abonamentului tau Orange YOXO cu numarul 0755287867. "
        "Asigura-te ca ai suficienti bani pe card. Poti vizualiza factura aici "
        "https://yoxo.onelink.me/f8ly/ijiwsfwu"
    )

    result = _apply_provider_gate_verdict(analysis, resolved_urls, raw_text=raw_text)

    assert result["risk_level"] == "low"
    assert result["detected_family_id"] == "provider-gate-official-clean"
    assert result["evidence"]["provider_gate"]["official_destination"] is True
    assert result["evidence"]["brand_warning"]["triggered"] is False


def test_provider_gate_yoxo_weak_virustotal_single_engine_does_not_hard_block():
    analysis = {
        "claimed_brand": "YOXO",
        "risk_level": "critical",
        "risk_score": 91,
        "detected_family": "Marketing sau abonament telecom",
        "detected_family_id": "telecom-subscription-notice",
        "reasons": ["Mesajul menționează cardul în contextul unei plăți automate de abonament."],
        "evidence": {
            "has_domain_mismatch": False,
            "offer_claim_verification": {"status": "inconclusive"},
            "external_intel_summary": {
                "google_web_risk": {"status": "clean", "verdict": "clean", "consulted": True},
                "virustotal": {
                    "status": "malicious",
                    "verdict": "malicious",
                    "consulted": True,
                    "malicious_hit_count": 1,
                    "details": {
                        "stats": {"harmless": 62, "malicious": 1, "suspicious": 0, "undetected": 32},
                        "flagged_engines": [
                            {"engine": "FlakyVendor", "category": "malicious", "result": "phishing"}
                        ],
                    },
                },
                "urlscan": {"status": "clean", "verdict": "No malicious classification", "consulted": True},
            },
        },
    }
    resolved_urls = [
        {
            "url": "https://yoxo.onelink.me/f8ly/ijiwsfwu",
            "final_url": "https://apps.apple.com/us/app/yoxo-voce-internet-roaming/id1481946568",
            "hostname": "yoxo.onelink.me",
            "final_hostname": "apps.apple.com",
            "registered_domain": "onelink.me",
            "final_registered_domain": "apple.com",
        }
    ]
    raw_text = (
        "In 24 de ore se va efectua automat plata abonamentului tau Orange YOXO cu numarul 0755287867. "
        "Asigura-te ca ai suficienti bani pe card. Poti vizualiza factura aici "
        "https://yoxo.onelink.me/f8ly/ijiwsfwu"
    )

    result = _apply_provider_gate_verdict(analysis, resolved_urls, raw_text=raw_text)

    assert result["risk_level"] == "low"
    assert result["detected_family_id"] == "provider-gate-official-clean"
    assert result["evidence"]["provider_gate"]["official_destination"] is True


def test_provider_gate_virustotal_consensus_still_hard_blocks():
    analysis = {
        "claimed_brand": "Nespecificat",
        "risk_level": "low",
        "risk_score": 10,
        "detected_family": "Provider clean înainte de consens",
        "detected_family_id": "provider-clean",
        "reasons": [],
        "evidence": {
            "offer_claim_verification": {"status": "skipped"},
            "external_intel_summary": {
                "google_web_risk": {"status": "clean", "verdict": "clean", "consulted": True},
                "virustotal": {
                    "status": "malicious",
                    "verdict": "malicious",
                    "consulted": True,
                    "malicious_hit_count": 3,
                    "details": {
                        "stats": {"harmless": 48, "malicious": 3, "suspicious": 1, "undetected": 30},
                    },
                },
                "urlscan": {"status": "clean", "verdict": "No malicious classification", "consulted": True},
            },
        },
    }
    resolved_urls = [
        {
            "url": "https://unknown.example.com/",
            "final_url": "https://unknown.example.com/",
            "hostname": "unknown.example.com",
            "final_hostname": "unknown.example.com",
            "registered_domain": "example.com",
            "final_registered_domain": "example.com",
        }
    ]

    result = _apply_provider_gate_verdict(analysis, resolved_urls, raw_text="Verifică aici https://unknown.example.com/")

    assert result["risk_level"] == "high"
    assert result["detected_family_id"] == "provider-gate-bad-provider"


def test_scam_atlas_yoxo_onelink_surface_domain_is_not_brand_mismatch():
    engine = ScamAtlasEngine()
    text = (
        "In 24 de ore se va efectua automat plata abonamentului tau Orange YOXO cu numarul 0755287867. "
        "Asigura-te ca ai suficienti bani pe card. Poti vizualiza factura aici "
        "https://yoxo.onelink.me/f8ly/ijiwsfwu"
    )
    resolved_urls = [
        {
            "url": "https://yoxo.onelink.me/f8ly/ijiwsfwu",
            "final_url": "https://yoxo.onelink.me/f8ly/ijiwsfwu",
            "hostname": "yoxo.onelink.me",
            "final_hostname": "yoxo.onelink.me",
            "registered_domain": "onelink.me",
            "final_registered_domain": "onelink.me",
        }
    ]

    result = engine.analyze(text, resolved_urls)

    assert result["claimed_brand"] == "YOXO"
    assert result["evidence"]["has_domain_mismatch"] is False
    assert "Solicitare date sensibile" not in " ".join(result["reasons"])
    assert "șantaj digital" not in " ".join(result["reasons"]).lower()


def test_scan_text_legacy_endpoint_starts_orchestrated_without_final_verdict(monkeypatch):
    client = TestClient(app_main.app)
    text = (
        "In 24 de ore se va efectua automat plata abonamentului tau Orange YOXO cu numarul 0755287867. "
        "Asigura-te ca ai suficienti bani pe card. Poti vizualiza factura aici "
        "https://yoxo.onelink.me/f8ly/ijiwsfwu"
    )

    def fake_stale_yoxo_onelink_scan(urls):
        return [
            {
                "url": "https://yoxo.onelink.me/f8ly/ijiwsfwu",
                "original_url": "https://yoxo.onelink.me/f8ly/ijiwsfwu",
                "final_url": "https://yoxo.onelink.me/f8ly/ijiwsfwu",
                "hostname": "yoxo.onelink.me",
                "final_hostname": "yoxo.onelink.me",
                "registered_domain": "onelink.me",
                "final_registered_domain": "onelink.me",
                "success": False,
                "error_message": "Too many redirects (library-level)",
                "redirect_chain": [],
                "redirect_count": 0,
                "shortener_count": 0,
                "uses_shortener": False,
                "detected_soft_redirects": [],
            }
        ]

    def fail_if_provider_runs_in_post(*args, **kwargs):
        raise AssertionError("Legacy /v1/scan/text must only create an orchestrated job in POST.")

    with monkeypatch.context() as patched:
        patched.setattr(app_main, "PRIVACY_SAFE_MODE", False)
        patched.setattr(app_main, "_safe_scan_url_list", fail_if_provider_runs_in_post)
        patched.setattr(app_main, "_gather_external_intel_safe", fail_if_provider_runs_in_post)
        patched.setattr(app_main, "_emit_scan_event", lambda *args, **kwargs: None)
        response = client.post("/v1/scan/text", json={"text": text, "source_channel": "android_native"})

    assert response.status_code == 200
    payload = response.json()
    assert payload["status"] == "scanning"
    assert payload["result"] is None
    assert str(payload["scan_id"]).startswith("orch_")
    assert "user_risk_label" not in payload
    assert "risk_level" not in payload


def test_provider_gate_deeplink_to_untrusted_destination_stays_suspicious():
    analysis = {
        "claimed_brand": "YOXO",
        "risk_level": "medium",
        "risk_score": 55,
        "detected_family": "Deep-link suspect",
        "reasons": ["Destinație finală neoficială."],
        "evidence": {
            "has_domain_mismatch": True,
            "offer_claim_verification": {"status": "not_found"},
            "external_intel_summary": {
                "google_web_risk": {"status": "clean", "verdict": "clean", "consulted": True},
                "virustotal": {"status": "clean", "verdict": "clean", "consulted": True},
                "urlscan": {"status": "clean", "verdict": "clean", "consulted": True},
            },
        },
    }
    resolved_urls = [
        {
            "url": "https://yoxo.onelink.me/f8ly/fake",
            "final_url": "https://promo-yoxo-login.example.test/verify",
            "hostname": "yoxo.onelink.me",
            "final_hostname": "promo-yoxo-login.example.test",
            "registered_domain": "onelink.me",
            "final_registered_domain": "example.test",
        }
    ]

    result = _apply_provider_gate_verdict(
        analysis,
        resolved_urls,
        raw_text="YOXO: confirmă datele contului aici https://yoxo.onelink.me/f8ly/fake",
    )

    assert result["risk_level"] != "low"
    assert result["evidence"]["provider_gate"]["official_destination"] is False


def test_provider_gate_keeps_official_bank_domain_suspect_when_message_requests_password_and_otp():
    analysis = {
        "claimed_brand": "ING Bank România",
        "risk_level": "medium",
        "risk_score": 58,
        "detected_family": "Solicitare credentiale",
        "reasons": ["Mesajul cere parola si codul OTP pentru verificare cont."],
        "evidence": {
            "offer_claim_verification": {"status": "confirmed"},
            "external_intel_summary": {
                "google_web_risk": {"status": "clean", "verdict": "clean", "consulted": True},
                "virustotal": {"status": "clean", "verdict": "clean", "consulted": True},
                "urlscan": {"status": "clean", "verdict": "clean", "consulted": True},
            },
        },
    }
    resolved_urls = [
        {
            "url": "https://ing.ro/login",
            "final_url": "https://ing.ro/login",
            "hostname": "ing.ro",
            "final_hostname": "ing.ro",
            "registered_domain": "ing.ro",
            "final_registered_domain": "ing.ro",
        }
    ]

    result = _apply_provider_gate_verdict(
        analysis,
        resolved_urls,
        raw_text="ING: Pentru deblocare cont, introdu parola si codul OTP pe ing.ro/login",
    )

    assert result["risk_level"] == "low"
    assert result["detected_family_id"] == "provider-gate-official-clean"
    assert result["evidence"]["brand_warning"]["triggered"] is True
    assert "otp" in result["evidence"]["brand_warning"]["matched_assets"]
    assert "password" in result["evidence"]["brand_warning"]["matched_assets"]


def test_provider_gate_exposes_brand_warning_for_fake_fan_delivery_payment():
    analysis = {
        "claimed_brand": "FAN Courier",
        "risk_level": "high",
        "risk_score": 81,
        "detected_family": "Curier fals",
        "detected_family_id": "courier-fake-payment",
        "reasons": ["Mesajul cere plata taxei vamale si datele cardului pentru relivrare."],
        "evidence": {
            "has_domain_mismatch": True,
            "offer_claim_verification": {"status": "inconclusive"},
            "external_intel_summary": {
                "google_web_risk": {"status": "clean", "verdict": "clean", "consulted": True},
                "virustotal": {"status": "clean", "verdict": "clean", "consulted": True},
                "urlscan": {"status": "clean", "verdict": "clean", "consulted": True},
            },
        },
    }
    resolved_urls = [
        {
            "url": "https://fancurier-relivrare.com/plata",
            "final_url": "https://fancurier-relivrare.com/plata",
            "hostname": "fancurier-relivrare.com",
            "final_hostname": "fancurier-relivrare.com",
            "registered_domain": "fancurier-relivrare.com",
            "final_registered_domain": "fancurier-relivrare.com",
        }
    ]

    result = _apply_provider_gate_verdict(
        analysis,
        resolved_urls,
        raw_text="FAN Courier: taxa vamala neachitata. Introdu datele cardului pentru relivrare.",
    )

    assert result["risk_level"] == "high"
    assert result["detected_family_id"] == "provider-gate-decisive-structural-danger"
    assert result["evidence"]["brand_warning"]["triggered"] is True
    assert "card_number" in result["evidence"]["brand_warning"]["matched_assets"]
    summary = result["evidence"]["external_intel_summary"]["brand_warning_corpus"]
    assert summary["verdict"] == "brand_warning"
    assert "card_number" in summary["matched_assets"]


def _fake_yoxo_safe_scan(urls):
    resolved = []
    for raw_url in urls:
        resolved.append(
            {
                "url": raw_url,
                "original_url": raw_url,
                "final_url": "https://buyback.yoxo.ro/",
                "hostname": "buyback.yoxo.ro",
                "final_hostname": "buyback.yoxo.ro",
                "registered_domain": "yoxo.ro",
                "final_registered_domain": "yoxo.ro",
                "redirect_chain": [{"url": raw_url}, {"url": "https://buyback.yoxo.ro/"}],
                "redirect_count": 1,
                "shortener_count": 0,
                "uses_shortener": False,
                "detected_soft_redirects": [],
                "domain_age_days": 1200,
                "domain_created_date": "2022-01-01",
                "has_mx_records": True,
                "success": True,
            }
        )
    return resolved


async def _fake_confirmed_offer_claim(text, analysis, resolved_urls):
    offer_claim = {
        "provider": "ai_offer_web_check",
        "status": "confirmed",
        "verdict": "confirmed",
        "severity": "low",
        "summary": "Oferta este confirmată pe domeniul oficial.",
        "details": "Oferta este confirmată pe domeniul oficial.",
        "confidence": 85,
        "claimed_brand": "YOXO",
        "official_domains": ["yoxo.ro", "buyback.yoxo.ro", "orange.ro"],
        "evidence_urls": ["https://buyback.yoxo.ro/"],
        "method": "test",
        "official_source_found": True,
    }
    app_main._attach_offer_claim_verification(analysis, offer_claim)
    return offer_claim


def _fake_urlscan_post(url, headers, json, timeout):
    return _FakeUrlscanResponse(payload={"uuid": "urlscan-yoxo-1"})


def _fake_urlscan_get_clean(url, headers, timeout, **kwargs):
    if "result/urlscan-yoxo-1" in url:
        return _FakeUrlscanResponse(
            payload={
                "task": {"url": "https://buyback.yoxo.ro/"},
                "page": {
                    "url": "https://buyback.yoxo.ro/",
                    "ip": "203.0.113.20",
                    "country": "RO",
                    "server": "cloudflare",
                },
                "verdicts": {
                    "overall": {
                        "malicious": False,
                        "suspicious": False,
                        "score": 0,
                        "categories": [],
                    }
                },
                "brands": ["YOXO"],
            }
        )
    return _FakeUrlscanResponse(content=b"\x89PNG\r\n", headers={"content-type": "image/png"})


def _fake_urlscan_get_clean_without_screenshot(url, headers, timeout, **kwargs):
    if "result/urlscan-yoxo-1" in url:
        return _fake_urlscan_get_clean(url, headers, timeout)
    return _FakeUrlscanResponse(status_code=404, payload={"message": "screenshot not ready"})


def _fake_urlscan_get_malicious(url, headers, timeout, **kwargs):
    if "result/urlscan-yoxo-1" in url:
        return _FakeUrlscanResponse(
            payload={
                "task": {"url": "https://buyback.yoxo.ro/"},
                "page": {
                    "url": "https://evil-phishing.test/login",
                    "ip": "203.0.113.66",
                    "country": "RO",
                    "server": "nginx",
                },
                "verdicts": {
                    "overall": {
                        "malicious": True,
                        "suspicious": True,
                        "score": 100,
                        "categories": ["phishing"],
                    }
                },
                "brands": ["YOXO"],
            }
        )
    return _FakeUrlscanResponse(content=b"\x89PNG\r\n", headers={"content-type": "image/png"})


def _poll_orchestrated(client: TestClient, scan_id: str, count: int = 1):
    payload = None
    response = None
    for _ in range(count):
        response = client.get(f"/v1/scan/orchestrated/{scan_id}")
        assert response.status_code == 200
        payload = response.json()
    return response, payload


def test_orchestrated_post_accepts_without_running_providers(monkeypatch):
    client = TestClient(app_main.app)
    message = (
        "Ai un telefon sau o tableta pe care nu le mai folosesti? "
        "Acum le poti transforma rapid in bani cu serviciul de buy-back YOXO. "
        "Afla cat valoreaza dispozitivul tau si incepe procesul chiar acum: buyback.yoxo.ro"
    )

    with monkeypatch.context() as patched:
        patched.setattr(app_main, "PRIVACY_SAFE_MODE", False)
        patched.setattr(app_main, "URLSCAN_API_KEY", "server-only-key")
        patched.setattr(
            app_main,
            "_safe_scan_url_list",
            lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("POST must not resolve URLs")),
        )
        patched.setattr(
            app_main,
            "_gather_external_intel_safe",
            lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("POST must not call providers")),
        )
        patched.setattr(
            app_main.requests,
            "post",
            lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("POST must not submit urlscan")),
        )

        response = client.post(
            "/v1/scan/orchestrated",
            json={"input_type": "text", "text": message, "source_channel": "android_native"},
        )

    assert response.status_code == 200
    payload = response.json()
    assert payload["status"] == "scanning"
    assert payload["scan_id"].startswith("orch_")
    assert payload["result"] is None
    assert payload["pillars"]["final_url"]["status"] == "pending"
    assert payload["pillars"]["google_web_risk"]["status"] == "pending"
    assert payload["pillars"]["virustotal"]["status"] == "pending"
    assert payload["pillars"]["claim_verifier"]["status"] == "not_required"
    assert payload["pillars"]["urlscan"]["status"] == "pending"
    assert payload["preview"]["screenshot_url"] is None


def test_orchestrated_first_poll_runs_fast_lane_without_blocking_on_preview(monkeypatch):
    calls = []
    job = {
        "scan_id": "orch_fast_lane",
        "created_at": int(time.time()),
        "pipeline_stage": "queued",
        "status": "scanning",
        "input_type": "text",
        "source_channel": "android_native",
        "urls": ["https://buyback.yoxo.ro"],
        "redacted_text": "YOXO buyback https://buyback.yoxo.ro",
        "analysis": {},
        "resolved_urls": [],
        "primary_final_url": None,
        "claim_verifier_required": False,
        "urlscan": {"status": "queued"},
        "preview": {},
        "extra_fields": {},
        "sandbox_options": {},
        "orchestration_metrics": {"poll_count": 0, "stage_sequence": [], "stage_durations_ms": {}},
    }
    resolved_urls = [
        {
            "url": "https://buyback.yoxo.ro",
            "final_url": "https://buyback.yoxo.ro",
            "hostname": "buyback.yoxo.ro",
            "final_hostname": "buyback.yoxo.ro",
            "registered_domain": "yoxo.ro",
            "final_registered_domain": "yoxo.ro",
            "success": True,
            "domain_age_days": 2500,
        }
    ]

    def fake_external_intel(urls, *args, **kwargs):
        calls.append(kwargs)
        output = _clean_web_risk_and_vt_for_resolved_urls(urls)
        for entry in output.values():
            entry.setdefault("sources", {})["urlhaus"] = {
                "status": "clean",
                "consulted": True,
                "score": 0,
                "threat_type": "unknown",
            }
        return output

    def fake_analyze(text, urls, **kwargs):
        summary = app_main._external_intel_summary_from_threat_intel(kwargs["threat_intel_override"])
        return {
            "risk_score": 10,
            "risk_level": "low",
            "detected_family": "Provideri curați",
            "detected_family_id": "clean",
            "claimed_brand": "YOXO",
            "reasons": [],
            "safe_actions": [],
            "evidence": {
                "external_intel_summary": summary,
                "semantic_review": {
                    "status": "done",
                    "risk_class": "benign",
                    "claim_matches_known_scam_family": False,
                    "claim_matches_legit_template": True,
                    "matched_template": "official_notice",
                    "completeness": True,
                },
            },
        }

    async def fail_submit(url, payload, request):
        raise AssertionError("First orchestrated poll must not submit urlscan preview.")

    async def fail_ai(*args, **kwargs):
        raise AssertionError("First orchestrated poll must use deterministic explanation, not cloud AI.")

    with monkeypatch.context() as patched:
        patched.setattr(app_main, "_safe_scan_url_list", lambda urls: resolved_urls)
        patched.setattr(app_main, "_gather_external_intel_safe", fake_external_intel)
        patched.setattr(app_main, "_analyze_with_reputation", fake_analyze)
        patched.setattr(app_main, "_claim_verifier_required", lambda analysis: False)
        patched.setattr(app_main, "_submit_orchestrated_urlscan", fail_submit)
        patched.setattr(app_main, "_build_ai_explanation_async", fail_ai)
        patched.setattr(app_main, "_persist_orchestrated_job", lambda candidate: candidate)
        patched.setattr(app_main, "_emit_orchestrated_telemetry", lambda *args, **kwargs: None)
        patched.setattr(app_main, "_emit_scan_event", lambda *args, **kwargs: None)
        refreshed = asyncio.run(app_main._refresh_orchestrated_job(job, None))

    assert refreshed["pipeline_stage"] == "analysis_ready"
    assert refreshed["result"]["user_risk_label"] == "SIGUR"
    assert refreshed["result"]["is_final"] is True
    assert refreshed["urlscan"]["status"] == "queued"
    assert refreshed["preview"].get("report_url") is None
    assert refreshed["preview"].get("screenshot_url") is None
    assert calls == [
        {
            "include_virustotal": True,
            "include_urlhaus": True,
            "persist_partial": False,
        }
    ]


def test_orchestrated_resolved_stage_collects_fast_reputation_without_urlhaus(monkeypatch):
    calls = []
    job = {
        "scan_id": "orch_urlhaus_initial",
        "created_at": int(time.time()),
        "pipeline_stage": "resolved",
        "status": "scanning",
        "input_type": "text",
        "source_channel": "test",
        "urls": ["https://example.com/login"],
        "redacted_text": "Verifica aici https://example.com/login",
        "resolved_urls": [
            {
                "url": "https://example.com/login",
                "final_url": "https://example.com/login",
                "final_hostname": "example.com",
                "final_registered_domain": "example.com",
                "success": True,
            }
        ],
        "analysis": {},
        "preview": {},
        "urlscan": {"status": "queued"},
        "orchestration_metrics": {"poll_count": 0, "stage_sequence": [], "stage_durations_ms": {}},
    }

    def fake_external_intel(resolved_urls, *args, **kwargs):
        calls.append(kwargs)
        return _clean_web_risk_and_vt_for_resolved_urls(resolved_urls)

    with monkeypatch.context() as patched:
        patched.setattr(app_main, "_gather_external_intel_safe", fake_external_intel)
        patched.setattr(app_main, "_persist_orchestrated_job", lambda candidate: candidate)
        patched.setattr(app_main, "_emit_orchestrated_telemetry", lambda *args, **kwargs: None)
        refreshed = asyncio.run(app_main._refresh_orchestrated_job(job, None))

    assert refreshed["pipeline_stage"] == "urlhaus_ready"
    assert calls == [
        {
            "include_virustotal": True,
            "include_urlhaus": False,
            "persist_partial": False,
        }
    ]


def test_orchestrated_urlhaus_stage_collects_urlhaus_once(monkeypatch):
    calls = []
    job = {
        "scan_id": "orch_urlhaus_stage",
        "created_at": int(time.time()),
        "pipeline_stage": "urlhaus_ready",
        "status": "scanning",
        "input_type": "text",
        "source_channel": "test",
        "urls": ["https://example.com/login"],
        "redacted_text": "Verifica aici https://example.com/login",
        "resolved_urls": [
            {
                "url": "https://example.com/login",
                "final_url": "https://example.com/login",
                "final_hostname": "example.com",
                "final_registered_domain": "example.com",
                "success": True,
            }
        ],
        "threat_intel": _clean_web_risk_and_vt_for_resolved_urls(
            [{"final_url": "https://example.com/login"}]
        ),
        "analysis": {
            "evidence": {
                "external_intel_summary": {
                    "google_web_risk": {"status": "clean", "consulted": True},
                    "virustotal": {"status": "clean", "consulted": True},
                }
            }
        },
        "preview": {},
        "urlscan": {"status": "queued"},
        "orchestration_metrics": {"poll_count": 0, "stage_sequence": [], "stage_durations_ms": {}},
    }

    def fake_external_intel(resolved_urls, *args, **kwargs):
        calls.append(kwargs)
        output = _clean_web_risk_and_vt_for_resolved_urls(resolved_urls)
        for entry in output.values():
            entry.setdefault("sources", {})["urlhaus"] = {
                "status": "clean",
                "consulted": True,
                "score": 0,
                "threat_type": "unknown",
            }
            entry["sources"]["virustotal"] = {
                "status": "unknown",
                "consulted": False,
                "score": 0,
                "threat_type": "unknown",
                "details": {"status": "skipped_fast_scan"},
            }
        return output

    with monkeypatch.context() as patched:
        patched.setattr(app_main, "_gather_external_intel_safe", fake_external_intel)
        patched.setattr(app_main, "_persist_orchestrated_job", lambda candidate: candidate)
        patched.setattr(app_main, "_emit_orchestrated_telemetry", lambda *args, **kwargs: None)
        refreshed = asyncio.run(app_main._refresh_orchestrated_job(job, None))

    assert refreshed["pipeline_stage"] == "reputation_ready"
    assert calls == [
        {
            "include_virustotal": False,
            "include_urlhaus": True,
            "persist_partial": False,
        }
    ]
    summary = refreshed["analysis"]["evidence"]["external_intel_summary"]
    assert summary["virustotal"]["status"] == "clean"
    assert summary["virustotal"]["consulted"] is True
    assert summary["urlhaus"]["status"] == "clean"
    assert summary["urlhaus"]["consulted"] is True


def test_orchestrated_reputation_stage_runs_mistral_as_semantic_pillar(monkeypatch):
    job = {
        "scan_id": "orch_semantic_test",
        "pipeline_stage": "reputation_ready",
        "redacted_text": "Promo magazin: verifică oferta aici https://example.com/promo",
        "source_channel": "sms",
        "resolved_urls": [
            {
                "url": "https://example.com/promo",
                "final_url": "https://example.com/promo",
                "final_hostname": "example.com",
                "final_registered_domain": "example.com",
                "success": True,
            }
        ],
        "threat_intel": {},
        "orchestration_metrics": {
            "poll_count": 0,
            "stage_sequence": [],
            "stage_durations_ms": {},
        },
    }

    def fake_analyze(text, resolved_urls, **kwargs):
        return {
            "risk_score": 0,
            "risk_level": "low",
            "detected_family": "Context benign",
            "detected_family_id": "semantic-test",
            "claimed_brand": "Nespecificat",
            "reasons": [],
            "safe_actions": [],
            "evidence": {
                "external_intel_summary": {
                    "google_web_risk": {"status": "clean", "verdict": "clean", "consulted": True},
                    "virustotal": {"status": "clean", "verdict": "clean", "consulted": True},
                }
            },
        }

    def fake_mistral(payload):
        return {
            "risk_class": "benign",
            "claim_matches_known_scam_family": False,
            "matched_family": None,
            "claim_matches_legit_template": True,
            "matched_template": "normal_promo",
            "reason_codes": ["semantic:benign_marketing"],
            "confidence": 0.86,
        }

    async def fake_finalize(candidate, request):
        return candidate

    with monkeypatch.context() as patched:
        patched.setattr(app_main, "PRIVACY_SAFE_MODE", False)
        patched.setattr(app_main, "ENABLE_MISTRAL_SEMANTIC_PILLAR", True)
        patched.setattr(app_main, "MISTRAL_SEMANTIC_API_KEY", "test-key")
        patched.setattr(app_main, "_analyze_with_reputation", fake_analyze)
        patched.setattr(app_main, "_claim_verifier_required", lambda analysis: False)
        patched.setattr(app_main, "_call_mistral_semantic_review", fake_mistral)
        patched.setattr(app_main, "_persist_orchestrated_job", lambda candidate: candidate)
        patched.setattr(app_main, "_finalize_orchestrated_job_if_ready", fake_finalize)
        patched.setattr(app_main, "_emit_orchestrated_telemetry", lambda *args, **kwargs: None)

        refreshed = asyncio.run(app_main._refresh_orchestrated_job(job, None))
        assert refreshed["pipeline_stage"] == "semantic_ready"
        assert "semantic_review" not in refreshed["analysis"].get("evidence", {})

        refreshed = asyncio.run(app_main._refresh_orchestrated_job(refreshed, None))

    review = refreshed["analysis"]["evidence"]["semantic_review"]
    assert refreshed["pipeline_stage"] == "claim_ready"
    assert review["source"] == "mistral_semantic_pillar"
    assert review["risk_class"] == "benign"
    assert review["claim_matches_legit_template"] is True
    assert review["claim_matches_known_scam_family"] is False
    assert "user_risk_label" not in review


def test_mistral_semantic_review_cannot_downgrade_atlas_high_risk_family():
    fallback = {
        "status": "done",
        "claim_matches_known_scam_family": True,
        "matched_family": "F13",
        "claim_matches_legit_template": False,
        "matched_template": None,
        "reason_codes": ["semantic:high", "family:f13"],
        "risk_class": "high",
        "confidence_class": "medium",
        "family_confidence": 0.42,
        "completeness": True,
        "source": "scam_atlas_structured",
    }
    raw = {
        "risk_class": "medium",
        "claim_matches_known_scam_family": True,
        "matched_family": "F13",
        "claim_matches_legit_template": False,
        "matched_template": None,
        "reason_codes": ["semantic:mistral_medium"],
        "confidence": 0.71,
    }

    review = app_main._normalize_mistral_semantic_review(raw, fallback)

    assert review["risk_class"] == "high"
    assert review["claim_matches_known_scam_family"] is True
    assert review["claim_matches_legit_template"] is False
    assert review["matched_family"] == "F13"
    assert "semantic:atlas_high_preserved" in review["reason_codes"]


def test_orchestrated_reputation_analysis_reuses_existing_intel_without_deep_fallback(monkeypatch):
    def fake_engine_analyze(text, **kwargs):
        return {
            "risk_score": 45,
            "risk_level": "medium",
            "detected_family": "Domeniu neoficial cu card",
            "detected_family_id": "domain-card-context",
            "claimed_brand": "YOXO",
            "reasons": [],
            "safe_actions": [],
            "evidence": {
                "has_domain_mismatch": True,
                "external_intel_summary": {
                    "google_web_risk": {"status": "clean", "consulted": True},
                    "virustotal": {"status": "clean", "consulted": True},
                },
            },
        }

    def fail_external_intel(*args, **kwargs):
        raise AssertionError("Orchestrated reputation stage must not run a second deep provider fallback.")

    with monkeypatch.context() as patched:
        patched.setattr(app_main, "PRIVACY_SAFE_MODE", False)
        patched.setattr(app_main, "ENABLE_VT_FALLBACK", True)
        patched.setattr(app_main.engine, "analyze", fake_engine_analyze)
        patched.setattr(app_main, "_gather_external_intel_safe", fail_external_intel)
        analysis = app_main._analyze_with_reputation(
            "YOXO card context https://example.com",
            [{"final_url": "https://example.com"}],
            fast_reputation=True,
            threat_intel_override={
                "https://example.com": {
                    "sources": {
                        "google_web_risk": {"status": "clean", "consulted": True},
                        "virustotal": {"status": "clean", "consulted": True},
                    }
                }
            },
            allow_deep_fallback=False,
        )

    assert analysis["evidence"]["vt_fallback"] is False


def test_orchestrated_text_scan_completes_safe_after_urlscan_preview(monkeypatch):
    client = TestClient(app_main.app)
    message = (
        "Ai un telefon sau o tableta pe care nu le mai folosesti? "
        "Acum le poti transforma rapid in bani cu serviciul de buy-back YOXO. "
        "Afla cat valoreaza dispozitivul tau si incepe procesul chiar acum: buyback.yoxo.ro"
    )

    with monkeypatch.context() as patched:
        patched.setattr(app_main, "PRIVACY_SAFE_MODE", False)
        patched.setattr(app_main, "URLSCAN_API_KEY", "server-only-key")
        patched.setattr(app_main, "_safe_scan_url_list", _fake_yoxo_safe_scan)
        patched.setattr(app_main, "_gather_external_intel_safe", _clean_external_intel_for_resolved_urls)
        patched.setattr(app_main, "_enrich_offer_claim_verification_async", _fake_confirmed_offer_claim)
        patched.setattr(app_main.requests, "post", _fake_urlscan_post)
        patched.setattr(app_main.requests, "get", _fake_urlscan_get_clean)

        start = client.post(
            "/v1/scan/orchestrated",
            json={"input_type": "text", "text": message, "source_channel": "android_native"},
        ).json()
        response, payload = _poll_orchestrated(client, start["scan_id"], count=9)

    assert response.status_code == 200
    assert payload["status"] == "complete"
    assert payload["pillars"]["urlscan"]["status"] == "ok"
    assert payload["preview"]["screenshot_url"]
    assert payload["result"]["user_risk_label"] == "SIGUR"
    assert payload["result"]["risk_level"] == "low"
    assert payload["result"]["is_final"] is True
    assert payload["result"]["evidence"]["provider_gate"]["urlscan_consulted"] is True


def test_orchestrated_scan_finalizes_when_urlscan_report_exists_but_screenshot_is_not_ready(monkeypatch):
    client = TestClient(app_main.app)
    message = (
        "Ai un telefon sau o tableta pe care nu le mai folosesti? "
        "Acum le poti transforma rapid in bani cu serviciul de buy-back YOXO. "
        "Afla cat valoreaza dispozitivul tau si incepe procesul chiar acum: buyback.yoxo.ro"
    )

    with monkeypatch.context() as patched:
        patched.setattr(app_main, "PRIVACY_SAFE_MODE", False)
        patched.setattr(app_main, "URLSCAN_API_KEY", "server-only-key")
        patched.setattr(app_main, "_safe_scan_url_list", _fake_yoxo_safe_scan)
        patched.setattr(app_main, "_gather_external_intel_safe", _clean_external_intel_for_resolved_urls)
        patched.setattr(app_main, "_enrich_offer_claim_verification_async", _fake_confirmed_offer_claim)
        patched.setattr(app_main.requests, "post", _fake_urlscan_post)
        patched.setattr(app_main.requests, "get", _fake_urlscan_get_clean_without_screenshot)

        start = client.post(
            "/v1/scan/orchestrated",
            json={"input_type": "text", "text": message, "source_channel": "android_native"},
        ).json()
        response, payload = _poll_orchestrated(client, start["scan_id"], count=8)

    assert response.status_code == 200
    assert payload["status"] == "complete"
    assert payload["pillars"]["urlscan"]["status"] == "ok"
    assert payload["result"]["user_risk_label"] == "SIGUR"
    assert payload["result"]["risk_level"] == "low"
    assert payload["result"]["is_final"] is True


def test_orchestrated_clean_verdict_submits_preview_before_complete(monkeypatch):
    client = TestClient(app_main.app)
    message = (
        "Ai un telefon sau o tableta pe care nu le mai folosesti? "
        "Acum le poti transforma rapid in bani cu serviciul de buy-back YOXO. "
        "Afla cat valoreaza dispozitivul tau si incepe procesul chiar acum: buyback.yoxo.ro"
    )

    with monkeypatch.context() as patched:
        patched.setattr(app_main, "PRIVACY_SAFE_MODE", False)
        patched.setattr(app_main, "ENABLE_CLOUD_AI_EXPLANATION", False)
        patched.setattr(app_main, "URLSCAN_API_KEY", "server-only-key")
        patched.setattr(app_main, "_safe_scan_url_list", _fake_yoxo_safe_scan)
        patched.setattr(app_main, "_gather_external_intel_safe", _clean_external_intel_for_resolved_urls)
        patched.setattr(app_main, "_enrich_offer_claim_verification_async", _fake_confirmed_offer_claim)
        patched.setattr(app_main.requests, "post", _fake_urlscan_post)

        start = client.post(
            "/v1/scan/orchestrated",
            json={"input_type": "text", "text": message, "source_channel": "android_native"},
        ).json()
        response, payload = _poll_orchestrated(client, start["scan_id"], count=1)
        _, with_preview = _poll_orchestrated(client, start["scan_id"], count=1)

    assert response.status_code == 200
    assert payload["status"] == "complete"
    assert payload["result"]["user_risk_label"] == "SIGUR"
    assert payload["result"]["risk_level"] == "low"
    assert payload["pillars"]["urlscan"]["required"] is False
    assert payload["pillars"]["urlscan"]["status"] == "pending"
    assert payload["preview"]["report_url"] is None
    assert payload["preview"]["screenshot_url"] is None
    assert with_preview["status"] == "complete"
    assert with_preview["result"]["user_risk_label"] == "SIGUR"
    assert with_preview["pillars"]["urlscan"]["status"] == "pending"
    assert with_preview["preview"]["report_url"] == "https://urlscan.io/result/urlscan-yoxo-1/"
    assert with_preview["preview"]["screenshot_url"] == "http://testserver/v1/sandbox/urlscan/urlscan-yoxo-1/screenshot"


def test_orchestrated_urlscan_late_risk_upgrades_provisional_safe_verdict(monkeypatch):
    client = TestClient(app_main.app)
    message = (
        "Ai un telefon sau o tableta pe care nu le mai folosesti? "
        "Acum le poti transforma rapid in bani cu serviciul de buy-back YOXO. "
        "Afla cat valoreaza dispozitivul tau si incepe procesul chiar acum: buyback.yoxo.ro"
    )

    with monkeypatch.context() as patched:
        patched.setattr(app_main, "PRIVACY_SAFE_MODE", False)
        patched.setattr(app_main, "ENABLE_CLOUD_AI_EXPLANATION", False)
        patched.setattr(app_main, "URLSCAN_API_KEY", "server-only-key")
        patched.setattr(app_main, "_safe_scan_url_list", _fake_yoxo_safe_scan)
        patched.setattr(app_main, "_gather_external_intel_safe", _clean_external_intel_for_resolved_urls)
        patched.setattr(app_main, "_enrich_offer_claim_verification_async", _fake_confirmed_offer_claim)
        patched.setattr(app_main.requests, "post", _fake_urlscan_post)
        patched.setattr(app_main.requests, "get", _fake_urlscan_get_malicious)

        start = client.post(
            "/v1/scan/orchestrated",
            json={"input_type": "text", "text": message, "source_channel": "android_native"},
        ).json()
        _, provisional = _poll_orchestrated(client, start["scan_id"], count=1)
        _, preview_pending = _poll_orchestrated(client, start["scan_id"], count=1)
        _, upgraded = _poll_orchestrated(client, start["scan_id"], count=1)

    assert provisional["status"] == "complete"
    assert provisional["result"]["user_risk_label"] == "SIGUR"
    assert provisional["pillars"]["urlscan"]["status"] == "pending"
    assert provisional["preview"]["report_url"] is None
    assert preview_pending["status"] == "complete"
    assert preview_pending["result"]["user_risk_label"] == "SIGUR"
    assert preview_pending["pillars"]["urlscan"]["status"] == "pending"
    assert preview_pending["preview"]["report_url"] == "https://urlscan.io/result/urlscan-yoxo-1/"
    assert upgraded["status"] == "complete"
    assert upgraded["pillars"]["urlscan"]["status"] == "ok"
    assert upgraded["result"]["user_risk_label"] == "PERICULOS"
    assert upgraded["result"]["risk_level"] == "high"
    assert upgraded["result"]["is_final"] is True
    assert upgraded["result"]["evidence"]["provider_gate"]["urlscan_consulted"] is True


def test_orchestrated_scan_keeps_clean_verdict_when_urlscan_screenshot_times_out(monkeypatch):
    client = TestClient(app_main.app)
    message = (
        "Ai primit produsul Flanco. Dorim sa fim mai buni pentru tine, "
        "acorda-ne un calificativ pentru livrare cu un clic aici: https://t.postis.io/9kj8p"
    )

    with monkeypatch.context() as patched:
        patched.setattr(app_main, "PRIVACY_SAFE_MODE", False)
        patched.setattr(app_main, "ENABLE_CLOUD_AI_EXPLANATION", False)
        patched.setattr(app_main, "URLSCAN_API_KEY", "server-only-key")
        patched.setattr(app_main, "ORCHESTRATED_URLSCAN_PENDING_TIMEOUT_SECONDS", 1)
        patched.setattr(app_main, "_safe_scan_url_list", _fake_yoxo_safe_scan)
        patched.setattr(app_main, "_gather_external_intel_safe", _clean_web_risk_and_vt_for_resolved_urls)
        patched.setattr(app_main, "_enrich_offer_claim_verification_async", _fake_inconclusive_offer_claim)
        patched.setattr(app_main.requests, "post", _fake_urlscan_post)
        patched.setattr(app_main.requests, "get", _fake_urlscan_get_clean_without_screenshot)

        start = client.post(
            "/v1/scan/orchestrated",
            json={"input_type": "text", "text": message, "source_channel": "android_native"},
        ).json()
        _poll_orchestrated(client, start["scan_id"], count=7)
        app_main._ORCHESTRATED_SCAN_JOBS[start["scan_id"]]["created_at"] -= 5
        response, payload = _poll_orchestrated(client, start["scan_id"], count=1)

    assert response.status_code == 200
    assert payload["status"] == "complete"
    assert payload["pillars"]["urlscan"]["status"] == "ok"
    assert "captura" in payload["pillars"]["urlscan"]["details"].lower()
    assert payload["result"]["user_risk_label"] == "SIGUR"
    assert payload["result"]["risk_level"] == "low"
    assert payload["result"]["is_final"] is True


def test_orchestrated_urlscan_result_poll_does_not_probe_screenshot_same_request(monkeypatch):
    async def fake_get_urlscan_result(uuid, request):
        return {
            "uuid": uuid,
            "status": "finished",
            "verdict": "No malicious classification",
            "severity": "low",
            "details": "urlscan verdict=No malicious classification; score=0",
            "final_url": "https://buyback.yoxo.ro/",
            "report_url": "https://urlscan.io/result/urlscan-yoxo-1/",
            "screenshot_url": "https://backend/screenshot",
            "score": 0,
            "categories": [],
            "brands": [],
        }

    async def fail_screenshot_probe(uuid):
        raise AssertionError("Screenshot readiness must be checked in a later poll.")

    job = {
        "scan_id": "orch_urlscan_result_budget",
        "created_at": int(time.time()),
        "pipeline_stage": "urlscan_submitted",
        "status": "complete",
        "input_type": "text",
        "source_channel": "test",
        "urls": ["https://buyback.yoxo.ro"],
        "redacted_text": "YOXO buyback https://buyback.yoxo.ro",
        "analysis": {
            "risk_score": 10,
            "risk_level": "low",
            "detected_family": "Destinație oficială",
            "detected_family_id": "provider-gate-official-clean",
            "claimed_brand": "YOXO",
            "reasons": [],
            "safe_actions": [],
            "evidence": {
                "external_intel_summary": {
                    "google_web_risk": {"status": "clean", "verdict": "clean", "consulted": True},
                    "virustotal": {"status": "clean", "verdict": "clean", "consulted": True},
                },
                "offer_claim_verification": {"status": "confirmed"},
                "semantic_review": {
                    "status": "done",
                    "claim_matches_known_scam_family": False,
                    "claim_matches_legit_template": True,
                    "risk_class": "benign",
                    "completeness": True,
                },
            },
        },
        "resolved_urls": [
            {
                "url": "https://buyback.yoxo.ro",
                "final_url": "https://buyback.yoxo.ro",
                "hostname": "buyback.yoxo.ro",
                "final_hostname": "buyback.yoxo.ro",
                "registered_domain": "yoxo.ro",
                "final_registered_domain": "yoxo.ro",
                "success": True,
            }
        ],
        "primary_final_url": "https://buyback.yoxo.ro",
        "claim_verifier_required": False,
        "urlscan": {
            "status": "pending",
            "uuid": "urlscan-yoxo-1",
            "report_url": "https://urlscan.io/result/urlscan-yoxo-1/",
        },
        "preview": {
            "final_url": "https://buyback.yoxo.ro",
            "report_url": "https://urlscan.io/result/urlscan-yoxo-1/",
            "screenshot_url": None,
        },
        "extra_fields": {},
        "result": {"is_final": True, "user_risk_label": "SIGUR", "risk_level": "low"},
        "orchestration_metrics": {"poll_count": 0, "stage_sequence": [], "stage_durations_ms": {}},
    }

    with monkeypatch.context() as patched:
        patched.setattr(app_main, "get_urlscan_result", fake_get_urlscan_result)
        patched.setattr(app_main, "_urlscan_screenshot_is_ready", fail_screenshot_probe)
        patched.setattr(app_main, "_persist_orchestrated_job", lambda candidate: candidate)
        patched.setattr(app_main, "_emit_orchestrated_telemetry", lambda *args, **kwargs: None)
        patched.setattr(app_main, "_emit_scan_event", lambda *args, **kwargs: None)
        refreshed = asyncio.run(app_main._refresh_orchestrated_job(job, None))

    assert refreshed["urlscan"]["status"] == "finished"
    assert refreshed["urlscan"]["screenshot_ready"] is False
    assert refreshed["preview"]["report_url"] == "https://urlscan.io/result/urlscan-yoxo-1/"
    assert refreshed["preview"]["screenshot_url"] == "https://backend/screenshot"


def test_orchestrated_load_prefers_persistent_store_over_stale_process_cache(monkeypatch):
    scan_id = "orch_store_first"
    app_main._ORCHESTRATED_SCAN_JOBS[scan_id] = {
        "scan_id": scan_id,
        "pipeline_stage": "queued",
        "created_at": 1,
    }

    persistent_job = {
        "scan_id": scan_id,
        "pipeline_stage": "resolved",
        "created_at": 2,
        "_storage_updated_at": "fresh",
    }

    with monkeypatch.context() as patched:
        patched.setattr(app_main.supabase_store, "load_scan_job", lambda sid: persistent_job if sid == scan_id else None)
        loaded = app_main._load_orchestrated_job(scan_id)

    assert loaded["pipeline_stage"] == "resolved"
    assert app_main._ORCHESTRATED_SCAN_JOBS[scan_id]["pipeline_stage"] == "resolved"


def test_persist_orchestrated_job_merges_urlscan_uuid_after_optimistic_conflict(monkeypatch):
    scan_id = "orch_conflict_merge"
    current_job = {
        "scan_id": scan_id,
        "created_at": 10,
        "_storage_updated_at": "stale",
        "pipeline_stage": "urlscan_submitted",
        "urlscan": {
            "uuid": "urlscan-keep-me",
            "status": "pending",
            "report_url": "https://urlscan.io/result/urlscan-keep-me/",
            "screenshot_url": "/v1/sandbox/urlscan/urlscan-keep-me/screenshot",
        },
        "preview": {
            "report_url": "https://urlscan.io/result/urlscan-keep-me/",
            "screenshot_url": "/v1/sandbox/urlscan/urlscan-keep-me/screenshot",
        },
    }
    reloaded_job = {
        "scan_id": scan_id,
        "created_at": 10,
        "_storage_updated_at": "fresh",
        "pipeline_stage": "analysis_ready",
        "urlscan": {"status": "queued"},
        "preview": {},
    }
    saved_jobs = []

    def fake_save(job):
        saved_jobs.append(json.loads(json.dumps(job)))
        return len(saved_jobs) > 1

    with monkeypatch.context() as patched:
        patched.setattr(app_main.supabase_store, "save_scan_job", fake_save)
        patched.setattr(app_main.supabase_store, "load_scan_job", lambda sid: dict(reloaded_job))
        merged = app_main._persist_orchestrated_job(current_job)

    assert merged["pipeline_stage"] == "urlscan_submitted"
    assert merged["urlscan"]["uuid"] == "urlscan-keep-me"
    assert merged["preview"]["report_url"] == "https://urlscan.io/result/urlscan-keep-me/"
    assert len(saved_jobs) == 2
    assert saved_jobs[1]["urlscan"]["uuid"] == "urlscan-keep-me"


def test_persist_orchestrated_job_retries_merged_conflict_save_twice(monkeypatch):
    scan_id = "orch_conflict_retry"
    current_job = {
        "scan_id": scan_id,
        "created_at": 10,
        "_storage_updated_at": "stale",
        "pipeline_stage": "urlscan_submitted",
        "urlscan": {
            "uuid": "urlscan-keep-me",
            "status": "pending",
            "report_url": "https://urlscan.io/result/urlscan-keep-me/",
        },
    }
    reloaded_job = {
        "scan_id": scan_id,
        "created_at": 10,
        "_storage_updated_at": "fresh",
        "pipeline_stage": "analysis_ready",
        "urlscan": {"status": "queued"},
    }
    saved_jobs = []

    def fake_save(job):
        saved_jobs.append(json.loads(json.dumps(job)))
        return len(saved_jobs) >= 3

    with monkeypatch.context() as patched:
        patched.setattr(app_main.supabase_store, "save_scan_job", fake_save)
        patched.setattr(app_main.supabase_store, "load_scan_job", lambda sid: dict(reloaded_job))
        patched.setattr(app_main, "_emit_orchestrated_telemetry", lambda *args, **kwargs: None)
        merged = app_main._persist_orchestrated_job(current_job)

    assert len(saved_jobs) == 3
    assert merged["urlscan"]["uuid"] == "urlscan-keep-me"
    assert merged["orchestration_metrics"]["conflict_merge_retry_count"] == 2


def test_orchestrated_final_verdict_reuses_ai_explanation_cache(monkeypatch):
    scan_id = "orch_ai_cache"
    analysis = {
        "risk_score": 10,
        "risk_level": "low",
        "detected_family": "Provideri curați",
        "detected_family_id": "provider-gate-official-clean",
        "claimed_brand": "YOXO",
        "reasons": ["Pilonii blocking sunt curați."],
        "safe_actions": [],
        "evidence": {
            "offer_claim_verification": {"status": "confirmed"},
                "external_intel_summary": {
                    "google_web_risk": {"status": "clean", "verdict": "clean", "consulted": True},
                    "virustotal": {"status": "clean", "verdict": "clean", "consulted": True},
                    "urlscan": {"status": "clean", "verdict": "clean", "consulted": True},
                },
            },
        }
    job = {
        "scan_id": scan_id,
        "created_at": int(time.time()),
        "pipeline_stage": "urlscan_submitted",
        "status": "scanning",
        "input_type": "text",
        "source_channel": "android_native",
        "urls": ["https://buyback.yoxo.ro"],
        "redacted_text": "YOXO buyback https://buyback.yoxo.ro",
        "analysis": analysis,
        "resolved_urls": [
            {
                "url": "https://buyback.yoxo.ro",
                "final_url": "https://buyback.yoxo.ro",
                "hostname": "buyback.yoxo.ro",
                "final_hostname": "buyback.yoxo.ro",
                "registered_domain": "yoxo.ro",
                "final_registered_domain": "yoxo.ro",
            }
        ],
        "primary_final_url": "https://buyback.yoxo.ro",
        "claim_verifier_required": False,
        "urlscan": {"uuid": "urlscan-finished", "status": "finished", "verdict": "clean", "screenshot_ready": False},
        "preview": {},
        "extra_fields": {},
    }
    calls = {"count": 0}

    async def fake_ai_explanation(text, analysis_payload, resolved_urls):
        calls["count"] += 1
        return {
            "verdict_summary": "Pare sigur.",
            "explanation": "Pilonii blocking sunt curați.",
            "offer_analysis": "Confirmat.",
            "key_dangers": [],
            "safe_actions": [],
        }

    with monkeypatch.context() as patched:
        patched.setattr(app_main, "_build_ai_explanation_async", fake_ai_explanation)
        patched.setattr(app_main, "_emit_scan_event", lambda *args, **kwargs: None)
        asyncio.run(app_main._finalize_orchestrated_job_if_ready(job, None))
        asyncio.run(app_main._finalize_orchestrated_job_if_ready(job, None))

    assert calls["count"] == 1
    assert job["result"]["is_final"] is True


def test_orchestrated_urlscan_final_url_can_downgrade_stale_structural_danger(monkeypatch):
    scan_id = "orch_yoxo_late_official"
    text = (
        "In 24 de ore se va efectua automat plata abonamentului tau Orange YOXO. "
        "Asigura-te ca ai suficienti bani pe card. "
        "Poti vizualiza factura aici https://yoxo.onelink.me/f8ly/ijiwsfwu"
    )
    analysis = {
        "risk_score": 91,
        "risk_level": "high",
        "detected_family": "Impostură brand cu acțiune sensibilă",
        "detected_family_id": "provider-gate-decisive-structural-danger",
        "claimed_brand": "YOXO",
        "reasons": ["Stale structural verdict înainte de urlscan final URL."],
        "safe_actions": [],
        "evidence": {
            "has_domain_mismatch": True,
            "offer_claim_verification": {"status": "inconclusive"},
            "external_intel_summary": {
                "google_web_risk": {"status": "clean", "verdict": "clean", "consulted": True},
                "virustotal": {"status": "clean", "verdict": "clean", "consulted": True},
                "urlscan": {
                    "status": "clean",
                    "verdict": "No malicious classification",
                    "consulted": True,
                    "final_url": "https://apps.apple.com/us/app/yoxo-voce-internet-roaming/id1481946568",
                },
            },
        },
    }
    job = {
        "scan_id": scan_id,
        "created_at": int(time.time()),
        "pipeline_stage": "urlscan_submitted",
        "status": "scanning",
        "input_type": "text",
        "source_channel": "android_native",
        "urls": ["https://yoxo.onelink.me/f8ly/ijiwsfwu"],
        "redacted_text": text,
        "analysis": analysis,
        "resolved_urls": [
            {
                "url": "https://yoxo.onelink.me/f8ly/ijiwsfwu",
                "final_url": "https://yoxo.onelink.me/f8ly/ijiwsfwu",
                "hostname": "yoxo.onelink.me",
                "final_hostname": "yoxo.onelink.me",
                "registered_domain": "onelink.me",
                "final_registered_domain": "onelink.me",
            }
        ],
        "primary_final_url": "https://yoxo.onelink.me/f8ly/ijiwsfwu",
        "claim_verifier_required": True,
        "urlscan": {
            "uuid": "urlscan-yoxo-app-store",
            "status": "finished",
            "screenshot_ready": True,
            "verdict": "No malicious classification",
        },
        "preview": {
            "final_url": "https://apps.apple.com/us/app/yoxo-voce-internet-roaming/id1481946568",
            "report_url": "https://urlscan.io/result/urlscan-yoxo-app-store/",
            "screenshot_url": "https://example.test/screenshot.png",
        },
        "result": {
            "is_final": True,
            "user_risk_label": "PERICULOS",
            "risk_level": "high",
            "detected_family_id": "provider-gate-decisive-structural-danger",
        },
        "extra_fields": {},
    }

    async def fake_ai_explanation(text, analysis_payload, resolved_urls):
        return {
            "verdict_summary": "Pare sigur.",
            "explanation": "Pilonii sunt curați, iar final URL este o destinație oficială YOXO.",
            "offer_analysis": "Inconclusiv, dar fără semnale de risc.",
            "key_dangers": [],
            "safe_actions": [],
        }

    with monkeypatch.context() as patched:
        patched.setattr(app_main, "_build_ai_explanation_async", fake_ai_explanation)
        patched.setattr(app_main, "_emit_scan_event", lambda *args, **kwargs: None)
        patched.setattr(app_main, "_emit_orchestrated_telemetry", lambda *args, **kwargs: None)
        asyncio.run(app_main._finalize_orchestrated_job_if_ready(job, None))

    assert job["result"]["is_final"] is True
    assert job["result"]["user_risk_label"] == "SIGUR"
    assert job["result"]["risk_level"] == "low"
    assert job["result"]["detected_family_id"] == "provider-gate-official-clean"
    assert job["result"]["evidence"]["provider_gate"]["official_destination"] is True
    assert job["resolved_urls"][0]["final_hostname"] == "apps.apple.com"


def test_orchestrated_urlscan_reservation_reclaims_after_ttl(monkeypatch):
    job = {
        "scan_id": "orch_urlscan_reclaim",
        "created_at": int(time.time()),
        "pipeline_stage": "urlscan_submitting",
        "status": "scanning",
        "input_type": "text",
        "source_channel": "android_native",
        "urls": ["https://buyback.yoxo.ro"],
        "redacted_text": "YOXO buyback https://buyback.yoxo.ro",
        "analysis": {},
        "resolved_urls": [],
        "primary_final_url": "https://buyback.yoxo.ro",
        "claim_verifier_required": False,
        "urlscan": {
            "status": "submitting",
            "submitted_url": "https://buyback.yoxo.ro",
            "submit_owner": "dead-instance",
            "submit_started_at": int(time.time()) - 31,
        },
        "preview": {},
        "extra_fields": {},
        "sandbox_options": {},
    }

    with monkeypatch.context() as patched:
        patched.setattr(app_main, "ORCHESTRATED_URLSCAN_SUBMIT_RESERVATION_TIMEOUT_SECONDS", 30)
        patched.setattr(app_main, "_persist_orchestrated_job", lambda candidate: candidate)
        patched.setattr(app_main, "_emit_orchestrated_telemetry", lambda *args, **kwargs: None)
        refreshed = asyncio.run(app_main._refresh_orchestrated_job(job, None))

    assert refreshed["pipeline_stage"] == "analysis_ready"
    assert refreshed["urlscan"]["status"] == "queued"
    assert refreshed["orchestration_metrics"]["urlscan_reclaim_count"] == 1


def test_urlscan_finished_without_screenshot_is_reputation_ok_not_error():
    job = {
        "scan_id": "orch_urlscan_report_ready",
        "urls": ["https://tiny.cc/MarTM"],
        "primary_final_url": "https://bilete.sublime.ro/eveniment",
        "resolved_urls": [{"final_url": "https://bilete.sublime.ro/eveniment"}],
        "analysis": {
            "evidence": {
                "external_intel_summary": {
                    "google_web_risk": {"status": "clean", "consulted": True},
                    "virustotal": {"status": "clean", "consulted": True},
                    "urlscan": {"status": "clean", "consulted": True},
                },
                "offer_claim_verification": {"status": "skipped"},
            }
        },
        "claim_verifier_required": False,
        "urlscan": {
            "status": "finished",
            "uuid": "urlscan-ready",
            "verdict": "No malicious classification",
            "screenshot_ready": False,
        },
    }

    pillars = app_main._build_orchestrated_pillars(job)

    assert pillars["urlscan"]["status"] == "ok"
    assert "captura" in pillars["urlscan"]["details"]


def test_orchestrated_urlscan_timeout_can_rehydrate_finished_report(monkeypatch):
    async def fake_get_urlscan_result(uuid, request):
        return {
            "uuid": uuid,
            "status": "finished",
            "verdict": "No malicious classification",
            "severity": "low",
            "details": "urlscan verdict=No malicious classification; score=0",
            "final_url": "https://bilete.sublime.ro/bilete-timisoara-stand-up-comedy-cu-dan-badea-domnu-danut-ora-21-00-119514/",
            "report_url": "https://urlscan.io/result/urlscan-late/",
            "screenshot_url": "https://backend/screenshot",
            "score": 0,
            "categories": [],
            "brands": [],
        }

    async def fake_screenshot_ready(uuid):
        return True

    async def fake_ai_explanation(*args, **kwargs):
        return {"verdict_summary": "", "explanation": ""}

    job = {
        "scan_id": "orch_urlscan_late",
        "created_at": int(time.time()) - 130,
        "pipeline_stage": "done",
        "status": "complete",
        "input_type": "text",
        "source_channel": "test",
        "urls": ["https://tiny.cc/MarTM"],
        "redacted_text": "Promo Martisor https://tiny.cc/MarTM",
        "analysis": {
            "risk_score": 50,
            "risk_level": "medium",
            "detected_family": "Verificare parțială",
            "detected_family_id": "provider-gate-partial-pillars",
            "claimed_brand": "Nespecificat",
            "reasons": ["Scanare parțială."],
            "safe_actions": [],
            "evidence": {
                "external_intel_summary": {
                    "google_web_risk": {"status": "clean", "consulted": True},
                    "virustotal": {"status": "clean", "consulted": True},
                },
                "offer_claim_verification": {"status": "skipped"},
            },
        },
        "resolved_urls": [
            {
                "original_url": "https://tiny.cc/MarTM",
                "final_url": "https://tiny.cc/MarTM",
                "final_hostname": "tiny.cc",
                "final_registered_domain": "tiny.cc",
                "success": False,
            }
        ],
        "primary_final_url": "https://tiny.cc/MarTM",
        "claim_verifier_required": False,
        "urlscan": {
            "status": "timeout",
            "uuid": "urlscan-late",
            "details": "urlscan preview timeout",
        },
        "preview": {
            "final_url": "https://tiny.cc/MarTM",
            "report_url": "https://urlscan.io/result/urlscan-late/",
            "screenshot_url": None,
        },
        "extra_fields": {"resolved_urls": []},
        "result": {"is_final": True},
        "orchestration_metrics": {"poll_count": 0, "stage_sequence": [], "stage_durations_ms": {}},
    }

    with monkeypatch.context() as patched:
        patched.setattr(app_main, "get_urlscan_result", fake_get_urlscan_result)
        patched.setattr(app_main, "_urlscan_screenshot_is_ready", fake_screenshot_ready)
        patched.setattr(app_main, "_persist_orchestrated_job", lambda candidate: candidate)
        patched.setattr(app_main, "_emit_orchestrated_telemetry", lambda *args, **kwargs: None)
        patched.setattr(app_main, "_emit_scan_event", lambda *args, **kwargs: None)
        patched.setattr(app_main, "_build_ai_explanation_async", fake_ai_explanation)
        refreshed = asyncio.run(app_main._refresh_orchestrated_job(job, None))
        refreshed = asyncio.run(app_main._refresh_orchestrated_job(refreshed, None))

    assert refreshed["urlscan"]["status"] == "finished"
    assert refreshed["preview"]["screenshot_url"] == "https://backend/screenshot"
    assert refreshed["primary_final_url"].startswith("https://bilete.sublime.ro/")
    assert refreshed["resolved_urls"][0]["final_registered_domain"] == "sublime.ro"
    assert refreshed["analysis"]["evidence"]["external_intel_summary"]["urlscan"]["status"] == "clean"


def test_orchestration_telemetry_payload_flags_anomalies(monkeypatch):
    records = [
        {
            "scan_id": "orch_a",
            "event_type": "orchestrated_verdict_final",
            "metadata": {
                "pipeline_stage": "urlscan_submitted",
                "poll_count": 5,
                "age_ms": 12000,
                "urlscan_status": "timeout",
                "stage_durations_ms": {"queued": 1000, "resolved": 3000},
            },
        },
        {
            "scan_id": "orch_a",
            "event_type": "orchestrated_urlscan_reservation_guard",
            "metadata": {"pipeline_stage": "urlscan_submitting"},
        },
        {
            "scan_id": "orch_b",
            "event_type": "orchestrated_conflict_merge",
            "metadata": {"pipeline_stage": "resolved", "conflict_merge_retry_failures": 1},
        },
    ]

    with monkeypatch.context() as patched:
        patched.setattr(app_main, "load_scan_records", lambda limit=None: records)
        payload = app_main._build_orchestration_telemetry_payload(limit=100, urlscan_timeout_rate_alert=0.1)

    assert payload["events_considered"] == 3
    assert payload["scan_count"] == 2
    assert payload["urlscan"]["reservation_guard_hits"] == 1
    assert payload["conflicts"]["merge_events"] == 1
    assert payload["conflicts"]["retry_failures"] == 1
    alert_codes = {alert["code"] for alert in payload["alerts"]}
    assert "urlscan_reservation_guard_hits" in alert_codes
    assert "conflict_merge_retry_failures" in alert_codes
    assert "urlscan_timeout_rate_high" in alert_codes


def test_orchestration_dashboard_renders_minimal_html(monkeypatch):
    with monkeypatch.context() as patched:
        patched.setattr(
            app_main,
            "_build_orchestration_telemetry_payload",
            lambda **kwargs: {
                "generated_at": 123,
                "events_considered": 4,
                "scan_count": 2,
                "by_event_type": {"orchestrated_poll": 2, "orchestrated_verdict_final": 1},
                "by_stage": {"resolved": 2},
                "polls_to_final": {"avg": 4, "max": 5, "samples": 1},
                "time_to_final_ms": {"avg": 1200, "max": 1300, "samples": 1},
                "stage_latency_ms": {"resolved": {"avg": 100, "max": 150, "samples": 2}},
                "urlscan": {
                    "reservation_guard_hits": 0,
                    "reclaim_events": 1,
                    "pending_timeout_events": 0,
                    "pending_timeout_rate": 0,
                },
                "conflicts": {"merge_events": 0, "retry_failures": 0},
                "alerts": [],
            },
        )
        response = app_main.orchestration_dashboard(limit=100)

    body = response.body.decode("utf-8")
    assert "SigurScan Orchestration Dashboard" in body
    assert "Scanări urmărite" in body
    assert "orchestrated_poll" in body
    assert "Nu există alerte" in body


def test_shadow_adjudication_payload_summarizes_disagreements_and_feedback(monkeypatch):
    records = [
        {
            "scan_id": "scan_a",
            "event_type": "adjudication_shadow",
            "user_risk_label": "SUSPECT",
            "evidence": {
                "evidence_hash": "sha256:a",
                "gate": {"label": "SUSPECT", "risk_level": "medium", "risk_score": 50},
                "shadow": {
                    "label": "PERICULOS",
                    "confidence": 0.84,
                    "motiv_ro": "Cere date pe domeniu neoficial.",
                },
                "valid": True,
                "latency_ms": 1200,
                "cache_hit": False,
                "model": "mistral-small-2503",
            },
        },
        {
            "scan_id": "scan_b",
            "event_type": "adjudication_shadow",
            "user_risk_label": "SUSPECT",
            "evidence": {
                "evidence_hash": "sha256:b",
                "gate": {"label": "SUSPECT", "risk_level": "medium", "risk_score": 50},
                "shadow": None,
                "valid": False,
                "fallback_reason": "validator_rejected",
                "latency_ms": 3000,
                "cache_hit": True,
                "model": "mistral-small-2503",
            },
        },
        {"scan_id": "orch_ignored", "event_type": "orchestrated_poll", "metadata": {}},
    ]
    feedback = [
        {"scan_id": "scan_a", "feedback": "false_negative", "timestamp": 10},
    ]

    with monkeypatch.context() as patched:
        patched.setattr(app_main, "load_scan_records", lambda limit=None: records)
        patched.setattr(app_main, "load_feedback_records", lambda: feedback)
        payload = app_main._build_shadow_adjudication_payload(
            limit=100,
            fallback_rate_alert=0.1,
            disagreement_rate_alert=0.1,
            latency_p95_alert_ms=2000,
        )

    assert payload["events_considered"] == 2
    assert payload["valid"] == 1
    assert payload["fallback"] == 1
    assert payload["fallback_rate"] == 0.5
    assert payload["agreement"]["disagreements"] == 1
    assert payload["cache"]["hits"] == 1
    assert payload["feedback_comparison"]["labeled"] == 1
    assert payload["feedback_comparison"]["shadow_would_improve"] == 1
    assert payload["promotion_gate"]["can_promote"] is False
    alert_codes = {alert["code"] for alert in payload["alerts"]}
    assert "mistral_shadow_fallback_rate_high" in alert_codes
    assert "mistral_shadow_disagreement_rate_high" in alert_codes
    assert payload["examples"]["disagreements"][0]["scan_id"] == "scan_a"
    assert payload["examples"]["fallbacks"][0]["fallback_reason"] == "validator_rejected"


def test_shadow_adjudication_dashboard_renders_minimal_html(monkeypatch):
    with monkeypatch.context() as patched:
        patched.setattr(
            app_main,
            "_build_shadow_adjudication_payload",
            lambda **kwargs: {
                "events_considered": 2,
                "valid": 1,
                "fallback": 1,
                "fallback_rate": 0.5,
                "agreement": {"disagreements": 1, "disagreement_rate": 1.0},
                "latency_ms": {"avg": 1200, "p95": 1200, "max": 1200, "samples": 1},
                "cache": {"hits": 1, "hit_rate": 0.5},
                "feedback_comparison": {
                    "labeled": 1,
                    "shadow_would_improve": 1,
                    "shadow_would_regress": 0,
                },
                "promotion_gate": {
                    "can_promote": False,
                    "current_labeled_real_messages": 1,
                    "min_labeled_real_messages": 150,
                },
                "alerts": [],
                "examples": {
                    "disagreements": [
                        {
                            "scan_id": "scan_a",
                            "gate_label": "SUSPECT",
                            "shadow_label": "PERICULOS",
                            "confidence": 0.84,
                            "reason": "Cere date.",
                        }
                    ],
                    "fallbacks": [],
                },
            },
        )
        response = app_main.shadow_adjudication_dashboard(limit=100)

    body = response.body.decode("utf-8")
    assert "SigurScan Shadow Adjudication" in body
    assert "Dezacorduri validate" in body
    assert "scan_a" in body
    assert "Nu există fallback-uri" in body


def test_orchestrated_urlscan_submit_requires_owned_reservation(monkeypatch):
    job = {
        "scan_id": "orch_urlscan_reservation",
        "created_at": int(time.time()),
        "pipeline_stage": "analysis_ready",
        "status": "scanning",
        "input_type": "text",
        "source_channel": "android_native",
        "urls": ["https://buyback.yoxo.ro"],
        "redacted_text": "YOXO buyback https://buyback.yoxo.ro",
        "analysis": {
            "risk_score": 10,
            "risk_level": "low",
            "detected_family": "Provideri curați",
            "detected_family_id": "provider-gate-official-clean",
            "claimed_brand": "YOXO",
            "reasons": [],
            "safe_actions": [],
            "evidence": {
                "offer_claim_verification": {"status": "confirmed"},
                "external_intel_summary": {
                    "google_web_risk": {"status": "clean", "verdict": "clean", "consulted": True},
                    "virustotal": {"status": "clean", "verdict": "clean", "consulted": True},
                },
            },
        },
        "resolved_urls": [
            {
                "url": "https://buyback.yoxo.ro",
                "final_url": "https://buyback.yoxo.ro",
                "hostname": "buyback.yoxo.ro",
                "final_hostname": "buyback.yoxo.ro",
                "registered_domain": "yoxo.ro",
                "final_registered_domain": "yoxo.ro",
            }
        ],
        "primary_final_url": "https://buyback.yoxo.ro",
        "claim_verifier_required": False,
        "urlscan": {"status": "queued"},
        "preview": {},
        "extra_fields": {},
        "sandbox_options": {},
    }

    def fake_persist(candidate):
        if candidate.get("urlscan", {}).get("status") == "submitting":
            reserved_elsewhere = dict(candidate)
            reserved_elsewhere["urlscan"] = {
                "status": "submitting",
                "submit_owner": "other-instance",
                "submit_started_at": int(time.time()),
                "submitted_url": "https://buyback.yoxo.ro",
            }
            return reserved_elsewhere
        return candidate

    async def fail_submit(*args, **kwargs):
        raise AssertionError("urlscan submit must not run without owning the reservation")

    with monkeypatch.context() as patched:
        patched.setattr(app_main, "_persist_orchestrated_job", fake_persist)
        patched.setattr(app_main, "_submit_orchestrated_urlscan", fail_submit)
        patched.setattr(app_main, "_emit_scan_event", lambda *args, **kwargs: None)
        refreshed = asyncio.run(app_main._refresh_orchestrated_job(job, None))

    assert refreshed["urlscan"]["submit_owner"] == "other-instance"
    assert refreshed["urlscan"]["status"] == "submitting"


def test_orchestrated_urlscan_submit_success_sets_submitted_stage(monkeypatch):
    job = {
        "scan_id": "orch_urlscan_submit_success",
        "created_at": int(time.time()),
        "pipeline_stage": "analysis_ready",
        "status": "scanning",
        "input_type": "text",
        "source_channel": "android_native",
        "urls": ["https://buyback.yoxo.ro"],
        "redacted_text": "YOXO buyback https://buyback.yoxo.ro",
        "analysis": {
            "risk_score": 10,
            "risk_level": "low",
            "detected_family": "Provideri curați",
            "detected_family_id": "provider-gate-official-clean",
            "claimed_brand": "YOXO",
            "reasons": [],
            "safe_actions": [],
            "evidence": {
                "offer_claim_verification": {"status": "confirmed"},
                "external_intel_summary": {
                    "google_web_risk": {"status": "clean", "verdict": "clean", "consulted": True},
                    "virustotal": {"status": "clean", "verdict": "clean", "consulted": True},
                },
            },
        },
        "resolved_urls": [
            {
                "url": "https://buyback.yoxo.ro",
                "final_url": "https://buyback.yoxo.ro",
                "hostname": "buyback.yoxo.ro",
                "final_hostname": "buyback.yoxo.ro",
                "registered_domain": "yoxo.ro",
                "final_registered_domain": "yoxo.ro",
            }
        ],
        "primary_final_url": "https://buyback.yoxo.ro",
        "claim_verifier_required": False,
        "urlscan": {"status": "queued"},
        "preview": {},
        "extra_fields": {},
        "sandbox_options": {},
    }

    async def fake_submit(url, payload, request):
        return {
            "uuid": "urlscan-submit-ok",
            "status": "pending",
            "submitted_url": url,
            "report_url": "https://urlscan.io/result/urlscan-submit-ok/",
            "screenshot_url": "/v1/sandbox/urlscan/urlscan-submit-ok/screenshot",
        }

    with monkeypatch.context() as patched:
        patched.setattr(app_main, "_persist_orchestrated_job", lambda candidate: candidate)
        patched.setattr(app_main, "_submit_orchestrated_urlscan", fake_submit)
        patched.setattr(app_main, "_emit_orchestrated_telemetry", lambda *args, **kwargs: None)
        patched.setattr(app_main, "_emit_scan_event", lambda *args, **kwargs: None)
        refreshed = asyncio.run(app_main._refresh_orchestrated_job(job, None))

    assert refreshed["pipeline_stage"] == "urlscan_submitted"
    assert refreshed["urlscan"]["status"] == "pending"
    assert refreshed["urlscan"]["uuid"] == "urlscan-submit-ok"
    assert refreshed["preview"]["report_url"] == "https://urlscan.io/result/urlscan-submit-ok/"
    assert refreshed["preview"]["screenshot_url"] == "/v1/sandbox/urlscan/urlscan-submit-ok/screenshot"


def _clean_external_intel_for_resolved_urls(resolved_urls, *args, **kwargs):
    output = {}
    for entry in resolved_urls:
        final_url = entry.get("final_url") or entry.get("url")
        if not final_url:
            continue
        output[final_url] = {
            "verdict": "clean",
            "risk_score": 0,
            "sources": {
                "google_web_risk": {"status": "clean", "consulted": True, "score": 0, "threat_type": "unknown"},
                "virustotal": {"status": "clean", "consulted": True, "score": 0, "threat_type": "unknown"},
                "urlscan": {"status": "clean", "consulted": True, "score": 0, "threat_type": "unknown"},
            },
        }
    return output


def _clean_web_risk_and_vt_for_resolved_urls(resolved_urls, *args, **kwargs):
    output = {}
    for entry in resolved_urls:
        final_url = entry.get("final_url") or entry.get("url")
        if not final_url:
            continue
        output[final_url] = {
            "verdict": "clean",
            "risk_score": 0,
            "sources": {
                "google_web_risk": {"status": "clean", "consulted": True, "score": 0, "threat_type": "unknown"},
                "virustotal": {"status": "clean", "consulted": True, "score": 0, "threat_type": "unknown"},
            },
        }
    return output


def _clean_web_risk_and_weak_vt_for_resolved_urls(resolved_urls, *args, **kwargs):
    output = {}
    for entry in resolved_urls:
        final_url = entry.get("final_url") or entry.get("url")
        if not final_url:
            continue
        output[final_url] = {
            "verdict": "suspicious",
            "risk_score": 35,
            "sources": {
                "google_web_risk": {"status": "clean", "consulted": True, "score": 0, "threat_type": "unknown"},
                "virustotal": {
                    "status": "suspicious",
                    "verdict": "suspicious",
                    "consulted": True,
                    "score": 35,
                    "threat_type": "suspicious",
                    "malicious_hit_count": 1,
                    "details": {
                        "stats": {"harmless": 62, "malicious": 1, "suspicious": 0, "undetected": 32},
                        "flagged_engines": [
                            {
                                "engine": "FlakyVendor",
                                "category": "malicious",
                                "result": "phishing",
                                "method": "blacklist",
                            }
                        ],
                    },
                },
            },
        }
    return output


def _clean_web_risk_and_consensus_vt_for_resolved_urls(resolved_urls, *args, **kwargs):
    output = {}
    for entry in resolved_urls:
        final_url = entry.get("final_url") or entry.get("url")
        if not final_url:
            continue
        output[final_url] = {
            "verdict": "malicious",
            "risk_score": 70,
            "sources": {
                "google_web_risk": {"status": "clean", "consulted": True, "score": 0, "threat_type": "unknown"},
                "virustotal": {
                    "status": "malicious",
                    "verdict": "malicious",
                    "consulted": True,
                    "score": 70,
                    "threat_type": "malicious",
                    "malicious_hit_count": 3,
                    "details": {
                        "stats": {"harmless": 48, "malicious": 3, "suspicious": 1, "undetected": 30},
                        "flagged_engines": [
                            {"engine": "VendorA", "category": "malicious", "result": "phishing", "method": "blacklist"},
                            {"engine": "VendorB", "category": "malicious", "result": "malware", "method": "blacklist"},
                            {"engine": "VendorC", "category": "malicious", "result": "phishing", "method": "blacklist"},
                        ],
                    },
                },
            },
        }
    return output


def test_external_intel_summary_preserves_virustotal_malicious_engine_count():
    summary = app_main._external_intel_summary_from_threat_intel(
        {
            "https://unknown.example.com/": {
                "verdict": "malicious",
                "risk_score": 70,
                "sources": {
                    "virustotal": {
                        "status": "malicious",
                        "verdict": "malicious",
                        "consulted": True,
                        "score": 70,
                        "malicious_hit_count": 3,
                        "details": {"stats": {"malicious": 3, "suspicious": 1}},
                    }
                },
            }
        }
    )

    assert summary["virustotal"]["malicious_hit_count"] == 3


def _malicious_web_risk_and_vt_for_resolved_urls(resolved_urls, *args, **kwargs):
    output = {}
    for entry in resolved_urls:
        final_url = entry.get("final_url") or entry.get("url")
        if not final_url:
            continue
        output[final_url] = {
            "verdict": "malicious",
            "risk_score": 95,
            "sources": {
                "google_web_risk": {
                    "status": "malicious",
                    "verdict": "malicious",
                    "consulted": True,
                    "score": 95,
                    "threat_type": "SOCIAL_ENGINEERING",
                },
                "virustotal": {
                    "status": "malicious",
                    "verdict": "malicious",
                    "consulted": True,
                    "score": 90,
                    "threat_type": "malicious",
                },
            },
        }
    return output


def _fake_google_test_phishing_scan(urls):
    resolved = []
    for raw_url in urls:
        resolved.append(
            {
                "url": raw_url,
                "original_url": raw_url,
                "final_url": "https://testsafebrowsing.appspot.com/s/phishing.html",
                "hostname": "testsafebrowsing.appspot.com",
                "final_hostname": "testsafebrowsing.appspot.com",
                "registered_domain": "appspot.com",
                "final_registered_domain": "appspot.com",
                "redirect_chain": [{"url": raw_url}],
                "redirect_count": 0,
                "shortener_count": 0,
                "uses_shortener": False,
                "detected_soft_redirects": [],
                "domain_age_days": None,
                "domain_created_date": None,
                "has_mx_records": False,
                "success": True,
            }
        )
    return resolved


def _fake_fan_relivrare_scan(urls):
    resolved = []
    for raw_url in urls:
        resolved.append(
            {
                "url": raw_url,
                "original_url": raw_url,
                "final_url": "https://fancurier-relivrare.com/plata",
                "hostname": "fancurier-relivrare.com",
                "final_hostname": "fancurier-relivrare.com",
                "registered_domain": "fancurier-relivrare.com",
                "final_registered_domain": "fancurier-relivrare.com",
                "redirect_chain": [{"url": raw_url}],
                "redirect_count": 0,
                "shortener_count": 0,
                "uses_shortener": False,
                "detected_soft_redirects": [],
                "domain_age_days": None,
                "domain_created_date": None,
                "has_mx_records": False,
                "success": False,
                "error": "DNS lookup failed",
            }
        )
    return resolved


async def _fake_inconclusive_offer_claim(text, analysis, resolved_urls):
    offer_claim = {
        "provider": "ai_offer_web_check",
        "status": "inconclusive",
        "verdict": "inconclusive",
        "severity": "unknown",
        "summary": "Nu exista confirmare oficiala pentru claim.",
        "details": "Nu exista confirmare oficiala pentru claim.",
        "confidence": 30,
        "claimed_brand": analysis.get("claimed_brand") or "FAN Courier",
        "official_domains": ["fancourier.ro", "selfawb.ro"],
        "evidence_urls": [],
        "method": "test",
        "official_source_found": False,
    }
    app_main._attach_offer_claim_verification(analysis, offer_claim)
    return offer_claim


def _fake_urlscan_post_rejects_domain(url, headers, json, timeout):
    return _FakeUrlscanResponse(status_code=400, payload={"message": "bad domain"})


def _fake_urlscan_post_scan_prevented(url, headers, json, timeout):
    return _FakeUrlscanResponse(
        status_code=400,
        payload={"message": "Scan prevented; submission blocked by urlscan policy"},
    )


def _fake_yoxo_onelink_to_app_store_scan(urls):
    resolved = []
    for raw_url in urls:
        resolved.append(
            {
                "url": raw_url,
                "original_url": raw_url,
                "final_url": "https://apps.apple.com/us/app/yoxo-voce-internet-roaming/id1481946568",
                "hostname": "yoxo.onelink.me",
                "final_hostname": "apps.apple.com",
                "registered_domain": "onelink.me",
                "final_registered_domain": "apple.com",
                "redirect_chain": [
                    {"url": raw_url},
                    {"url": "https://apps.apple.com/us/app/yoxo-voce-internet-roaming/id1481946568"},
                ],
                "redirect_count": 1,
                "shortener_count": 0,
                "uses_shortener": False,
                "detected_soft_redirects": [],
                "domain_age_days": 1600,
                "domain_created_date": "2021-01-01",
                "has_mx_records": True,
                "success": True,
            }
        )
    return resolved


async def _fake_inconclusive_yoxo_offer_claim(text, analysis, resolved_urls):
    offer_claim = {
        "provider": "ai_offer_web_check",
        "status": "inconclusive",
        "verdict": "inconclusive",
        "severity": "unknown",
        "summary": "Nu există risc confirmat în claim.",
        "details": "Nu există risc confirmat în claim.",
        "confidence": 45,
        "claimed_brand": "YOXO",
        "official_domains": ["yoxo.ro", "orange.ro", "apps.apple.com", "play.google.com"],
        "evidence_urls": [],
        "method": "test",
        "official_source_found": False,
    }
    app_main._attach_offer_claim_verification(analysis, offer_claim)
    return offer_claim


def test_orchestrated_yoxo_weak_vt_and_urlscan_prevented_finalizes_safe(monkeypatch):
    client = TestClient(app_main.app)
    message = (
        "In 24 de ore se va efectua automat plata abonamentului tau Orange YOXO cu numarul 0755287867. "
        "Asigura-te ca ai suficienti bani pe card. Poti vizualiza factura aici "
        "https://yoxo.onelink.me/f8ly/ijiwsfwu"
    )

    with monkeypatch.context() as patched:
        patched.setattr(app_main, "PRIVACY_SAFE_MODE", False)
        patched.setattr(app_main, "ENABLE_CLOUD_AI_EXPLANATION", False)
        patched.setattr(app_main, "URLSCAN_API_KEY", "server-only-key")
        patched.setattr(app_main, "_safe_scan_url_list", _fake_yoxo_onelink_to_app_store_scan)
        patched.setattr(app_main, "_gather_external_intel_safe", _clean_web_risk_and_weak_vt_for_resolved_urls)
        patched.setattr(app_main, "_enrich_offer_claim_verification_async", _fake_inconclusive_yoxo_offer_claim)
        patched.setattr(app_main.requests, "post", _fake_urlscan_post_scan_prevented)

        start = client.post(
            "/v1/scan/orchestrated",
            json={"input_type": "text", "text": message, "source_channel": "android_native"},
        ).json()
        response, payload = _poll_orchestrated(client, start["scan_id"], count=7)

    assert response.status_code == 200
    assert payload["status"] == "complete"
    assert payload["pillars"]["google_web_risk"]["status"] == "ok"
    assert payload["pillars"]["virustotal"]["status"] == "ok"
    assert payload["pillars"]["urlscan"]["status"] in {"ok", "not_required"}
    assert payload["preview"]["screenshot_url"] is None
    assert payload["result"]["user_risk_label"] == "SIGUR"
    assert payload["result"]["risk_level"] == "low"
    assert payload["result"]["detected_family_id"] == "provider-gate-official-clean"
    assert payload["result"]["evidence"]["provider_gate"]["detected_family_id"] == "provider-gate-official-clean"
    assert payload["result"]["evidence"]["provider_gate"]["official_destination"] is True


def test_orchestrated_fan_payment_scam_finalizes_dangerous_when_urlscan_rejects_domain(monkeypatch):
    client = TestClient(app_main.app)
    message = (
        "FanCourier: Coletul dvs. nr. 8842231 nu a putut fi livrat — taxă vamală neachitată 3,50 RON. "
        "Reprogramați livrarea: https://fancurier-relivrare.com/plata"
    )

    with monkeypatch.context() as patched:
        patched.setattr(app_main, "PRIVACY_SAFE_MODE", False)
        patched.setattr(app_main, "ENABLE_CLOUD_AI_EXPLANATION", False)
        patched.setattr(app_main, "URLSCAN_API_KEY", "server-only-key")
        patched.setattr(app_main, "_safe_scan_url_list", _fake_fan_relivrare_scan)
        patched.setattr(app_main, "_gather_external_intel_safe", _clean_web_risk_and_vt_for_resolved_urls)
        patched.setattr(app_main, "_enrich_offer_claim_verification_async", _fake_inconclusive_offer_claim)
        patched.setattr(app_main.requests, "post", _fake_urlscan_post_rejects_domain)

        start = client.post(
            "/v1/scan/orchestrated",
            json={"input_type": "text", "text": message, "source_channel": "android_native"},
        ).json()
        response, payload = _poll_orchestrated(client, start["scan_id"], count=7)

    assert response.status_code == 200
    assert payload["status"] == "complete"
    assert payload["pillars"]["google_web_risk"]["status"] == "ok"
    assert payload["pillars"]["virustotal"]["status"] == "ok"
    assert payload["pillars"]["urlscan"]["status"] == "error"
    assert payload["preview"]["screenshot_url"] is None
    assert payload["result"]["user_risk_label"] == "PERICULOS"
    assert payload["result"]["risk_level"] == "high"
    assert payload["result"]["detected_family_id"] == "F04"
    assert payload["result"]["evidence"]["provider_gate"]["detected_family_id"] == "provider-gate-decisive-structural-danger"


def test_orchestrated_hard_malicious_provider_finalizes_even_when_urlscan_rejects(monkeypatch):
    client = TestClient(app_main.app)

    with monkeypatch.context() as patched:
        patched.setattr(app_main, "PRIVACY_SAFE_MODE", False)
        patched.setattr(app_main, "ENABLE_CLOUD_AI_EXPLANATION", False)
        patched.setattr(app_main, "URLSCAN_API_KEY", "server-only-key")
        patched.setattr(app_main, "_safe_scan_url_list", _fake_google_test_phishing_scan)
        patched.setattr(app_main, "_gather_external_intel_safe", _malicious_web_risk_and_vt_for_resolved_urls)
        patched.setattr(
            app_main,
            "_enrich_offer_claim_verification_async",
            lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("Hard provider risk must not wait for claim verifier")),
        )
        patched.setattr(app_main.requests, "post", _fake_urlscan_post_rejects_domain)

        start = client.post(
            "/v1/scan/orchestrated",
            json={
                "input_type": "url",
                "url": "https://testsafebrowsing.appspot.com/s/phishing.html",
                "source_channel": "android_native",
            },
        ).json()
        response, payload = _poll_orchestrated(client, start["scan_id"], count=3)

    assert response.status_code == 200
    assert payload["status"] == "complete"
    assert payload["pillars"]["google_web_risk"]["status"] == "ok"
    assert payload["pillars"]["virustotal"]["status"] == "ok"
    assert payload["pillars"]["urlscan"]["status"] == "error"
    assert payload["pillars"]["claim_verifier"]["status"] == "not_required"
    assert payload["result"]["user_risk_label"] == "PERICULOS"
    assert payload["result"]["risk_level"] == "high"
    assert payload["result"]["detected_family_id"] == "provider-gate-bad-provider"
    assert payload["result"]["evidence"]["provider_gate"]["urlscan_consulted"] is False


def test_user_risk_level_labels():
    assert _user_risk_level_label("critical") == "PERICULOS"
    assert _user_risk_level_label("high") == "PERICULOS"
    assert _user_risk_level_label("medium") == "SUSPECT"
    assert _user_risk_level_label("safe") == "SIGUR"
    assert _user_risk_level_label("suspect") == "SUSPECT"
    assert _user_risk_level_label("dangerous") == "PERICULOS"


def test_user_facing_status_text_and_recommendation():
    assert _user_risk_level_text("safe") == "Probabil sigur"
    assert _user_risk_level_text("low") == "Probabil sigur"
    assert _user_risk_level_text("suspect") == "Suspect"
    assert _user_risk_level_text("medium") == "Suspect"
    assert _user_risk_level_text("dangerous") == "Periculos"
    assert _user_risk_level_text("critical") == "Periculos"
    assert _user_risk_level_text("") == "Neclar"

    assert _user_recommended_action("safe").startswith("Mesajul pare")
    assert "Nu apăsați" in _user_recommended_action("critical")
    assert "Trimiteți mesajul" in _user_recommended_action("unknown")


def test_build_scan_response_exposes_non_technical_status():
    payload = _build_scan_response(
        "text",
        analysis_results={"risk_score": 73, "risk_level": "critical", "detected_family": "Test", "detected_family_id": "test" , "safe_actions": ["Sigurați-vă"]},
        redacted_text="mesaj test",
        ai_explanation={"verdict_summary": "v", "explanation": "e", "key_dangers": [], "safe_actions": ["a"]},
    )

    assert payload["user_risk_level"] == "dangerous"
    assert payload["user_risk_text"] == "Periculos"
    assert payload["user_recommended_action"]
    assert payload["user_risk_label"] == "PERICULOS"


def test_privacy_policy_is_public_and_discloses_user_initiated_scans(monkeypatch):
    original_require_api_key = app_main.REQUIRE_API_KEY
    app_main.REQUIRE_API_KEY = True
    try:
        client = TestClient(app_main.app)
        response = client.get("/privacy")
    finally:
        app_main.REQUIRE_API_KEY = original_require_api_key

    assert response.status_code == 200
    assert "text/html" in response.headers["content-type"]
    body = response.text.lower()
    assert "nu citeste automat notificari" in body
    assert "clipboard" in body
    assert "urlscan.io" in body
    assert "google web risk" in body
    assert "virustotal" in body


def test_build_ai_explanation_uses_fallback_in_safe_mode(monkeypatch):
    original_mode = app_main.PRIVACY_SAFE_MODE
    app_main.PRIVACY_SAFE_MODE = True
    try:
        called = {"fallback": 0, "cloud": 0}

        def fake_fallback(text, analysis, resolved_urls=None):
            called["fallback"] += 1
            return {
                "verdict_summary": "fallback-safe",
                "explanation": "fallback explanation",
                "key_dangers": [],
                "safe_actions": [],
            }

        def fake_cloud(text, analysis, resolved_urls):
            called["cloud"] += 1
            return {
                "verdict_summary": "cloud",
                "explanation": "cloud explanation",
                "key_dangers": [],
                "safe_actions": [],
            }

        monkeypatch.setattr(app_main, "generate_ai_explanation", fake_cloud)
        monkeypatch.setattr(app_main, "generate_fallback_explanation", fake_fallback)

        result = _build_ai_explanation("text", {"risk_level": "low"}, [])
        assert result["verdict_summary"] == "fallback-safe"
        assert called["fallback"] == 1
        assert called["cloud"] == 0
    finally:
        app_main.PRIVACY_SAFE_MODE = original_mode


def test_safe_scan_url_entry_is_non_network_static():
    original_mode = app_main.PRIVACY_SAFE_MODE
    app_main.PRIVACY_SAFE_MODE = True
    try:
        entry = _safe_mode_url_entry("https://bit.ly/example")
        assert entry["final_url"] == "https://bit.ly/example"
        assert entry["shortener_count"] == 1
        assert entry["uses_shortener"] is True
        assert entry["success"] is True
        assert entry["error_message"] and "SIGURSCAN_SAFE_MODE" in entry["error_message"]
    finally:
        app_main.PRIVACY_SAFE_MODE = original_mode


def test_fast_reputation_skips_vt_and_does_not_persist_partial(monkeypatch, tmp_path):
    cache_path = tmp_path / "url_reputation_cache.json"
    saved_cache = []

    monkeypatch.setattr(url_reputation, "ENABLE_URL_REPUTATION", True)
    monkeypatch.setattr(url_reputation, "REPUTATION_CACHE_PATH", cache_path)
    monkeypatch.setattr(url_reputation, "_load_cache", lambda path: {})
    monkeypatch.setattr(url_reputation, "_save_cache", lambda path, data, remote_subset=None: saved_cache.append(dict(data)))
    monkeypatch.setattr(url_reputation, "has_web_risk_key", lambda: True)
    monkeypatch.setattr(url_reputation, "check_urls_against_web_risk", lambda urls: {})
    monkeypatch.setattr(
        url_reputation,
        "_fetch_virustotal",
        lambda urls, api_key: (_ for _ in ()).throw(AssertionError("VT should be skipped in fast mode")),
    )
    monkeypatch.setattr(
        url_reputation,
        "_fetch_urlhaus",
        lambda urls: (_ for _ in ()).throw(AssertionError("URLhaus should be skipped in fast mode")),
    )

    result = url_reputation.get_reputation_for_urls(
        ["https://example.com/login"],
        include_virustotal=False,
        include_urlhaus=False,
    )

    key = url_reputation._url_hash("https://example.com/login")
    assert key in result
    assert result[key]["cached"] is False
    assert result[key]["sources"]["virustotal"]["consulted"] is False
    assert result[key]["sources"]["urlhaus"]["consulted"] is False
    assert saved_cache == []


def test_reputation_cache_persists_only_touched_remote_entries(monkeypatch, tmp_path):
    cache_path = tmp_path / "url_reputation_cache.json"
    old_key = "old-cache-key"
    saved_remote_subsets = []
    existing_cache = {
        old_key: {
            "version": url_reputation.REPUTATION_CACHE_VERSION,
            "url": "https://old.example",
            "verdict": "clean",
            "expires_at": 1,
            "sources": {},
        }
    }

    def fake_save(path, data, remote_subset=None):
        saved_remote_subsets.append(dict(remote_subset or {}))

    monkeypatch.setattr(url_reputation, "ENABLE_URL_REPUTATION", True)
    monkeypatch.setattr(url_reputation, "REPUTATION_CACHE_PATH", cache_path)
    monkeypatch.setattr(url_reputation, "_load_cache", lambda path: dict(existing_cache))
    monkeypatch.setattr(url_reputation, "_save_cache", fake_save)
    monkeypatch.setattr(url_reputation, "has_web_risk_key", lambda: True)
    monkeypatch.setattr(url_reputation, "check_urls_against_web_risk", lambda urls: {})
    monkeypatch.setattr(
        url_reputation,
        "_fetch_virustotal",
        lambda urls, api_key: {
            url_reputation._url_hash(urls[0]): {
                "status": "clean",
                "threat_type": "unknown",
                "score": 0,
                "details": {"status": "clean"},
                "query_ms": 12,
            }
        },
    )
    monkeypatch.setattr(
        url_reputation,
        "_fetch_urlhaus",
        lambda urls, auth_key=None: {
            url_reputation._url_hash(urls[0]): {
                "status": "clean",
                "threat_type": "unknown",
                "score": 0,
                "details": {"status": "not_listed"},
                "query_ms": 10,
            }
        },
    )

    result = url_reputation.get_reputation_for_urls(
        ["https://new.example/path"],
        include_virustotal=True,
        include_urlhaus=True,
    )

    new_key = url_reputation._url_hash("https://new.example/path")
    assert new_key in result
    assert saved_remote_subsets
    assert set(saved_remote_subsets[0].keys()) == {new_key}
    assert old_key not in saved_remote_subsets[0]


def test_urlhaus_without_auth_key_is_not_consulted(monkeypatch):
    def fail_post(*args, **kwargs):
        raise AssertionError("URLhaus must not be called without Auth-Key.")

    monkeypatch.setattr(url_reputation, "URLHAUS_AUTH_KEY", "")
    monkeypatch.setattr(url_reputation.requests, "post", fail_post)

    result = url_reputation._fetch_urlhaus(["https://example.com/path"])
    key = url_reputation._url_hash("https://example.com/path")

    assert result[key]["status"] == "unknown"
    assert result[key]["details"]["status"] == "not_configured"


def test_urlhaus_uses_auth_key_header_and_form_payload(monkeypatch):
    captured = {}

    class FakeResponse:
        status_code = 200

        @staticmethod
        def json():
            return {"query_status": "no_results"}

    def fake_post(url, *, data, headers, timeout):
        captured["url"] = url
        captured["data"] = data
        captured["headers"] = headers
        captured["timeout"] = timeout
        return FakeResponse()

    monkeypatch.setattr(url_reputation.requests, "post", fake_post)

    result = url_reputation._fetch_urlhaus(["https://example.com/path"], "urlhaus-secret")
    key = url_reputation._url_hash("https://example.com/path")

    assert captured["headers"] == {"Auth-Key": "urlhaus-secret"}
    assert captured["data"] == {"url": "https://example.com/path"}
    assert result[key]["status"] == "clean"
    assert result[key]["details"]["status"] == "not_listed"


def test_local_reputation_cache_is_lru_capped(monkeypatch):
    now = int(time.time())
    old_key = "old"
    middle_key = "middle"
    newest_key = "newest"
    monkeypatch.setattr(url_reputation, "REPUTATION_CACHE_MAX_ITEMS", 2)
    monkeypatch.setattr(url_reputation, "REPUTATION_CACHE_TTL_SECONDS", 100)

    pruned = url_reputation._prune_cache_for_save(
        {
            old_key: {"created_at": now - 50, "cached_at": now - 50, "expires_at": now + 50},
            middle_key: {"created_at": now - 20, "cached_at": now - 20, "expires_at": now + 80},
            newest_key: {"created_at": now - 1, "cached_at": now - 1, "expires_at": now + 99},
        }
    )

    assert set(pruned.keys()) == {middle_key, newest_key}


def test_supabase_reputation_cache_uses_single_batch_upsert(monkeypatch):
    posted = []

    class FakeResponse:
        @staticmethod
        def raise_for_status():
            return None

    def fake_post(url, *, headers, json, timeout):
        posted.append({"url": url, "headers": headers, "json": json, "timeout": timeout})
        return FakeResponse()

    monkeypatch.setattr(supabase_store, "SUPABASE_URL", "https://example.supabase.co")
    monkeypatch.setattr(supabase_store, "SUPABASE_SERVICE_ROLE_KEY", "service-role")
    monkeypatch.setattr(supabase_store.requests, "post", fake_post)

    supabase_store.save_reputation_cache(
        {
            "hash-a": {"url": "https://a.example", "verdict": "clean", "sources": {}, "details": "ignored"},
            "hash-b": {"url": "https://b.example", "verdict": "unknown", "sources": {}},
        }
    )

    assert len(posted) == 1
    assert isinstance(posted[0]["json"], list)
    assert {row["url_hash"] for row in posted[0]["json"]} == {"hash-a", "hash-b"}
    assert "resolution=merge-duplicates" in posted[0]["headers"]["Prefer"]


def test_virustotal_single_engine_is_suspicious_not_malicious(monkeypatch):
    class FakeResponse:
        status_code = 200

        @staticmethod
        def json():
            return {
                "data": {
                    "attributes": {
                        "last_analysis_stats": {
                            "harmless": 62,
                            "malicious": 1,
                            "suspicious": 0,
                            "undetected": 32,
                        },
                        "last_analysis_results": {
                            "FlakyVendor": {
                                "category": "malicious",
                                "result": "phishing",
                                "method": "blacklist",
                            }
                        },
                        "last_analysis_date": 1780000000,
                    }
                }
            }

    monkeypatch.setattr(url_reputation.requests, "get", lambda *args, **kwargs: FakeResponse())
    monkeypatch.setattr(url_reputation, "VIRUS_TOTAL_MALICIOUS_CONSENSUS_MIN_ENGINES", 2)

    result = url_reputation._fetch_virustotal(["https://apps.apple.com/example"], "fake-key")
    key = url_reputation._url_hash("https://apps.apple.com/example")

    assert result[key]["status"] == "suspicious"
    assert result[key]["threat_type"] == "suspicious"
    assert result[key]["details"]["stats"]["malicious"] == 1
    assert result[key]["details"]["flagged_engines"][0]["engine"] == "FlakyVendor"


def test_email_auth_context_skips_dns_in_safe_mode(monkeypatch):
    msg = EmailMessage()
    msg["From"] = "Phishing <scammer@evil.example>"
    msg["Authentication-Results"] = "spf=pass; dkim=pass; dmarc=pass"
    msg["DKIM-Signature"] = "v=1; d=mail.evil.example; s=selector"
    msg["Received-SPF"] = "pass"

    original_mode = app_main.PRIVACY_SAFE_MODE
    app_main.PRIVACY_SAFE_MODE = True
    try:
        monkeypatch.setattr(app_main, "get_spf_dns_record", lambda domain: (_ for _ in ()).throw(AssertionError("DNS SPF called in safe mode")))
        monkeypatch.setattr(app_main, "get_dmarc_policy", lambda domain: (_ for _ in ()).throw(AssertionError("DMARC DNS called in safe mode")))
        monkeypatch.setattr(app_main, "check_dkim_dns_record", lambda selector, domain: (_ for _ in ()).throw(AssertionError("DKIM DNS called in safe mode")))

        ctx = _extract_email_auth_context(msg)
        assert ctx["dns_checks"]["dns_checks_disabled"] is True
        assert ctx["dns_checks"]["spf_record"] is None
        assert ctx["dns_checks"]["dkim_dns"] is None
        assert ctx["dns_checks"]["dmarc_policy"] == {}
        assert any("SIGURSCAN_SAFE_MODE" in reason for reason in ctx["auth_fail_reasons"])
    finally:
        app_main.PRIVACY_SAFE_MODE = original_mode


def test_forwarded_html_without_headers_does_not_create_auth_risk():
    ctx = _extract_email_auth_context(None, is_forwarded_guess=True)
    assert ctx["auth_strength"] == "unavailable"
    assert ctx["auth_fail_reasons"] == []
    assert ctx["auth_action_plan"]["risk_score_delta"] == 0


def test_click_target_extraction_from_email_html():
    html = """
    <html>
      <body>
        <a href="https://revolut-security.net/unlock">Apasă aici să deblochezi contul Revolut</a>
        <button onclick=\"window.location.href='https://phishing-unlock.example/rev'\">Continuă sigur</button>
        <form action="https://form-fallback.example/recover">
          <button>Trimite acum</button>
        </form>
        <input type="submit" value="Verifică contul" formaction="https://input-fallback.example/verify" />
      </body>
    </html>
    """
    soup = BeautifulSoup(html, "html.parser")
    targets = _collect_click_targets_from_html(soup)
    urls = {item["original_url"] for item in targets}

    assert "https://revolut-security.net/unlock" in urls
    assert "https://phishing-unlock.example/rev" in urls
    assert "https://form-fallback.example/recover" in urls
    assert "https://input-fallback.example/verify" in urls
    assert any(item["source_tag"] == "a" and item["source_attr"] == "href" for item in targets)
    assert any(item["source_tag"] == "button" and item["source_attr"] == "onclick" for item in targets)
    assert any(item["source_tag"] == "form" and item["source_attr"] == "action" for item in targets)
    assert any(item["source_tag"] == "input" and item["source_attr"] == "formaction" for item in targets)


def test_extract_email_endpoint_returns_intake_evidence_without_verdict():
    client = TestClient(app_main.app)
    html = """
    <html><body>
      <p>Comanda ta a fost expediată.</p>
      <a href="https://awb.fan.ro/hJ90LuI0605A8">Urmărește coletul</a>
    </body></html>
    """

    response = client.post("/v1/extract/email", data={"html_content": html, "source_channel": "android_test"})

    assert response.status_code == 200
    payload = response.json()
    assert payload["input_type"] == "email"
    assert "https://awb.fan.ro/hJ90LuI0605A8" in payload["extracted_urls"]
    assert payload["buttons"][0]["original_url"] == "https://awb.fan.ro/hJ90LuI0605A8"
    assert "risk_level" not in payload
    assert "risk_score" not in payload
    assert "user_risk_label" not in payload


def test_extract_image_endpoint_returns_ocr_evidence_without_verdict(monkeypatch):
    client = TestClient(app_main.app)

    async def fake_extract_text_for_scan(filename, file_bytes, extract_fn):
        return "Vezi detalii aici https://example.com/status", None

    monkeypatch.setattr(app_main, "extract_text_for_scan", fake_extract_text_for_scan)

    response = client.post(
        "/v1/extract/image",
        data={"source_channel": "android_test"},
        files={"image_file": ("screenshot.png", b"not-a-real-image-but-valid-for-contract", "image/png")},
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["input_type"] == "image_ocr"
    assert payload["redacted_text"] == "Vezi detalii aici https://example.com/status"
    assert "https://example.com/status" in payload["extracted_urls"]
    assert "risk_level" not in payload
    assert "risk_score" not in payload
    assert "user_risk_label" not in payload


def test_extract_email_captures_button_only_cta_without_verdict(monkeypatch):
    html = """
    <html>
      <body>
        <p>Revolut: Contul tău este blocat. Apasă butonul ca să verifici.</p>
        <button onclick="window.location.href='https://phish-revolut.example/release'">Deblochează</button>
      </body>
    </html>
    """

    def fake_safe_scan(urls):
        resolved = []
        for raw_url in urls:
            parsed = urllib.parse.urlparse(raw_url)
            host = parsed.hostname or ""
            resolved.append(
                {
                    "url": raw_url,
                    "final_url": raw_url,
                    "final_hostname": host,
                    "final_registered_domain": host,
                    "redirect_chain": [],
                    "redirect_count": 0,
                    "shortener_count": 0,
                    "uses_shortener": False,
                    "detected_soft_redirects": [],
                    "domain_age_days": None,
                    "domain_created_date": None,
                    "has_mx_records": None,
                    "success": True,
                }
            )
        return resolved

    client = TestClient(app_main.app)

    with monkeypatch.context() as patched:
        patched.setattr(app_main, "_safe_scan_url_list", fake_safe_scan)
        patched.setattr(app_main, "_gather_external_intel_safe", lambda urls, **kwargs: {})
        response = client.post("/v1/extract/email", data={"html_content": html})

    assert response.status_code == 200
    payload = response.json()
    assert any(item.get("source_tag") == "button" and item.get("source_attr") == "onclick" for item in payload.get("buttons", []))
    assert any(item.get("original_url") == "https://phish-revolut.example/release" for item in payload.get("buttons", []))
    assert "risk_level" not in payload
    assert "user_risk_label" not in payload


def test_click_target_extraction_from_relative_and_js_protocol_html():
    html = """
    <html>
      <head>
        <base href="https://base-site.example/app/">
      </head>
      <body>
        <a href="/verify/account?step=1">Confirmare</a>
        <a href="javascript:window.location='https://js-protocol.example/rev'">JavaScript link</a>
      </body>
    </html>
    """
    soup = BeautifulSoup(html, "html.parser")
    targets = _collect_click_targets_from_html(soup)
    urls = {item["original_url"] for item in targets}
    assert "https://base-site.example/verify/account?step=1" in urls
    assert "https://js-protocol.example/rev" in urls


class _FakeUrlscanResponse:
    def __init__(self, status_code=200, payload=None, content=b"", headers=None):
        self.status_code = status_code
        self._payload = payload or {}
        self.content = content
        self.headers = headers or {}

    def json(self):
        return self._payload


def test_urlscan_sandbox_submit_returns_backend_proxy_urls(monkeypatch):
    client = TestClient(app_main.app)
    captured = {}

    def fake_post(url, headers, json, timeout):
        captured["url"] = url
        captured["headers"] = headers
        captured["json"] = json
        captured["timeout"] = timeout
        return _FakeUrlscanResponse(payload={"uuid": "scan-123"})

    with monkeypatch.context() as patched:
        patched.setattr(app_main, "URLSCAN_API_KEY", "server-only-key")
        patched.setattr(app_main, "PRIVACY_SAFE_MODE", False)
        patched.setattr(app_main.requests, "post", fake_post)
        response = client.post("/v1/sandbox/urlscan", json={"url": "https://example.com/path?utm_source=x"})

    assert response.status_code == 200
    payload = response.json()
    assert payload["uuid"] == "scan-123"
    assert payload["status"] == "pending"
    assert "/v1/sandbox/urlscan/scan-123" in payload["result_url"]
    assert "/v1/sandbox/urlscan/scan-123/screenshot" in payload["screenshot_url"]
    assert "server-only-key" not in str(payload)
    assert captured["headers"]["api-key"] == "server-only-key"
    assert captured["json"]["url"] == "https://example.com/path"
    assert captured["json"]["visibility"] == "private"


def test_urlscan_sandbox_submit_accepts_scan_persona(monkeypatch):
    client = TestClient(app_main.app)
    captured = {}

    def fake_post(url, headers, json, timeout):
        captured["json"] = json
        return _FakeUrlscanResponse(payload={"uuid": "scan-persona"})

    mobile_agent = "Mozilla/5.0 (Linux; Android 15) AppleWebKit/537.36 Chrome/120 Mobile Safari/537.36"
    with monkeypatch.context() as patched:
        patched.setattr(app_main, "URLSCAN_API_KEY", "server-only-key")
        patched.setattr(app_main, "PRIVACY_SAFE_MODE", False)
        patched.setattr(app_main.requests, "post", fake_post)
        response = client.post(
            "/v1/sandbox/urlscan",
            json={
                "url": "https://example.com/",
                "country": "ro",
                "customagent": mobile_agent,
            },
        )

    assert response.status_code == 200
    assert captured["json"]["country"] == "ro"
    assert captured["json"]["customagent"] == mobile_agent


def test_urlscan_sandbox_retries_unlisted_without_invalid_persona(monkeypatch):
    client = TestClient(app_main.app)
    captured = []

    def fake_post(url, headers, json, timeout):
        captured.append(dict(json))
        if len(captured) == 1:
            return _FakeUrlscanResponse(
                status_code=400,
                payload={"message": 'ValidationError: "country" failed custom validation'},
            )
        if len(captured) == 2:
            return _FakeUrlscanResponse(status_code=403, payload={"message": "private visibility unavailable"})
        return _FakeUrlscanResponse(payload={"uuid": "scan-no-persona"})

    with monkeypatch.context() as patched:
        patched.setattr(app_main, "URLSCAN_API_KEY", "server-only-key")
        patched.setattr(app_main, "PRIVACY_SAFE_MODE", False)
        patched.setattr(app_main.requests, "post", fake_post)
        response = client.post(
            "/v1/sandbox/urlscan",
            json={
                "url": "https://delivery2.sameday.ro/demo",
                "visibility": "private",
                "country": "ro",
                "customagent": "Mobile Test Agent",
            },
        )

    assert response.status_code == 200
    assert response.json()["uuid"] == "scan-no-persona"
    assert len(captured) == 3
    assert captured[0]["visibility"] == "private"
    assert captured[0]["country"] == "ro"
    assert captured[1]["visibility"] == "private"
    assert "country" not in captured[1]
    assert "customagent" not in captured[1]
    assert captured[2]["visibility"] == "unlisted"
    assert "country" not in captured[2]
    assert "customagent" not in captured[2]


def test_urlscan_sandbox_sanitizes_long_source_channel_tag(monkeypatch):
    client = TestClient(app_main.app)
    captured = {}

    def fake_post(url, headers, json, timeout):
        captured["json"] = json
        return _FakeUrlscanResponse(payload={"uuid": "scan-tags"})

    with monkeypatch.context() as patched:
        patched.setattr(app_main, "URLSCAN_API_KEY", "server-only-key")
        patched.setattr(app_main, "PRIVACY_SAFE_MODE", False)
        patched.setattr(app_main.requests, "post", fake_post)
        response = client.post(
            "/v1/sandbox/urlscan",
            json={
                "url": "https://example.com/",
                "source_channel": "Codex Live Big Pillars YOXO 20260604 !!! very long",
            },
        )

    assert response.status_code == 200
    tags = captured["json"]["tags"]
    assert tags[:2] == ["sigurscan", "android"]
    assert len(tags[2]) <= 32
    assert tags[2] == "codex-live-big-pillars-yoxo-20"


def test_urlscan_sandbox_result_summarizes_malicious_payload(monkeypatch):
    client = TestClient(app_main.app)

    def fake_get(url, headers, timeout):
        return _FakeUrlscanResponse(
            payload={
                "task": {"url": "https://initial.example/login"},
                "page": {
                    "url": "https://final-phish.example/login",
                    "ip": "203.0.113.10",
                    "country": "RO",
                    "server": "nginx",
                },
                "verdicts": {
                    "overall": {
                        "malicious": True,
                        "score": 100,
                        "categories": ["phishing"],
                    }
                },
                "brands": ["Revolut"],
            }
        )

    with monkeypatch.context() as patched:
        patched.setattr(app_main, "URLSCAN_API_KEY", "server-only-key")
        patched.setattr(app_main, "PRIVACY_SAFE_MODE", False)
        patched.setattr(app_main.requests, "get", fake_get)
        response = client.get("/v1/sandbox/urlscan/scan-123")

    assert response.status_code == 200
    payload = response.json()
    assert payload["status"] == "finished"
    assert payload["verdict"] == "Malicious phishing"
    assert payload["severity"] == "high"
    assert payload["final_url"] == "https://final-phish.example/login"
    assert "/v1/sandbox/urlscan/scan-123/screenshot" in payload["screenshot_url"]
    assert "server-only-key" not in str(payload)


def test_urlscan_sandbox_screenshot_is_proxied_without_exposing_key(monkeypatch):
    client = TestClient(app_main.app)
    captured = {}

    def fake_get(url, headers, timeout):
        captured["url"] = url
        captured["headers"] = headers
        return _FakeUrlscanResponse(content=b"\x89PNG\r\n", headers={"content-type": "image/png"})

    with monkeypatch.context() as patched:
        patched.setattr(app_main, "URLSCAN_API_KEY", "server-only-key")
        patched.setattr(app_main, "PRIVACY_SAFE_MODE", False)
        patched.setattr(app_main.requests, "get", fake_get)
        response = client.get("/v1/sandbox/urlscan/scan-123/screenshot")

    assert response.status_code == 200
    assert response.headers["content-type"].startswith("image/png")
    assert response.content == b"\x89PNG\r\n"
    assert captured["headers"]["api-key"] == "server-only-key"
    assert "server-only-key" not in response.text


def test_urlscan_sandbox_blocks_local_targets(monkeypatch):
    client = TestClient(app_main.app)

    with monkeypatch.context() as patched:
        patched.setattr(app_main, "URLSCAN_API_KEY", "server-only-key")
        patched.setattr(app_main, "PRIVACY_SAFE_MODE", False)
        response = client.post("/v1/sandbox/urlscan", json={"url": "http://127.0.0.1/admin"})

    assert response.status_code == 400
    assert "URL blocat" in response.json()["detail"]


def test_click_target_extraction_from_fake_button_elements():
    html = """
    <html>
      <body>
        <div role=\"button\" onclick=\"location.href='https://role-button.example/claim'\">Deblochează cont</div>
        <span data-url=\"https://data-url.example/review\">Află mai multe</span>
      </body>
    </html>
    """
    soup = BeautifulSoup(html, "html.parser")
    targets = _collect_click_targets_from_html(soup)
    urls = {item["original_url"] for item in targets}
    assert "https://role-button.example/claim" in urls
    assert "https://data-url.example/review" in urls
    assert any(item["source_tag"] == "div" and item["source_attr"] == "onclick" for item in targets)
    assert any(item["source_tag"] == "span" and item["source_attr"] == "data-url" for item in targets)


def test_click_target_extraction_from_js_concat_and_vars():
    html = """
    <html>
      <body>
        <button onclick="
          var base='https://var-domain.example';
          var path='/unlock';
          window.location.href = base + path;
        ">Deschide</button>
        <a href=\"javascript:var target='https://href-domain.example'; window.open(target + '/verify', '_blank');\">Apasă</a>
      </body>
    </html>
    """
    soup = BeautifulSoup(html, "html.parser")
    targets = _collect_click_targets_from_html(soup)
    urls = {item["original_url"] for item in targets}
    assert "https://var-domain.example/unlock" in urls
    assert "https://href-domain.example/verify" in urls


def test_click_target_extraction_from_js_bracket_not_false_positive():
    html = """
    <html>
      <head>
        <base href=\"https://base.example/app/\">
      </head>
      <body>
        <button onclick=\"window['location'].href='/account';\">Deblochează cont</button>
        <div onclick=\"location['href']='https://bracket.example/secure'\">Verifică aici</div>
      </body>
    </html>
    """
    soup = BeautifulSoup(html, "html.parser")
    targets = _collect_click_targets_from_html(soup)
    urls = {item["original_url"] for item in targets}
    assert "https://base.example/account" in urls
    assert "https://bracket.example/secure" in urls
    assert not any(u in {"https://location/", "https://href/"} for u in urls)
    assert any(item["source_tag"] == "button" and item["source_attr"] == "onclick" for item in targets)
    assert any(item["source_tag"] == "div" and item["source_attr"] == "onclick" for item in targets)


def test_click_target_extraction_from_button_relative_js_without_base():
    html = """
    <html>
      <body>
        <button onclick=\"window['location']='/unlock';\">Deblochează contul</button>
        <div onclick=\"location='/account/settings';\">Confirmă identitatea</div>
      </body>
    </html>
    """
    soup = BeautifulSoup(html, "html.parser")
    targets = _collect_click_targets_from_html(soup)
    urls = {item["original_url"] for item in targets}

    assert "/unlock" in urls
    assert "/account/settings" in urls
    assert any(item["source_tag"] == "button" and item["source_attr"] == "onclick" for item in targets)
    assert any(item["source_tag"] == "div" and item["source_attr"] == "onclick" for item in targets)


def test_click_target_extraction_from_form_action():
    html = """
    <html>
      <body>
        <form action="/verify">
          <button type="submit">Confirmă</button>
        </form>
      </body>
    </html>
    """
    soup = BeautifulSoup(html, "html.parser")
    targets = _collect_click_targets_from_html(soup)
    urls = {item["original_url"] for item in targets}
    assert "/verify" in urls
    assert any(item["source_tag"] == "form" and item["source_attr"] == "action" for item in targets)


def test_scan_email_detects_relative_button_link(monkeypatch):
    html = """
    <html>
      <body>
        <p>Revolut: Contul tău este blocat. Apasă butonul ca să verifici.</p>
        <button onclick=\"window['location']='/unlock';\">Deblochează</button>
      </body>
    </html>
    """

    def fake_safe_scan(urls):
        resolved = []
        for raw_url in urls:
            parsed = urllib.parse.urlparse(raw_url)
            resolved.append(
                {
                    "url": raw_url,
                    "final_url": raw_url,
                    "final_hostname": parsed.hostname,
                    "final_registered_domain": parsed.hostname,
                    "redirect_chain": [],
                    "redirect_count": 0,
                    "shortener_count": 0,
                    "uses_shortener": False,
                    "detected_soft_redirects": [],
                    "domain_age_days": None,
                    "domain_created_date": None,
                    "has_mx_records": None,
                    "success": False,
                }
            )
        return resolved

    client = TestClient(app_main.app)

    with monkeypatch.context() as patched:
        patched.setattr(app_main, "_safe_scan_url_list", fake_safe_scan)
        patched.setattr(app_main, "_gather_external_intel_safe", lambda urls, **kwargs: {})
        response = client.post("/v1/extract/email", data={"html_content": html})

    assert response.status_code == 200
    payload = response.json()
    assert any(item.get("original_url") == "/unlock" for item in payload.get("buttons", []))
    assert "risk_level" not in payload
    assert "user_risk_label" not in payload


def test_button_text_only_cta_is_captured_with_sensitive_flag(monkeypatch):
    html = """
    <html>
      <body>
        <p>Revolut: contul tău este blocat. Apasă aici ca să deblochezi contul imediat.</p>
        <button onclick="window.location='https://rev-unlock.example/reset'">Apasă aici să deblochezi contul</button>
      </body>
    </html>
    """

    def fake_safe_scan(urls):
        resolved = []
        for raw_url in urls:
            parsed = urllib.parse.urlparse(raw_url)
            resolved.append(
                {
                    "url": raw_url,
                    "final_url": raw_url,
                    "final_hostname": parsed.hostname,
                    "final_registered_domain": parsed.hostname,
                    "redirect_chain": [],
                    "redirect_count": 0,
                    "shortener_count": 0,
                    "uses_shortener": False,
                    "detected_soft_redirects": [],
                    "domain_age_days": None,
                    "domain_created_date": None,
                    "has_mx_records": None,
                    "success": True,
                }
            )
        return resolved

    client = TestClient(app_main.app)
    with monkeypatch.context() as patched:
        patched.setattr(app_main, "_safe_scan_url_list", fake_safe_scan)
        patched.setattr(app_main, "_gather_external_intel_safe", _clean_external_intel_for_resolved_urls)
        response = client.post("/v1/extract/email", data={"html_content": html})

    assert response.status_code == 200
    payload = response.json()
    buttons = payload.get("buttons", [])
    assert any(item.get("original_url") == "https://rev-unlock.example/reset" for item in buttons)
    assert any(item.get("is_sensitive_cta") for item in buttons)
    assert "user_risk_text" not in payload


def test_scan_email_detects_form_action_relative(monkeypatch):
    html = """
    <html>
      <body>
        <form action="/verify"><button>Confirmă</button></form>
      </body>
    </html>
    """

    def fake_safe_scan(urls):
        return [
            {
                "url": raw_url,
                "final_url": raw_url,
                "final_hostname": urllib.parse.urlparse(raw_url).hostname,
                "final_registered_domain": urllib.parse.urlparse(raw_url).hostname,
                "redirect_chain": [],
                "redirect_count": 0,
                "shortener_count": 0,
                "uses_shortener": False,
                "detected_soft_redirects": [],
                "domain_age_days": None,
                "domain_created_date": None,
                "has_mx_records": None,
                "success": False,
            }
            for raw_url in urls
        ]

    client = TestClient(app_main.app)
    with monkeypatch.context() as patched:
        patched.setattr(app_main, "_safe_scan_url_list", fake_safe_scan)
        patched.setattr(app_main, "_gather_external_intel_safe", _clean_external_intel_for_resolved_urls)
        response = client.post("/v1/extract/email", data={"html_content": html})

    assert response.status_code == 200
    payload = response.json()
    assert any(item.get("original_url") == "/verify" for item in payload.get("buttons", []))
    assert any(item.get("source_attr") == "action" for item in payload.get("buttons", []))


def test_domain_alignment_modes():
    assert _is_domain_aligned("mail.example.com", "newsletter.example.com", "r") is True
    assert _is_domain_aligned("mail.example.com", "newsletter.example.com", "s") is False
    assert _is_domain_aligned("mail.example.com", "example.com", "s") is False
    assert _is_domain_aligned("mail.example.com", "example.co.uk", "r") is False
    assert _is_domain_aligned("mail.example.co.uk", "ops.example.co.uk", "r") is True
    assert _is_domain_aligned(None, "example.com", "r") is None


def test_email_auth_alignment_rejects_when_dmarc_strict_but_domains_mismatch(monkeypatch):
    msg = EmailMessage()
    msg["From"] = "Phishing <attacker@evil.example>"
    msg["Return-Path"] = "bounces@relay.bad.net"
    msg["DKIM-Signature"] = "v=1; d=mail.bad.org; s=selector123;"
    msg["Authentication-Results"] = "spf=pass dkim=pass dmarc=pass"
    msg["Received-SPF"] = "pass"

    monkeypatch.setattr("main.get_spf_dns_record", lambda domain: "v=spf1 -all")
    monkeypatch.setattr("main.get_dmarc_policy", lambda domain: {"p": "reject", "aspf": "s", "adkim": "s"})
    monkeypatch.setattr("main.check_dkim_dns_record", lambda selector, domain: "v=DKIM1; p=TESTKEY")

    email_ctx = _extract_email_auth_context(msg)
    assert email_ctx["alignment"]["spf_aligned"] is False
    assert email_ctx["alignment"]["dkim_aligned"] is False
    assert email_ctx["auth_action_plan"]["action"] == "reject"
    assert email_ctx["auth_action_plan"]["risk_score_delta"] >= 28
    assert any("non-aliniate" in reason.lower() for reason in email_ctx["auth_action_plan"]["reasons"])

    signals = _collect_signal_ids({"evidence": {"email_auth": email_ctx}})
    assert "email_spf_alignment_mismatch" in signals
    assert "email_dkim_alignment_mismatch" in signals


def test_email_auth_alignment_keeps_monitor_when_aligned(monkeypatch):
    msg = EmailMessage()
    msg["From"] = "Phishing <attacker@evil.example>"
    msg["Return-Path"] = "bounce@evil.example"
    msg["DKIM-Signature"] = "v=1; d=evil.example; s=selector123;"
    msg["Authentication-Results"] = "spf=pass dkim=pass dmarc=pass"
    msg["Received-SPF"] = "pass"

    monkeypatch.setattr("main.get_spf_dns_record", lambda domain: "v=spf1 -all")
    monkeypatch.setattr("main.get_dmarc_policy", lambda domain: {"p": "reject", "aspf": "r", "adkim": "r"})
    monkeypatch.setattr("main.check_dkim_dns_record", lambda selector, domain: "v=DKIM1; p=TESTKEY")

    email_ctx = _extract_email_auth_context(msg)
    assert email_ctx["alignment"]["spf_aligned"] is True
    assert email_ctx["alignment"]["dkim_aligned"] is True
    assert email_ctx["auth_action_plan"]["action"] == "monitor"
    signals = _collect_signal_ids({"evidence": {"email_auth": email_ctx}})
    assert "email_spf_alignment_mismatch" not in signals


def test_email_auth_context_without_received_spf_does_not_crash(monkeypatch):
    msg = EmailMessage()
    msg["From"] = "Scam <attacker@evil.example>"

    monkeypatch.setattr("main.get_spf_dns_record", lambda domain: None)
    monkeypatch.setattr("main.get_dmarc_policy", lambda domain: None)
    monkeypatch.setattr("main.check_dkim_dns_record", lambda selector, domain: None)

    email_ctx = _extract_email_auth_context(msg)
    assert email_ctx["alignment"]["from_domain"] == "evil.example"
    assert email_ctx["auth_action_plan"]["action"] == "monitor"
    assert any(
        "SPF DNS" in reason or "DMARC" in reason
        for reason in email_ctx["auth_fail_reasons"]
    )


def test_url_extraction_filters_malformed_domain_tokens():
    print("Testing URL extraction filters invalid-domain noise...")
    raw = "Nu deschide linkul dvs.de sau activat.Accesati si trimite datele."
    urls = extract_urls(raw)
    assert not any("dvs.de" in item for item in urls), urls
    assert not any("activat.accesati" in item for item in urls), urls
    print("  - URL extraction noise filter: PASS\n")


def test_url_extraction_supports_unknown_tld_links():
    print("Testing extraction for scheme-based unknown TLD links...")
    raw = "Verifica aici: https://security-check.alert/login?session=ok"
    urls = extract_urls(raw)
    assert "https://security-check.alert/login?session=ok" in urls, urls


def test_official_brand_link_paths_do_not_raise_false_positive():
    engine = ScamAtlasEngine()
    message = "Revolut: verifică-ți accesul la cont prin panoul tău."
    urls = [{
        "url": "https://www.revolut.com/security",
        "final_url": "https://www.revolut.com/security",
        "final_hostname": "www.revolut.com",
        "final_registered_domain": "revolut.com",
    }]
    result = engine.analyze(message, urls)
    assert result["risk_level"] == "low"
    assert not any("Pattern de risc pe cale URL" in reason for reason in result["reasons"])


def test_uber_marketing_tracker_link_does_not_raise_false_positive():
    engine = ScamAtlasEngine()
    message = "Uber: Comandă o cursă cu oferta ta din aplicație."
    urls = [{
        "url": "https://rides.sng.link/Aw5zn/hw3r?_fallback_redirect=https%3A%2F%2Fwww.uber.com",
        "final_url": "https://rides.sng.link/Aw5zn/hw3r?_fallback_redirect=https%3A%2F%2Fwww.uber.com",
        "final_hostname": "rides.sng.link",
        "final_registered_domain": "sng.link",
        "success": False,
    }]

    result = engine.analyze(message, urls)

    assert result["claimed_brand"] == "Uber"
    assert result["evidence"]["has_domain_mismatch"] is False
    assert result["risk_level"] not in {"high", "critical"}
    assert not any("extensie de domeniu neobișnuită" in reason.lower() for reason in result["reasons"])


def test_scan_email_infers_uber_from_deep_link_without_visible_brand(monkeypatch):
    html = """
    <a href="https://rides.sng.link/Aw5zn/hw3r?_dl=uber%3A%2F%2F&amp;_fallback_redirect=https%3A%2F%2Fwww.uber.com&amp;partner=crm">
      Comandă o cursă
    </a>
    """

    def fake_safe_scan(urls):
        resolved = []
        for raw_url in urls:
            parsed = urllib.parse.urlparse(raw_url)
            resolved.append(
                {
                    "url": raw_url,
                    "final_url": raw_url,
                    "final_hostname": parsed.hostname,
                    "final_registered_domain": "sng.link",
                    "redirect_chain": [],
                    "redirect_count": 0,
                    "shortener_count": 0,
                    "uses_shortener": False,
                    "detected_soft_redirects": [],
                    "domain_age_days": 2668,
                    "domain_created_date": "2019-02-11",
                    "has_mx_records": True,
                    "success": False,
                }
            )
        return resolved

    client = TestClient(app_main.app)

    with monkeypatch.context() as patched:
        patched.setattr(app_main, "_safe_scan_url_list", fake_safe_scan)
        patched.setattr(app_main, "_gather_external_intel_safe", _clean_external_intel_for_resolved_urls)
        response = client.post("/v1/extract/email", data={"html_content": html})

    assert response.status_code == 200
    payload = response.json()
    assert payload["inferred_brand_hints"] == ["Uber"]
    assert "risk_level" not in payload
    assert "claimed_brand" not in payload


def test_plain_benign_external_url_is_not_suspicious_by_itself():
    engine = ScamAtlasEngine()
    urls = [{
        "url": "https://example.com/",
        "final_url": "https://example.com/",
        "final_hostname": "example.com",
        "final_registered_domain": "example.com",
        "domain_age_days": 10000,
        "has_mx_records": True,
        "success": True,
    }]

    result = engine.analyze("Link: https://example.com/", urls)

    assert result["risk_level"] == "low"
    assert result["risk_score"] < 25
    assert not any("linkuri externe" in reason.lower() for reason in result["reasons"])


def test_short_name_typosquatting_only_when_brand_claimed():
    engine = ScamAtlasEngine()

    message = "Te rugăm să verifici factura."
    urls = [{
        "url": "https://bnr.ro/facturi",
        "final_url": "https://bnr.ro/facturi",
        "final_hostname": "bnr.ro",
        "final_registered_domain": "bnr.ro",
    }]
    no_claim_result = engine.analyze(message, urls)
    assert not any("typosquatting" in reason.lower() for reason in no_claim_result["reasons"])
    assert no_claim_result["risk_level"] == "low"

    message_with_claim = "Contul tău BCR necesită actualizare de securitate."
    with_claim_result = engine.analyze(message_with_claim, urls)
    assert any("typosquatting" in reason.lower() for reason in with_claim_result["reasons"])


def test_provider_gate_uses_infrastructure_signals_for_lookalike_domain():
    analysis = {
        "claimed_brand": "BCR",
        "risk_level": "high",
        "risk_score": 84,
        "detected_family": "Imitare brand",
        "reasons": [
            "Detecție Typosquatting: Domeniul 'bcr-login-secure.example' este extrem de similar cu brandul oficial 'BCR'",
            "Solicitare date sensibile (card, CVC, PIN, cod de securitate)",
        ],
        "evidence": {
            "has_domain_mismatch": True,
            "url_lexical": {
                "penalty": 50,
                "has_signal": True,
                "reasons": [
                    "Detecție Typosquatting: Domeniul 'bcr-login-secure.example' este extrem de similar cu brandul oficial 'BCR'",
                ],
            },
            "extracted_urls": [
                {
                    "url": "https://bcr-login-secure.example/card",
                    "final_url": "https://bcr-login-secure.example/card",
                    "hostname": "bcr-login-secure.example",
                    "final_hostname": "bcr-login-secure.example",
                    "registered_domain": "bcr-login-secure.example",
                    "final_registered_domain": "bcr-login-secure.example",
                    "domain_age_days": 4,
                }
            ],
            "external_intel_summary": {
                "google_web_risk": {"status": "clean", "verdict": "clean", "consulted": True},
                "urlscan": {"status": "clean", "verdict": "clean", "consulted": True},
            },
        },
    }
    resolved_urls = analysis["evidence"]["extracted_urls"]

    result = _apply_provider_gate_verdict(analysis, resolved_urls)
    summary = result["evidence"]["external_intel_summary"]

    assert result["risk_level"] == "high"
    assert result["detected_family_id"] in {
        "provider-gate-lookalike-domain",
        "provider-gate-decisive-structural-danger",
    }
    assert "sigurscan_lexical" in summary
    assert "infra_domain_age" in summary


def test_feedback_summary_infers_labels():
    print("Testing feedback summary auto label inference...")
    records = [
        {
            "scan_id": "s1",
            "feedback": "false_positive",
            "predicted_is_scam": True,
            "signal_ids": ["email_domain_mismatch", "family:test"],
            "timestamp": 1710000000,
        },
        {
            "scan_id": "s2",
            "feedback": "correct",
            "predicted_is_scam": False,
            "signal_ids": ["family:test"],
            "timestamp": 1710000000,
        },
        {
            "scan_id": "s3",
            "feedback": "false_negative",
            "predicted_is_scam": False,
            "signal_ids": ["external_url_reputation"],
            "timestamp": 1710000000,
        },
    ]
    summary = summarize_feedback_records(records)
    confusion = summary["confusion_matrix"]
    assert confusion["fp"] == 1
    assert confusion["tn"] == 1
    assert confusion["fn"] == 1
    fp_by_signal = summary["false_positive_by_signal"]
    assert any(item["signal"] == "email_domain_mismatch" for item in fp_by_signal)
    print("  - Feedback summary inference: PASS\n")


def test_feedback_summary_signal_performance():
    print("Testing feedback signal performance matrix...")
    records = [
        {
            "scan_id": "s1",
            "feedback": "correct",
            "actual_is_scam": True,
            "predicted_is_scam": True,
            "signal_ids": ["email_auth", "external_url_reputation"],
            "timestamp": 1710000001,
        },
        {
            "scan_id": "s2",
            "feedback": "false_positive",
            "actual_is_scam": False,
            "predicted_is_scam": True,
            "signal_ids": ["email_auth"],
            "timestamp": 1710000001,
        },
        {
            "scan_id": "s3",
            "feedback": "correct",
            "actual_is_scam": False,
            "predicted_is_scam": False,
            "signal_ids": ["url_transport"],
            "timestamp": 1710000001,
        },
    ]
    summary = summarize_feedback_records(records)
    perf = summary["signal_feedback_performance"]
    email_auth = next(item for item in perf if item["signal"] == "email_auth")
    external = next(item for item in perf if item["signal"] == "external_url_reputation")
    transport = next(item for item in perf if item["signal"] == "url_transport")
    assert email_auth["tp"] == 1
    assert email_auth["fp"] == 1
    assert email_auth["feedback_error_rate"] == 0.5
    assert external["tp"] == 1
    assert external["precision"] == 1.0
    assert transport["tn"] == 1
    print("  - Feedback signal performance: PASS\n")


def test_feedback_trend_highlights_signal_drift():
    rows = [
        {
            "scan_id": "sig1",
            "feedback": "false_positive",
            "predicted_is_scam": True,
            "actual_is_scam": False,
            "signal_ids": ["email_auth"],
            "timestamp": 1700000000,
            "risk_level": "critical",
        },
        {
            "scan_id": "sig2",
            "feedback": "correct",
            "predicted_is_scam": False,
            "actual_is_scam": False,
            "signal_ids": ["email_auth"],
            "timestamp": 1700003600,
            "risk_level": "low",
        },
        {
            "scan_id": "sig3",
            "feedback": "correct",
            "predicted_is_scam": True,
            "actual_is_scam": True,
            "signal_ids": ["email_auth"],
            "timestamp": 1700086400,
            "risk_level": "critical",
        },
        {
            "scan_id": "sig4",
            "feedback": "false_negative",
            "predicted_is_scam": False,
            "actual_is_scam": True,
            "signal_ids": ["url_reputation"],
            "timestamp": 1700086800,
            "risk_level": "low",
        },
        {
            "scan_id": "sig5",
            "feedback": "false_negative",
            "predicted_is_scam": False,
            "actual_is_scam": True,
            "signal_ids": ["email_auth", "url_reputation"],
            "timestamp": 1700173000,
            "risk_level": "low",
        },
    ]

    trend = summarize_feedback_trend(
        rows,
        bucket_size_days=1,
        include_uncertain=False,
        min_bucket_support=1,
        top_signals=5,
        min_signal_support=1,
    )
    assert trend["bucket_count"] == 3
    assert trend["items_evaluated"] == 5
    assert any(item["signal"] == "email_auth" for item in trend["signal_trends"])
    auth_signal = next(item for item in trend["signal_trends"] if item["signal"] == "email_auth")
    assert auth_signal["support"] == 4
    assert isinstance(auth_signal["drift_score"], float)


def test_evaluation_readiness_payload(monkeypatch):
    monkeypatch.setattr(
        app_main,
        "load_feedback_records",
        lambda: [
            {
                "scan_id": "r1",
                "feedback": "correct",
                "predicted_is_scam": True,
                "actual_is_scam": True,
                "signal_ids": ["email_auth"],
                "timestamp": 1710000000,
                "risk_level": "high",
            },
            {
                "scan_id": "r2",
                "feedback": "false_positive",
                "predicted_is_scam": True,
                "actual_is_scam": False,
                "signal_ids": ["email_auth", "url_reputation"],
                "timestamp": 1710000100,
                "risk_level": "critical",
            },
            {
                "scan_id": "r3",
                "feedback": "correct",
                "predicted_is_scam": False,
                "actual_is_scam": False,
                "signal_ids": ["url_reputation"],
                "timestamp": 1710086400,
                "risk_level": "low",
            },
        ],
    )
    monkeypatch.setattr(
        app_main,
        "load_scan_records",
        lambda: [
            {
                "scan_id": "r1",
                "risk_score": 80,
                "risk_level": "high",
                "predicted_is_scam": True,
                "signal_ids": ["email_auth"],
                "source_channel": "text",
            },
            {
                "scan_id": "r2",
                "risk_score": 85,
                "risk_level": "critical",
                "predicted_is_scam": True,
                "signal_ids": ["email_auth", "url_reputation"],
                "source_channel": "text",
            },
            {
                "scan_id": "r3",
                "risk_score": 20,
                "risk_level": "low",
                "predicted_is_scam": False,
                "signal_ids": ["url_reputation"],
                "source_channel": "text",
            },
        ],
    )
    monkeypatch.setattr(
        app_main,
        "get_reputation_cache_stats",
        lambda: {
            "enabled": True,
            "ttl_seconds": 43200,
            "items": 10,
            "valid_items": 8,
            "provider_errors": {"google_web_risk": 0, "virustotal": 1},
            "source_stats": {
                "google_web_risk": {"entries": 10, "consulted": 10},
                "virustotal": {"entries": 10, "consulted": 10},
                "urlhaus": {"entries": 10, "consulted": 10},
            },
        },
    )

    result = app_main.evaluation_readiness(
        source_channel="text",
        bucket_size_days=1,
        trend_top_signals=5,
        trend_min_bucket_support=1,
        trend_min_signal_support=1,
    )
    assert result["status"] in {"healthy", "watch", "degraded"}
    assert result["feedback"]["items"] == 3
    assert result["feedback"]["confusion_matrix"]["tp"] == 1
    assert result["reputation"]["enabled"] is True
    assert result["trend"]["bucket_count"] >= 1


def test_health_reports_provider_config_without_secrets(monkeypatch):
    with monkeypatch.context() as patched:
        patched.setenv("MISTRAL_API_KEY", "super-secret-mistral")
        patched.setenv("GEMINI_API_KEY", "super-secret-gemini")
        patched.setenv("GOOGLE_WEB_RISK_API_KEY", "super-secret-webrisk")
        patched.setenv("VIRUSTOTAL_API_KEY", "super-secret-vt")
        patched.setattr(app_main, "URLSCAN_API_KEY", "super-secret-urlscan")
        patched.setattr(app_main, "PRIVACY_SAFE_MODE", False)
        payload = app_main.read_health()

    serialized = json.dumps(payload)
    assert payload["config"]["providers"]["urlscan"]["configured"] is True
    assert payload["config"]["providers"]["google_web_risk"]["configured"] is True
    assert payload["config"]["providers"]["virustotal"]["configured"] is True
    assert payload["config"]["providers"]["ai_explanation"]["configured"] is True
    assert "super-secret" not in serialized


def test_google_web_risk_does_not_use_safe_browsing_key(monkeypatch):
    with monkeypatch.context() as patched:
        patched.delenv("GOOGLE_WEB_RISK_API_KEY", raising=False)
        patched.delenv("GOOGLE_API_KEY", raising=False)
        patched.setenv("GOOGLE_SAFE_BROWSING_API_KEY", "legacy-safe-browsing-key")
        assert google_web_risk.has_web_risk_key() is False
        assert google_web_risk._web_risk_api_key() == ""


def test_health_does_not_report_google_api_key_as_web_risk_configured(monkeypatch):
    with monkeypatch.context() as patched:
        patched.delenv("GOOGLE_WEB_RISK_API_KEY", raising=False)
        patched.setenv("GOOGLE_API_KEY", "generic-google-key")
        patched.setattr(app_main, "PRIVACY_SAFE_MODE", False)
        payload = app_main.read_health()

    assert payload["config"]["providers"]["google_web_risk"]["configured"] is False


def test_evidence_bundle_is_stable_and_privacy_safe():
    analysis = {
        "risk_level": "low",
        "risk_score": 10,
        "detected_family": "Destinatie oficiala verificata",
        "detected_family_id": "provider-gate-official-clean",
        "claimed_brand": "YOXO",
        "reasons": ["Linkul ajunge pe o destinatie validata."],
        "evidence": {
            "has_domain_mismatch": False,
            "external_intel_summary": {
                "google_web_risk": {"status": "clean", "verdict": "no_match", "consulted": True},
                "virustotal": {"status": "clean", "verdict": "clean", "consulted": True},
            },
            "provider_gate": {
                "official_destination": True,
                "direct_sensitive_request": False,
                "sensitive_url_path": False,
            },
        },
    }
    resolved_urls = [
        {
            "original_url": "https://yoxo.onelink.me/f8ly/ijiwsfwu",
            "final_url": "https://apps.apple.com/us/app/yoxo-voce-internet-roaming/id1481946568",
            "final_hostname": "apps.apple.com",
            "final_registered_domain": "apple.com",
            "redirect_count": 2,
            "success": True,
        }
    ]
    scan_payload = {"risk_level": "low", "risk_score": 10, "user_risk_label": "SIGUR"}

    first = build_evidence_bundle(
        input_type="text",
        redacted_text="Factura pentru [PHONE_REDACTED] este disponibilă.",
        analysis=analysis,
        resolved_urls=resolved_urls,
        scan_payload=scan_payload,
    )
    second = build_evidence_bundle(
        input_type="text",
        redacted_text="Factura pentru [PHONE_REDACTED] este disponibilă.",
        analysis=analysis,
        resolved_urls=resolved_urls,
        scan_payload=scan_payload,
    )

    assert first["evidence_hash"] == second["evidence_hash"]
    assert first["urls"][0]["is_known_deeplink_provider"] is True
    assert first["urls"][0]["subdomain_matches_brand"] == "YOXO"
    assert "0755287867" not in json.dumps(first, ensure_ascii=False)


def test_adjudication_validator_rejects_invented_danger():
    evidence = {
        "providers": {"google_web_risk": {"status": "clean"}, "virustotal": {"status": "clean"}},
        "brand": {"official_destination": True, "mismatch": False},
        "text_signals": {"direct_sensitive_request": False, "sensitive_url_path": False},
        "urls": [{"final_registered_domain": "apple.com"}],
        "gate": {"detected_family_id": "provider-gate-official-clean"},
    }
    llm = {
        "label": "PERICULOS",
        "confidence": 0.91,
        "motiv_ro": "Pare periculos.",
        "evidence_used": ["providers.google_web_risk", "brand.official_destination"],
    }

    assert validate_and_guard(llm, evidence) is None


def test_adjudication_validator_enforces_hard_provider_floor():
    evidence = {
        "providers": {"urlscan": {"status": "malicious", "verdict": "phishing"}},
        "brand": {"official_destination": False, "mismatch": True},
        "text_signals": {"direct_sensitive_request": False},
        "urls": [{"final_registered_domain": "fraud.test"}],
        "gate": {"detected_family_id": "provider-gate-bad-provider"},
    }
    llm = {
        "label": "SIGUR",
        "confidence": 0.7,
        "motiv_ro": "Pare ok.",
        "evidence_used": ["providers.urlscan"],
    }

    guarded = validate_and_guard(llm, evidence)
    assert guarded is not None
    assert guarded["label"] == "PERICULOS"


def test_shadow_adjudicator_only_targets_ambiguous_cases():
    safe = {"gate": {"user_risk_label": "SIGUR", "detected_family_id": "provider-gate-official-clean"}}
    dangerous = {"gate": {"user_risk_label": "PERICULOS", "detected_family_id": "provider-gate-bad-provider"}}
    suspect = {"gate": {"user_risk_label": "SUSPECT", "detected_family_id": "provider-gate-unofficial-inconclusive"}}

    assert is_ambiguous(safe) is False
    assert is_ambiguous(dangerous) is False
    assert is_ambiguous(suspect) is True


def test_threshold_sweep_finds_best():
    print("Testing threshold sweep calibration...")
    sweep = run_threshold_sweep(
        dataset_path=Path("data/eval_dataset.jsonl"),
        disable_redirects=True,
        disable_reputation=True,
        sweep_start=0,
        sweep_end=100,
        sweep_step=25,
        optimize_metric="f1",
        max_rows=8,
    )
    assert sweep["best"]["risk_threshold"] in {25, 50}
    assert len(sweep["candidates"]) >= 5
    print(
        f"  - Threshold sweep best: t={sweep['best']['risk_threshold']} "
        f"F1={sweep['best']['f1']:.3f}: PASS\n"
    )


def test_feedback_evaluation_rows_from_logs():
    print("Testing feedback-driven evaluation dataset build + sweep...")
    feedback = [
        {
            "scan_id": "fb1",
            "feedback": "false_positive",
            "timestamp": 1700000000,
            "predicted_risk_score": 85,
            "risk_level": "critical",
            "signal_ids": ["email_auth", "url"],
        },
        {
            "scan_id": "fb2",
            "feedback": "false_negative",
            "timestamp": 1700000010,
            "predicted_risk_score": 20,
            "risk_level": "low",
            "signal_ids": ["url_transport"],
        },
        {
            "scan_id": "fb3",
            "feedback": "correct",
            "timestamp": 1700000020,
            "predicted_risk_score": 10,
            "actual_is_scam": False,
            "risk_level": "low",
            "signal_ids": ["email_action_reject"],
        },
    ]
    scans = [
        {
            "scan_id": "fb1",
            "risk_score": 85,
            "risk_level": "critical",
            "predicted_is_scam": True,
            "signal_ids": ["email_auth", "url"],
            "source_channel": "text",
            "timestamp": 1700000000,
        },
        {
            "scan_id": "fb1",
            "event_type": "orchestrated_poll",
            "risk_score": 0,
            "risk_level": None,
            "predicted_is_scam": False,
            "signal_ids": [],
            "source_channel": "text",
            "timestamp": 1700000099,
        },
        {
            "scan_id": "fb2",
            "risk_score": 20,
            "risk_level": "low",
            "predicted_is_scam": False,
            "signal_ids": ["url_transport"],
            "source_channel": "text",
            "timestamp": 1700000010,
        },
        {
            "scan_id": "fb3",
            "risk_score": 10,
            "risk_level": "low",
            "predicted_is_scam": False,
            "signal_ids": ["email_action_reject"],
            "source_channel": "text",
            "timestamp": 1700000020,
        },
    ]

    rows = build_feedback_evaluation_rows(
        feedback,
        scans,
        fallback_threshold=50,
        include_uncertain=False,
        dedupe_latest_per_scan=True,
    )
    assert len(rows) == 3
    assert rows[0]["actual_is_scam"] is False
    assert rows[0]["scan_context"]["risk_score"] == 85
    assert rows[1]["actual_is_scam"] is True
    assert rows[2]["actual_is_scam"] is False

    quality = run_feedback_threshold_sweep(
        rows,
        sweep_start=0,
        sweep_end=100,
        sweep_step=25,
        optimize_metric="f1",
    )
    assert quality["items_evaluated"] == 3
    assert len(quality["candidates"]) >= 5
    print("  - Feedback-driven quality sweep: PASS\n")

def test_domain_info():
    print("Testing Domain Info Extractor...")
    hostname, reg_domain = get_domain_info("https://subdomain.fancourier.ro/some/path?param=1")
    assert hostname == "subdomain.fancourier.ro"
    assert reg_domain == "fancourier.ro"
    
    hostname, reg_domain = get_domain_info("https://revolut-security.net/verify")
    assert hostname == "revolut-security.net"
    assert reg_domain == "revolut-security.net"
    print("Domain Info Extractor Tests: ALL PASS\n")


def test_known_shortener_detection():
    """Tests that our shortener database correctly identifies known services."""
    print("Testing Known Shortener Detection...")

    # Known shorteners should be detected
    assert is_known_shortener("https://bit.ly/3xAbCdE") is True
    assert is_known_shortener("https://tinyurl.com/y12345") is True
    assert is_known_shortener("https://t.ly/abc") is True
    assert is_known_shortener("https://cutt.ly/short") is True
    assert is_known_shortener("https://rb.gy/abc") is True
    assert is_known_shortener("https://clck.ru/foo") is True
    print("  - Known shorteners detected: PASS")

    # Official domains should NOT be flagged as shorteners
    assert is_known_shortener("https://fancourier.ro/awb") is False
    assert is_known_shortener("https://anaf.ro/spv") is False
    assert is_known_shortener("https://revolut.com/app") is False
    assert is_known_shortener("https://emag.ro/product") is False
    print("  - Official domains NOT flagged: PASS")

    # Verify the database has adequate coverage
    assert len(KNOWN_SHORTENERS) >= 25, f"Expected >=25 shorteners, got {len(KNOWN_SHORTENERS)}"
    print(f"  - Shortener database size: {len(KNOWN_SHORTENERS)} entries: PASS")

    print("Known Shortener Detection Tests: ALL PASS\n")


def test_ssrf_guard_in_redirect_resolver():
    """Tests that clearly private/internal targets are blocked before network fetch."""
    print("Testing redirect resolver SSRF guard...")

    assert _is_scan_target_blocked("http://127.0.0.1/login") is not None
    assert _is_scan_target_blocked("http://localhost/") is not None
    assert _is_scan_target_blocked("ftp://example.com") is not None
    assert _is_scan_target_blocked("https://fancourier.ro") is None

    print("  - Redirect resolver SSRF guard: PASS\n")


def test_redirect_resolver_follows_shortener_to_large_pdf_without_library_redirect_error(monkeypatch):
    """Short links must expose the final URL so urlscan can scan the real destination."""
    class FakeResponse:
        def __init__(self, status_code, headers):
            self.status_code = status_code
            self.headers = headers

        def close(self):
            return None

    class FakeSession:
        def __init__(self):
            self.max_redirects = None

        def get(self, url, headers, timeout, allow_redirects, stream, verify):
            assert allow_redirects is False
            if self.max_redirects == 0:
                raise redirect_resolver.requests.exceptions.TooManyRedirects()
            if url == "https://bit.ly/4qt0UnU":
                return FakeResponse(
                    301,
                    {"Location": "https://www.helpnet.ro/data/images/_orig/6/3_55726.pdf"},
                )
            if url == "https://www.helpnet.ro/data/images/_orig/6/3_55726.pdf":
                return FakeResponse(
                    200,
                    {"Content-Type": "application/pdf", "Content-Length": "6016873"},
                )
            raise AssertionError(f"Unexpected URL {url}")

    monkeypatch.setattr(redirect_resolver.requests, "Session", FakeSession)
    monkeypatch.setattr(redirect_resolver, "check_domain_age", lambda domain: (None, None))
    monkeypatch.setattr(redirect_resolver, "check_mx_records", lambda domain: None)

    result = resolve_redirects_safely("https://bit.ly/4qt0UnU", max_redirects=20)

    assert result["success"] is True
    assert result["error_message"] is None
    assert result["final_url"] == "https://www.helpnet.ro/data/images/_orig/6/3_55726.pdf"
    assert result["redirect_count"] == 1
    assert result["uses_shortener"] is True
    assert result["redirect_chain"][-1]["body_scan_skipped_reason"].startswith("Content length too large")


def test_meta_refresh_detection():
    """Tests meta-refresh redirect extraction from HTML snippets."""
    print("Testing Meta-Refresh Redirect Detection...")

    # Standard meta-refresh
    html = '<html><head><meta http-equiv="refresh" content="0; url=https://phishing.ru/steal"></head></html>'
    target = _extract_soft_redirect(html, "https://bit.ly/abc")
    assert target == "https://phishing.ru/steal"
    print("  - Standard meta-refresh: PASS")

    # Meta-refresh with single quotes
    html = "<meta http-equiv='refresh' content='3; url=https://evil.top/login'>"
    target = _extract_soft_redirect(html, "https://example.com")
    assert target == "https://evil.top/login"
    print("  - Meta-refresh single quotes: PASS")

    # No redirect in normal HTML
    html = '<html><head><title>FAN Courier</title></head><body><p>AWB valid</p></body></html>'
    target = _extract_soft_redirect(html, "https://fancourier.ro")
    assert target is None
    print("  - Clean HTML (no redirect): PASS")

    print("Meta-Refresh Detection Tests: ALL PASS\n")


def test_js_redirect_detection():
    """Tests JavaScript redirect extraction from HTML snippets."""
    print("Testing JS Redirect Detection (regex, no execution)...")

    # window.location.href
    html = '<script>window.location.href = "https://anaf-fals.xyz/login";</script>'
    target = _extract_soft_redirect(html, "https://shortener.com/x")
    assert target == "https://anaf-fals.xyz/login"
    print("  - window.location.href: PASS")

    # location.replace
    html = '<script>location.replace("https://posta-romana-taxe.top/pay");</script>'
    target = _extract_soft_redirect(html, "https://t.ly/abc")
    assert target == "https://posta-romana-taxe.top/pay"
    print("  - location.replace: PASS")

    # document.location
    html = "<script>document.location = 'https://revolut-verify.online/auth';</script>"
    target = _extract_soft_redirect(html, "https://cutt.ly/xyz")
    assert target == "https://revolut-verify.online/auth"
    print("  - document.location: PASS")

    # window.open
    html = '<script>window.open("https://olx-plata.site/card");</script>'
    target = _extract_soft_redirect(html, "https://bit.ly/abc")
    assert target == "https://olx-plata.site/card"
    print("  - window.open: PASS")

    # No JS redirect (clean page)
    html = '<script>console.log("Hello");</script><p>Normal page</p>'
    target = _extract_soft_redirect(html, "https://example.com")
    assert target is None
    print("  - Clean JS (no redirect): PASS")

    print("JS Redirect Detection Tests: ALL PASS\n")


def test_multi_shortener_scoring():
    """Tests that multi-shortener chains receive higher risk scores."""
    print("Testing Multi-Shortener Chain Scoring...")
    engine = ScamAtlasEngine()

    # Scenario: FAN Courier scam routed through 2 shorteners → phishing domain
    message = "FAN Courier: Coletul tau nu a fost livrat. Reprogrameaza: https://bit.ly/3xFake"
    urls = [{
        "original_url": "https://bit.ly/3xFake",
        "final_url": "https://fan-locker-ridicare.ru/awb",
        "final_hostname": "fan-locker-ridicare.ru",
        "final_registered_domain": "fan-locker-ridicare.ru",
        "redirect_count": 3,
        "shortener_count": 2,
        "uses_shortener": True,
        "detected_soft_redirects": [],
        "redirect_chain": [
            {"url": "https://bit.ly/3xFake", "hostname": "bit.ly", "registered_domain": "bit.ly", "is_shortener": True, "redirect_type": "initial"},
            {"url": "https://tinyurl.com/y9abc", "hostname": "tinyurl.com", "registered_domain": "tinyurl.com", "is_shortener": True, "redirect_type": "http"},
            {"url": "https://trk.example.com/r", "hostname": "trk.example.com", "registered_domain": "example.com", "is_shortener": False, "redirect_type": "http"},
            {"url": "https://fan-locker-ridicare.ru/awb", "hostname": "fan-locker-ridicare.ru", "registered_domain": "fan-locker-ridicare.ru", "is_shortener": False, "redirect_type": "http"},
        ]
    }]

    result = engine.analyze(message, urls)
    assert result["risk_score"] >= 75, f"Expected >=75 for multi-shortener chain, got {result['risk_score']}"
    assert result["risk_level"] == "critical"
    has_chain_reason = any("lanț" in r.lower() and "scurtătoare" in r.lower() for r in result["reasons"])
    assert has_chain_reason, f"Expected multi-shortener reason, got: {result['reasons']}"
    print(f"  - Multi-shortener chain → score={result['risk_score']}, level={result['risk_level']}: PASS")

    # Scenario: Single shortener (should score lower than multi)
    message2 = "FAN: Coletul tau e la locker: https://bit.ly/3xSingle"
    urls2 = [{
        "original_url": "https://bit.ly/3xSingle",
        "final_url": "https://fan-locker.ru/awb",
        "final_hostname": "fan-locker.ru",
        "final_registered_domain": "fan-locker.ru",
        "redirect_count": 1,
        "shortener_count": 1,
        "uses_shortener": True,
        "detected_soft_redirects": [],
        "redirect_chain": [
            {"url": "https://bit.ly/3xSingle", "hostname": "bit.ly", "registered_domain": "bit.ly", "is_shortener": True, "redirect_type": "initial"},
            {"url": "https://fan-locker.ru/awb", "hostname": "fan-locker.ru", "registered_domain": "fan-locker.ru", "is_shortener": False, "redirect_type": "http"},
        ]
    }]

    result2 = engine.analyze(message2, urls2)
    has_single_reason = any("link scurtat" in r.lower() for r in result2["reasons"])
    assert has_single_reason, f"Expected single shortener reason, got: {result2['reasons']}"
    assert result["risk_score"] >= result2["risk_score"], "Multi-shortener should score >= single shortener"
    print(f"  - Single shortener → score={result2['risk_score']}: PASS")
    print(f"  - Multi > Single scoring: PASS")

    print("Multi-Shortener Chain Scoring Tests: ALL PASS\n")


def test_soft_redirect_scoring():
    """Tests that meta-refresh / JS redirects increase risk score."""
    print("Testing Soft Redirect Scoring...")
    engine = ScamAtlasEngine()

    # Scenario: ANAF scam with a JS redirect detected in the chain
    message = "ANAF: Ai o datorie. Verifica: https://t.ly/anaf-fals"
    urls = [{
        "original_url": "https://t.ly/anaf-fals",
        "final_url": "https://anaf-spv-plati.info/login",
        "final_hostname": "anaf-spv-plati.info",
        "final_registered_domain": "anaf-spv-plati.info",
        "redirect_count": 2,
        "shortener_count": 1,
        "uses_shortener": True,
        "detected_soft_redirects": ["https://anaf-spv-plati.info/login"],
        "redirect_chain": [
            {"url": "https://t.ly/anaf-fals", "hostname": "t.ly", "registered_domain": "t.ly", "is_shortener": True, "redirect_type": "initial"},
            {"url": "https://intermediate.com/r", "hostname": "intermediate.com", "registered_domain": "intermediate.com", "is_shortener": False, "redirect_type": "http"},
            {"url": "https://anaf-spv-plati.info/login", "hostname": "anaf-spv-plati.info", "registered_domain": "anaf-spv-plati.info", "is_shortener": False, "redirect_type": "js_redirect"},
        ]
    }]

    result = engine.analyze(message, urls)
    has_soft_reason = any("redirecționăr" in r.lower() and ("html" in r.lower() or "javascript" in r.lower()) for r in result["reasons"])
    assert has_soft_reason, f"Expected soft redirect reason, got: {result['reasons']}"
    assert result["risk_score"] >= 50, f"Expected >=50 for soft redirect scenario, got {result['risk_score']}"
    print(f"  - Soft redirect detected → score={result['risk_score']}: PASS")

    print("Soft Redirect Scoring Tests: ALL PASS\n")


def test_scam_atlas_engine():
    print("Testing Scam Atlas Rule Engine...")
    engine = ScamAtlasEngine()
    
    # 1. Test FAN Courier Mismatch Case
    message = "FAN Courier: Coletul tau nr. 5928-RO nu poate fi livrat. Reatribuie adresa locker: https://fan-box-locker.ru/awb"
    urls = [{
        "url": "https://fan-box-locker.ru/awb",
        "final_url": "https://fan-box-locker.ru/awb",
        "final_hostname": "fan-box-locker.ru",
        "final_registered_domain": "fan-box-locker.ru"
    }]
    
    result = engine.analyze(message, urls)
    assert result["claimed_brand"] == "FAN Courier"
    assert result["evidence"]["has_domain_mismatch"] is True
    assert result["risk_score"] >= 50
    assert result["risk_level"] in ("high", "critical")
    assert any("mismatch" in r.lower() or "neoficial" in r.lower() for r in result["reasons"])
    print("  - FAN Courier Mismatch: PASS")

    # 2. Test OLX Card Scam Case
    message = "Sunt de acord sa cumpar. Am platit pe OLX, intra sa primesti banii direct pe card: https://olx-ro-incasare.site"
    urls = [{
        "url": "https://olx-ro-incasare.site",
        "final_url": "https://olx-ro-incasare.site",
        "final_hostname": "olx-ro-incasare.site",
        "final_registered_domain": "olx-ro-incasare.site"
    }]
    
    result = engine.analyze(message, urls)
    assert result["claimed_brand"] == "OLX"
    assert result["risk_score"] >= 50
    assert result["risk_level"] in ("high", "critical")
    assert any("card" in r.lower() or "primire" in r.lower() for r in result["reasons"])
    print("  - OLX Card Request: PASS")

    # 3. Test Benign/Official Case
    message = "FAN Courier: AWB-ul tau este 123456789. Detalii livrare: https://fancourier.ro/awb"
    urls = [{
        "url": "https://fancourier.ro/awb",
        "final_url": "https://fancourier.ro/awb",
        "final_hostname": "fancourier.ro",
        "final_registered_domain": "fancourier.ro"
    }]
    
    result = engine.analyze(message, urls)
    assert result["claimed_brand"] == "FAN Courier"
    assert result["evidence"]["has_domain_mismatch"] is False
    assert result["risk_level"] == "low"
    print("  - Benign/Official Domain: PASS")

    print("Scam Atlas Rule Engine Tests: ALL PASS\n")


def test_backend_scam_atlas_loads_romania_knowledge_pack_registry():
    assert "Ghișeul.ro" in scam_atlas.BRAND_REGISTRY
    assert "ghiseul.ro" in scam_atlas.BRAND_REGISTRY["Ghișeul.ro"]
    assert "PPC Energie" in scam_atlas.BRAND_REGISTRY
    assert "ppcenergy.ro" in scam_atlas.BRAND_REGISTRY["PPC Energie"]
    assert "Orange / YOXO" in scam_atlas.BRAND_REGISTRY
    assert "newsroom.orange.ro" in scam_atlas.BRAND_REGISTRY["Orange / YOXO"]
    assert "Help Net" in scam_atlas.BRAND_REGISTRY
    assert "helpnet.ro" in scam_atlas.BRAND_REGISTRY["Help Net"]
    assert "ghiseul" in scam_atlas.TRUSTED_BASE_NAMES
    assert scam_atlas.TRUSTED_BASE_NAMES["ghiseul"] == "Ghișeul.ro"
    assert "helpnet" in scam_atlas.TRUSTED_BASE_NAMES
    assert scam_atlas.TRUSTED_BASE_NAMES["helpnet"] == "Help Net"

    result = ScamAtlasEngine().analyze(
        "Ghișeul.ro: mesaj informativ, intră manual pe portal pentru taxe locale.",
        [
            {
                "url": "https://ghiseul.ro",
                "final_url": "https://ghiseul.ro",
                "final_hostname": "ghiseul.ro",
                "final_registered_domain": "ghiseul.ro",
            }
        ],
    )

    assert result["claimed_brand"] == "Ghișeul.ro"
    assert result["evidence"]["has_domain_mismatch"] is False

    helpnet_result = ScamAtlasEngine().analyze(
        "La Help Net poti castiga un sejur de vis. Regulament: https://bit.ly/4qt0UnU",
        [
            {
                "url": "https://bit.ly/4qt0UnU",
                "registered_domain": "bit.ly",
                "final_url": "https://www.helpnet.ro/data/images/_orig/6/3_55726.pdf",
                "final_hostname": "www.helpnet.ro",
                "final_registered_domain": "helpnet.ro",
            }
        ],
    )

    assert helpnet_result["claimed_brand"] == "Help Net"
    assert helpnet_result["evidence"]["has_domain_mismatch"] is False


def test_scam_atlas_seed_is_loaded_from_repo_data():
    engine = ScamAtlasEngine()
    assert len(engine.families) >= 20
    assert any(family.get("id") == "RO_SCN_001_FAN_LOCKER_WHATSAPP" for family in engine.families)
    assert any("FAN Courier" in family.get("family", "") for family in engine.families)


def test_scam_atlas_seed_stays_in_sync_with_android_scenario_corpus():
    root = Path(__file__).resolve().parents[1]
    android_knowledge = json.loads(
        (root / "app" / "src" / "main" / "assets" / "knowledge" / "romania_knowledge_layer_compact.json").read_text(encoding="utf-8")
    )
    backend_seed = json.loads(
        (root / "backend" / "data" / "scam_atlas_ro_2025_2026_seed.json").read_text(encoding="utf-8")
    )

    android_ids = {entry.get("scenario_id") for entry in android_knowledge.get("scenario_corpus", [])}
    backend_ids = {entry.get("id") for entry in backend_seed.get("scam_families", [])}

    assert android_ids
    assert android_ids == backend_ids


def test_backend_brand_pack_covers_android_official_registry_domains():
    root = Path(__file__).resolve().parents[1]
    android_knowledge = json.loads(
        (root / "app" / "src" / "main" / "assets" / "knowledge" / "romania_knowledge_layer_compact.json").read_text(encoding="utf-8")
    )
    backend_pack = json.loads(
        (root / "backend" / "data" / "brand_knowledge_pack.json").read_text(encoding="utf-8")
    )

    brand_name_map = {
        "anaf": "ANAF",
        "ministerul_finantelor": "Ministerul Finanțelor",
        "bnr": "BNR",
        "dnsc": "DNSC",
        "fan_courier": "FAN Courier",
        "posta_romana": "Poșta Română",
        "sameday": "SAMEDAY",
        "cargus": "Cargus",
        "olx": "OLX România",
        "emag": "eMAG",
        "altex": "Altex",
        "revolut": "Revolut",
        "bcr": "BCR",
        "bt": "Banca Transilvania",
        "ing": "ING Bank România",
        "raiffeisen": "Raiffeisen Bank România",
        "orange_yoxo": "Orange / YOXO",
        "vodafone": "Vodafone România",
        "digi": "DIGI România",
        "hidroelectrica": "Hidroelectrica",
        "ppc": "PPC Energie",
        "eon": "E.ON România",
        "ghiseul": "Ghișeul.ro",
    }

    backend_registry = backend_pack.get("brand_registry", {})
    missing = []
    for entry in android_knowledge.get("official_registry_updates", []):
        backend_name = brand_name_map[entry["brand_id"]]
        backend_domains = {domain.lower() for domain in backend_registry.get(backend_name, [])}
        for domain in entry.get("official_domains", []):
            if domain.lower() not in backend_domains:
                missing.append(f"{backend_name}:{domain}")

    assert not missing, f"Backend brand pack is missing Android official domains: {missing}"


def test_backend_brand_pack_carries_android_runtime_claim_targets_and_warnings():
    root = Path(__file__).resolve().parents[1]
    android_knowledge = json.loads(
        (root / "app" / "src" / "main" / "assets" / "knowledge" / "romania_knowledge_layer_compact.json").read_text(encoding="utf-8")
    )
    backend_pack = json.loads(
        (root / "backend" / "data" / "brand_knowledge_pack.json").read_text(encoding="utf-8")
    )

    assert len(backend_pack.get("claim_verifier_targets", [])) == len(android_knowledge.get("claim_verifier_targets", []))
    assert len(backend_pack.get("brand_warnings", [])) == len(android_knowledge.get("brand_warnings", []))
    assert any(
        entry.get("claim_type") == "buyback YOXO"
        for entry in backend_pack.get("claim_verifier_targets", [])
    )


def test_scam_atlas_regression_false_positives():
    print("Testing Scam Atlas FP regressions (hard_eval alignment)...")
    engine = ScamAtlasEngine()

    # ANAF: domain in observed public flow, should not force automatic mismatch.
    anaf_urls = [{
        "final_url": "https://anaf-spv.info/plata",
        "url": "https://anaf-spv.info/plata",
        "final_registered_domain": "anaf-spv.info",
        "final_hostname": "anaf-spv.info",
    }]
    anaf_result = engine.analyze("ANAF: Verifica declaratia. Acceseaza plata la contul ...", anaf_urls)
    assert anaf_result["evidence"]["has_domain_mismatch"] is False
    assert "Domeniu Lookalike" not in "\n".join(anaf_result["reasons"])
    assert anaf_result["risk_score"] < 50

    # Banca Transilvania oficială pe bt.ro nu trebuie clasificată ca mismatch.
    bt_urls = [{
        "final_url": "https://bt.ro/verify?next=%2Flogin",
        "url": "https://bt.ro/verify?next=%2Flogin",
        "final_registered_domain": "bt.ro",
        "final_hostname": "bt.ro",
        "final_path": "/verify",
    }]
    bt_result = engine.analyze(
        "Banca Transilvania: Actualizare card - accesati https://bt.ro/verify?next=/login",
        bt_urls,
    )
    assert bt_result["evidence"]["has_domain_mismatch"] is False

    # Generic “acces” without clear payment threat should not trigger sextortion signal.
    generic_urls = [{
        "final_url": "https://security-check.alert/login",
        "url": "https://security-check.alert/login",
        "final_registered_domain": "security-check.alert",
        "final_hostname": "security-check.alert",
    }]
    generic_result = engine.analyze(
        "Verifica: ai o alerta de acces. Deschide https://security-check.alert/login",
        generic_urls,
    )
    assert not any("Semnal de șantaj digital" in reason for reason in generic_result["reasons"])

    print("Scam Atlas FP regressions: ALL PASS\n")


def test_advanced_scam_detection_modules():
    print("Testing Advanced Scam Detection Modules...")
    engine = ScamAtlasEngine()

    # 1. Levenshtein & Typosquatting
    assert engine.levenshtein_distance("revolut", "revolut") == 0
    assert engine.levenshtein_distance("revolut", "revolutt") == 1
    assert engine.levenshtein_distance("revolut", "revlout") == 2
    print("  - Levenshtein Distance Calculation: PASS")

    # Typosquatting detection test
    urls_typo = [{
        "url": "https://revolutt.ro",
        "final_url": "https://revolutt.ro",
        "final_hostname": "revolutt.ro",
        "final_registered_domain": "revolutt.ro"
    }]
    penalty, reasons = engine.check_typosquatting_and_lexical(urls_typo)
    assert penalty == 40
    assert any("typosquatting" in r.lower() for r in reasons)
    print("  - Typosquatting (revolutt.ro): PASS")

    # Lookalike (trusted base is a substring)
    urls_lookalike = [{
        "url": "https://revolut-romania.com",
        "final_url": "https://revolut-romania.com",
        "final_hostname": "revolut-romania.com",
        "final_registered_domain": "revolut-romania.com"
    }]
    penalty, reasons = engine.check_typosquatting_and_lexical(urls_lookalike)
    assert penalty == 35
    assert any("lookalike" in r.lower() for r in reasons)
    print("  - Lookalike (revolut-romania.com): PASS")

    # 2. Punycode IDN Detection
    urls_puny = [{
        "url": "https://xn--revolt-g1a.com",
        "final_url": "https://xn--revolt-g1a.com",
        "final_hostname": "xn--revolt-g1a.com",
        "final_registered_domain": "xn--revolt-g1a.com"
    }]
    penalty, reasons = engine.check_typosquatting_and_lexical(urls_puny)
    assert penalty >= 25
    assert any("punycode" in r.lower() for r in reasons)
    print("  - Punycode IDN (xn--revolt-g1a.com): PASS")

    # 3. Shannon Entropy
    entropy_clean = engine.calculate_entropy("emag")
    entropy_dga = engine.calculate_entropy("a8d2j4k9rux1z2y3")
    assert entropy_dga > entropy_clean
    
    # Entropy check threshold
    urls_dga = [{
        "url": "https://a8d2j4k9rux1z2y3.com",
        "final_url": "https://a8d2j4k9rux1z2y3.com",
        "final_hostname": "a8d2j4k9rux1z2y3.com",
        "final_registered_domain": "a8d2j4k9rux1z2y3.com"
    }]
    penalty, reasons = engine.check_typosquatting_and_lexical(urls_dga)
    assert penalty >= 15
    assert any("entropie" in r.lower() for r in reasons)
    print("  - Shannon Entropy (a8d2j4k9rux1z2y3.com): PASS")

    # 4. Domain Age (RDAP & Socket WHOIS)
    # Check .ro domain (google.ro) via ROTLD WHOIS
    age_days, created_date = check_domain_age("google.ro")
    assert age_days is not None and age_days > 365 * 20
    assert created_date == "2000-07-17"
    print("  - ROTLD Socket WHOIS (google.ro): PASS")

    # Check non-existent .ro domain returns None
    age_days_nx, created_date_nx = check_domain_age("nonexistent-domain-123456789.ro")
    assert age_days_nx is None
    print("  - ROTLD Socket WHOIS Unregistered Fallback: PASS")

    # Check .com domain (google.com) via RDAP
    age_days_com, created_date_com = check_domain_age("google.com")
    assert age_days_com is not None and age_days_com > 365 * 20
    assert created_date_com == "1997-09-15"
    print("  - RDAP Check (google.com): PASS")

    # 5. Cloudflare DoH MX Records
    has_mx_gmail = check_mx_records("gmail.com")
    assert has_mx_gmail is True
    print("  - Cloudflare DoH MX (gmail.com has MX): PASS")

    has_mx_nx = check_mx_records("non-existent-domain-123456789.xyz")
    assert has_mx_nx is False
    print("  - Cloudflare DoH MX (nxdomain has no MX): PASS")

    print("Advanced Scam Detection Modules Tests: ALL PASS\n")


def test_supabase_store_requires_server_only_credentials():
    source = (Path(__file__).resolve().parent / "services" / "supabase_store.py").read_text()

    assert "SUPABASE_SERVICE_ROLE_KEY" in source
    assert "SUPABASE_ANON_KEY" not in source
    assert "hslqboubacrdhatmqcky.supabase.co" not in source
    assert "eyJhbGci" not in source


class _FakeSupabaseResponse:
    def __init__(self, data):
        self._data = data
        self.content = json.dumps(data).encode("utf-8")

    def raise_for_status(self):
        return None

    def json(self):
        return self._data


def test_supabase_scan_job_load_attaches_storage_timestamp(monkeypatch):
    with monkeypatch.context() as patched:
        patched.setattr(supabase_store, "SUPABASE_URL", "https://example.supabase.co")
        patched.setattr(supabase_store, "SUPABASE_SERVICE_ROLE_KEY", "server-only-key")
        patched.setattr(
            supabase_store.requests,
            "get",
            lambda *args, **kwargs: _FakeSupabaseResponse(
                [
                    {
                        "payload": {"scan_id": "orch_test", "status": "scanning"},
                        "updated_at": "2026-06-04T10:00:00+00:00",
                    }
                ]
            ),
        )

        job = supabase_store.load_scan_job("orch_test")

    assert job["scan_id"] == "orch_test"
    assert job["_storage_updated_at"] == "2026-06-04T10:00:00+00:00"


def test_supabase_scan_job_save_uses_optimistic_concurrency(monkeypatch):
    calls = []

    def fake_patch(*args, **kwargs):
        calls.append(kwargs)
        return _FakeSupabaseResponse([{"updated_at": "2026-06-04T10:00:01+00:00"}])

    with monkeypatch.context() as patched:
        patched.setattr(supabase_store, "SUPABASE_URL", "https://example.supabase.co")
        patched.setattr(supabase_store, "SUPABASE_SERVICE_ROLE_KEY", "server-only-key")
        patched.setattr(supabase_store.requests, "patch", fake_patch)

        job = {
            "scan_id": "orch_test",
            "status": "scanning",
            "payload_field": "value",
            "_storage_updated_at": "2026-06-04T10:00:00+00:00",
        }
        saved = supabase_store.save_scan_job(job)

    assert saved is True
    assert calls[0]["params"]["scan_id"] == "eq.orch_test"
    assert calls[0]["params"]["updated_at"] == "eq.2026-06-04T10:00:00+00:00"
    assert "_storage_updated_at" not in calls[0]["json"]["payload"]
    assert job["_storage_updated_at"] == "2026-06-04T10:00:01+00:00"


def test_supabase_scan_job_save_reports_concurrency_conflict(monkeypatch):
    with monkeypatch.context() as patched:
        patched.setattr(supabase_store, "SUPABASE_URL", "https://example.supabase.co")
        patched.setattr(supabase_store, "SUPABASE_SERVICE_ROLE_KEY", "server-only-key")
        patched.setattr(
            supabase_store.requests,
            "patch",
            lambda *args, **kwargs: _FakeSupabaseResponse([]),
        )

        saved = supabase_store.save_scan_job(
            {
                "scan_id": "orch_test",
                "status": "scanning",
                "_storage_updated_at": "2026-06-04T10:00:00+00:00",
            }
        )

    assert saved is False


def test_backend_security_defaults_are_launch_safe():
    assert app_main.ENABLE_RATE_LIMIT is True
    assert app_main.RATE_LIMIT_PER_MINUTE <= 60
    assert "*" not in app_main.ALLOWED_ORIGINS
    assert "https://nudaclick-backend.vercel.app" in app_main.ALLOWED_ORIGINS


if __name__ == "__main__":
    print("=== Running Backend Local Unit Tests ===")
    test_pii_redaction()
    test_feedback_summary_infers_labels()
    test_feedback_summary_signal_performance()
    test_threshold_sweep_finds_best()
    test_feedback_evaluation_rows_from_logs()
    test_domain_info()
    test_known_shortener_detection()
    test_meta_refresh_detection()
    test_js_redirect_detection()
    test_multi_shortener_scoring()
    test_soft_redirect_scoring()
    test_scam_atlas_engine()
    test_advanced_scam_detection_modules()
    print("=== All tests completed successfully! ===")
