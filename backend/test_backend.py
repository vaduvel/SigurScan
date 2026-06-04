import sys
import os
import json
import urllib.parse
import pytest
from fastapi.testclient import TestClient
from pathlib import Path
from bs4 import BeautifulSoup

# Add current directory to path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from services.pii_redactor import redact_pii
from services.redirect_resolver import (
    get_domain_info,
    is_known_shortener,
    _is_scan_target_blocked,
    _extract_soft_redirect,
    KNOWN_SHORTENERS,
    query_rotld_whois,
    check_domain_age,
    check_mx_records,
)
from services.scam_atlas import ScamAtlasEngine
from services.offer_claim_verifier import verify_offer_claim
from services.telemetry import (
    build_feedback_evaluation_rows,
    run_feedback_threshold_sweep,
    summarize_feedback_records,
    summarize_feedback_trend,
)
from services import scam_atlas, supabase_store, url_reputation
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
)

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

    assert result["risk_level"] == "medium"
    assert result["risk_score"] == 50
    assert result["detected_family_id"] == "provider-gate-partial-pillars"
    assert result["evidence"]["provider_gate"]["consulted_count"] == 2
    assert result["evidence"]["provider_gate"]["official_destination"] is True
    assert result["evidence"]["provider_gate"]["urlscan_consulted"] is False
    assert result["evidence"]["provider_gate"]["legacy_score_ignored"] is True


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
    assert result["evidence"]["provider_gate"]["legacy_score_ignored"] is True


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

    assert result["risk_level"] == "medium"
    assert result["detected_family_id"] == "provider-gate-official-sensitive"
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
        response, payload = _poll_orchestrated(client, start["scan_id"], count=4)

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
        response, payload = _poll_orchestrated(client, start["scan_id"], count=4)

    assert response.status_code == 200
    assert payload["status"] == "scanning"
    assert payload["pillars"]["urlscan"]["status"] == "pending"
    assert payload["result"]["user_risk_label"] == "SIGUR"
    assert payload["result"]["risk_level"] == "low"
    assert payload["result"]["is_final"] is False


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
        _, provisional = _poll_orchestrated(client, start["scan_id"], count=2)
        _, upgraded = _poll_orchestrated(client, start["scan_id"], count=2)

    assert provisional["status"] == "scanning"
    assert provisional["result"]["user_risk_label"] == "SIGUR"
    assert provisional["result"]["is_final"] is False
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
        _poll_orchestrated(client, start["scan_id"], count=3)
        app_main._ORCHESTRATED_SCAN_JOBS[start["scan_id"]]["created_at"] -= 5
        response, payload = _poll_orchestrated(client, start["scan_id"], count=1)

    assert response.status_code == 200
    assert payload["status"] == "complete"
    assert payload["pillars"]["urlscan"]["status"] == "error"
    assert "captura" in payload["pillars"]["urlscan"]["details"].lower()
    assert payload["result"]["user_risk_label"] == "SIGUR"
    assert payload["result"]["risk_level"] == "low"
    assert payload["result"]["is_final"] is True


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
        response, payload = _poll_orchestrated(client, start["scan_id"], count=3)

    assert response.status_code == 200
    assert payload["status"] == "complete"
    assert payload["pillars"]["google_web_risk"]["status"] == "ok"
    assert payload["pillars"]["virustotal"]["status"] == "ok"
    assert payload["pillars"]["urlscan"]["status"] == "error"
    assert payload["preview"]["screenshot_url"] is None
    assert payload["result"]["user_risk_label"] == "PERICULOS"
    assert payload["result"]["risk_level"] == "high"
    assert payload["result"]["detected_family_id"] == "provider-gate-decisive-structural-danger"


def test_orchestrated_hard_malicious_provider_finalizes_even_when_urlscan_rejects(monkeypatch):
    client = TestClient(app_main.app)

    with monkeypatch.context() as patched:
        patched.setattr(app_main, "PRIVACY_SAFE_MODE", False)
        patched.setattr(app_main, "ENABLE_CLOUD_AI_EXPLANATION", False)
        patched.setattr(app_main, "URLSCAN_API_KEY", "server-only-key")
        patched.setattr(app_main, "_safe_scan_url_list", _fake_google_test_phishing_scan)
        patched.setattr(app_main, "_gather_external_intel_safe", _malicious_web_risk_and_vt_for_resolved_urls)
        patched.setattr(app_main, "_enrich_offer_claim_verification_async", _fake_inconclusive_offer_claim)
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
    monkeypatch.setattr(url_reputation, "_save_cache", lambda path, data: saved_cache.append(dict(data)))
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


def test_scan_email_classifies_button_only_cta_as_risky(monkeypatch):
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
        response = client.post("/v1/scan/email", data={"html_content": html})

    assert response.status_code == 200
    payload = response.json()
    assert payload.get("risk_level") == "high"
    assert payload.get("user_risk_level") == "dangerous"
    assert any("brand" in reason.lower() or "domeniu" in reason.lower() for reason in payload.get("reasons", []))
    assert any(item.get("source_tag") == "button" and item.get("source_attr") == "onclick" for item in payload.get("buttons", []))
    assert any(item.get("original_url") == "https://phish-revolut.example/release" for item in payload.get("buttons", []))


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
        response = client.post("/v1/scan/email", data={"html_content": html})

    assert response.status_code == 200
    payload = response.json()
    assert any(item.get("original_url") == "/unlock" for item in payload.get("buttons", []))
    assert payload.get("risk_level") == "medium"
    assert any(
        "scan" in reason.lower() or "verific" in reason.lower()
        for reason in payload.get("reasons", [])
    )


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
        response = client.post("/v1/scan/email", data={"html_content": html})

    assert response.status_code == 200
    payload = response.json()
    buttons = payload.get("buttons", [])
    assert any(item.get("original_url") == "https://rev-unlock.example/reset" for item in buttons)
    assert any(item.get("is_sensitive_cta") for item in buttons)
    assert payload.get("user_risk_text") in {"Periculos", "Suspect", "Neclar", "Probabil sigur"}


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
        response = client.post("/v1/scan/email", data={"html_content": html})

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
        response = client.post("/v1/scan/email", data={"html_content": html})

    assert response.status_code == 200
    payload = response.json()
    assert payload["claimed_brand"] == "Uber"
    assert payload["risk_level"] == "low"
    assert payload["risk_score"] == 10
    assert payload["inferred_brand_hints"] == ["Uber"]
    assert not any("extensie de domeniu neobișnuită" in reason.lower() for reason in payload["reasons"])


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
    assert "ghiseul" in scam_atlas.TRUSTED_BASE_NAMES
    assert scam_atlas.TRUSTED_BASE_NAMES["ghiseul"] == "Ghișeul.ro"

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
