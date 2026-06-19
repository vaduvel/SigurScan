import urllib.parse

import pytest
from fastapi.testclient import TestClient

import main as app_main
from test_backend import (
    _clean_external_intel_for_resolved_urls,
    _fake_inconclusive_offer_claim,
    _fake_urlscan_post_rejects_domain,
    _poll_orchestrated,
)


SEVERITY_RANK = {"SAFE": 0, "UNVERIFIED": 1, "SUSPECT": 2, "DANGEROUS": 3}


def _safe_test_resolver(urls):
    resolved = []
    for raw_url in urls:
        parsed = urllib.parse.urlparse(raw_url)
        host = (parsed.hostname or "").lower()
        if not host and parsed.scheme not in {"http", "https"}:
            host = parsed.scheme
        registered_domain = ".".join(host.split(".")[-2:]) if host.count(".") else host
        resolved.append(
            {
                "url": raw_url,
                "original_url": raw_url,
                "final_url": raw_url,
                "hostname": host,
                "final_hostname": host,
                "registered_domain": registered_domain,
                "final_registered_domain": registered_domain,
                "redirect_chain": [{"url": raw_url}],
                "redirect_count": 0,
                "shortener_count": 0,
                "uses_shortener": False,
                "detected_soft_redirects": [],
                "domain_age_days": 3,
                "domain_created_date": "2026-06-13",
                "has_mx_records": False,
                "success": True,
            }
        )
    return resolved


async def _fresh_test_domain_signals(domain: str) -> dict:
    return {
        "ssl": {"valid": True, "cert_age_days": 2, "issuer_org": "Test CA"},
        "rdap": {"age_days": 3, "registered": True},
    }


RAW_EML_HIDDEN_PAYMENT_FORM = """From: Furnizor <facturi@furnizor.example>
To: client@example.com
Subject: Factura disponibila
MIME-Version: 1.0
Content-Type: text/html; charset=utf-8

<html><body>
  <p>Factura este disponibila in portalul oficial.</p>
  <p><a href="https://furnizor.example/facturi">Vezi factura</a></p>
  <form action="https://factura-reconciliere.test/plata" method="post">
    <input name="card" type="text">
    <input name="cvv" type="password">
    <button>Confirma plata</button>
  </form>
</body></html>
"""

RAW_EML_CSS_OVERLAY_PAYMENT = """From: Furnizor <facturi@furnizor.example>
To: client@example.com
Subject: Copie factura
MIME-Version: 1.0
Content-Type: text/html; charset=utf-8

<html><body>
  <p>Factura lunara este atasata ca imagine.</p>
  <div style="position:relative">
    <img alt="Factura" src="cid:invoice">
    <a href="https://factura-reconciliere.test/plata"
       style="position:absolute;inset:0;display:block;color:transparent">.</a>
  </div>
</body></html>
"""

RAW_EML_FALSE_TRAINING_LOGIN = """From: IT Security <security@example.com>
To: user@example.com
Subject: Test de securitate obligatoriu
MIME-Version: 1.0
Content-Type: text/html; charset=utf-8
Content-Transfer-Encoding: quoted-printable

<html><body>
Nu comunica parola nimanui. Pentru a demonstra ca ai inteles, autentifica-=
te o singura data in simulator: Start test -&gt;
<a href=3D"https://secure-beneficiar.test/login">Start test</a>
</body></html>
"""


NOVEL_HOLDOUT_REGRESSIONS = [
    pytest.param(
        "SMS-NOV-002",
        "text",
        "sms",
        "Operator mobil: profilul SIM va fi dezactivat. Pentru recuperare, trimite agentului captura codului QR eSIM primit in aplicatie. Nu reporni telefonul pana la confirmare.",
        "DANGEROUS",
        id="esim-qr-secret-exfiltration",
    ),
    pytest.param(
        "SMS-NOV-004",
        "text",
        "sms",
        "ANAF Digital: semnatura vocala a administratorului trebuie revalidata. Suna la numarul din mesaj si citeste codul unic afisat in aplicatia bancara pentru confirmarea identitatii.",
        "DANGEROUS",
        id="bank-app-code-via-phone-callback",
    ),
    pytest.param(
        "URL-NOV-004",
        "url",
        "url_scan",
        "Verifica acest link: https://bt.ro@secure-beneficiar.test/confirm?session=TEST",
        "DANGEROUS",
        id="userinfo-brand-spoofing-url",
    ),
    pytest.param(
        "URL-NOV-006",
        "url",
        "url_scan",
        "Verifica acest link: data:text/html;base64,PGZvcm0gYWN0aW9uPSdodHRwczovL2xvZ2luLWJ0LnRlc3QvbG9naW4nPjxpbnB1dCBuYW1lPSd1c2VyJz48aW5wdXQgbmFtZT0nb3RwJz48L2Zvcm0+",
        "DANGEROUS",
        id="data-url-login-form",
    ),
    pytest.param(
        "URL-NOV-001",
        "url",
        "url_scan",
        "Verifica acest link: https://trusted-links.example/open?_dl=bankapp%3A%2F%2Fbeneficiary-check&_fallback_redirect=https%3A%2F%2Fsecure-beneficiar.test%2Flogin",
        "DANGEROUS",
        id="trusted-wrapper-bankapp-fallback-login",
    ),
    pytest.param(
        "URL-NOV-003",
        "url",
        "url_scan",
        "Verifica acest link: https://actualizare-securitate.test/install?source=bank-alert",
        "DANGEROUS",
        id="security-update-install-link",
    ),
    pytest.param(
        "URL-NOV-005",
        "url",
        "url_scan",
        "Verifică acest link:\nhttps://click.example/route?dest=https%253A%252F%252Fportal-furnizor.example%252F&next=https%3A%2F%2Ffactura-reconciliere.test%2Fplata",
        "DANGEROUS",
        id="double-encoded-hidden-payment-redirect",
    ),
    pytest.param(
        "QR-NOV-001",
        "text",
        "qr",
        "intent://verify#Intent;scheme=bank-secure;package=com.security.update;S.browser_fallback_url=https%3A%2F%2Factualizare-securitate.test%2Finstall;end",
        "DANGEROUS",
        id="qr-intent-fallback-install",
    ),
    pytest.param(
        "QR-NOV-002",
        "text",
        "qr",
        "BCD\n002\n1\nSCT\nAGENT SECURITATE\nRO27FAKE0000000000000003\nRON1250.00\n\nProtecție cont",
        "DANGEROUS",
        id="qr-epc-safe-account-payment",
    ),
    pytest.param(
        "QR-NOV-003",
        "text",
        "qr",
        "otpauth://totp/WhatsApp:cont-test?secret=JBSWY3DPEHPK3PXP&issuer=LockerSecure",
        "DANGEROUS",
        id="qr-totp-account-takeover",
    ),
    pytest.param(
        "QR-NOV-005",
        "text",
        "qr",
        "mailto:validari@identitate-fiscala.test?subject=Confirmare&body=CUI%3D00000000%26IBAN%3DRO08TEST0000000000000001",
        "DANGEROUS",
        id="qr-prefilled-sensitive-email",
    ),
    pytest.param(
        "QR-NOV-006",
        "url",
        "qr",
        "https://portal-furnizor.example/confirm#next=https://secure-beneficiar.test/login",
        "DANGEROUS",
        id="qr-fragment-hidden-login-target",
    ),
    pytest.param(
        "QR-NOV-004",
        "text",
        "qr",
        "WIFI:T:WPA;S:Parcare_Oficiala;P:PlataAcum2026;;",
        "DANGEROUS",
        id="qr-wifi-captive-payment-pretext",
    ),
    pytest.param(
        "OCR-NOV-006",
        "text",
        "ocr_image",
        "Portal oficial furnizor\nScanează pentru plata rapidă a facturii\nAfiș actualizat pentru 2026\nhttps://qr-plata.test/confirm",
        "DANGEROUS",
        id="official-poster-payment-qr-overlay",
    ),
    pytest.param(
        "EML-NOV-006",
        "email",
        "email",
        "Nu comunica parola nimanui. Pentru a demonstra ca ai inteles, autentifica-te o singura data in simulator: https://training-secure.test/login",
        "DANGEROUS",
        id="safety-education-used-as-login-pretext",
    ),
    pytest.param(
        "EML-NOV-005",
        "email",
        "email",
        'Vezi soldul <svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink"><a xlink:href="https://secure-beneficiar.test/confirm"><text>Vezi soldul</text></a></svg>',
        "DANGEROUS",
        id="svg-xlink-hidden-payment-cta",
    ),
    pytest.param(
        "EML-NOV-002-RAW",
        "email",
        "email",
        RAW_EML_HIDDEN_PAYMENT_FORM,
        "DANGEROUS",
        id="raw-eml-hidden-sensitive-payment-form",
    ),
    pytest.param(
        "EML-NOV-004-RAW",
        "email",
        "email",
        RAW_EML_CSS_OVERLAY_PAYMENT,
        "DANGEROUS",
        id="raw-eml-css-overlay-payment-target",
    ),
    pytest.param(
        "EML-NOV-006-RAW",
        "email",
        "email",
        RAW_EML_FALSE_TRAINING_LOGIN,
        "DANGEROUS",
        id="raw-eml-quoted-printable-false-training-login",
    ),
    pytest.param(
        "CONV-NOV-001",
        "text",
        "whatsapp",
        "EI: Sistemul AI a detectat o clona a contului tau. Mai intai adaugam un beneficiar temporar de siguranta. Dupa ce il adaugi, confirma transferul de test ca sa blocam clona.",
        "DANGEROUS",
        id="safe-beneficiary-test-transfer",
    ),
    pytest.param(
        "CONV-NOV-003",
        "text",
        "whatsapp",
        "EI: Sunt eu. Stiu parola noastra de familie: ciresul. Vocea mea nu merge bine dupa accident, dar am nevoie urgent de bani pentru operatie. Trimite acum 900 lei.",
        "DANGEROUS",
        id="family-voice-clone-emergency-payment",
    ),
    pytest.param(
        "CONV-NOV-006",
        "text",
        "whatsapp",
        "EI: Nu imi spune codul complet. Pentru verificare, trimite doar prima, a treia si a cincea cifra din codul primit in aplicatia bancara.",
        "DANGEROUS",
        id="partial-otp-digit-exfiltration",
    ),
    pytest.param(
        "OCR-NOV-001",
        "text",
        "ocr_image",
        "Nu trimite codul nimanui. Introdu-l doar in caseta de mai jos pentru verificarea automata. Cod SMS: ______",
        "DANGEROUS",
        id="safety-negation-exception-code-box",
    ),
    pytest.param(
        "OCR-NOV-002",
        "text",
        "ocr_image",
        "Mesaj 1: Pentru identificare avem nevoie doar de codul primit.\nMesaj 2: Trimite-l aici și închidem alerta.",
        "DANGEROUS",
        id="multi-block-code-request",
    ),
    pytest.param(
        "OCR-NOV-005",
        "url",
        "ocr_image",
        "Adresă browser: https://paypaI-secure.test/verify\nConfirmați cardul pentru a evita blocarea contului.",
        "DANGEROUS",
        id="visual-homoglyph-card-collection",
    ),
    pytest.param(
        "CONV-NOV-002",
        "text",
        "whatsapp",
        "EI: Banca noastra a migrat conturile. Factura ramane aceeasi. EU: Pot confirma telefonic? EI: Da, dar folositi numarul nou din semnatura acestui mesaj; vechiul departament nu mai are acces. EI: Plata trebuie refacuta astazi in noul IBAN.",
        "DANGEROUS",
        id="vendor-migration-callback-poison",
    ),
    pytest.param(
        "CONV-NOV-005",
        "text",
        "whatsapp",
        "EI: Pachetul medical a ajuns in UE, dar robotul vamal nu poate asocia destinatarul. EI: Trebuie cumparat un token digital de eliberare pe numele tau. EI: Plateste tokenul si il rambursez cand ajung.",
        "DANGEROUS",
        id="package-release-token-advance-fee",
    ),
    pytest.param(
        "AUD-NOV-003",
        "text",
        "phone_transcript",
        "Exista o sesizare pe numele dumneavoastra. Pentru suspendarea executarii, suma trebuie mutata temporar in contul de custodie digitala comunicat de agent.",
        "DANGEROUS",
        id="authority-digital-custody-transfer",
    ),
    pytest.param(
        "AUD-NOV-004",
        "text",
        "phone_transcript",
        "Sunt directorul financiar. Achita acum avansul catre partenerul nou. Nu porni aprobarea interna, documentele vor veni dupa inchiderea tranzactiei.",
        "DANGEROUS",
        id="cfo-bypass-new-partner-payment",
    ),
    pytest.param(
        "AUD-NOV-006",
        "text",
        "phone_transcript",
        "Am localizat fondurile pierdute. Pentru a semna traseul blockchain trebuie achitata taxa de audit inainte de rambursare.",
        "DANGEROUS",
        id="recovery-audit-fee-before-refund",
    ),
]


@pytest.mark.parametrize("case_id,input_type,source_channel,text,expected", NOVEL_HOLDOUT_REGRESSIONS)
def test_novel_holdout_high_risk_patterns_are_not_missed(monkeypatch, case_id, input_type, source_channel, text, expected):
    app_main._ORCHESTRATED_SCAN_JOBS.clear()
    client = TestClient(app_main.app)

    with monkeypatch.context() as patched:
        patched.setattr(app_main, "PRIVACY_SAFE_MODE", False)
        patched.setattr(app_main, "ENABLE_CLOUD_AI_EXPLANATION", False)
        patched.setattr(app_main, "ORCHESTRATED_DEFER_AI_EXPLANATION", False)
        patched.setattr(app_main, "URLSCAN_API_KEY", "server-only-key")
        patched.setattr(app_main, "MISTRAL_SEMANTIC_API_KEY", "")
        patched.setattr(app_main, "_safe_scan_url_list", _safe_test_resolver)
        patched.setattr(app_main, "_gather_external_intel_safe", _clean_external_intel_for_resolved_urls)
        patched.setattr(app_main, "_enrich_offer_claim_verification_async", _fake_inconclusive_offer_claim)
        patched.setattr(app_main, "check_domain_ssl_parallel", _fresh_test_domain_signals)
        patched.setattr(app_main.requests, "post", _fake_urlscan_post_rejects_domain)
        patched.setattr(app_main, "_emit_scan_event", lambda *args, **kwargs: None)
        patched.setattr(app_main, "_emit_orchestrated_telemetry", lambda *args, **kwargs: None)

        start = client.post(
            "/v1/scan/orchestrated",
            json={"input_type": input_type, "text": text, "source_channel": source_channel},
        ).json()
        _, payload = _poll_orchestrated(client, start["scan_id"], count=8)

    result = payload.get("result") or {}
    actual = str(result.get("user_risk_label") or "UNVERIFIED").upper()

    assert payload["status"] == "complete"
    assert result.get("is_final") is True
    assert SEVERITY_RANK[actual] >= SEVERITY_RANK[expected], (
        f"{case_id} expected at least {expected}, got {actual}; "
        f"family={result.get('detected_family_id')} reasons={result.get('reasons')}"
    )


def test_official_safety_education_without_action_stays_non_dangerous():
    text = (
        "Alerta de siguranta: banca nu iti va cere niciodata OTP, PIN, CVV sau transfer "
        "intr-un cont sigur. Inchide apelul si suna numarul oficial din aplicatie."
    )

    review = app_main._local_high_risk_semantic_review(text)
    signal = app_main._social_engineering_signal_for_decision_bundle(
        text,
        request_sensitive="none",
        source_channel="sms",
        semantic_review={"risk_class": "benign", "matched_template": "safety_education"},
    )

    assert review is None
    assert signal["intent"] == "benign"
    assert signal["ask_present"] is False


def test_plain_public_payment_url_is_not_structural_qr_overlay(monkeypatch):
    app_main._ORCHESTRATED_SCAN_JOBS.clear()
    client = TestClient(app_main.app)

    with monkeypatch.context() as patched:
        patched.setattr(app_main, "PRIVACY_SAFE_MODE", False)
        patched.setattr(app_main, "ENABLE_CLOUD_AI_EXPLANATION", False)
        patched.setattr(app_main, "ORCHESTRATED_DEFER_AI_EXPLANATION", False)
        patched.setattr(app_main, "URLSCAN_API_KEY", "server-only-key")
        patched.setattr(app_main, "MISTRAL_SEMANTIC_API_KEY", "")
        patched.setattr(app_main, "_safe_scan_url_list", _safe_test_resolver)
        patched.setattr(app_main, "_gather_external_intel_safe", _clean_external_intel_for_resolved_urls)
        patched.setattr(app_main, "_enrich_offer_claim_verification_async", _fake_inconclusive_offer_claim)
        patched.setattr(app_main, "check_domain_ssl_parallel", _fresh_test_domain_signals)
        patched.setattr(app_main.requests, "post", _fake_urlscan_post_rejects_domain)
        patched.setattr(app_main, "_emit_scan_event", lambda *args, **kwargs: None)
        patched.setattr(app_main, "_emit_orchestrated_telemetry", lambda *args, **kwargs: None)

        start = client.post(
            "/v1/scan/orchestrated",
            json={
                "input_type": "url",
                "text": "https://portal-furnizor.example/plata",
                "source_channel": "qr",
            },
        ).json()
        _, payload = _poll_orchestrated(client, start["scan_id"], count=8)

    result = payload.get("result") or {}
    assert payload["status"] == "complete"
    assert str(result.get("user_risk_label") or "").upper() != "DANGEROUS"
    assert result.get("detected_family_id") != "official_poster_payment_qr_overlay"


def test_plain_official_portal_qr_payload_is_not_structural_poster_overlay(monkeypatch):
    app_main._ORCHESTRATED_SCAN_JOBS.clear()
    client = TestClient(app_main.app)

    with monkeypatch.context() as patched:
        patched.setattr(app_main, "PRIVACY_SAFE_MODE", False)
        patched.setattr(app_main, "ENABLE_CLOUD_AI_EXPLANATION", False)
        patched.setattr(app_main, "ORCHESTRATED_DEFER_AI_EXPLANATION", False)
        patched.setattr(app_main, "URLSCAN_API_KEY", "server-only-key")
        patched.setattr(app_main, "MISTRAL_SEMANTIC_API_KEY", "")
        patched.setattr(app_main, "_safe_scan_url_list", _safe_test_resolver)
        patched.setattr(app_main, "_gather_external_intel_safe", _clean_external_intel_for_resolved_urls)
        patched.setattr(app_main, "_enrich_offer_claim_verification_async", _fake_inconclusive_offer_claim)
        patched.setattr(app_main, "check_domain_ssl_parallel", _fresh_test_domain_signals)
        patched.setattr(app_main.requests, "post", _fake_urlscan_post_rejects_domain)
        patched.setattr(app_main, "_emit_scan_event", lambda *args, **kwargs: None)
        patched.setattr(app_main, "_emit_orchestrated_telemetry", lambda *args, **kwargs: None)

        start = client.post(
            "/v1/scan/orchestrated",
            json={
                "input_type": "text",
                "text": "QR portal oficial control\nCoduri QR extrase:\nhttps://portal-furnizor.example/plata",
                "source_channel": "qr",
            },
        ).json()
        _, payload = _poll_orchestrated(client, start["scan_id"], count=8)

    result = payload.get("result") or {}
    assert payload["status"] == "complete"
    assert str(result.get("user_risk_label") or "").upper() != "DANGEROUS"
    assert result.get("detected_family_id") != "official_poster_payment_qr_overlay"


def test_invoice_with_insufficient_evidence_finishes_as_final_unverified(monkeypatch):
    app_main._ORCHESTRATED_SCAN_JOBS.clear()
    client = TestClient(app_main.app)

    with monkeypatch.context() as patched:
        patched.setattr(app_main, "PRIVACY_SAFE_MODE", False)
        patched.setattr(app_main, "ENABLE_CLOUD_AI_EXPLANATION", False)
        patched.setattr(app_main, "ORCHESTRATED_DEFER_AI_EXPLANATION", False)
        patched.setattr(app_main, "URLSCAN_API_KEY", "server-only-key")
        patched.setattr(app_main, "MISTRAL_SEMANTIC_API_KEY", "")
        patched.setattr(app_main, "_safe_scan_url_list", _safe_test_resolver)
        patched.setattr(app_main, "_gather_external_intel_safe", _clean_external_intel_for_resolved_urls)
        patched.setattr(app_main, "_enrich_offer_claim_verification_async", _fake_inconclusive_offer_claim)
        patched.setattr(app_main, "check_domain_ssl_parallel", _fresh_test_domain_signals)
        patched.setattr(app_main.requests, "post", _fake_urlscan_post_rejects_domain)
        patched.setattr(app_main, "_emit_scan_event", lambda *args, **kwargs: None)
        patched.setattr(app_main, "_emit_orchestrated_telemetry", lambda *args, **kwargs: None)

        start = client.post(
            "/v1/scan/orchestrated",
            json={"input_type": "invoice", "text": "Factura cu TVA\nTotal: 100 RON", "source_channel": "invoice"},
        ).json()
        _, payload = _poll_orchestrated(client, start["scan_id"], count=8)

    result = payload.get("result") or {}
    assert payload["status"] == "complete"
    assert result.get("is_final") is True
    assert str(result.get("user_risk_label") or "").upper() == "UNVERIFIED"
