import pytest

from main import _apply_provider_gate_verdict, brand_truth_registry


class TestAcceptancePR2:
    """PR-2 acceptance: /v1/verify/provenance + EvidenceBundle.provenance + gate integration.

    Acceptance:
    - FAN oficial tracking, fără sensibil → SAFE
    - FAN domeniu fals + card/CVV → DANGEROUS
    - ANAF link plată fals → DANGEROUS
    - reclamă Isărescu + investiții + canal neoficial → DANGEROUS
    - promo necunoscut → UNVERIFIED/SUSPECT, nu SAFE
    """

    def test_fan_official_tracking_no_sensitive_is_safe(self):
        analysis = {
            "claimed_brand": "FAN Courier",
            "risk_level": "medium",
            "risk_score": 55,
            "detected_family": "Tracking curier",
            "evidence": {
                "external_intel_summary": {
                    "google_web_risk": {"status": "clean", "verdict": "clean", "consulted": True},
                    "phishing_database": {"status": "clean", "verdict": "clean", "consulted": True},
                    "urlscan": {"status": "clean", "verdict": "clean", "consulted": True},
                },
            },
        }
        resolved_urls = [
            {
                "url": "https://fancourier.ro/tracking/awb123",
                "final_url": "https://fancourier.ro/tracking/awb123",
                "hostname": "fancourier.ro",
                "final_hostname": "fancourier.ro",
                "registered_domain": "fancourier.ro",
                "final_registered_domain": "fancourier.ro",
            }
        ]
        result = _apply_provider_gate_verdict(
            analysis, resolved_urls,
            raw_text="FAN Courier: ai un colet in drum. Urmareste AWB aici: https://fancourier.ro/tracking/awb123",
        )
        gate = result["evidence"]["verdict_gate"]
        assert gate["label"] == "SAFE", f"Expected SAFE, got {gate['label']}"
        assert result["risk_level"] == "low"

    def test_fan_fake_domain_with_card_is_dangerous(self):
        analysis = {
            "claimed_brand": "FAN Courier",
            "risk_level": "medium",
            "risk_score": 55,
            "detected_family": "Plata curier",
            "evidence": {
                "external_intel_summary": {
                    "google_web_risk": {"status": "clean", "verdict": "clean", "consulted": True},
                    "phishing_database": {"status": "clean", "verdict": "clean", "consulted": True},
                    "urlscan": {"status": "clean", "verdict": "clean", "consulted": True},
                },
            },
        }
        resolved_urls = [
            {
                "url": "https://fan-livrare-fake.xyz/pay",
                "final_url": "https://fan-livrare-fake.xyz/pay",
                "hostname": "fan-livrare-fake.xyz",
                "final_hostname": "fan-livrare-fake.xyz",
                "registered_domain": "fan-livrare-fake.xyz",
                "final_registered_domain": "fan-livrare-fake.xyz",
            }
        ]
        brand_warning = {
            "triggered": True,
            "matched_assets": ["card_number", "cvv"],
        }
        analysis["evidence"]["brand_warning"] = brand_warning
        result = _apply_provider_gate_verdict(
            analysis, resolved_urls,
            raw_text="FAN Courier: taxa vamala 5 RON. Plateste cardul aici: https://fan-livrare-fake.xyz/pay",
        )
        gate = result["evidence"]["verdict_gate"]
        assert gate["label"] == "DANGEROUS", f"Expected DANGEROUS, got {gate['label']}"
        assert result["risk_level"] == "high"

    def test_anaf_fake_payment_link_is_dangerous(self):
        analysis = {
            "claimed_brand": "ANAF",
            "risk_level": "medium",
            "risk_score": 55,
            "detected_family": "Plata ANAF",
            "evidence": {
                "external_intel_summary": {
                    "google_web_risk": {"status": "clean", "verdict": "clean", "consulted": True},
                    "phishing_database": {"status": "clean", "verdict": "clean", "consulted": True},
                    "urlscan": {"status": "clean", "verdict": "clean", "consulted": True},
                },
            },
        }
        resolved_urls = [
            {
                "url": "https://anaf-plateste-online.xyz/pay",
                "final_url": "https://anaf-plateste-online.xyz/pay",
                "hostname": "anaf-plateste-online.xyz",
                "final_hostname": "anaf-plateste-online.xyz",
                "registered_domain": "anaf-plateste-online.xyz",
                "final_registered_domain": "anaf-plateste-online.xyz",
            }
        ]
        result = _apply_provider_gate_verdict(
            analysis, resolved_urls,
            raw_text="ANAF: aveti de plata 2.350 RON. Achitati online: https://anaf-plateste-online.xyz/pay",
        )
        gate = result["evidence"]["verdict_gate"]
        assert gate["label"] == "DANGEROUS", f"Expected DANGEROUS, got {gate['label']}"
        assert result["risk_level"] == "high"

    def test_isarescu_deepfake_investment_is_dangerous(self):
        analysis = {
            "claimed_brand": "Mugur Isărescu",
            "risk_level": "medium",
            "risk_score": 65,
            "detected_family": "Deepfake investițional",
            "evidence": {
                "external_intel_summary": {
                    "google_web_risk": {"status": "clean", "verdict": "clean", "consulted": True},
                    "phishing_database": {"status": "clean", "verdict": "clean", "consulted": True},
                    "urlscan": {"status": "clean", "verdict": "clean", "consulted": True},
                },
                "violated_never_does": ["investment_endorsement", "investment_recommendation"],
                "source_channel": "social_dm",
            },
        }
        result = _apply_provider_gate_verdict(
            analysis, [],
            raw_text="Mugur Isărescu: oportunitate unică de investiții. Depozit cu randament garantat 15%!",
        )
        gate = result["evidence"]["verdict_gate"]
        assert gate["label"] == "DANGEROUS", f"Expected DANGEROUS, got {gate['label']}"
        assert any("never_does" in c for c in gate.get("reason_codes", [])), f"Expected never_does reason, got {gate.get('reason_codes')}"

    def test_unknown_promo_is_not_safe(self):
        analysis = {
            "claimed_brand": "Nespecificat",
            "risk_level": "medium",
            "risk_score": 55,
            "detected_family": "Promotie",
            "evidence": {
                "external_intel_summary": {
                    "google_web_risk": {"status": "clean", "verdict": "clean", "consulted": True},
                    "phishing_database": {"status": "clean", "verdict": "clean", "consulted": True},
                    "urlscan": {"status": "clean", "verdict": "clean", "consulted": True},
                },
            },
        }
        resolved_urls = [
            {
                "url": "https://promo-super-oferta.xyz/castiga",
                "final_url": "https://promo-super-oferta.xyz/castiga",
                "hostname": "promo-super-oferta.xyz",
                "final_hostname": "promo-super-oferta.xyz",
                "registered_domain": "promo-super-oferta.xyz",
                "final_registered_domain": "promo-super-oferta.xyz",
            }
        ]
        result = _apply_provider_gate_verdict(
            analysis, resolved_urls,
            raw_text="Felicitari! Ai castigat 10.000 RON! Intra pe: https://promo-super-oferta.xyz/castiga",
        )
        gate = result["evidence"]["verdict_gate"]
        assert gate["label"] not in {"SAFE"}, f"Expected NOT SAFE, got {gate['label']}"
        assert result["risk_level"] != "low"


class TestProvenanceEndpoint:
    def test_fan_courier_official_domain(self):
        result = brand_truth_registry.provenance_check(
            claimed_brand="FAN Courier",
            observed_channel="sms",
            observed_domain="fancourier.ro",
            observed_phone_e164=None,
            sensitive_asks=[],
            payment_method=None,
            final_url="https://fancourier.ro/tracking",
        )
        assert result.manifest_id == "fan_courier"
        assert result.provenance == "partial"

    def test_fan_courier_fake_domain_with_card(self):
        result = brand_truth_registry.provenance_check(
            claimed_brand="FAN Courier",
            observed_channel="sms",
            observed_domain="fan-livrare-fake.xyz",
            observed_phone_e164=None,
            sensitive_asks=["card_number", "cvv"],
            payment_method="card_form",
            final_url="https://fan-livrare-fake.xyz/pay",
        )
        assert result.provenance == "mismatch"
        assert "card_number" in result.violated_never_asks
        assert result.evidence_power == "decisive"
        assert result.max_effect == "can_raise_dangerous_with_combo"

    def test_unknown_brand_returns_no_manifest(self):
        result = brand_truth_registry.provenance_check(
            claimed_brand="Companie Necunoscuta SRL",
            observed_channel="sms",
            observed_domain="unknown-site.xyz",
            observed_phone_e164=None,
            sensitive_asks=[],
            payment_method=None,
            final_url="https://unknown-site.xyz",
        )
        assert result.manifest_id is None
        assert result.provenance == "unknown"

    def test_btr_version_available(self):
        assert brand_truth_registry.version.startswith("btr-ro-")

    def test_provenance_endpoint_contract(self):
        from services.brand_truth_registry import ProvenanceResult
        r = brand_truth_registry.provenance_check(
            claimed_brand="OLX",
            observed_channel="whatsapp",
            observed_domain=None,
            observed_phone_e164=None,
            sensitive_asks=["card_number"],
            payment_method=None,
            final_url=None,
        )
        assert isinstance(r, ProvenanceResult)
        assert hasattr(r, "manifest_id")
        assert hasattr(r, "provenance")
        assert hasattr(r, "identity_status")
        assert hasattr(r, "official_match")
        assert hasattr(r, "violated_never_asks")
        assert hasattr(r, "violated_never_does")
        assert hasattr(r, "evidence_power")
        assert hasattr(r, "reason_codes")
        assert hasattr(r, "max_effect")
