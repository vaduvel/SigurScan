"""PR-0: EvidenceGate 4-stări — 18 golden fixtures din tabelul de adevăr §1."""

from services.verdict_gate import verdict


def _bundle(
    *,
    providers_verdict: str = "clean",
    identity_status: str = "unknown",
    sensitive: str = "none",
    channel: str = "official",
    semantic_risk: str = "unknown",
    provenance_domain_match: bool = False,
    provenance_email_match: bool = False,
    provenance_shortcode_match: bool = False,
    provenance_phone_match: bool = False,
    campaign_status: str = "no_match",
    campaign_confidence: float = 0.0,
    violated_never_asks: list | None = None,
    violated_never_does: list | None = None,
    tld_suspicious: bool = False,
    domain_age_days: int | None = None,
    ssl_invalid: bool = False,
    resolution_status: str = "resolved",
    bundle_completeness: bool = True,
    provider_completeness: bool = True,
    semantic_status: str = "done",
) -> dict:
    return {
        "schema": "sigurscan_evidence_bundle_v2",
        "resolution": {
            "status": resolution_status,
            "completeness": bundle_completeness,
            "final_url": "https://example.com/",
        },
        "providers": {
            "verdict": providers_verdict,
            "hits": [],
            "completeness": provider_completeness,
        },
        "identity": {
            "claimed_brand": None,
            "status": identity_status,
            "tld_suspicious": tld_suspicious,
            "domain_age_days": domain_age_days,
            "domain_reputation": "established" if domain_age_days and domain_age_days >= 365 else "unknown",
            "ssl_invalid": ssl_invalid,
            "violated_never_asks": violated_never_asks or [],
            "violated_never_does": violated_never_does or [],
            "completeness": True,
        },
        "provenance": {
            "official_domain_match": provenance_domain_match,
            "official_email_match": provenance_email_match,
            "official_shortcode_match": provenance_shortcode_match,
            "official_phone_match": provenance_phone_match,
        },
        "request": {
            "sensitive": sensitive,
            "channel": channel,
            "completeness": True,
        },
        "campaign_match": {
            "status": campaign_status,
            "confidence": campaign_confidence,
            "devices_seen_bucket": "0",
            "family": None,
        },
        "semantic_review": {
            "status": semantic_status,
            "risk_class": semantic_risk,
            "claim_matches_known_scam_family": False,
            "claim_matches_legit_template": False,
            "reason_codes": [f"semantic:{semantic_risk}"],
            "completeness": True,
        },
    }


# ─── Rule 1: Provider malicious → DANGEROUS ────────────────────────────────

def test_provider_malicious_web_risk_is_dangerous():
    b = _bundle(providers_verdict="malicious")
    r = verdict(b)
    assert r["label"] == "DANGEROUS"
    assert "provider_malicious" in r["reason_codes"]
    assert r["is_final"] is True


def test_provider_malicious_urlhaus_is_dangerous():
    b = _bundle(
        providers_verdict="clean",
        identity_status="official",
    )
    b["providers"]["verdict"] = ""
    b["providers"]["urlhaus"] = {
        "status": "malicious",
        "verdict": "malicious",
        "severity": "high",
    }
    r = verdict(b)
    assert r["label"] == "DANGEROUS"
    assert "provider_malicious" in r["reason_codes"]


def test_provider_suspicious_open_feed_is_suspect_not_dangerous():
    b = _bundle(providers_verdict="suspicious")
    b["providers"]["hits"] = ["scam_blocklist_nrd"]
    r = verdict(b)
    assert r["label"] == "SUSPECT"
    assert r["risk_level"] == "medium"
    assert r["reason_codes"] == ["provider_suspicious"]


# ─── Rule 2: BTR mismatch + sensitive request → DANGEROUS ──────────────────

def test_btr_mismatch_with_card_sensitive_is_dangerous():
    b = _bundle(
        identity_status="unrelated",
        sensitive="card",
        channel="sms",
    )
    r = verdict(b)
    assert r["label"] == "DANGEROUS"
    assert r["reason_codes"] == ["identity_spoof"]


def test_btr_mismatch_with_otp_sensitive_is_dangerous():
    b = _bundle(
        identity_status="lookalike",
        sensitive="otp",
        channel="sms",
    )
    r = verdict(b)
    assert r["label"] == "DANGEROUS"
    assert r["reason_codes"] == ["identity_spoof"]


# ─── Rule 2c: Person manifest "never_does" violated → DANGEROUS ───────────

def test_person_manifest_never_does_violated_is_dangerous():
    b = _bundle(
        identity_status="unknown",
        violated_never_does=["investment_endorsement"],
    )
    r = verdict(b)
    assert r["label"] == "DANGEROUS"
    assert any("never_does" in c for c in r["reason_codes"])


# ─── Rule 3: Sensitive on wrong channel → DANGEROUS ────────────────────────

def test_card_sensitive_on_sms_channel_is_dangerous():
    b = _bundle(
        sensitive="card",
        channel="sms",
        identity_status="unknown",
    )
    r = verdict(b)
    # identity unknown + card + sms = HARD_SENSITIVE + WRONG_CHANNEL
    assert r["label"] == "DANGEROUS"
    assert "sensitive_wrong_channel" in r["reason_codes"]


def test_otp_sensitive_on_whatsapp_channel_is_dangerous():
    b = _bundle(
        sensitive="otp",
        channel="whatsapp",
        identity_status="unknown",
    )
    r = verdict(b)
    assert r["label"] == "DANGEROUS"
    assert "sensitive_wrong_channel" in r["reason_codes"]


# ─── Rule 4: Provider error → NU SAFE ─────────────────────────────────────

def test_provider_error_blocks_safe_even_with_official_identity():
    b = _bundle(
        providers_verdict="error",
        identity_status="official",
        sensitive="none",
    )
    r = verdict(b)
    assert r["label"] != "SAFE"
    assert r["label"] == "UNVERIFIED"
    assert "provider_error" in r["reason_codes"]


# ─── Rule 5: Incomplete evidence → UNVERIFIED ──────────────────────────────

def test_incomplete_resolution_is_unverified():
    b = _bundle(
        resolution_status="pending",
        bundle_completeness=True,
    )
    r = verdict(b)
    assert r["label"] == "UNVERIFIED"
    assert r["is_final"] is False


def test_pending_semantic_review_is_unverified():
    b = _bundle(semantic_status="pending")
    r = verdict(b)
    assert r["label"] == "UNVERIFIED"
    assert r["is_final"] is False


# ─── Rule 6: Positive provenance → SAFE ────────────────────────────────────

def test_official_identity_clean_no_sensitive_is_safe():
    b = _bundle(
        identity_status="official",
        providers_verdict="clean",
        sensitive="none",
        channel="official",
    )
    r = verdict(b)
    assert r["label"] == "SAFE"
    assert r["reason_codes"] == ["positive_provenance_clean"]
    assert r["is_final"] is True


def test_official_domain_match_provenance_is_safe():
    b = _bundle(
        identity_status="unknown",
        provenance_domain_match=True,
        providers_verdict="clean",
        sensitive="none",
        channel="official",
    )
    r = verdict(b)
    assert r["label"] == "SAFE"
    assert r["is_final"] is True


def test_delegated_identity_clean_no_sensitive_is_safe():
    b = _bundle(
        identity_status="delegated",
        providers_verdict="clean",
        sensitive="none",
        channel="official",
    )
    r = verdict(b)
    assert r["label"] == "SAFE"
    assert r["is_final"] is True


def test_official_identity_with_card_on_official_channel_is_safe():
    b = _bundle(
        identity_status="official",
        providers_verdict="clean",
        sensitive="card",
        channel="official",
        semantic_risk="benign",
    )
    r = verdict(b)
    # Card on official channel with official identity → SAFE (card on official site is expected)
    assert r["label"] == "SAFE"


# ─── Rule 7: Campaign fingerprint match solo → max SUSPECT ────────────────

def test_campaign_match_high_confidence_without_provenance_is_suspect():
    b = _bundle(
        identity_status="unknown",
        campaign_status="match",
        campaign_confidence=0.92,
        sensitive="none",
        channel="sms",
    )
    r = verdict(b)
    assert r["label"] == "SUSPECT"
    assert "campaign_match_only" in r["reason_codes"]
    assert r["is_final"] is True


# ─── Rule 8: Semantic high + sensitive → DANGEROUS ────────────────────────

def test_semantic_high_with_sensitive_is_dangerous():
    """Use 'unknown' channel to test semantic_high path (not wrong_channel path)."""
    b = _bundle(
        semantic_risk="high",
        sensitive="card",
        channel="unknown",
    )
    r = verdict(b)
    assert r["label"] == "DANGEROUS"
    assert "semantic_high_risk_match" in r["reason_codes"]


# ─── Rule 9: Unknown + clean → UNVERIFIED (NOT SAFE) ──────────────────────

def test_unknown_clean_no_sensitive_is_unverified():
    """Breaking change: old gate returned SIGUR for clean established domain."""
    b = _bundle(
        identity_status="unknown",
        providers_verdict="clean",
        sensitive="none",
        channel="official",
        domain_age_days=2400,
    )
    r = verdict(b)
    assert r["label"] == "UNVERIFIED"
    assert r["is_final"] is False
    assert r["label"] != "SAFE"  # no longer safe without provenance


def test_unknown_clean_young_domain_is_unverified():
    b = _bundle(
        identity_status="unknown",
        providers_verdict="clean",
        sensitive="none",
        domain_age_days=20,
    )
    r = verdict(b)
    assert r["label"] == "UNVERIFIED"


def test_known_brand_without_official_channel_but_clean_providers_is_unverified():
    """BTR match NOT achieved (claimed_brand but no provenance match)."""
    b = _bundle(
        identity_status="unknown",
        providers_verdict="clean",
        sensitive="none",
    )
    b["identity"]["claimed_brand"] = "FAN Courier"
    r = verdict(b)
    assert r["label"] == "UNVERIFIED"
    assert r["label"] != "SAFE"


# ─── Rule 10: Value transfer without decisive evidence → SUSPECT ─────────

def test_value_transfer_without_provenance_is_suspect():
    b = _bundle(
        identity_status="unknown",
        sensitive="transfer",
        channel="email",
        semantic_risk="medium",
    )
    r = verdict(b)
    assert r["label"] == "SUSPECT"
    assert "value_request_needs_verification" in r["reason_codes"]


def test_coherent_identity_with_checked_unknown_payment_destination_is_suspect():
    b = _bundle(
        identity_status="coherent",
        providers_verdict="clean",
        sensitive="transfer",
        channel="invoice",
        semantic_risk="low",
    )
    b["providers"]["payment_destination"] = {
        "status": "unknown",
        "verdict": "unknown",
        "matched": False,
        "brand_matches": None,
        "registry_has_brand_destinations": True,
        "trust_tier": "T4_STRUCTURALLY_VALID_UNKNOWN",
        "can_contribute_to_safe": False,
    }

    r = verdict(b)

    assert r["label"] == "SUSPECT"
    assert "value_request_needs_verification" in r["reason_codes"]


def test_coherent_generic_invoice_without_confirmed_payment_destination_can_be_safe():
    b = _bundle(
        identity_status="coherent",
        providers_verdict="clean",
        sensitive="transfer",
        channel="invoice",
        semantic_risk="low",
    )

    r = verdict(b)

    assert r["label"] == "SAFE"
    assert r["reason_codes"] == ["positive_provenance_clean"]


# ─── Rule 11: Residual → UNVERIFIED ──────────────────────────────────────

def test_no_signals_at_all_is_unverified():
    """Default when no signal = UNVERIFIED."""
    b = _bundle(
        identity_status="unknown",
        providers_verdict="clean",
        sensitive="none",
        channel="unknown",
        resolution_status="resolved",
        domain_age_days=None,
    )
    r = verdict(b)
    assert r["label"] == "UNVERIFIED"
    assert r["is_final"] is False
    assert r["confidence"] >= 0
