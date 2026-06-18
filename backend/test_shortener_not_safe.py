"""RES-02: a URL shortener whose final destination was not confirmed must not be
granted SAFE via clean_public_navigation_url. The shortener host is "established"
and providers are clean, but the actual destination is unknown — SAFE there is a
blank cheque for any phishing link hidden behind tinyurl/bit.ly.

A shortener that resolved to a real established domain is fine (the destination is
known), and ordinary established public URLs (wikipedia) stay SAFE.
"""

from services.verdict_gate import verdict


def _public_nav_bundle(final_url, *, input_url=None):
    return {
        "schema": "sigurscan_evidence_bundle_v2",
        "input": {"type": "url_scan", "redacted_text": input_url or final_url},
        "resolution": {"status": "resolved", "final_url": final_url, "completeness": True},
        "providers": {"verdict": "clean", "hits": [], "completeness": True},
        "identity": {
            "claimed_brand": None,
            "status": "unknown",
            "tld_suspicious": False,
            "domain_age_days": 5000,
            "domain_reputation": "established",
            "completeness": True,
        },
        "request": {"sensitive": "none", "channel": "url", "completeness": True},
        "context": {"urgency": False, "passive_payment": False, "apk_or_remote_mention": False},
        "semantic_review": {"status": "done", "risk_class": "unknown", "completeness": True},
    }


def test_unresolved_shortener_is_not_safe():
    bundle = _public_nav_bundle("https://tinyurl.com/fake404phish")
    assert verdict(bundle)["label"] != "SAFE"


def test_bitly_unresolved_is_not_safe():
    bundle = _public_nav_bundle("https://bit.ly/3xFAKE")
    assert verdict(bundle)["label"] != "SAFE"


def test_established_non_shortener_public_url_stays_safe():
    bundle = _public_nav_bundle("https://www.wikipedia.org/wiki/Phishing")
    assert verdict(bundle)["label"] == "SAFE"


def test_shortener_resolved_to_established_domain_can_be_safe():
    # input was a shortener, but it resolved to a real established destination
    bundle = _public_nav_bundle(
        "https://www.wikipedia.org/wiki/Phishing", input_url="https://bit.ly/abc"
    )
    assert verdict(bundle)["label"] == "SAFE"
