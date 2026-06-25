"""Guard for the fake security-app / remote-control install family.

SYNTHETIC TEST VECTORS ONLY (constructed, not real reported cases) -> kept OUT of
the provenance corpus.

The differentiator is the scam-specific app type + dangerous distribution, NOT the
mere words "install" + "app": real banks tell you to install their OWN app from the
official store. So:
- "install a security/protection app via link" / "install AnyDesk and give me the
  access code" -> DANGEROUS.
- "download our official app from Google Play / App Store" -> must NOT escalate.
"""

import os

import eval.large_offline_fixture_runner as runner


def _verdict(text, channel="app"):
    for k, v in {
        "PRIVACY_SAFE_MODE": "false", "ENABLE_CLOUD_AI_EXPLANATION": "false",
        "ENABLE_MISTRAL_SHADOW_ADJUDICATION": "false", "ENABLE_DNS_REPUTATION": "false",
        "INVOICE_CACHE_HMAC_KEY": "ci-test-hmac-key",
    }.items():
        os.environ.setdefault(k, v)
    return runner._run_case({"id": "x", "text": text, "expected": "DANGEROUS",
                             "source": "synthetic", "meta": {"input_type": channel}}).get("actual")


def test_fake_security_app_via_link_escalates():
    text = ("Pentru a va proteja cardul, instalati aplicatia oficiala de securitate "
            "de la linkul de mai jos si urmati pasii de activare.")
    assert _verdict(text) == "DANGEROUS"


def test_remote_control_app_escalates():
    text = ("Suport bancar: pentru a remedia problema contului, instalati AnyDesk si "
            "dati-mi codul de acces ca sa preiau controlul.")
    assert _verdict(text) == "DANGEROUS"


def test_legit_official_store_app_does_not_escalate():
    # FP boundary: installing the bank's OWN app from the official store.
    text = ("Banca Transilvania: gestioneaza-ti contul oriunde. Descarca aplicatia "
            "oficiala BT Pay din Google Play sau App Store.")
    assert _verdict(text) != "DANGEROUS"
