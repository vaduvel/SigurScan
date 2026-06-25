"""Guard for the SE high-confidence `remote_install` anchor (#77).

SYNTHETIC TEST VECTORS ONLY (constructed, not real reported cases) -> kept OUT of
the provenance corpus.

The local social-engineering classifier used to add a `remote_install` ask on the
bare shape "instaleaz[ăa] ... aplica[țt]ia", which over-fired on *legit anti-sideload
advice* ("instalează aplicația oficială din Google Play") through the
`social_engineering_high_confidence_intent` gate path. The differentiator is a
remote-control / tech-support context (or a sideloaded APK / named remote tool), NOT
the mere instruction to install an app. So:
- "install AnyDesk and give me the code so I take control" / "install the remote-control
  app" / "install bank.apk from this link" -> DANGEROUS.
- "install the official app from Google Play, don't sideload it" -> must NOT escalate.
"""

import os

import eval.large_offline_fixture_runner as runner


def _verdict(text, channel="sms"):
    for k, v in {
        "PRIVACY_SAFE_MODE": "false", "ENABLE_CLOUD_AI_EXPLANATION": "false",
        "ENABLE_MISTRAL_SHADOW_ADJUDICATION": "false", "ENABLE_DNS_REPUTATION": "false",
        "INVOICE_CACHE_HMAC_KEY": "ci-test-hmac-key",
    }.items():
        os.environ.setdefault(k, v)
    return runner._run_case({"id": "x", "text": text, "expected": "SAFE",
                             "source": "synthetic", "meta": {"input_type": channel}}).get("actual")


# ── TP escalations (must stay DANGEROUS) ────────────────────────────────────
def test_named_remote_tool_escalates():
    text = ("Sunt de la suport tehnic. Instalează aplicația AnyDesk și dă-mi codul "
            "ca să preiau controlul contului.")
    assert _verdict(text, channel="phone") == "DANGEROUS"


def test_generic_remote_control_install_escalates():
    text = ("Pentru a remedia problema, instalează aplicația de control la distanță "
            "și lasă-mă să preiau controlul dispozitivului.")
    assert _verdict(text, channel="phone") == "DANGEROUS"


def test_sideloaded_apk_escalates():
    text = ("Descarcă și instalează aplicația din acest link (banca.apk) pentru a "
            "verifica contul.")
    assert _verdict(text) == "DANGEROUS"


# ── FP boundaries (legit install advice must stay UNVERIFIED, never DANGEROUS) ──
def test_install_official_bank_app_advice_does_not_escalate():
    text = ("Pentru siguranță, instalează aplicația oficială a băncii din Google Play. "
            "Nu o instala din alte surse.")
    assert _verdict(text) == "UNVERIFIED"


def test_install_official_antivirus_advice_does_not_escalate():
    text = ("Instalează aplicația antivirus oficială de pe site-ul producătorului "
            "pentru a-ți proteja telefonul.")
    assert _verdict(text) == "UNVERIFIED"


def test_install_official_named_app_from_store_does_not_escalate():
    text = ("Instalează aplicația George din magazinul oficial pentru a-ți gestiona "
            "contul.")
    assert _verdict(text) == "UNVERIFIED"
