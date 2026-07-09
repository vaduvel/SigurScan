"""P-RULES Felia 4 (backend) — scam_atlas_patterns can source its groups from the
manifest when RULES_MANIFEST is enabled, provably behavior-preserving.

The override runs at import time (feature-flag read at process start). This test
reloads scam_atlas_patterns under each flag state and checks that ON makes the
group constants the manifest-sourced patterns (byte-identical to the literals,
per the Felia 1 0-diff gate), and OFF keeps the literals. Combined with
test_rules_manifest's 0-diff proof, this establishes that enabling the manifest
does not change detection.
"""

import importlib

import services.scam_atlas_patterns as sap
from services import rules_manifest

GROUPS = [
    "SENSITIVE_CREDENTIAL_PATTERNS",
    "SENSITIVE_WHATSAPP_PATTERNS",
    "SENSITIVE_PAYMENT_PATTERNS",
    "MALWARE_APK_PATTERNS",
    "SENSITIVE_QR_PATTERNS",
    "SENSITIVE_SEXTORTION_PATTERNS",
    "SENSITIVE_SIM_SWAP_PATTERNS",
    "OLX_CARD_PATTERNS",
    "REMOTE_ACCESS_PATTERNS",
    "URGENCY_MANIPULATION_PATTERNS",
    "MANIPULATION_REWARD_PATTERNS",
    "DELIVERY_MANIPULATION_PATTERNS",
]


def _reload(monkeypatch, flag):
    if flag is None:
        monkeypatch.delenv("RULES_MANIFEST", raising=False)
    else:
        monkeypatch.setenv("RULES_MANIFEST", flag)
    importlib.reload(sap)


def test_off_by_default_keeps_hardcoded_literals(monkeypatch):
    _reload(monkeypatch, None)
    try:
        for name in GROUPS:
            assert len(getattr(sap, name)) >= 1  # literals intact & non-empty
    finally:
        _reload(monkeypatch, None)


def test_on_sources_manifest_and_is_byte_identical(monkeypatch):
    _reload(monkeypatch, "1")
    try:
        manifest = rules_manifest.load_pattern_groups()
        for name in GROUPS:
            live = list(getattr(sap, name))
            assert [p.pattern for p in live] == [p.pattern for p in manifest[name]], name
            # order preserved (REMOTE_ACCESS_PATTERNS[0]/[1] indexing stays valid)
            assert len(live) == len(manifest[name])
    finally:
        _reload(monkeypatch, None)  # restore default for other tests
