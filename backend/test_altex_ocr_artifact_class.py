"""R7: OCR client-code artifact regression class (Altex-anchored).

Generalizes the Altex/Media Galaxy false-positive fix beyond the single literal
client code. Each case keeps the registry-consistent Altex identity (brand text,
CUI RO2864518, the real BRD + Trezorerie accounts) and varies ONLY the OCR
client-code artifact -- its token, spacing and position -- since OCR emits a
different IBAN-ish garbage string on every scan.

Every artifact token below was sandbox-verified to FAIL mod-97, so
payment_target_ibans must drop it. The invariants mirror the green
test_altex_real_invoice_not_dangerous guard; the point is they must hold for ANY
such artifact, not just the photographed string. A change that special-cases the
literal Altex client code would break here.

Brand identity is held constant on purpose: reusing a brand's registered IBAN
under a *different* brand legitimately trips PAYMENT_DESTINATION_BRAND_MISMATCH
(anti-fraud working as intended), so this class does not vary the brand.
"""

import pytest
from unittest.mock import AsyncMock, patch

from services.anaf_cui import CuiResult
from services.invoice_orchestrator import evaluate_invoice_verdict, scan_invoice

_ALTEX_BRD_IBAN = "RO53BRDE450SV01797384500"
_ALTEX_TREZ_IBAN = "RO67TREZ7005069XXX008077"


def _cui_ok(denumire: str = "ALTEX ROMANIA SRL") -> CuiResult:
    return CuiResult(
        exists=True, checked=True, denumire=denumire, activ=True,
        data_inactivare=None, platitor_tva=True, enrolled_efactura=True,
        raw=None, source="test",
    )


@pytest.fixture(autouse=True)
def _clean_invoice_state(monkeypatch):
    monkeypatch.setenv("INVOICE_CACHE_HMAC_KEY", "testkey")
    from services import invoice_orchestrator as io

    io._verdict_cache.clear()
    io._cui_cache.clear()
    try:
        from services import vendor_memory as vm

        vm._memory.clear()
    except Exception:
        pass
    yield
    io._verdict_cache.clear()
    io._cui_cache.clear()


def _build(artifact: str, *, artifact_before: bool) -> str:
    header = "ALTEX ROMANIA SRL   MEDIA GALAXY\nCod fiscal: RO2864518\n"
    ibans = (
        f"Cont IBAN: {_ALTEX_BRD_IBAN}\nBanca: BRD Romania\n"
        f"Cont IBAN 2: {_ALTEX_TREZ_IBAN}\nBanca 2: Trezoreria Bucuresti\n"
    )
    client = f"Client: {artifact}\n"
    footer = (
        "FACTURA F314027126-08562\nData factura: 03/07/2026\n"
        "Telefon Galaxy A16, 4GB, 128GB\nTotal: 630.00 RON\nTVA 21%: 109.34 RON\n"
    )
    middle = client + ibans if artifact_before else ibans + client
    return header + middle + footer


# (case_id, artifact token, forbidden normalized substring, artifact_before_ibans)
_CASES = [
    ("literal_client_code_nospaces", "CL006876853MARKETINGGROWTHHUBSRL",    "MARKETINGGROWTHHUBSRL", False),
    ("client_code_spaced",           "CL006876853 MARKETING GROWTH HUB SRL","MARKETINGGROWTHHUBSRL", False),
    ("alt_token_depozit",            "CL118002934DEPOZITBUCURESTISRL",      "DEPOZITBUCURESTISRL",   False),
    ("alt_token_before_ibans",       "CL900574112COMANDAONLINE2026",        "COMANDAONLINE2026",     True),
    ("client_prefix_variant",        "CLIENT0099213COMANDARETAILSRL",       "COMANDARETAILSRL",      False),
]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "artifact,forbidden,artifact_before",
    [c[1:] for c in _CASES],
    ids=[c[0] for c in _CASES],
)
async def test_altex_ocr_artifact_class_not_dangerous(artifact, forbidden, artifact_before):
    text = _build(artifact, artifact_before=artifact_before)
    with patch("services.invoice_orchestrator.check_cui", new_callable=AsyncMock) as mock_cui:
        mock_cui.return_value = _cui_ok()
        result = await scan_invoice(text)

    verdict = evaluate_invoice_verdict(result, result.raw_text, source_channel="android_native")
    all_ibans = result.fields.all_ibans or []

    # Both legitimate Altex accounts survive validation.
    assert _ALTEX_BRD_IBAN in all_ibans
    assert _ALTEX_TREZ_IBAN in all_ibans
    # The OCR client-code artifact never becomes a payment target.
    assert not any(forbidden in iban for iban in all_ibans)
    assert not any(iban.startswith("CL") for iban in all_ibans)
    # Dual legit accounts -> MULTIPLE_IBANS, but no fragmented target, correct brand,
    # no brand mismatch, and not dangerous.
    assert "MULTIPLE_IBANS" in result.fraud_flags
    assert "FRAGMENTED_IBAN_PAYMENT_TARGET" not in result.fraud_flags
    assert result.brand == "altex"
    assert "PAYMENT_DESTINATION_BRAND_MISMATCH" not in result.fraud_flags
    assert verdict["gate"]["label"] != "DANGEROUS"
