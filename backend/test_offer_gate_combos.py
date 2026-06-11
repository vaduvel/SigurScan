"""EvidenceGate combos pe ruta ofertă — toate trec prin verdict_gate.reduce_verdict.

Filosofia: PERICULOS = COMBINAȚIE. Lipsă/ANAF indisponibil = SUSPECT (nu PERICULOS,
nu SIGUR). Determinism: același input → același verdict.
"""
from unittest.mock import AsyncMock, patch

import pytest

from services.anaf_cui import CuiResult
from services.invoice_coherence import check_coherence
from services.iban_validator import validate_iban
from services.family_classifier import classify_offer_family
from services.offer_parser import parse_offer
from services.offer_readiness import evaluate_offer_readiness
from services.offer_signals import derive_offer_signals
from services.payment_method_classifier import classify_payment_method
from services.offer_entity_verifier import verify_offer_entity
from services.offer_evidence_gate_mapper import evaluate_offer_verdict


def _cui(checked=True, exists=True, activ=True, denumire="SC TEST SRL"):
    return CuiResult(
        exists=exists, checked=checked, denumire=denumire, activ=activ,
        data_inactivare=None, platitor_tva=True, enrolled_efactura=False, raw=None,
    )


async def _run(text, *, cui_result=None, links=None, qr=None):
    fields = parse_offer(text, links=links, qr_payloads=qr)
    with patch("services.offer_entity_verifier.check_cui", new_callable=AsyncMock) as mock:
        mock.return_value = cui_result or _cui(checked=False, exists=False, denumire=None)
        entity = await verify_offer_entity(fields, links=links)
    coherence = check_coherence(fields.subtotal, fields.tva, fields.total, fields.data_emitere, fields.scadenta)
    iban_res = validate_iban(fields.iban) if fields.iban else None
    payment = classify_payment_method(fields.raw_text)
    family_code, _, fconf = classify_offer_family(fields.raw_text)
    readiness = evaluate_offer_readiness(fields)
    signals = derive_offer_signals(
        fields, iban_result=iban_res, coherence=coherence, payment=payment,
        family_code=family_code, readiness=readiness,
    )
    out = evaluate_offer_verdict(
        fields, signals=signals, entity=entity, coherence=coherence,
        family_code=family_code, family_confidence=fconf, readiness=readiness,
    )
    return out


class TestPericulosCombos:
    @pytest.mark.asyncio
    async def test_crypto_payment(self):
        out = await _run("Plătește avansul în crypto wallet USDT pentru rezervare")
        assert out["gate"]["label"] == "PERICULOS"

    @pytest.mark.asyncio
    async def test_card_cvv_off_platform(self):
        out = await _run("Hai pe WhatsApp; introdu datele cardului și codul CVV ca să primești banii")
        assert out["gate"]["label"] == "PERICULOS"

    @pytest.mark.asyncio
    async def test_id_document_request(self):
        out = await _run("Trimite o poză cu buletinul și CNP-ul ca să pregătesc contractul, plus avans")
        assert out["gate"]["label"] == "PERICULOS"

    @pytest.mark.asyncio
    async def test_cui_inexistent_claims_company_payment(self):
        text = "SC Ghost Travel SRL\nCUI: 99999999\nPlătește avans în contul IBAN RO33RNCB1234567890123456"
        out = await _run(text, cui_result=_cui(exists=False, denumire=None))
        assert out["gate"]["label"] == "PERICULOS"

    @pytest.mark.asyncio
    async def test_brand_impersonation_payment(self):
        text = "ENEL ENERGIE SA\nFactura restanta\nCUI: 11111111\nPlateste in contul IBAN RO33RNCB1234567890123456"
        out = await _run(text, cui_result=_cui(exists=True, activ=True, denumire="FIRMA ALEATOARE SRL"))
        assert out["gate"]["label"] == "PERICULOS"

    @pytest.mark.asyncio
    async def test_iban_invalid_payment_urgency(self):
        text = "Oferta doar azi! Plateste acum avans in contul IBAN RO00RNCB1234567890123456"
        out = await _run(text)
        assert out["gate"]["label"] == "PERICULOS"


class TestSuspectNotPericulos:
    @pytest.mark.asyncio
    async def test_anaf_unavailable_with_payment_is_suspect(self):
        # checked=False NU → PERICULOS și NU → SIGUR
        text = "SC Real SRL\nCUI: 24387371\nPlateste in cont IBAN RO33RNCB1234567890123456\nTotal: 100 lei"
        out = await _run(text, cui_result=_cui(checked=False, exists=False, denumire=None))
        assert out["gate"]["label"] == "SUSPECT"

    @pytest.mark.asyncio
    async def test_benign_no_payment_is_suspect_or_safe_not_danger(self):
        out = await _run("Buna, vand o canapea, detalii in privat")
        assert out["gate"]["label"] != "PERICULOS"

    @pytest.mark.asyncio
    async def test_only_urgency_price_is_not_periculos(self):
        out = await _run("Super oferta, pret redus doar azi, grabeste-te!")
        assert out["gate"]["label"] != "PERICULOS"


class TestSafe:
    @pytest.mark.asyncio
    async def test_verified_active_company_transfer_is_safe(self):
        text = (
            "Furnizor: ENEL ENERGIE SA\nCUI: 24387371\nTotal: 245,00 RON\n"
            "IBAN: RO33RNCB1234567890123456\nData: 01.06.2026\nScadenta: 15.06.2026"
        )
        out = await _run(text, cui_result=_cui(exists=True, activ=True, denumire="ENEL ENERGIE SA"))
        assert out["gate"]["label"] == "SIGUR"


class TestDeterminism:
    @pytest.mark.asyncio
    async def test_same_input_same_verdict_and_hash(self):
        text = "SC Ghost Travel SRL\nCUI: 99999999\nPlătește avans în contul IBAN RO33RNCB1234567890123456"
        out1 = await _run(text, cui_result=_cui(exists=False, denumire=None))
        out2 = await _run(text, cui_result=_cui(exists=False, denumire=None))
        assert out1["gate"]["label"] == out2["gate"]["label"]
        assert out1["bundle"]["evidence_hash"] == out2["bundle"]["evidence_hash"]

    @pytest.mark.asyncio
    async def test_gate_result_is_final(self):
        out = await _run("Plătește în crypto wallet")
        assert out["gate"]["is_final"] is True
