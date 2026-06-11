"""Consumarea corectă a anaf_cui.check_cui pe ruta ofertă.

Regula cheie: ANAF date_generale:null → checked=True, exists=False (UNKNOWN, nu
eșec). Timeout total → checked=False. Niciuna nu trebuie interpretată ca verdict.
"""
from unittest.mock import AsyncMock, patch

import pytest

from services.anaf_cui import CuiResult
from services.offer_parser import parse_offer
from services.offer_entity_verifier import verify_offer_entity
from services.offer_evidence_gate_mapper import build_offer_bundle
from services.offer_signals import derive_offer_signals
from services.offer_readiness import evaluate_offer_readiness
from services.iban_validator import validate_iban


def _cui(checked, exists, activ=True, denumire="SC X SRL"):
    return CuiResult(
        exists=exists, checked=checked, denumire=denumire, activ=activ,
        data_inactivare=None, platitor_tva=False, enrolled_efactura=False, raw=None,
    )


async def _entity(text, cui_result):
    fields = parse_offer(text)
    with patch("services.offer_entity_verifier.check_cui", new_callable=AsyncMock) as mock:
        mock.return_value = cui_result
        return fields, await verify_offer_entity(fields)


class TestCheckedFlagSemantics:
    @pytest.mark.asyncio
    async def test_date_generale_null_is_checked_true_exists_false(self):
        _, entity = await _entity("SC X SRL CUI: 99999999", _cui(checked=True, exists=False, denumire=None))
        assert entity.cui_checked is True
        assert entity.cui_exists is False

    @pytest.mark.asyncio
    async def test_timeout_is_checked_false(self):
        _, entity = await _entity("SC X SRL CUI: 24387371", _cui(checked=False, exists=False, denumire=None))
        assert entity.cui_checked is False

    @pytest.mark.asyncio
    async def test_checked_false_maps_to_unknown_identity_not_bad(self):
        # checked=False → identity „unknown" (nu „unrelated") → nu poate produce PERICULOS solo
        text = "SC X SRL\nCUI: 24387371\nIBAN: RO33RNCB1234567890123456"
        fields, entity = await _entity(text, _cui(checked=False, exists=False, denumire=None))
        readiness = evaluate_offer_readiness(fields)
        iban_res = validate_iban(fields.iban) if fields.iban else None
        signals = derive_offer_signals(fields, iban_result=iban_res, readiness=readiness)
        bundle = build_offer_bundle(
            fields, signals=signals, entity=entity, coherence=None,
            family_code="OP-00", readiness=readiness,
        )
        assert bundle["identity"]["status"] == "unknown"

    @pytest.mark.asyncio
    async def test_inexistent_cui_maps_to_unrelated_identity(self):
        text = "SC Ghost SRL\nCUI: 99999999\nIBAN: RO33RNCB1234567890123456"
        fields, entity = await _entity(text, _cui(checked=True, exists=False, denumire=None))
        readiness = evaluate_offer_readiness(fields)
        signals = derive_offer_signals(fields, readiness=readiness)
        bundle = build_offer_bundle(
            fields, signals=signals, entity=entity, coherence=None,
            family_code="OP-00", readiness=readiness,
        )
        assert bundle["identity"]["status"] == "unrelated"
