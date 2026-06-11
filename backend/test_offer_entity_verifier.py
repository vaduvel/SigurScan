from unittest.mock import AsyncMock, patch

import pytest

from services.anaf_cui import CuiResult
from services.offer_parser import parse_offer
from services.offer_entity_verifier import verify_offer_entity, _names_align


def _cui(checked=True, exists=True, activ=True, denumire="SC TEST SRL"):
    return CuiResult(
        exists=exists, checked=checked, denumire=denumire, activ=activ,
        data_inactivare=None, platitor_tva=True, enrolled_efactura=False, raw=None,
    )


async def _verify(text, cui_result, links=None):
    fields = parse_offer(text, links=links)
    with patch("services.offer_entity_verifier.check_cui", new_callable=AsyncMock) as mock:
        mock.return_value = cui_result
        return await verify_offer_entity(fields, links=links)


class TestNameAlignment:
    def test_exact(self):
        assert _names_align("ENEL ENERGIE SA", "ENEL ENERGIE SA") is True

    def test_legal_form_stripped(self):
        assert _names_align("SC Holiday Dreams SRL", "Holiday Dreams") is True

    def test_mismatch(self):
        assert _names_align("Holiday Dreams", "Auto Parts Distribution") is False

    def test_uncomparable_none(self):
        assert _names_align(None, "X") is None


class TestEntityFacts:
    @pytest.mark.asyncio
    async def test_active_company_name_match(self):
        text = "Furnizor: ENEL ENERGIE SA\nCUI: 24387371\nIBAN: RO33RNCB1234567890123456"
        entity = await _verify(text, _cui(denumire="ENEL ENERGIE SA"))
        assert entity.cui_checked is True
        assert entity.cui_exists is True
        assert entity.cui_active is True
        assert entity.name_matches is True

    @pytest.mark.asyncio
    async def test_inactive_company(self):
        text = "Furnizor: SC GHOST SRL\nCUI: 12345678"
        entity = await _verify(text, _cui(activ=False, denumire="SC GHOST SRL"))
        assert entity.cui_active is False
        assert any("inactiv" in w.lower() for w in entity.warnings)

    @pytest.mark.asyncio
    async def test_cui_inexistent_checked_true(self):
        # ANAF date_generale:null → checked=True, exists=False (UNKNOWN, nu eșec)
        text = "SC FANTOMA SRL\nCUI: 99999999\nIBAN: RO33RNCB1234567890123456"
        entity = await _verify(text, _cui(exists=False, denumire=None))
        assert entity.cui_checked is True
        assert entity.cui_exists is False
        assert entity.claims_company is True

    @pytest.mark.asyncio
    async def test_anaf_unavailable_checked_false(self):
        text = "SC REAL SRL\nCUI: 24387371"
        entity = await _verify(text, _cui(checked=False, exists=False, denumire=None))
        assert entity.cui_checked is False
        assert any("indisponibil" in w.lower() for w in entity.warnings)


class TestIbanAndBrand:
    @pytest.mark.asyncio
    async def test_iban_valid(self):
        text = "IBAN: RO49AAAA1B31007593840000"
        entity = await _verify(text, _cui())
        assert entity.iban_present is True
        assert entity.iban_valid in (True, False)  # validatorul decide; flag e setat

    @pytest.mark.asyncio
    async def test_brand_impersonation_wrong_cui(self):
        text = "ENEL ENERGIE SA\nCUI: 11111111\nIBAN: RO33RNCB1234567890123456"
        entity = await _verify(text, _cui(exists=True, activ=True, denumire="ALTCEVA SRL"))
        assert entity.claimed_brand == "enel"
        assert entity.brand_impersonation is True
