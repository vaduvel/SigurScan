"""PR4 — verificări oneste în registre publice (snapshot-uri, fără API-uri inventate).

Contract: registry_verification produce DOAR dovezi structurate
(RegistryVerificationResult). Singurul judecător rămâne verdict_gate.reduce_verdict.

Reguli pinuite aici:
- ONRC = exclusiv snapshot CSV oficial (data.gov.ro), cale prin env. Fără date fake.
- Snapshot lipsă -> NOT_CONFIGURED (checked=False); corupt -> SOURCE_ERROR;
  prea vechi -> INCONCLUSIVE.
- NO_MATCH solo = max SUSPECT; MATCH solo nu produce SIGUR; sursele indisponibile
  nu pot coborî verdictul la SIGUR.
- NO_MATCH + avans/transfer + IBAN/canal riscant escaladează DOAR prin reduce_verdict.
- Determinism: aceeași intrare -> același verdict + evidence_hash.
"""
import os
import time
from unittest.mock import AsyncMock, patch

import pytest

from services.anaf_cui import CuiResult
from services.invoice_readiness_gate import evaluate_offer_readiness
from services.offer_entity_verifier import OfferEntityResult, verify_offer_entity
from services.offer_evidence_gate_mapper import build_offer_bundle, evaluate_offer_verdict
from services.offer_parser import parse_offer
from services.offer_signals import derive_offer_signals
from services.registry_verification import (
    RegistryStatus,
    RegistryVerificationResult,
    route_sources,
    source_metadata,
    verify_offer_registries,
)
from services.registry_verification.onrc import verify_onrc
from services.registry_verification.stubs import STUB_SOURCE_IDS, verify_stub


VALID_CSV = (
    "CUI,DENUMIRE,STARE_FIRMA\n"
    "24387371,ENEL ENERGIE S.A.,INREGISTRAT\n"
    "12345678,HOLIDAY DREAMS S.R.L.,INREGISTRAT\n"
)


@pytest.fixture
def onrc_snapshot(tmp_path, monkeypatch):
    path = tmp_path / "onrc_snapshot.csv"
    path.write_text(VALID_CSV, encoding="utf-8")
    monkeypatch.setenv("ONRC_SNAPSHOT_PATH", str(path))
    monkeypatch.delenv("ONRC_SNAPSHOT_MAX_AGE_DAYS", raising=False)
    return path


def _cui(checked=True, exists=True, activ=True, denumire="SC TEST SRL"):
    return CuiResult(
        exists=exists, checked=checked, denumire=denumire, activ=activ,
        data_inactivare=None, platitor_tva=True, enrolled_efactura=False, raw=None,
    )


def _registry(source_id="onrc", status=RegistryStatus.NO_MATCH, checked=True,
              confidence=0.6, matched=None):
    return RegistryVerificationResult(
        source_id=source_id, status=status, confidence=confidence,
        matched_entity_name=matched, details={}, checked=checked,
    )


# ─────────────────────────────────────────────────────────────
# ONRC — snapshot CSV
# ─────────────────────────────────────────────────────────────
class TestOnrcSnapshot:
    def test_match_by_cui(self, onrc_snapshot):
        result = verify_onrc(cui="24387371", name=None)
        assert result.status == RegistryStatus.MATCH
        assert result.checked is True
        assert result.matched_entity_name == "ENEL ENERGIE S.A."
        assert result.confidence > 0.8

    def test_match_by_normalized_name(self, onrc_snapshot):
        # „SC Holiday Dreams SRL" trebuie să se potrivească cu „HOLIDAY DREAMS S.R.L."
        result = verify_onrc(cui=None, name="SC Holiday Dreams SRL")
        assert result.status == RegistryStatus.MATCH
        assert result.matched_entity_name == "HOLIDAY DREAMS S.R.L."

    def test_no_match(self, onrc_snapshot):
        result = verify_onrc(cui="99999999", name="Firma Fantoma SRL")
        assert result.status == RegistryStatus.NO_MATCH
        assert result.checked is True

    def test_missing_snapshot_not_configured(self, tmp_path, monkeypatch):
        monkeypatch.setenv("ONRC_SNAPSHOT_PATH", str(tmp_path / "absent.csv"))
        result = verify_onrc(cui="24387371", name=None)
        assert result.status == RegistryStatus.NOT_CONFIGURED
        assert result.checked is False

    def test_corrupt_snapshot_source_error(self, tmp_path, monkeypatch):
        path = tmp_path / "corrupt.csv"
        path.write_bytes(b"\xff\xfe\x00\x00garbage-without-headers")
        monkeypatch.setenv("ONRC_SNAPSHOT_PATH", str(path))
        result = verify_onrc(cui="24387371", name=None)
        assert result.status == RegistryStatus.SOURCE_ERROR

    def test_incompatible_columns_source_error(self, tmp_path, monkeypatch):
        path = tmp_path / "weird.csv"
        path.write_text("foo,bar\n1,2\n", encoding="utf-8")
        monkeypatch.setenv("ONRC_SNAPSHOT_PATH", str(path))
        result = verify_onrc(cui="24387371", name=None)
        assert result.status == RegistryStatus.SOURCE_ERROR

    def test_stale_snapshot_inconclusive(self, onrc_snapshot, monkeypatch):
        monkeypatch.setenv("ONRC_SNAPSHOT_MAX_AGE_DAYS", "30")
        old = time.time() - 90 * 86400
        os.utime(onrc_snapshot, (old, old))
        result = verify_onrc(cui="24387371", name=None)
        assert result.status == RegistryStatus.INCONCLUSIVE

    def test_metadata_includes_source_and_freshness(self, onrc_snapshot):
        meta = source_metadata("onrc")
        assert meta["configured"] is True
        assert meta["updated_at"]
        assert "data.gov.ro" in str(meta.get("official_source", ""))

    def test_metadata_not_configured(self, tmp_path, monkeypatch):
        monkeypatch.setenv("ONRC_SNAPSHOT_PATH", str(tmp_path / "absent.csv"))
        meta = source_metadata("onrc")
        assert meta["configured"] is False

    def test_metadata_exposes_honest_official_source_inventory(self):
        situr = source_metadata("situr")
        asf = source_metadata("asf")
        bnr = source_metadata("bnr")

        assert situr["official_source"] == "https://situr.gov.ro/portal/open-data"
        assert situr["recommended_runtime"] == "snapshot"
        assert situr["configured"] is False

        assert asf["official_source"] == "https://www.asfromania.ro/ro/a/2818/registrul-a.s.f."
        assert asf["recommended_runtime"] == "live/hybrid"
        assert asf["configured"] is False

        assert bnr["official_source"] == "https://www.bnr.ro/Registre-si-Liste-717.aspx"
        assert bnr["recommended_runtime"] == "live/hybrid"
        assert bnr["configured"] is False


# ─────────────────────────────────────────────────────────────
# Stubs oneste
# ─────────────────────────────────────────────────────────────
class TestStubs:
    def test_all_stub_sources_not_configured(self):
        for source_id in ["situr", "bnr", "asf", "anpc", "ancpi", "rar_auto_pass", "itm", "anofm"]:
            assert source_id in STUB_SOURCE_IDS
            result = verify_stub(source_id)
            assert result.status == RegistryStatus.NOT_CONFIGURED
            assert result.checked is False
            assert result.source_id == source_id


# ─────────────────────────────────────────────────────────────
# Router — alege sursele pe familie + identificatori
# ─────────────────────────────────────────────────────────────
class TestRouter:
    def test_turism_routes_to_situr_and_onrc(self):
        fields = parse_offer("SC Holiday Dreams SRL\nCUI: 12345678\nPachet turistic")
        sources = route_sources("OP-01", fields)
        assert "situr" in sources
        assert "onrc" in sources

    def test_financial_routes_to_asf_bnr(self):
        fields = parse_offer("Investitie garantata profit rapid")
        sources = route_sources("OP-09", fields)
        assert "asf" in sources
        assert "bnr" in sources

    def test_auto_routes_to_rar(self):
        fields = parse_offer("Vand BMW, VIN WVWZZZ1KZAW123456, firma EuroTransport SRL")
        sources = route_sources("OP-04", fields)
        assert "rar_auto_pass" in sources

    def test_company_cui_routes_to_onrc(self):
        fields = parse_offer("SC Firma SRL\nCUI: 12345678")
        assert "onrc" in route_sources("OP-00", fields)

    def test_no_identifiers_no_onrc(self):
        fields = parse_offer("vand canapea")
        assert "onrc" not in route_sources("OP-00", fields)

    def test_verify_offer_registries_returns_results(self, onrc_snapshot):
        fields = parse_offer("SC Holiday Dreams SRL\nCUI: 12345678\nPachet turistic cu licenta")
        results = verify_offer_registries(fields, "OP-01")
        by_source = {r.source_id: r for r in results}
        assert by_source["onrc"].status == RegistryStatus.MATCH
        assert by_source["situr"].status == RegistryStatus.NOT_CONFIGURED


# ─────────────────────────────────────────────────────────────
# Reguli de verdict — totul prin reduce_verdict (gate unic)
# ─────────────────────────────────────────────────────────────
async def _verdict(text, *, cui_result=None, registry_results=None):
    fields = parse_offer(text)
    with patch("services.offer_entity_verifier.check_cui", new_callable=AsyncMock) as mock:
        mock.return_value = cui_result or _cui(checked=False, exists=False, denumire=None)
        entity = await verify_offer_entity(fields)
    readiness = evaluate_offer_readiness(fields)
    signals = derive_offer_signals(fields, readiness=readiness)
    return evaluate_offer_verdict(
        fields, signals=signals, entity=entity, coherence=None,
        family_code="OP-00", readiness=readiness,
        registry_results=registry_results or [],
    )


class TestVerdictRules:
    @pytest.mark.asyncio
    async def test_no_match_solo_is_not_periculos(self):
        out = await _verdict(
            "SC Firma Necunoscuta SRL ofera servicii",
            registry_results=[_registry(status=RegistryStatus.NO_MATCH)],
        )
        assert out["gate"]["label"] != "DANGEROUS"

    @pytest.mark.asyncio
    async def test_match_solo_is_not_sigur(self):
        out = await _verdict(
            "SC Firma SRL ofera servicii",
            registry_results=[_registry(status=RegistryStatus.MATCH, confidence=0.95, matched="FIRMA S.R.L.")],
        )
        assert out["gate"]["label"] != "SAFE"

    @pytest.mark.asyncio
    @pytest.mark.parametrize("status", [
        RegistryStatus.NOT_CONFIGURED,
        RegistryStatus.SOURCE_TIMEOUT,
        RegistryStatus.SOURCE_ERROR,
        RegistryStatus.INCONCLUSIVE,
    ])
    async def test_unavailable_sources_never_sigur(self, status):
        out = await _verdict(
            "SC Firma SRL ofera servicii",
            registry_results=[_registry(status=status, checked=False, confidence=0.0)],
        )
        assert out["gate"]["label"] != "SAFE"

    @pytest.mark.asyncio
    async def test_no_match_plus_payment_escalates_via_gate(self):
        # ANAF indisponibil (checked=False) + ONRC NO_MATCH (consultat) + avans + IBAN
        # → escaladează prin reduce_verdict (semantic high + value + canal riscant).
        text = "SC Ghost Travel SRL\nCUI: 99999999\nPlateste avans in contul IBAN RO33RNCB1234567890123456"
        out = await _verdict(
            text,
            cui_result=_cui(checked=False, exists=False, denumire=None),
            registry_results=[_registry(status=RegistryStatus.NO_MATCH)],
        )
        assert out["gate"]["label"] == "DANGEROUS"

    @pytest.mark.asyncio
    async def test_no_match_without_payment_stays_unverified(self):
        """Breaking change: registry unknown → UNVERIFIED, not SUSPECT."""
        text = "SC Ghost Travel SRL\nCUI: 99999999\nOferta speciala vacanta"
        out = await _verdict(
            text,
            cui_result=_cui(checked=False, exists=False, denumire=None),
            registry_results=[_registry(status=RegistryStatus.NO_MATCH)],
        )
        assert out["gate"]["label"] == "UNVERIFIED"

    @pytest.mark.asyncio
    async def test_anaf_confirmed_not_undermined_by_registry_no_match(self):
        # ANAF live confirmă firma activă + nume → un snapshot ONRC incomplet
        # (NO_MATCH) NU dărâmă verdictul; ANAF e sursa mai puternică.
        text = (
            "Furnizor: ENEL ENERGIE SA\nCUI: 24387371\nTotal: 245,00 RON\n"
            "IBAN: RO33RNCB1234567890123456\nData: 01.06.2026\nScadenta: 15.06.2026"
        )
        out = await _verdict(
            text,
            cui_result=_cui(exists=True, activ=True, denumire="ENEL ENERGIE SA"),
            registry_results=[_registry(status=RegistryStatus.NO_MATCH)],
        )
        assert out["gate"]["label"] == "SAFE"

    @pytest.mark.asyncio
    async def test_registry_evidence_lands_in_bundle(self):
        out = await _verdict(
            "SC Firma SRL ofera servicii",
            registry_results=[_registry(status=RegistryStatus.MATCH, matched="FIRMA S.R.L.")],
        )
        registry_ctx = out["bundle"]["context"]["registry"]
        assert registry_ctx[0]["source_id"] == "onrc"
        assert registry_ctx[0]["status"] == "MATCH"

    @pytest.mark.asyncio
    async def test_determinism_same_input_same_hash(self):
        text = "SC Ghost SRL\nCUI: 99999999\nPlateste avans IBAN RO33RNCB1234567890123456"
        kwargs = dict(
            cui_result=_cui(checked=False, exists=False, denumire=None),
            registry_results=[_registry(status=RegistryStatus.NO_MATCH)],
        )
        out1 = await _verdict(text, **kwargs)
        out2 = await _verdict(text, **kwargs)
        assert out1["gate"]["label"] == out2["gate"]["label"]
        assert out1["bundle"]["evidence_hash"] == out2["bundle"]["evidence_hash"]


# ─────────────────────────────────────────────────────────────
# Integrare scan_offer
# ─────────────────────────────────────────────────────────────
class TestScanOfferIntegration:
    @pytest.mark.asyncio
    async def test_scan_offer_carries_registry_results(self, onrc_snapshot):
        from services.invoice_orchestrator import scan_offer

        text = "SC Holiday Dreams SRL\nCUI: 12345678\nPachet turistic, plateste avans IBAN RO33RNCB1234567890123456"
        with patch("services.offer_entity_verifier.check_cui", new_callable=AsyncMock) as mock:
            mock.return_value = _cui(exists=True, activ=True, denumire="HOLIDAY DREAMS S.R.L.")
            result = await scan_offer(text)
        assert result.registry, "scan_offer trebuie să populeze registry"
        by_source = {r.source_id: r for r in result.registry}
        assert by_source["onrc"].status == RegistryStatus.MATCH
        assert result.bundle["context"]["registry"]
