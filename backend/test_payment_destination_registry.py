import pytest
from unittest.mock import AsyncMock, patch


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
    try:
        from services import vendor_memory as vm

        vm._memory.clear()
    except Exception:
        pass


def test_registry_loads_ppc_official_destination():
    from services.payment_destination_registry import match_payment_destination

    match = match_payment_destination(
        "RO45 BTRL RONI NCS0 0073 9101",
        claimed_brand="ppc",
        cui="22000460",
    )

    assert match["matched"] is True
    assert match["brand_matches"] is True
    assert match["brand_id"] == "ppc_energy"
    assert match["trust_tier"] == "T1_PUBLIC_OFFICIAL"
    assert match["can_contribute_to_safe"] is True
    assert match["client_distribution_allowed"] is False
    assert match["iban_masked_for_client"] == "RO45 BTRL **** **** **** 9101"


def test_registry_loads_supplemental_hidroelectrica_destination():
    from services.payment_destination_registry import match_payment_destination

    match = match_payment_destination(
        "RO63 RNCB 0072 0183 3187 0495",
        claimed_brand="hidroelectrica",
        cui="13267213",
    )

    assert match["matched"] is True
    assert match["brand_matches"] is True
    assert match["cui_matches"] is True
    assert match["brand_id"] == "hidroelectrica"
    assert match["can_contribute_to_safe"] is True


def test_registry_loads_orange_communications_official_destination():
    from services.payment_destination_registry import match_payment_destination

    match = match_payment_destination(
        "RO51 RNCB 0080 0029 7151 0001",
        claimed_brand="orange_romania_communications",
        cui="427320",
    )

    assert match["matched"] is True
    assert match["brand_matches"] is True
    assert match["brand_id"] == "orange_romania_communications"
    assert match["can_contribute_to_safe"] is True


def test_registry_loads_apa_nova_official_destination_from_utility_delta():
    from services.payment_destination_registry import match_payment_destination

    match = match_payment_destination(
        "RO84 INGB 5001 0082 2644 8910",
        claimed_brand="Apa Nova Bucuresti",
    )

    assert match["matched"] is True
    assert match["brand_matches"] is True
    assert match["brand_id"] == "apa_nova_bucuresti"
    assert match["trust_tier"] == "T1_PUBLIC_OFFICIAL"
    assert match["can_contribute_to_safe"] is True
    assert match["client_distribution_allowed"] is False


def test_registry_loads_electrica_official_destination():
    from services.payment_destination_registry import match_payment_destination

    match = match_payment_destination(
        "RO74 INGB 5001 0081 9799 8990",
        claimed_brand="electrica",
        cui="28909028",
    )

    assert match["matched"] is True
    assert match["brand_matches"] is True
    assert match["brand_id"] == "electrica_furnizare"
    assert match["can_contribute_to_safe"] is True


def test_registry_loads_cargus_logistics_fee_destination():
    from services.payment_destination_registry import match_payment_destination

    match = match_payment_destination(
        "RO75 RNCB 0081 1046 1395 0180",
        claimed_brand="cargus",
        cui="3541906",
    )

    assert match["matched"] is True
    assert match["brand_matches"] is True
    assert match["cui_matches"] is True
    assert match["brand_id"] == "cargus"
    assert match["scope"] == "logistics_fee"
    assert match["can_contribute_to_safe"] is True


def test_registry_loads_dpd_non_eu_fee_destinations():
    from services.payment_destination_registry import match_payment_destination

    match = match_payment_destination(
        "RO92 RZBR 0000 0600 0295 1611",
        claimed_brand="dpd",
        cui="9566918",
    )

    assert match["matched"] is True
    assert match["brand_matches"] is True
    assert match["cui_matches"] is True
    assert match["brand_id"] == "dpd_romania"
    assert match["scope"] == "non_eu_logistics_fee"
    assert match["can_contribute_to_safe"] is True


def test_registry_loads_dedeman_online_order_destination_but_not_masked_trezorerie():
    from services.payment_destination_registry import match_payment_destination

    bcr = match_payment_destination(
        "RO76 RNCB 0279 0143 8209 0139",
        claimed_brand="dedeman",
        cui="2816464",
    )
    masked_trezorerie = match_payment_destination(
        "RO75 TREZ 0615 069X XX00 1476",
        claimed_brand="dedeman",
        cui="2816464",
    )

    assert bcr["matched"] is True
    assert bcr["brand_matches"] is True
    assert bcr["cui_matches"] is True
    assert bcr["brand_id"] == "dedeman"
    assert bcr["scope"] == "online_order_payment"
    assert bcr["can_contribute_to_safe"] is True
    assert masked_trezorerie["matched"] is False


def test_registry_loads_raja_official_collection_destination_but_not_masked_bt():
    from services.payment_destination_registry import match_payment_destination

    ing = match_payment_destination(
        "RO26 INGB 0004 0082 1410 8913",
        claimed_brand="raja",
        cui="1890420",
    )
    masked_bt = match_payment_destination(
        "RO23 BTRL 0140 1202 T080 01XX",
        claimed_brand="raja",
        cui="1890420",
    )

    assert ing["matched"] is True
    assert ing["brand_matches"] is True
    assert ing["cui_matches"] is True
    assert ing["brand_id"] == "raja"
    assert ing["scope"] == "bill_payment"
    assert ing["can_contribute_to_safe"] is True
    assert masked_bt["matched"] is False


def test_eon_raiffeisen_billpay_iban_is_not_safe_contributor():
    from services.payment_destination_registry import match_payment_destination

    match = match_payment_destination(
        "RO86 RZBR 0000 0600 1235 5190",
        claimed_brand="eon",
        cui="22043010",
    )

    assert match["matched"] is True
    assert match["brand_matches"] is True
    assert match["can_contribute_to_safe"] is False


def test_registry_loads_apavital_official_destination_but_not_masked_bt():
    from services.payment_destination_registry import match_payment_destination

    brd = match_payment_destination(
        "RO37 BRDE 240S V477 5717 2400",
        claimed_brand="apavital",
    )
    masked_bt = match_payment_destination(
        "RO56 BTRL 0240 1202 E610 68XX",
        claimed_brand="apavital",
    )

    assert brd["matched"] is True
    assert brd["brand_matches"] is True
    assert brd["brand_id"] == "apavital_iasi"
    assert brd["can_contribute_to_safe"] is True
    assert masked_bt["matched"] is False


def test_registry_loads_contextual_insurance_destinations_without_safe_contribution():
    from services.payment_destination_registry import match_payment_destination

    omniasig = match_payment_destination(
        "RO17 RNCB 0090 0005 0611 0001",
        claimed_brand="omniasig",
        cui="14360018",
    )
    allianz = match_payment_destination(
        "RO69 BACX 0000 0000 3006 3255",
        claimed_brand="allianz tiriac",
        cui="6120740",
    )

    assert omniasig["matched"] is True
    assert omniasig["brand_matches"] is True
    assert omniasig["brand_id"] == "omniasig"
    assert omniasig["confidence"] == "medium"
    assert omniasig["can_contribute_to_safe"] is False
    assert allianz["matched"] is True
    assert allianz["brand_matches"] is True
    assert allianz["brand_id"] == "allianz_tiriac"
    assert allianz["confidence"] == "medium"
    assert allianz["can_contribute_to_safe"] is False


def test_registry_loads_vodafone_direct_debit_without_safe_contribution():
    from services.payment_destination_registry import match_payment_destination

    match = match_payment_destination(
        "RO13 RNCB 0076 0063 8603 0001",
        claimed_brand="vodafone",
        cui="8971726",
    )

    assert match["matched"] is True
    assert match["brand_matches"] is True
    assert match["cui_matches"] is True
    assert match["brand_id"] == "vodafone_romania"
    assert match["scope"] == "direct_debit"
    assert match["confidence"] == "medium"
    assert match["can_contribute_to_safe"] is False


def test_registry_loads_nextgen_official_destinations_but_not_masked_trezorerie():
    from services.payment_destination_registry import match_payment_destination

    bt = match_payment_destination(
        "RO66 BTRL 0450 1601 0072 5245",
        claimed_brand="next-gen",
        cui="24166583",
    )
    brd = match_payment_destination(
        "RO82 BRDE 450S V831 8659 4500",
        claimed_brand="nextgen communications",
        cui="24166583",
    )
    masked_trezorerie = match_payment_destination(
        "RO52 TREZ 7005 069X XX00 8541",
        claimed_brand="nextgen",
        cui="24166583",
    )

    assert bt["matched"] is True
    assert bt["brand_matches"] is True
    assert bt["cui_matches"] is True
    assert bt["brand_id"] == "nextgen_communications"
    assert bt["can_contribute_to_safe"] is True
    assert brd["matched"] is True
    assert brd["brand_matches"] is True
    assert brd["can_contribute_to_safe"] is True
    assert masked_trezorerie["matched"] is False


def test_registry_loads_apa_canal_galati_official_destination():
    from services.payment_destination_registry import match_payment_destination

    match = match_payment_destination(
        "RO69 RZBR 0000 0600 0579 0827",
        claimed_brand="Apa Canal Galati",
        cui="16914128",
    )

    assert match["matched"] is True
    assert match["brand_matches"] is True
    assert match["cui_matches"] is True
    assert match["brand_id"] == "apa_canal_galati"
    assert match["scope"] == "invoice_payment"
    assert match["confidence"] == "high"
    assert match["can_contribute_to_safe"] is True


def test_registry_loads_salubris_official_destination():
    from services.payment_destination_registry import match_payment_destination

    match = match_payment_destination(
        "RO70 BTRL RONC RT0V 1370 3401",
        claimed_brand="salubris iasi",
        cui="14816433",
    )

    assert match["matched"] is True
    assert match["brand_matches"] is True
    assert match["cui_matches"] is True
    assert match["brand_id"] == "salubris_iasi"
    assert match["scope"] == "invoice_payment"
    assert match["confidence"] == "high"
    assert match["can_contribute_to_safe"] is True


def test_registry_loads_contextual_utility_destinations_without_safe_contribution():
    from services.payment_destination_registry import match_payment_destination

    apa_olt = match_payment_destination(
        "RO33 BRDE 290S V149 9557 2900",
        claimed_brand="apa olt",
        cui="21307548",
    )
    retim = match_payment_destination(
        "RO54 BRDE 360S V071 9509 3600",
        claimed_brand="retim",
        cui="9112229",
    )
    emag_ads = match_payment_destination(
        "RO02 BTRL RONC RT00 W671 7503",
        claimed_brand="emag ads",
        cui="14399840",
    )

    assert apa_olt["matched"] is True
    assert apa_olt["brand_matches"] is True
    assert apa_olt["confidence"] == "medium"
    assert apa_olt["can_contribute_to_safe"] is False
    assert retim["matched"] is True
    assert retim["brand_matches"] is True
    assert retim["confidence"] == "medium"
    assert retim["can_contribute_to_safe"] is False
    assert emag_ads["matched"] is True
    assert emag_ads["brand_matches"] is True
    assert emag_ads["confidence"] == "medium"
    assert emag_ads["can_contribute_to_safe"] is False


def test_registry_loads_compania_apa_brasov_official_destination_but_not_masked_trezorerie():
    from services.payment_destination_registry import match_payment_destination

    unicredit = match_payment_destination(
        "RO78 BACX 0000 0006 4257 9002",
        claimed_brand="apa_brasov",
        cui="1096128",
    )
    masked_trezorerie = match_payment_destination(
        "RO63 TREZ 1315 069X XX00 0650",
        claimed_brand="apa_brasov",
        cui="1096128",
    )

    assert unicredit["matched"] is True
    assert unicredit["brand_matches"] is True
    assert unicredit["cui_matches"] is True
    assert unicredit["brand_id"] == "compania_apa_brasov"
    assert unicredit["can_contribute_to_safe"] is True
    assert masked_trezorerie["matched"] is False


def test_registry_knows_brand_destinations_by_cui_when_brand_detection_misses():
    from services.payment_destination_registry import match_payment_destination

    match = match_payment_destination(
        "RO49AAAA1B31007593840000",
        claimed_brand=None,
        cui="1096128",
        issuer_name="Compania Apa Brasov",
    )

    assert match["matched"] is False
    assert match["registry_has_brand_destinations"] is True
    assert match["trust_tier"] == "T4_STRUCTURALLY_VALID_UNKNOWN"
    assert match["can_contribute_to_safe"] is False


@pytest.mark.asyncio
async def test_cui_official_destination_can_confirm_brand_not_in_static_registry():
    from services.anaf_cui import CuiResult
    from services.invoice_orchestrator import evaluate_invoice_verdict, scan_invoice

    cui = CuiResult(
        exists=True,
        checked=True,
        denumire="Aquatim SA",
        activ=True,
        data_inactivare=None,
        platitor_tva=True,
        enrolled_efactura=False,
        raw=None,
    )
    with patch("services.invoice_orchestrator.check_cui", new_callable=AsyncMock) as mock_cui:
        mock_cui.return_value = cui
        result = await scan_invoice(
            "Furnizor: Aquatim S.A.\n"
            "CUI: RO3041480\n"
            "IBAN RO62BUCU1072235330509RON\n"
            "Total 119 RON"
        )

    verdict = evaluate_invoice_verdict(result, result.raw_text, source_channel="android_native")

    assert result.brand is None
    assert result.payment_destination["matched"] is True
    assert result.payment_destination["cui_matches"] is True
    assert verdict["gate"]["label"] == "SAFE"


@pytest.mark.asyncio
async def test_known_cui_unknown_payment_destination_does_not_become_safe_when_brand_detection_misses():
    from services.anaf_cui import CuiResult
    from services.invoice_orchestrator import evaluate_invoice_verdict, scan_invoice

    cui = CuiResult(
        exists=True,
        checked=True,
        denumire="Compania Apa Brasov",
        activ=True,
        data_inactivare=None,
        platitor_tva=True,
        enrolled_efactura=True,
        raw=None,
    )
    with patch("services.invoice_orchestrator.check_cui", new_callable=AsyncMock) as mock_cui:
        mock_cui.return_value = cui
        result = await scan_invoice(
            "Furnizor: Compania Apa Brasov\n"
            "CUI: RO1096128\n"
            "IBAN RO49AAAA1B31007593840000\n"
            "Data emiterii: 01.06.2026\n"
            "Scadenta: 15.06.2026\n"
            "Total 8500 RON"
        )

    verdict = evaluate_invoice_verdict(result, result.raw_text, source_channel="android_native")

    assert result.brand is None
    assert result.payment_destination["matched"] is False
    assert result.payment_destination["registry_has_brand_destinations"] is True
    assert "UNKNOWN_PAYMENT_DESTINATION" in result.fraud_flags
    assert verdict["bundle"]["identity"]["status"] == "unknown"
    assert verdict["gate"]["label"] == "SUSPECT"


@pytest.mark.asyncio
async def test_ppc_official_iban_can_support_safe_invoice():
    from services.anaf_cui import CuiResult
    from services.invoice_orchestrator import evaluate_invoice_verdict, scan_invoice

    cui = CuiResult(
        exists=True,
        checked=True,
        denumire="PPC Energie SA",
        activ=True,
        data_inactivare=None,
        platitor_tva=True,
        enrolled_efactura=False,
        raw=None,
    )
    with patch("services.invoice_orchestrator.check_cui", new_callable=AsyncMock) as mock_cui:
        mock_cui.return_value = cui
        result = await scan_invoice(
            "Furnizor: PPC Energie S.A.\n"
            "CUI: RO22000460\n"
            "IBAN RO45 BTRL RONI NCS0 0073 9101\n"
            "Total 119 RON"
        )

    verdict = evaluate_invoice_verdict(result, result.raw_text, source_channel="android_native")

    assert result.payment_destination["matched"] is True
    assert verdict["gate"]["label"] == "SAFE"


@pytest.mark.asyncio
async def test_ppc_unknown_iban_does_not_become_safe():
    from services.anaf_cui import CuiResult
    from services.invoice_orchestrator import evaluate_invoice_verdict, scan_invoice

    cui = CuiResult(
        exists=True,
        checked=True,
        denumire="PPC Energie SA",
        activ=True,
        data_inactivare=None,
        platitor_tva=True,
        enrolled_efactura=False,
        raw=None,
    )
    with patch("services.invoice_orchestrator.check_cui", new_callable=AsyncMock) as mock_cui:
        mock_cui.return_value = cui
        result = await scan_invoice(
            "Furnizor: PPC Energie S.A.\n"
            "CUI: RO22000460\n"
            "IBAN RO49AAAA1B31007593840000\n"
            "Total 119 RON"
        )

    verdict = evaluate_invoice_verdict(result, result.raw_text, source_channel="android_native")

    assert result.payment_destination["matched"] is False
    assert result.payment_destination["registry_has_brand_destinations"] is True
    assert verdict["gate"]["label"] != "SAFE"
    assert verdict["gate"]["label"] != "DANGEROUS"
    assert verdict["gate"]["label"] == "SUSPECT"


@pytest.mark.asyncio
async def test_destination_official_for_other_brand_is_dangerous_mismatch():
    from services.anaf_cui import CuiResult
    from services.invoice_orchestrator import evaluate_invoice_verdict, scan_invoice

    cui = CuiResult(
        exists=True,
        checked=True,
        denumire="E.ON Energie Romania SA",
        activ=True,
        data_inactivare=None,
        platitor_tva=True,
        enrolled_efactura=False,
        raw=None,
    )
    with patch("services.invoice_orchestrator.check_cui", new_callable=AsyncMock) as mock_cui:
        mock_cui.return_value = cui
        result = await scan_invoice(
            "Furnizor: E.ON Energie Romania S.A.\n"
            "CUI: RO22043010\n"
            "IBAN RO45 BTRL RONI NCS0 0073 9101\n"
            "Total 119 RON"
        )

    verdict = evaluate_invoice_verdict(result, result.raw_text, source_channel="android_native")

    assert "PAYMENT_DESTINATION_BRAND_MISMATCH" in result.fraud_flags
    assert result.payment_destination["matched"] is True
    assert result.payment_destination["brand_matches"] is False
    assert verdict["gate"]["label"] == "DANGEROUS"


@pytest.mark.asyncio
async def test_generic_real_company_unknown_payment_destination_is_safe_with_bank_check_guidance():
    from services.anaf_cui import CuiResult
    from services.invoice_orchestrator import evaluate_invoice_verdict, scan_invoice

    cui = CuiResult(
        exists=True,
        checked=True,
        denumire="SC REAL SRL",
        activ=True,
        data_inactivare=None,
        platitor_tva=True,
        enrolled_efactura=False,
        raw=None,
    )
    with patch("services.invoice_orchestrator.check_cui", new_callable=AsyncMock) as mock_cui:
        mock_cui.return_value = cui
        result = await scan_invoice(
            "Furnizor: SC REAL SRL\n"
            "CUI: RO12345678\n"
            "IBAN RO49AAAA1B31007593840000\n"
            "Data emiterii: 01.06.2026\n"
            "Scadenta: 15.06.2026\n"
            "Total 8500 RON"
        )

    verdict = evaluate_invoice_verdict(result, result.raw_text, source_channel="android_native")

    assert "UNKNOWN_PAYMENT_DESTINATION" not in result.fraud_flags
    assert result.payment_destination["matched"] is False
    assert verdict["bundle"]["identity"]["status"] == "coherent"
    assert result.beneficiary_name_check is not None
    assert result.beneficiary_name_check["recommended"] is True
    assert verdict["gate"]["label"] == "SAFE"
    assert verdict["gate"]["reason_codes"] == ["positive_provenance_clean"]
    assert verdict["gate"]["is_final"] is True


@pytest.mark.asyncio
async def test_sameday_payment_request_by_sms_violates_never_asks():
    from services.invoice_orchestrator import evaluate_invoice_verdict, scan_invoice

    result = await scan_invoice(
        "SAMEDAY CUI RO21303530: ai o taxa de livrare neachitata de 9.99 RON. "
        "Plateste acum prin virament in IBAN RO49AAAA1B31007593840000."
    )

    verdict = evaluate_invoice_verdict(result, result.raw_text, source_channel="sms")

    assert "payment_request_sms" in verdict["bundle"]["identity"]["violated_never_asks"]
    assert verdict["gate"]["label"] == "DANGEROUS"
    assert "never_asks_violated:payment_request_sms" in verdict["gate"]["reason_codes"]


@pytest.mark.asyncio
async def test_sameday_payment_request_on_native_invoice_is_not_never_asks_dangerous():
    from services.invoice_orchestrator import evaluate_invoice_verdict, scan_invoice

    result = await scan_invoice(
        "Factura SAMEDAY\n"
        "CUI RO21303530\n"
        "Taxa transport 9.99 RON\n"
        "IBAN RO49AAAA1B31007593840000"
    )

    verdict = evaluate_invoice_verdict(result, result.raw_text, source_channel="android_native")

    assert verdict["bundle"]["identity"]["violated_never_asks"] == []
    assert verdict["gate"]["label"] != "DANGEROUS"


@pytest.mark.asyncio
async def test_ghiseul_payment_obligation_by_sms_violates_never_asks():
    from services.invoice_orchestrator import evaluate_invoice_verdict, scan_invoice

    result = await scan_invoice(
        "Ghiseul.ro: aveti o obligatie de plata de 129 RON. "
        "Platiti acum pe https://ghiseul-plata.example/regularizare"
    )

    verdict = evaluate_invoice_verdict(result, result.raw_text, source_channel="sms")

    assert "payment_obligation_sms" in verdict["bundle"]["identity"]["violated_never_asks"]
    assert verdict["gate"]["label"] == "DANGEROUS"


@pytest.mark.asyncio
async def test_fan_courier_sms_card_request_violates_never_asks():
    from services.invoice_orchestrator import evaluate_invoice_verdict, scan_invoice

    result = await scan_invoice(
        "FAN Courier: taxa colet 7.99 RON. Completeaza datele cardului si codul CVV "
        "pentru livrare."
    )

    verdict = evaluate_invoice_verdict(result, result.raw_text, source_channel="sms")

    assert {"card_number", "cvv"} <= set(verdict["bundle"]["identity"]["violated_never_asks"])
    assert verdict["gate"]["label"] == "DANGEROUS"


@pytest.mark.asyncio
async def test_posta_romana_sms_delivery_tax_link_violates_never_asks():
    from services.invoice_orchestrator import evaluate_invoice_verdict, scan_invoice

    result = await scan_invoice(
        "Posta Romana: coletul necesita taxa de livrare 6.50 RON. "
        "Plateste pe https://posta-confirmare.example/card si introdu CVV."
    )

    verdict = evaluate_invoice_verdict(result, result.raw_text, source_channel="sms")

    assert "delivery_fee_sms" in verdict["bundle"]["identity"]["violated_never_asks"]
    assert "cvv" in verdict["bundle"]["identity"]["violated_never_asks"]
    assert verdict["gate"]["label"] == "DANGEROUS"


@pytest.mark.asyncio
async def test_banca_transilvania_sms_pin_cvv_violates_never_asks():
    from services.invoice_orchestrator import evaluate_invoice_verdict, scan_invoice

    result = await scan_invoice(
        "Banca Transilvania: actualizeaza contul. Introdu PIN-ul cardului si CVV. "
        "Suma blocata 10 RON."
    )

    verdict = evaluate_invoice_verdict(result, result.raw_text, source_channel="sms")

    assert {"pin", "cvv"} <= set(verdict["bundle"]["identity"]["violated_never_asks"])
    assert verdict["gate"]["label"] == "DANGEROUS"


@pytest.mark.asyncio
async def test_anaf_sms_link_request_violates_never_asks():
    from services.invoice_orchestrator import evaluate_invoice_verdict, scan_invoice

    result = await scan_invoice(
        "ANAF: aveti o suma de recuperat. Accesati https://anaf-formular.example "
        "si introduceti date bancare."
    )

    verdict = evaluate_invoice_verdict(result, result.raw_text, source_channel="sms")

    assert {"link_request", "financial_data"} <= set(verdict["bundle"]["identity"]["violated_never_asks"])
    assert verdict["gate"]["label"] == "DANGEROUS"


@pytest.mark.asyncio
async def test_politia_safe_account_transfer_violates_never_asks():
    from services.invoice_orchestrator import evaluate_invoice_verdict, scan_invoice

    result = await scan_invoice(
        "Politia Romana: pentru verificare muta banii intr-un cont de siguranta. "
        "Un ofiter iti va cere codul OTP."
    )

    verdict = evaluate_invoice_verdict(result, result.raw_text, source_channel="phone")

    assert {"safe_account_transfer", "otp"} <= set(verdict["bundle"]["identity"]["violated_never_asks"])
    assert verdict["gate"]["label"] == "DANGEROUS"


@pytest.mark.asyncio
async def test_orange_password_or_bank_data_request_violates_never_asks():
    from services.invoice_orchestrator import evaluate_invoice_verdict, scan_invoice

    result = await scan_invoice(
        "Orange: pentru factura restanta confirma parola contului si contul bancar."
    )

    verdict = evaluate_invoice_verdict(result, result.raw_text, source_channel="sms")

    assert {"password", "financial_data"} <= set(verdict["bundle"]["identity"]["violated_never_asks"])
    assert verdict["gate"]["label"] == "DANGEROUS"


@pytest.mark.asyncio
async def test_bcr_remote_access_and_safe_account_transfer_violates_never_asks():
    from services.invoice_orchestrator import evaluate_invoice_verdict, scan_invoice

    result = await scan_invoice(
        "BCR: instaleaza AnyDesk si transfera banii intr-un cont de siguranta "
        "pentru verificarea tranzactiilor."
    )

    verdict = evaluate_invoice_verdict(result, result.raw_text, source_channel="phone")

    assert {"remote_access", "safe_account_transfer"} <= set(verdict["bundle"]["identity"]["violated_never_asks"])
    assert verdict["gate"]["label"] == "DANGEROUS"


@pytest.mark.asyncio
async def test_ing_crypto_safe_account_and_otp_violates_never_asks():
    from services.invoice_orchestrator import evaluate_invoice_verdict, scan_invoice

    result = await scan_invoice(
        "ING: muta banii intr-un cont sigur si cumpara crypto la ATM. "
        "Confirma codul OTP primit."
    )

    verdict = evaluate_invoice_verdict(result, result.raw_text, source_channel="phone")

    assert {"safe_account_transfer", "crypto", "otp"} <= set(verdict["bundle"]["identity"]["violated_never_asks"])
    assert verdict["gate"]["label"] == "DANGEROUS"


@pytest.mark.asyncio
async def test_revolut_phone_safe_account_and_remote_access_violates_never_asks():
    from services.invoice_orchestrator import evaluate_invoice_verdict, scan_invoice

    result = await scan_invoice(
        "Revolut: pentru siguranta instaleaza TeamViewer si muta banii "
        "intr-un cont securizat."
    )

    verdict = evaluate_invoice_verdict(result, result.raw_text, source_channel="phone")

    assert {"remote_access", "safe_account_transfer"} <= set(verdict["bundle"]["identity"]["violated_never_asks"])
    assert verdict["gate"]["label"] == "DANGEROUS"


@pytest.mark.asyncio
async def test_dhl_customs_payment_sms_is_not_never_asks_violation():
    from services.invoice_orchestrator import evaluate_invoice_verdict, scan_invoice

    result = await scan_invoice(
        "DHL: ai taxe vamale de achitat pentru colet. Plateste prin linkul securizat."
    )

    verdict = evaluate_invoice_verdict(result, result.raw_text, source_channel="sms")

    assert verdict["bundle"]["identity"]["violated_never_asks"] == []


@pytest.mark.asyncio
async def test_dhl_non_customs_delivery_fee_sms_violates_never_asks():
    from services.invoice_orchestrator import evaluate_invoice_verdict, scan_invoice

    result = await scan_invoice(
        "DHL: coletul tau este blocat. Achita taxa de livrare suplimentara "
        "si confirma datele cardului."
    )

    verdict = evaluate_invoice_verdict(result, result.raw_text, source_channel="sms")

    assert "delivery_fee_sms" in verdict["bundle"]["identity"]["violated_never_asks"]
    assert "card_number" in verdict["bundle"]["identity"]["violated_never_asks"]
    assert verdict["gate"]["label"] == "DANGEROUS"


@pytest.mark.asyncio
async def test_orange_card_and_otp_request_uses_official_audit_delta():
    from services.invoice_orchestrator import evaluate_invoice_verdict, scan_invoice

    result = await scan_invoice(
        "Orange: pentru reactivarea contului confirma numarul cardului si codul OTP."
    )

    verdict = evaluate_invoice_verdict(result, result.raw_text, source_channel="sms")

    assert {"card_number", "otp"} <= set(verdict["bundle"]["identity"]["violated_never_asks"])
    assert verdict["gate"]["label"] == "DANGEROUS"


@pytest.mark.asyncio
async def test_brd_otp_and_remote_access_use_official_audit_delta():
    from services.invoice_orchestrator import evaluate_invoice_verdict, scan_invoice

    result = await scan_invoice(
        "BRD securitate: instaleaza AnyDesk si comunica OTP-ul pentru verificare."
    )

    verdict = evaluate_invoice_verdict(result, result.raw_text, source_channel="sms")

    assert {"otp", "remote_access"} <= set(verdict["bundle"]["identity"]["violated_never_asks"])
    assert verdict["gate"]["label"] == "DANGEROUS"
