import pytest
import signal
import time

from services.b2b_invoice_signals import evaluate_b2b_invoice_signals
from services.cross_scan_knowledge import evaluate_cross_scan_knowledge
from services.invoice_orchestrator import evaluate_invoice_verdict, scan_invoice


@pytest.fixture(autouse=True)
def _clean_state(monkeypatch):
    monkeypatch.setenv("INVOICE_CACHE_HMAC_KEY", "testkey")
    from services import invoice_orchestrator as io
    from services import vendor_memory

    io._verdict_cache.clear()
    io._cui_cache.clear()
    vendor_memory._memory.clear()
    yield
    io._verdict_cache.clear()
    vendor_memory._memory.clear()


def test_b2b_signal_detector_finds_reply_to_mismatch_and_bec_combo():
    result = evaluate_b2b_invoice_signals(
        "From: facturi@furnizor-real.ro\n"
        "Reply-To: plata-furnizor@gmail.com\n"
        "Factura TEST SRL CUI RO12345678. Contul nou este RO33RNCB1234567890123456."
    )

    assert "REPLY_TO_MISMATCH" in result.flags
    assert "BEC_REPLY_TO_ACCOUNT_CHANGE" in result.flags
    assert result.metadata["from_domain"] == "furnizor-real.ro"
    assert result.metadata["reply_to_domain"] == "gmail.com"


def test_b2b_signal_detector_does_not_backtrack_on_long_non_bec_tax_text():
    text = (
        "From: ANAF RO <noreply@anaf-ro.test> Subject: ANAF rambursare taxe. "
        "Stimate contribuabil, în evidența noastră apare o notificare privind rambursare taxe. "
        "Pentru continuarea procesului este necesară validarea datelor în termen de 24 de ore. "
        "Accesează butonul de mai jos și confirmă CNP-ul, telefonul și cardul pe care se virează suma. "
    ) * 4

    class RegexTimeout(Exception):
        pass

    def _timeout(_signum, _frame):
        raise RegexTimeout

    previous_handler = signal.signal(signal.SIGALRM, _timeout)
    start = time.perf_counter()
    try:
        signal.setitimer(signal.ITIMER_REAL, 0.2)
        result = evaluate_b2b_invoice_signals(text)
        elapsed = time.perf_counter() - start
    except RegexTimeout:
        pytest.fail("B2B signal detector timed out on long non-BEC tax text")
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, previous_handler)

    assert elapsed < 0.2
    assert "BEC_EXCLUSIVE_NEW_IBAN_WITH_OLD_DETAILS_SUPPRESSION" not in result.flags
    assert "TAX_AUTHORITY_SENSITIVE_DATA_REQUEST" in result.flags


@pytest.mark.asyncio
async def test_reply_to_mismatch_plus_new_bank_account_is_dangerous():
    result = await scan_invoice(
        "From: facturi@furnizor-real.ro\n"
        "Reply-To: plata-furnizor@gmail.com\n"
        "Furnizor: TEST SRL\nCUI RO12345678\n"
        "Am schimbat contul bancar. Noul IBAN este RO33RNCB1234567890123456.\n"
        "Total 4800 RON"
    )
    verdict = evaluate_invoice_verdict(result, result.raw_text, source_channel="email")

    assert {"REPLY_TO_MISMATCH", "BEC_REPLY_TO_ACCOUNT_CHANGE", "ACCOUNT_CHANGE_LANGUAGE"} <= set(result.fraud_flags)
    assert verdict["gate"]["label"] == "DANGEROUS"


@pytest.mark.asyncio
async def test_ceo_confidential_payment_instruction_is_dangerous():
    result = await scan_invoice(
        "Directorul cere confidențialitate, nu suna și nu discuta cu nimeni. "
        "Plătește urgent în IBAN RO33RNCB1234567890123456 suma 12500 RON."
    )
    verdict = evaluate_invoice_verdict(result, result.raw_text, source_channel="email")

    assert "CEO_CONFIDENTIAL_PAYMENT" in result.fraud_flags
    assert verdict["gate"]["label"] == "DANGEROUS"


@pytest.mark.asyncio
async def test_unknown_payment_link_with_card_request_is_dangerous():
    result = await scan_invoice(
        "Factura restantă TEST SRL. Plătește aici https://pay-factura-secure.example/checkout "
        "și reconfirmă datele cardului, CVV și codul OTP."
    )
    verdict = evaluate_invoice_verdict(result, result.raw_text, source_channel="email")

    assert "PAYMENT_LINK_UNKNOWN_PSP" in result.fraud_flags
    assert "SENSITIVE_DATA_REQUESTED" in result.fraud_flags
    assert verdict["gate"]["label"] == "DANGEROUS"


@pytest.mark.asyncio
async def test_efactura_claim_without_xml_proof_blocks_safe_but_not_hard_dangerous():
    result = await scan_invoice(
        "Furnizor: TEST SRL CUI RO12345678\n"
        "Factura este în e-Factura/SPV. Plătiți IBAN RO33RNCB1234567890123456.\n"
        "Total 100 RON"
    )
    verdict = evaluate_invoice_verdict(result, result.raw_text, source_channel="android_native")

    assert "EFACTURA_CLAIM_WITHOUT_DOCUMENT" in result.fraud_flags
    assert verdict["gate"]["label"] in {"SUSPECT", "UNVERIFIED"}


@pytest.mark.asyncio
async def test_fragmented_iban_is_reassembled_from_ocr_text():
    result = await scan_invoice(
        "Furnizor: TEST SRL\n"
        "CUI: RO12345678\n"
        "IBAN: RO33 RNCB 1234\n"
        "5678 9012 3456\n"
        "Total 100 RON"
    )
    verdict = evaluate_invoice_verdict(result, result.raw_text, source_channel="android_native")

    assert result.fields.iban == "RO33RNCB1234567890123456"
    assert "RO33RNCB1234567890123456" in result.fields.all_ibans
    assert "FRAGMENTED_IBAN_PAYMENT_TARGET" in result.fraud_flags
    assert verdict["gate"]["label"] != "DANGEROUS"


@pytest.mark.asyncio
async def test_qr_payment_iban_mismatch_with_printed_invoice_is_dangerous():
    result = await scan_invoice(
        "Furnizor: TEST SRL\n"
        "CUI: RO12345678\n"
        "IBAN: RO33RNCB1234567890123456\n"
        "Total 200 RON",
        links=[
            "BCD\n002\n1\nSCT\nTEST SRL\nRO49AAAA1B31007593840000\nRON200.00\n\nFactura TEST"
        ],
    )
    verdict = evaluate_invoice_verdict(result, result.raw_text, source_channel="android_native")

    assert "QR_PRINTED_IBAN_MISMATCH" in result.fraud_flags
    assert verdict["gate"]["label"] == "DANGEROUS"


@pytest.mark.asyncio
async def test_efactura_reconciliation_payment_pretext_is_dangerous():
    result = await scan_invoice(
        "Furnizor: TEST SRL CUI RO12345678\n"
        "Factura este în e-Factura/SPV, dar trebuie validată prin reconciliere manuală.\n"
        "Achitați taxa de deblocare în IBAN RO33RNCB1234567890123456.\n"
        "Total 100 RON"
    )
    verdict = evaluate_invoice_verdict(result, result.raw_text, source_channel="email")

    assert "EFACTURA_CLAIM_WITHOUT_DOCUMENT" in result.fraud_flags
    assert "FAKE_EFACTURA_RECONCILIATION_PAYMENT" in result.fraud_flags
    assert verdict["gate"]["label"] == "DANGEROUS"


@pytest.mark.asyncio
async def test_undisclosed_intermediary_company_beneficiary_is_dangerous():
    result = await scan_invoice(
        "Factura nr. 8844\n"
        "Emitent: Service Expert SRL\n"
        "CUI: 12345678\n"
        "Total: 6200 RON\n"
        "IBAN: RO06MIDL0000000000000005\n"
        "Beneficiar plată: Procesator Rapid SRL\n"
        "Nu este necesar act adițional."
    )
    verdict = evaluate_invoice_verdict(result, result.raw_text, source_channel="email")

    assert "UNDISCLOSED_INTERMEDIARY_BENEFICIARY" in result.fraud_flags
    assert verdict["gate"]["label"] == "DANGEROUS"


@pytest.mark.asyncio
async def test_pdf_text_layer_iban_conflict_is_dangerous():
    result = await scan_invoice(
        "Factura nr. 8841\n"
        "Total: 1280 RON\n"
        "IBAN tipărit: RO39SAFE0000000000000004\n"
        "Beneficiar: Furnizor Demo SRL\n"
        "Instrucțiuni procesare: utilizați IBAN RO27FAKE0000000000000003"
    )
    verdict = evaluate_invoice_verdict(result, result.raw_text, source_channel="pdf_invoice")

    assert "MULTIPLE_IBANS" in result.fraud_flags
    assert "DOCUMENT_LAYER_IBAN_CONFLICT" in result.fraud_flags
    assert verdict["gate"]["label"] == "DANGEROUS"


def test_cross_scan_exports_b2b_invoice_signals_for_non_invoice_text():
    result = evaluate_cross_scan_knowledge(
        text=(
            "From: contabilitate@firma-real.ro\n"
            "Reply-To: plata-firma@gmail.com\n"
            "Contul nou pentru factura este RO33RNCB1234567890123456."
        ),
        claimed_brand=None,
        cui="12345678",
        source_channel="email",
    )

    assert "REPLY_TO_MISMATCH" in result["fraud_flags"]
    assert "BEC_REPLY_TO_ACCOUNT_CHANGE" in result["b2b_invoice_signals"]["flags"]


@pytest.mark.asyncio
async def test_osim_trademark_fee_from_unofficial_sender_is_dangerous():
    result = await scan_invoice(
        "From: taxe@osim-tax-ro.example\n"
        "Factura OSIM/TMview pentru inregistrare marca. Achitati azi taxa in "
        "IBAN RO49AAAA1B31007593840000. Total 1000 RON"
    )
    verdict = evaluate_invoice_verdict(result, result.raw_text, source_channel="email")

    assert "OSIM_TRADEMARK_FEE_UNOFFICIAL_SENDER" in result.fraud_flags
    assert verdict["gate"]["label"] == "DANGEROUS"


def test_osim_trademark_fee_official_portal_is_guarded():
    result = evaluate_b2b_invoice_signals(
        "OSIM taxa marca confirmata pe https://portal.osim.ro si osim.ro pentru plata oficiala."
    )

    assert "OSIM_TRADEMARK_FEE_UNOFFICIAL_SENDER" not in result.flags


@pytest.mark.asyncio
async def test_legal_demand_new_iban_is_dangerous():
    result = await scan_invoice(
        "Somatie recuperare creante: achitati urgent penalitatile in cont nou "
        "IBAN RO49AAAA1B31007593840000. Total 4200 RON"
    )
    verdict = evaluate_invoice_verdict(result, result.raw_text, source_channel="email")

    assert "LEGAL_DEMAND_PAYMENT_TO_NEW_IBAN" in result.fraud_flags
    assert verdict["gate"]["label"] == "DANGEROUS"


@pytest.mark.asyncio
async def test_domain_renewal_unknown_vendor_is_suspect_not_safe():
    result = await scan_invoice(
        "Factura reinnoire domeniu si SSL pentru firma dvs. Payment due today. "
        "IBAN RO49AAAA1B31007593840000 Total 390 RON"
    )
    verdict = evaluate_invoice_verdict(result, result.raw_text, source_channel="email")

    assert "DOMAIN_RENEWAL_INVOICE_NO_EXISTING_VENDOR" in result.fraud_flags
    assert verdict["gate"]["label"] in {"SUSPECT", "DANGEROUS"}


@pytest.mark.asyncio
async def test_saas_license_audit_urgent_payment_is_dangerous():
    result = await scan_invoice(
        "Microsoft 365 software compliance audit: plata urgenta pentru regularizare "
        "altfel suspendare. IBAN RO49AAAA1B31007593840000 Total 2500 RON"
    )
    verdict = evaluate_invoice_verdict(result, result.raw_text, source_channel="email")

    assert "SAAS_LICENSE_AUDIT_URGENT_PAYMENT" in result.fraud_flags
    assert verdict["gate"]["label"] == "DANGEROUS"


@pytest.mark.asyncio
async def test_overpayment_return_request_is_dangerous():
    result = await scan_invoice(
        "Purchase order PO-8831 achitat cu eroare plata. Returnati diferenta in "
        "IBAN RO49AAAA1B31007593840000 si pastrati comisionul."
    )
    verdict = evaluate_invoice_verdict(result, result.raw_text, source_channel="email")

    assert "PO_OR_OVERPAYMENT_RETURN_REQUEST" in result.fraud_flags
    assert verdict["gate"]["label"] == "DANGEROUS"


@pytest.mark.asyncio
async def test_payroll_data_request_in_invoice_thread_is_dangerous():
    result = await scan_invoice(
        "In threadul facturii, transmiteti date angajati, CNP si IBAN salariu "
        "pentru actualizare stat de plata."
    )
    verdict = evaluate_invoice_verdict(result, result.raw_text, source_channel="email")

    assert "PAYROLL_OR_EMPLOYEE_DATA_REQUEST_VIA_INVOICE_THREAD" in result.fraud_flags
    assert verdict["gate"]["label"] == "DANGEROUS"


@pytest.mark.asyncio
async def test_procurement_registration_fee_is_suspect():
    result = await scan_invoice(
        "Invitatie subcontractare SEAP pentru contract public. Achitati taxa de "
        "inscriere dosar in IBAN RO49AAAA1B31007593840000."
    )
    verdict = evaluate_invoice_verdict(result, result.raw_text, source_channel="email")

    assert "NEW_VENDOR_PUBLIC_PROCUREMENT_FEE" in result.fraud_flags
    assert verdict["gate"]["label"] in {"SUSPECT", "DANGEROUS"}


@pytest.mark.asyncio
async def test_urgent_payment_override_without_ticket_is_dangerous():
    result = await scan_invoice(
        "Urgent azi, nu suna, sunt in sedinta. Fa plata prin transfer in "
        "IBAN RO49AAAA1B31007593840000 fara ticket sau aprobare."
    )
    verdict = evaluate_invoice_verdict(result, result.raw_text, source_channel="email")

    assert "URGENT_PAYMENT_OVERRIDE_NO_TICKET" in result.fraud_flags
    assert verdict["gate"]["label"] == "DANGEROUS"


@pytest.mark.asyncio
async def test_payment_diversion_hold_payments_pending_new_account_is_dangerous():
    result = await scan_invoice(
        "From: finance@vendor-real.example\n"
        "Subject: facturi deschise\n"
        "Va rugam sa tineti toate platile pana la noi instructiuni. "
        "Trimiteti lista facturilor deschise; noul cont bancar va fi comunicat ulterior."
    )
    verdict = evaluate_invoice_verdict(result, result.raw_text, source_channel="email")

    assert "PAYMENT_DIVERSION_HOLD_INSTRUCTIONS" in result.fraud_flags
    assert verdict["gate"]["label"] == "DANGEROUS"


@pytest.mark.asyncio
async def test_wipo_epo_euipo_fee_from_unofficial_channel_is_dangerous():
    result = await scan_invoice(
        "From: admin@wipo-office.com\n"
        "WIPO / EPO administrative protection fee pentru marca dvs. "
        "Achitati urgent taxa de protectie in contul UA123203710000000260046015700."
    )
    verdict = evaluate_invoice_verdict(result, result.raw_text, source_channel="email")

    assert "IP_OFFICE_PAYMENT_REQUEST_UNOFFICIAL_CHANNEL" in result.fraud_flags
    assert verdict["gate"]["label"] == "DANGEROUS"
