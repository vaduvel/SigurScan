from api_models import OrchestratedScanRequest
from services.orchestrated_scan import orchestrated_engine


def test_text_input_with_structured_invoice_routes_to_invoice_lane():
    text = (
        "Buna ziua,\n\n"
        "Factura proforma nr. P-7789 din data de 17 iunie 2026, valoare 12.000 RON fara TVA, "
        "pentru servicii de dezvoltare software conform contractului nr. 45/2025.\n\n"
        "Va rugam confirmarea prin email in vederea emiterii facturii fiscale.\n\n"
        "IBAN: RO98INGB0000999900000001\n"
        "Banca: ING Bank\n\n"
        "O zi buna!"
    )

    context = orchestrated_engine._build_orchestrated_text_context(
        OrchestratedScanRequest(
            input_type="text",
            text=text,
            source_channel="android_native",
        )
    )

    assert context["input_type"] == "invoice"
    assert context["extra_fields"]["invoice_scan"] is True
    assert context["extra_fields"]["auto_invoice_route"] is True


def test_text_input_with_invoice_link_only_stays_text_or_url_context():
    text = (
        "In data de 07-06-2026 s-a emis factura ta Orange in valoare de 32.32 lei. "
        "Descarca factura aici https://orange.ro/r/KK5IMyT"
    )

    context = orchestrated_engine._build_orchestrated_text_context(
        OrchestratedScanRequest(
            input_type="text",
            text=text,
            source_channel="android_native",
        )
    )

    assert context["input_type"] == "text"
    assert "auto_invoice_route" not in context["extra_fields"]
