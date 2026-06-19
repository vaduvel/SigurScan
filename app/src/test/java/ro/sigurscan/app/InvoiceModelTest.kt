package ro.sigurscan.app

import com.google.gson.Gson
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class InvoiceModelTest {
    @Test
    fun invoiceResponseParsesAllIbansAndPaymentBeneficiary() {
        val json = """
            {
              "fields": {
                "emitent": "ATELIER DIGITAL SIBIU SRL",
                "cui": "12345678",
                "iban": "RO33RNCB1234567890123456",
                "all_ibans": [
                  "RO33RNCB1234567890123456",
                  "RO83BTRLRONCRT0299335701"
                ],
                "payment_beneficiary": "ION POPESCU"
              },
              "fraud_flags": ["MULTIPLE_IBANS", "BENEFICIARY_PERSON_MISMATCH"]
            }
        """.trimIndent()

        val response = Gson().fromJson(json, InvoiceScanResponse::class.java)

        assertEquals("ION POPESCU", response.fields?.paymentBeneficiary)
        assertEquals(
            listOf("RO33RNCB1234567890123456", "RO83BTRLRONCRT0299335701"),
            response.fields?.allIbans
        )
    }

    @Test
    fun invoiceResponseParsesBeneficiaryNameCheckGuidance() {
        val json = """
            {
              "fields": {
                "emitent": "ATELIER DIGITAL SIBIU SRL",
                "cui": "12345678",
                "iban": "RO33RNCB1234567890123456"
              },
              "beneficiary_name_check": {
                "recommended": true,
                "method": "bank_app_beneficiary_name_check",
                "local_service_hint": "SANB/BNDS dacă banca ta îl afișează",
                "title": "Verifică numele beneficiarului în aplicația băncii",
                "reason": "Nu avem o sursă publică suficientă care să confirme proprietarul IBAN-ului.",
                "expected_beneficiary": "ATELIER DIGITAL SIBIU SRL",
                "iban_masked_for_client": "RO33...3456",
                "bank_code": "RNCB",
                "bank": "BCR",
                "sanb": {
                  "payee_bank_participant": true,
                  "participant_name": "BANCA COMERCIALA ROMANA S.A.",
                  "bic": "RNCBROBU",
                  "source": "https://www.transfond.ro/pdf/Lista_bancilor_care_ofera_SANB.pdf",
                  "source_accessed_at": "2026-06-15",
                  "requires_payer_bank_participation": true
                },
                "steps": ["Începe o plată nouă.", "Verifică numele beneficiarului."],
                "privacy_note": "SigurScan nu îți cere acces la banca ta, parolă, OTP, PIN sau captură de ecran."
              }
            }
        """.trimIndent()

        val response = Gson().fromJson(json, InvoiceScanResponse::class.java)

        assertNotNull(response.beneficiaryNameCheck)
        assertEquals(true, response.beneficiaryNameCheck?.recommended)
        assertEquals("ATELIER DIGITAL SIBIU SRL", response.beneficiaryNameCheck?.expectedBeneficiary)
        assertEquals("RO33...3456", response.beneficiaryNameCheck?.ibanMaskedForClient)
        assertEquals("RNCB", response.beneficiaryNameCheck?.bankCode)
        assertEquals(true, response.beneficiaryNameCheck?.sanb?.payeeBankParticipant)
        assertEquals("RNCBROBU", response.beneficiaryNameCheck?.sanb?.bic)
        assertTrue(response.beneficiaryNameCheck?.privacyNote.orEmpty().contains("OTP"))
    }

    @Test
    fun invoiceResponseParsesGateFlagsAndUnknownPaymentDestination() {
        val json = """
            {
              "brand": "DIGI",
              "brand_match": {
                "domain_matches": null,
                "cui_matches": true,
                "iban_matches": null,
                "impersonation_risk": false
              },
              "payment_destination": {
                "matched": false,
                "brand_matches": null,
                "cui_matches": null,
                "iban_matches": null,
                "can_contribute_to_safe": false,
                "matched_entity": null,
                "match_reason": "unknown_payment_destination"
              },
              "fraud_flags": ["UNKNOWN_PAYMENT_DESTINATION"],
              "verdict_gate": {
                "label": "SUSPECT",
                "risk_level": "medium",
                "risk_score": 55,
                "reason_codes": ["value_request_needs_verification"]
              }
            }
        """.trimIndent()

        val response = Gson().fromJson(json, InvoiceScanResponse::class.java)

        assertNotNull(response.brandMatch)
        assertNull(response.brandMatch?.domainMatches)
        assertEquals(true, response.brandMatch?.cuiMatches)
        assertNull(response.brandMatch?.ibanMatches)
        assertEquals(false, response.paymentDestination?.matched)
        assertEquals(false, response.paymentDestination?.canContributeToSafe)
        assertEquals(listOf("UNKNOWN_PAYMENT_DESTINATION"), response.fraudFlags)
        assertEquals("SUSPECT", response.verdictGate?.label)
        assertEquals(55, response.verdictGate?.riskScore)
        assertEquals(listOf("value_request_needs_verification"), response.verdictGate?.reasonCodes)
    }

    @Test
    fun invoiceResponseParsesOfficialDocumentMismatch() {
        val json = """
            {
              "official_document_check": {
                "provided": true,
                "status": "mismatch",
                "risk_flag": "EFACTURA_OFFICIAL_DOCUMENT_MISMATCH",
                "matched_fields": ["cui", "total"],
                "mismatches": [
                  {
                    "field": "iban",
                    "invoice_value": "RO42INGB0000999912242622",
                    "official_value": "RO49AAAA1B31007593840000",
                    "severity": "high"
                  }
                ]
              },
              "fraud_flags": ["EFACTURA_OFFICIAL_DOCUMENT_MISMATCH"]
            }
        """.trimIndent()

        val response = Gson().fromJson(json, InvoiceScanResponse::class.java)

        assertEquals(true, response.officialDocumentCheck?.provided)
        assertEquals("mismatch", response.officialDocumentCheck?.status)
        assertEquals("EFACTURA_OFFICIAL_DOCUMENT_MISMATCH", response.officialDocumentCheck?.riskFlag)
        assertEquals(listOf("cui", "total"), response.officialDocumentCheck?.matchedFields)
        assertEquals("iban", response.officialDocumentCheck?.mismatches?.firstOrNull()?.field)
        assertEquals("high", response.officialDocumentCheck?.mismatches?.firstOrNull()?.severity)
    }

    @Test
    fun invoiceResponseParsesHumanInvoiceTruthContract() {
        val json = """
            {
              "invoice_truth": {
                "schema": "sigurscan_invoice_truth_v4",
                "verdict": "VERIFY_BEFORE_PAYING",
                "decision_status": "ACTION_REQUIRED",
                "safe_to_pay": false,
                "primary_reason_code": "UNCONFIRMED_DESTINATION",
                "display": {
                  "title": "Verifică înainte să plătești",
                  "message": "Factura nu pare fraudă, dar verifică înainte să plătești.",
                  "tone": "pending"
                },
                "verified_items": [
                  {"code": "ISSUER_CONFIRMED", "label": "Firma este verificată"}
                ],
                "unconfirmed_items": [
                  {"code": "PAYMENT_BENEFICIARY_UNCONFIRMED", "label": "Beneficiarul plății nu este confirmat automat"}
                ],
                "hard_conflicts": [
                  {"code": "VISIBLE_VS_QR_PAYMENT_HIJACK", "label": "IBAN-ul din QR diferă de cel tipărit"}
                ],
                "next_action": {
                  "type": "VERIFY_BENEFICIARY_IN_BANK",
                  "title": "Verifică numele beneficiarului în aplicația băncii",
                  "requires_authorization": false
                }
              }
            }
        """.trimIndent()

        val response = Gson().fromJson(json, InvoiceScanResponse::class.java)

        assertEquals("VERIFY_BEFORE_PAYING", response.invoiceTruth?.verdict)
        assertEquals("ACTION_REQUIRED", response.invoiceTruth?.decisionStatus)
        assertEquals(false, response.invoiceTruth?.safeToPay)
        assertEquals("Verifică înainte să plătești", response.invoiceTruth?.display?.title)
        assertEquals("pending", response.invoiceTruth?.display?.tone)
        assertEquals("ISSUER_CONFIRMED", response.invoiceTruth?.verifiedItems?.firstOrNull()?.code)
        assertEquals(
            "PAYMENT_BENEFICIARY_UNCONFIRMED",
            response.invoiceTruth?.unconfirmedItems?.firstOrNull()?.code
        )
        assertEquals("VISIBLE_VS_QR_PAYMENT_HIJACK", response.invoiceTruth?.hardConflicts?.firstOrNull()?.code)
        assertEquals("VERIFY_BENEFICIARY_IN_BANK", response.invoiceTruth?.nextAction?.type)
    }
}
