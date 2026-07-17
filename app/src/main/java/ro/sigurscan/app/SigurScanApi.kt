package ro.sigurscan.app

import com.google.gson.annotations.SerializedName
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import retrofit2.http.Body
import retrofit2.http.GET
import retrofit2.http.Path
import retrofit2.http.POST
import retrofit2.http.Query

data class UrlscanSandboxSubmitRequest(
    val url: String,
    val visibility: String = "private",
    val country: String? = null,
    val customagent: String? = null,
    @SerializedName("source_channel") val sourceChannel: String = "android_native"
)

data class UrlscanSandboxSubmitResponse(
    val uuid: String? = null,
    val status: String? = null,
    @SerializedName("report_url") val reportUrl: String? = null,
    @SerializedName("result_url") val resultUrl: String? = null,
    @SerializedName("screenshot_url") val screenshotUrl: String? = null,
    @SerializedName("submitted_url") val submittedUrl: String? = null
)

data class UrlscanSandboxResultResponse(
    val uuid: String? = null,
    val status: String? = null,
    val verdict: String? = null,
    val severity: String? = null,
    val details: String? = null,
    @SerializedName("final_url") val finalUrl: String? = null,
    @SerializedName("report_url") val reportUrl: String? = null,
    @SerializedName("screenshot_url") val screenshotUrl: String? = null
)

data class ScanResponse(
    @SerializedName("scan_id") val scanId: String,
    @SerializedName("risk_score") val riskScore: Int,
    @SerializedName("risk_level") val riskLevel: String,
    @SerializedName("is_final") val isFinal: Boolean? = null,
    @SerializedName("user_risk_level") val userRiskLevel: String? = null,
    @SerializedName("user_risk_label") val userRiskLabel: String? = null,
    @SerializedName("detected_family") val detectedFamily: String? = null,
    @SerializedName("claimed_brand") val claimedBrand: String? = null,
    val reasons: List<String>? = null,
    @SerializedName("redacted_text") val redactedText: String? = null,
    @SerializedName("ai_verdict") val aiVerdict: String? = null,
    @SerializedName("ai_explanation") val aiExplanation: String? = null,
    @SerializedName("offer_analysis") val offerAnalysis: String? = null,
    @SerializedName("key_dangers") val keyDangers: List<String>? = null,
    @SerializedName("safe_actions") val safeActions: List<String>? = null,
    @SerializedName("legal") val legal: LegalSection? = null,
    @SerializedName("action_plan") val actionPlan: ActionPlan? = null,
    val evidence: Map<String, Any>? = null,
    @SerializedName("extracted_urls") val extractedUrls: List<Map<String, Any>>? = null,
    @SerializedName("resolved_urls") val resolvedUrls: List<Map<String, Any>>? = null,
    @SerializedName("buttons") val buttons: List<Map<String, Any>>? = null,
    @SerializedName("email_auth") val emailAuth: Map<String, Any>? = null
)

// Strat educativ „Ce spune legea" (PR5). Clientul randează verbatim, sub verdict;
// nu calculează nimic și nu modifică verdictul.
data class LegalCard(
    val id: String? = null,
    val title: String? = null,
    val summary: String? = null,
    val actions: List<String>? = null,
    @SerializedName("source_refs") val sourceRefs: List<String>? = null
)

data class LegalSection(
    val label: String? = null,
    val cards: List<LegalCard>? = null,
    val disclaimer: String? = null
)

data class ActionPlanStep(
    val order: Int? = null,
    val urgency: String? = null,
    val title: String? = null,
    val detail: String? = null,
    val channel: String? = null,
    @SerializedName("legal_card_id") val legalCardId: String? = null
)

data class ActionPlanReportChannel(
    val name: String? = null,
    val contact: String? = null,
    @SerializedName("for") val purpose: String? = null,
    @SerializedName("prefilled_subject") val prefilledSubject: String? = null,
    @SerializedName("prefilled_body") val prefilledBody: String? = null
)

data class ActionPlanReportPackage(
    val channels: List<ActionPlanReportChannel>? = null,
    val disclaimer: String? = null
)

data class OneTapReportRequest(
    @SerializedName("target_type") val targetType: String = "url",
    @SerializedName("target_redacted") val targetRedacted: String = "[redactat]",
    val family: String? = null,
    val verdict: String = "SUSPECT",
    @SerializedName("redacted_summary") val redactedSummary: String? = null
)

data class OneTapReportTarget(
    val type: String? = null,
    @SerializedName("value_redacted") val valueRedacted: String? = null
)

data class OneTapReportPackage(
    @SerializedName("generated_for") val generatedFor: Map<String, Any>? = null,
    @SerializedName("redacted_summary") val redactedSummary: String? = null,
    val channels: List<ActionPlanReportChannel>? = null,
    val disclaimer: String? = null
)

data class ActionPlan(
    val label: String? = null,
    val verdict: String? = null,
    val family: String? = null,
    val impacts: List<String>? = null,
    val steps: List<ActionPlanStep>? = null,
    @SerializedName("report_package") val reportPackage: ActionPlanReportPackage? = null,
    val disclaimer: String? = null
)

data class ActionPlanRequest(
    val verdict: String = "SUSPECT",
    val family: String? = null,
    val impacts: List<String>? = null,
    @SerializedName("target_type") val targetType: String? = null,
    @SerializedName("target_redacted") val targetRedacted: String? = null,
    @SerializedName("document_type") val documentType: String? = null
)

data class AudioSemanticReviewRequest(
    @SerializedName("transcript_redacted") val transcriptRedacted: String,
    val locale: String = "ro-RO",
    val channel: String = "call_live",
    @SerializedName("local_verdict") val localVerdict: String = "UNVERIFIED",
    @SerializedName("local_reason_codes") val localReasonCodes: List<String> = emptyList(),
    @SerializedName("claimed_identity") val claimedIdentity: String? = null,
    @SerializedName("arc_family") val arcFamily: String? = null
)

data class AudioSemanticReviewPayload(
    val status: String? = null,
    @SerializedName("risk_class") val riskClass: String? = null,
    @SerializedName("matched_family") val matchedFamily: String? = null,
    @SerializedName("reason_codes") val reasonCodes: List<String> = emptyList(),
    val source: String? = null
)

data class AudioSemanticReviewResponse(
    val status: String? = null,
    @SerializedName("semantic_review") val semanticReview: AudioSemanticReviewPayload? = null,
    @SerializedName("reason_codes") val reasonCodes: List<String> = emptyList(),
    val escalates: Boolean = false,
    val model: String? = null,
    val privacy: Map<String, Any>? = null
)

data class ExtractionResponse(
    @SerializedName("input_type") val inputType: String? = null,
    @SerializedName("source_channel") val sourceChannel: String? = null,
    @SerializedName("redacted_text") val redactedText: String? = null,
    @SerializedName("html_content") val htmlContent: String? = null,
    @SerializedName("extracted_urls") val extractedUrls: List<String>? = null,
    @SerializedName("qr_payloads") val qrPayloads: List<String>? = null,
    val warning: String? = null,
    @SerializedName("hidden_url_visibility") val hiddenUrlVisibility: Boolean? = null,
    val buttons: List<Map<String, Any>>? = null,
    @SerializedName("email_auth") val emailAuth: Map<String, Any>? = null,
    @SerializedName("email_evidence_ledger") val emailEvidenceLedger: Map<String, Any>? = null,
    @SerializedName("email_compound_active") val emailCompoundActive: Boolean = false
)

data class OrchestratedScanRequest(
    @SerializedName("input_type") val inputType: String,
    val text: String? = null,
    val url: String? = null,
    @SerializedName("html_content") val htmlContent: String? = null,
    @SerializedName("source_channel") val sourceChannel: String = "android_native",
    @SerializedName("email_auth") val emailAuth: Map<String, Any>? = null,
    @SerializedName("email_evidence_ledger") val emailEvidenceLedger: Map<String, Any>? = null,
    @SerializedName("email_compound_active") val emailCompoundActive: Boolean = false
)

data class OrchestratedPillarState(
    val status: String? = null,
    val required: Boolean? = null,
    val details: String? = null,
    val ref: String? = null
)

data class OrchestratedPreview(
    val status: String? = null,
    val source: String? = null,
    val reason: String? = null,
    val details: String? = null,
    @SerializedName("screenshot_url") val screenshotUrl: String? = null,
    @SerializedName("report_url") val reportUrl: String? = null,
    @SerializedName("final_url") val finalUrl: String? = null
)

data class OrchestratedScanResponse(
    @SerializedName("scan_id") val scanId: String,
    val status: String? = null,
    @SerializedName("status_message") val statusMessage: String? = null,
    @SerializedName("poll_after_ms") val pollAfterMs: Long? = null,
    val pillars: Map<String, OrchestratedPillarState>? = null,
    val preview: OrchestratedPreview? = null,
    val result: ScanResponse? = null
)

data class ReadinessResponse(
    val status: String? = null,
    @SerializedName("readiness_score") val readinessScore: Float? = null,
    @SerializedName("readiness_components") val readinessComponents: Map<String, Float>? = null,
    val trend: Map<String, Any>? = null
)

data class QualityResponse(
    @SerializedName("items_evaluated") val itemsEvaluated: Int? = null,
    val summary: Map<String, Any>? = null
)

data class FeedbackRequest(
    @SerializedName("scan_id") val scanId: String,
    val feedback: String, // correct, false_positive, false_negative
    @SerializedName("predicted_risk_score") val predictedRiskScore: Int? = null,
    @SerializedName("risk_level") val riskLevel: String? = null,
    @SerializedName("signal_ids") val signalIds: List<String> = emptyList(),
    val notes: String? = null
)

data class FeedbackSamplesResponse(
    @SerializedName("recent_samples") val recentSamples: List<FeedbackSampleItem> = emptyList(),
    @SerializedName("top_false_positive") val topFalsePositive: List<String> = emptyList(),
    @SerializedName("top_false_negative") val topFalseNegative: List<String> = emptyList()
)

data class FeedbackSampleItem(
    @SerializedName("scan_id") val scanId: String,
    @SerializedName("user_feedback") val userFeedback: String,
    @SerializedName("detected_family") val detectedFamily: String? = null,
    @SerializedName("risk_level") val riskLevel: String? = null,
    val timestamp: String? = null
)

data class ReputationCacheStats(
    @SerializedName("cache_hit_ratio") val cacheHitRatio: Float? = null,
    @SerializedName("entries") val entries: Int? = null,
    @SerializedName("cached_domains") val cachedDomains: Int? = null,
    @SerializedName("last_updated") val lastUpdated: String? = null
)

data class CampaignRiskLocation(
    @SerializedName("lat") val lat: Double? = null,
    @SerializedName("lon") val lon: Double? = null,
)

data class ScamCampaign(
    val id: String,
    val title: String,
    val brand: String,
    @SerializedName("riskLevel") val riskLevel: String? = null,
    @SerializedName("risk_level") val riskLevelSnake: String? = null,
    val description: String,
    @SerializedName("safeAction") val safeAction: String? = null,
    @SerializedName("safe_action") val safeActionSnake: String? = null,
    @SerializedName("scanCount") val scanCount: Int? = null,
    @SerializedName("scan_count") val scanCountSnake: Int? = null,
    @SerializedName("lastSeen") val lastSeen: String? = null,
    @SerializedName("last_seen") val lastSeenSnake: String? = null,
    @SerializedName("status") val status: String? = null,
    @SerializedName("region") val region: String? = null,
    @SerializedName("lat") val lat: Double? = null,
    @SerializedName("lon") val lon: Double? = null
) {
    val risk: String
        get() = riskLevel ?: riskLevelSnake ?: "medium"

    val count: Int
        get() = scanCount ?: scanCountSnake ?: 0

    val safeActionText: String
        get() = safeAction ?: safeActionSnake ?: "Ai grijă înainte de a apasă"

    val lastSeenText: String
        get() = lastSeen ?: lastSeenSnake ?: ""
}

data class RadarHotCampaign(
    @SerializedName("campaign_id") val campaignId: String,
    val family: String? = null,
    @SerializedName("warning_title") val warningTitle: String? = null,
    @SerializedName("warning_body") val warningBody: String? = null,
    val regions: List<String> = emptyList(),
    @SerializedName("phone_hash_prefixes") val phoneHashPrefixes: List<String> = emptyList(),
    val confidence: String? = null
)

data class RadarNumberReputation(
    @SerializedName("phone_hash") val phoneHash: String,
    val status: String? = null,
    val family: String? = null,
    @SerializedName("bucket_count") val bucketCount: String? = null
)

data class RadarHotCacheResponse(
    @SerializedName("generated_at") val generatedAt: String? = null,
    @SerializedName("ttl_minutes") val ttlMinutes: Int = 60,
    @SerializedName("hot_campaigns") val hotCampaigns: List<RadarHotCampaign> = emptyList(),
    @SerializedName("number_reputation") val numberReputation: List<RadarNumberReputation> = emptyList()
)

data class BtrSourceRef(
    val url: String? = null,
    val publisher: String? = null,
    @SerializedName("accessed_at") val accessedAt: String? = null,
    val confidence: String? = null
)

data class BtrManifest(
    @SerializedName("manifest_id") val manifestId: String,
    val type: String? = null,
    @SerializedName("display_name") val displayName: String,
    val category: String? = null,
    val country: String? = null,
    @SerializedName("official_domains") val officialDomains: List<String> = emptyList(),
    @SerializedName("official_email_domains") val officialEmailDomains: List<String> = emptyList(),
    @SerializedName("official_shortcodes") val officialShortcodes: List<String> = emptyList(),
    @SerializedName("official_phones_e164") val officialPhonesE164: List<String> = emptyList(),
    @SerializedName("official_channels") val officialChannels: List<String> = emptyList(),
    @SerializedName("never_asks") val neverAsks: List<String> = emptyList(),
    @SerializedName("never_does") val neverDoes: List<String> = emptyList(),
    @SerializedName("source_refs") val sourceRefs: List<BtrSourceRef> = emptyList(),
    @SerializedName("last_verified_at") val lastVerifiedAt: String? = null,
    val confidence: String? = null,
    @SerializedName("review_status") val reviewStatus: String? = null
)

data class BtrSyncResponse(
    val changed: Boolean = false,
    val version: String? = null,
    @SerializedName("generated_at") val generatedAt: String? = null,
    val manifests: List<BtrManifest>? = null,
    val count: Int = 0
)

// P-RULES Felia 3 — /v1/rules/sync (semantic rules manifest, version-gated).
data class RulesManifestPatternDto(
    val pattern: String,
    val flags: List<String> = emptyList()
)

data class RulesManifestDto(
    val version: String? = null,
    val groups: Map<String, List<RulesManifestPatternDto>> = emptyMap()
)

data class RulesSyncResponse(
    val changed: Boolean = false,
    val version: String? = null,
    val manifest: RulesManifestDto? = null,
    val count: Int = 0
)

data class CirclePairRequest(
    @SerializedName("protected_id") val protectedId: String,
    @SerializedName("verifier_id") val verifierId: String,
    val consent: String = "explicit"
)

data class CircleLinkResponse(
    @SerializedName("link_id") val linkId: String,
    @SerializedName("protected_user_id") val protectedUserId: String,
    @SerializedName("verifier_user_id") val verifierUserId: String,
    val consent: String? = null,
    val active: Boolean = true,
    val revocable: Boolean = true,
    @SerializedName("created_at") val createdAt: Double? = null,
    @SerializedName("revoked_at") val revokedAt: Double? = null,
    @SerializedName("verifier_can_read_content") val verifierCanReadContent: Boolean = false,
    @SerializedName("verifier_can_surveil") val verifierCanSurveil: Boolean = false
)

data class CirclePingRequest(
    @SerializedName("link_id") val linkId: String,
    val claim: String = "caller_claims_to_be_verifier"
)

data class VerificationPingResponse(
    @SerializedName("ping_id") val pingId: String,
    @SerializedName("link_id") val linkId: String,
    val claim: String? = null,
    @SerializedName("payload_class") val payloadClass: String? = null,
    @SerializedName("default_on_timeout") val defaultOnTimeout: String? = null,
    @SerializedName("latency_target_s") val latencyTargetSeconds: Int? = null,
    val status: String? = null,
    @SerializedName("verifier_response") val verifierResponse: String? = null,
    @SerializedName("created_at") val createdAt: Double? = null,
    @SerializedName("resolved_at") val resolvedAt: Double? = null,
    @SerializedName("raw_stored") val rawStored: Boolean = false,
    val delivery: Map<String, Any>? = null
)

data class CircleRespondRequest(
    @SerializedName("ping_id") val pingId: String,
    val response: String
)

data class CirclePingOutcome(
    val status: String? = null,
    val verified: Boolean = false,
    @SerializedName("recommended_action") val recommendedAction: Map<String, Any>? = null
)

data class CircleRevokeRequest(
    @SerializedName("link_id") val linkId: String,
    @SerializedName("by_user") val byUser: String
)

data class GuardianSecondOpinionRequest(
    @SerializedName("case_id") val caseId: String,
    @SerializedName("protected_id") val protectedId: String,
    @SerializedName("guardian_id") val guardianId: String,
    @SerializedName("redacted_summary") val redactedSummary: Map<String, Any>? = null,
    @SerializedName("share_level") val shareLevel: String? = "metadata_only",
    val consent: Boolean = false
)

data class GuardianSecondOpinionResponse(
    @SerializedName("request_id") val requestId: String,
    @SerializedName("case_id") val caseId: String,
    @SerializedName("protected_user_id") val protectedUserId: String,
    @SerializedName("guardian_user_id") val guardianUserId: String,
    @SerializedName("share_level") val shareLevel: String? = null,
    @SerializedName("redacted_summary") val redactedSummary: Map<String, Any>? = null,
    @SerializedName("share_downgraded") val shareDowngraded: Boolean = false,
    val status: String? = null,
    @SerializedName("created_at") val createdAt: Double? = null,
    @SerializedName("resolved_at") val resolvedAt: Double? = null
)

@Serializable
data class CommunityReport(
    val hash: String,
    @SerialName("risk_level") @SerializedName("risk_level") val riskLevel: String,
    val family: String? = null,
    @SerialName("source") @SerializedName("source") val source: String = "android",
    @SerialName("target_type") @SerializedName("target_type") val targetType: String = "unknown"
)

data class InvoiceFieldsResponse(
    val emitent: String? = null,
    val cui: String? = null,
    val iban: String? = null,
    @SerializedName("all_ibans") val allIbans: List<String> = emptyList(),
    @SerializedName("payment_beneficiary") val paymentBeneficiary: String? = null,
    @SerializedName("nr_factura") val nrFactura: String? = null,
    @SerializedName("data_emitere") val dataEmitere: String? = null,
    val scadenta: String? = null,
    val subtotal: Double? = null,
    val tva: Double? = null,
    val total: Double? = null,
    val currency: String? = null,
    @SerializedName("invoice_profile") val invoiceProfile: String? = null,
)

data class InvoiceReadinessItem(
    val id: String,
    val label: String,
    val detail: String,
    @SerializedName("next_action") val nextAction: String,
)

data class InvoiceReadinessResponse(
    val state: String,
    @SerializedName("blocks_safe_verdict") val blocksSafeVerdict: Boolean,
    val items: List<InvoiceReadinessItem> = emptyList(),
)

data class InvoiceCoherenceResponse(
    @SerializedName("totals_match") val totalsMatch: Boolean,
    @SerializedName("tva_rate_plausible") val tvaRatePlausible: Boolean,
    @SerializedName("dates_plausible") val datesPlausible: Boolean,
    @SerializedName("all_ok") val allOk: Boolean,
)

data class InvoiceIbanResponse(
    val valid: Boolean? = null,
    val bank: String? = null,
    @SerializedName("is_trezorerie") val isTrezorerie: Boolean? = null,
)

data class InvoiceBrandMatchResponse(
    @SerializedName("domain_matches") val domainMatches: Boolean? = null,
    @SerializedName("cui_matches") val cuiMatches: Boolean? = null,
    @SerializedName("iban_matches") val ibanMatches: Boolean? = null,
    @SerializedName("impersonation_risk") val impersonationRisk: Boolean = false,
)

data class InvoicePaymentSourceRef(
    val url: String? = null,
    val publisher: String? = null,
    @SerializedName("accessed_at") val accessedAt: String? = null,
    val confidence: String? = null,
)

data class InvoicePaymentDestinationResponse(
    val status: String? = null,
    val verdict: String? = null,
    val matched: Boolean? = null,
    @SerializedName("trust_tier") val trustTier: String? = null,
    val display: String? = null,
    @SerializedName("brand_id") val brandId: String? = null,
    @SerializedName("brand_matches") val brandMatches: Boolean? = null,
    @SerializedName("cui_matches") val cuiMatches: Boolean? = null,
    @SerializedName("iban_matches") val ibanMatches: Boolean? = null,
    @SerializedName("can_contribute_to_safe") val canContributeToSafe: Boolean? = null,
    @SerializedName("source_kind") val sourceKind: String? = null,
    @SerializedName("source_refs") val sourceRefs: List<InvoicePaymentSourceRef> = emptyList(),
    @SerializedName("iban_masked_for_client") val ibanMaskedForClient: String? = null,
    val reasons: List<String> = emptyList(),
    @SerializedName("matched_entity") val matchedEntity: String? = null,
    @SerializedName("match_reason") val matchReason: String? = null,
)

data class InvoiceVerdictGateResponse(
    val label: String? = null,
    @SerializedName("risk_level") val riskLevel: String? = null,
    @SerializedName("risk_score") val riskScore: Int? = null,
    @SerializedName("reason_codes") val reasonCodes: List<String>? = null,
)

data class InvoiceTruthDisplayResponse(
    val title: String? = null,
    val message: String? = null,
    val tone: String? = null,
)

data class InvoiceTruthItemResponse(
    val code: String? = null,
    val label: String? = null,
)

data class InvoiceTruthNextActionResponse(
    val type: String? = null,
    val title: String? = null,
    @SerializedName("requires_authorization") val requiresAuthorization: Boolean? = null,
    val available: Boolean? = null,
)

data class InvoiceTruthResponse(
    val schema: String? = null,
    val verdict: String? = null,
    @SerializedName("decision_status") val decisionStatus: String? = null,
    @SerializedName("safe_to_pay") val safeToPay: Boolean? = null,
    @SerializedName("primary_reason_code") val primaryReasonCode: String? = null,
    val display: InvoiceTruthDisplayResponse? = null,
    @SerializedName("verified_items") val verifiedItems: List<InvoiceTruthItemResponse> = emptyList(),
    @SerializedName("unconfirmed_items") val unconfirmedItems: List<InvoiceTruthItemResponse> = emptyList(),
    @SerializedName("hard_conflicts") val hardConflicts: List<InvoiceTruthItemResponse> = emptyList(),
    @SerializedName("next_action") val nextAction: InvoiceTruthNextActionResponse? = null,
)

data class InvoiceDecisionScopeResponse(
    @SerializedName("primary_verdict_scope") val primaryVerdictScope: String? = null,
    @SerializedName("payment_status") val paymentStatus: String? = null,
    @SerializedName("payment_assurance") val paymentAssurance: String? = null,
)

data class SanbCheckResponse(
    @SerializedName("payee_bank_participant") val payeeBankParticipant: Boolean = false,
    @SerializedName("participant_name") val participantName: String? = null,
    val bic: String? = null,
    val source: String? = null,
    @SerializedName("source_accessed_at") val sourceAccessedAt: String? = null,
    @SerializedName("requires_payer_bank_participation") val requiresPayerBankParticipation: Boolean = true,
)

data class BeneficiaryNameCheckResponse(
    val recommended: Boolean = false,
    val method: String? = null,
    @SerializedName("local_service_hint") val localServiceHint: String? = null,
    val title: String? = null,
    val reason: String? = null,
    @SerializedName("expected_beneficiary") val expectedBeneficiary: String? = null,
    @SerializedName("iban_masked_for_client") val ibanMaskedForClient: String? = null,
    @SerializedName("bank_code") val bankCode: String? = null,
    val bank: String? = null,
    val sanb: SanbCheckResponse? = null,
    val steps: List<String> = emptyList(),
    @SerializedName("privacy_note") val privacyNote: String? = null,
)

data class OfficialDocumentMismatchResponse(
    val field: String? = null,
    @SerializedName("invoice_value") val invoiceValue: String? = null,
    @SerializedName("official_value") val officialValue: String? = null,
    val severity: String? = null,
)

data class OfficialDocumentCheckResponse(
    val provided: Boolean = false,
    val status: String? = null,
    @SerializedName("risk_flag") val riskFlag: String? = null,
    @SerializedName("matched_fields") val matchedFields: List<String> = emptyList(),
    val mismatches: List<OfficialDocumentMismatchResponse> = emptyList(),
    val error: String? = null,
)

data class InvoiceScanResponse(
    val fields: InvoiceFieldsResponse? = null,
    val readiness: InvoiceReadinessResponse? = null,
    val coherence: InvoiceCoherenceResponse? = null,
    val iban: InvoiceIbanResponse? = null,
    val brand: String? = null,
    @SerializedName("brand_match") val brandMatch: InvoiceBrandMatchResponse? = null,
    @SerializedName("payment_destination") val paymentDestination: InvoicePaymentDestinationResponse? = null,
    @SerializedName("beneficiary_name_check") val beneficiaryNameCheck: BeneficiaryNameCheckResponse? = null,
    @SerializedName("official_document_check") val officialDocumentCheck: OfficialDocumentCheckResponse? = null,
    val anaf: Map<String, Any>? = null,
    @SerializedName("fraud_flags") val fraudFlags: List<String>? = null,
    @SerializedName("verdict_gate") val verdictGate: InvoiceVerdictGateResponse? = null,
    @SerializedName("decision_scope") val decisionScope: InvoiceDecisionScopeResponse? = null,
    @SerializedName("invoice_truth") val invoiceTruth: InvoiceTruthResponse? = null,
    @SerializedName("sanb_attestation") val sanbAttestation: String? = null,
    val warnings: List<String>? = null,
    val error: String? = null,
    @SerializedName("ocr_warning") val ocrWarning: String? = null,
)

interface SigurScanApi {
    @POST("v1/scan/orchestrated")
    suspend fun startOrchestratedScan(@Body request: OrchestratedScanRequest): OrchestratedScanResponse

    @GET("v1/scan/orchestrated/{scan_id}")
    suspend fun getOrchestratedScan(@Path("scan_id") scanId: String): OrchestratedScanResponse

    @GET("v1/scan/orchestrated/{scan_id}/status")
    suspend fun getOrchestratedScanStatus(@Path("scan_id") scanId: String): OrchestratedScanResponse

    @retrofit2.http.Multipart
    @POST("v1/extract/image")
    suspend fun extractImage(
        @retrofit2.http.Part image: okhttp3.MultipartBody.Part,
        @retrofit2.http.Part("source_channel") sourceChannel: okhttp3.RequestBody
    ): ExtractionResponse

    @retrofit2.http.Multipart
    @POST("v1/extract/email")
    suspend fun extractEmail(
        @retrofit2.http.Part emailFile: okhttp3.MultipartBody.Part,
        @retrofit2.http.Part("source_channel") sourceChannel: okhttp3.RequestBody
    ): ExtractionResponse

    @retrofit2.http.Multipart
    @POST("v1/extract/pdf")
    suspend fun extractPdf(
        @retrofit2.http.Part pdfFile: okhttp3.MultipartBody.Part,
        @retrofit2.http.Part("source_channel") sourceChannel: okhttp3.RequestBody
    ): ExtractionResponse

    @POST("v1/sandbox/urlscan")
    suspend fun submitUrlscanSandbox(@Body request: UrlscanSandboxSubmitRequest): UrlscanSandboxSubmitResponse

    @GET("v1/sandbox/urlscan/{uuid}")
    suspend fun getUrlscanSandboxResult(@Path("uuid") uuid: String): UrlscanSandboxResultResponse

    @POST("v1/feedback")
    suspend fun sendFeedback(@Body request: FeedbackRequest): Map<String, Any>

    @retrofit2.http.Multipart
    @POST("v1/scan/invoice")
    suspend fun scanInvoice(
        @retrofit2.http.Part file: okhttp3.MultipartBody.Part,
        @retrofit2.http.Part("source_channel") sourceChannel: okhttp3.RequestBody,
        @retrofit2.http.Part officialXmlFile: okhttp3.MultipartBody.Part? = null,
        @retrofit2.http.Part("sanb_attestation") sanbAttestation: okhttp3.RequestBody? = null,
    ): InvoiceScanResponse

    @POST("v1/community/report")
    suspend fun sendCommunityReport(@Body request: CommunityReport): Map<String, Any>

    @POST("v1/report")
    suspend fun buildOneTapReport(@Body request: OneTapReportRequest): OneTapReportPackage

    @GET("v1/community/campaigns")
    suspend fun getCampaigns(
        @Query("status") status: String = "active",
        @Query("limit") limit: Int = 50
    ): List<ScamCampaign>

    @GET("v1/radar/hot-iocs")
    suspend fun getRadarHotIocs(): RadarHotCacheResponse

    @GET("v1/btr/sync")
    suspend fun getBtrSync(@Query("client_version") clientVersion: String? = null): BtrSyncResponse

    @GET("v1/rules/sync")
    suspend fun getRulesSync(@Query("client_version") clientVersion: String? = null): RulesSyncResponse

    @POST("v1/circle/pair")
    suspend fun createCirclePair(@Body request: CirclePairRequest): CircleLinkResponse

    @POST("v1/circle/ping")
    suspend fun createCirclePing(@Body request: CirclePingRequest): VerificationPingResponse

    @POST("v1/circle/respond")
    suspend fun respondCirclePing(@Body request: CircleRespondRequest): CirclePingOutcome

    @POST("v1/circle/revoke")
    suspend fun revokeCirclePair(@Body request: CircleRevokeRequest): CircleLinkResponse

    @POST("v1/guardian/second-opinion")
    suspend fun requestGuardianSecondOpinion(@Body request: GuardianSecondOpinionRequest): GuardianSecondOpinionResponse

    @POST("v1/legal/action-plan")
    suspend fun getActionPlan(@Body request: ActionPlanRequest): ActionPlan

    @POST("v1/audio/semantic-review")
    suspend fun reviewAudioTranscript(@Body request: AudioSemanticReviewRequest): AudioSemanticReviewResponse

    @GET("v1/evaluation/readiness")
    suspend fun getReadiness(
        @Query("bucket_size_days") bucketSize: Int = 1,
        @Query("trend_top_signals") topSignals: Int = 6
    ): ReadinessResponse

    @GET("v1/feedback/quality")
    suspend fun getQuality(): QualityResponse

    @GET("v1/feedback/samples")
    suspend fun getFeedbackSamples(
        @Query("limit") limit: Int = 8
    ): FeedbackSamplesResponse

    @GET("v1/reputation/cache/stats")
    suspend fun getReputationStats(): ReputationCacheStats
}
