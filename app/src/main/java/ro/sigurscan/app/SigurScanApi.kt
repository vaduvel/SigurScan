package ro.sigurscan.app

import com.google.gson.annotations.SerializedName
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import retrofit2.http.Body
import retrofit2.http.Field
import retrofit2.http.FormUrlEncoded
import retrofit2.http.GET
import retrofit2.http.Path
import retrofit2.http.POST
import retrofit2.http.Query

data class ScanRequest(
    val text: String,
    @SerializedName("source_channel") val sourceChannel: String = "android_native"
)

data class UrlScanRequest(
    val url: String,
    @SerializedName("source_channel") val sourceChannel: String = "android_native"
)

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
    val evidence: Map<String, Any>? = null,
    @SerializedName("extracted_urls") val extractedUrls: List<Map<String, Any>>? = null,
    @SerializedName("resolved_urls") val resolvedUrls: List<Map<String, Any>>? = null,
    @SerializedName("buttons") val buttons: List<Map<String, Any>>? = null,
    @SerializedName("email_auth") val emailAuth: Map<String, Any>? = null
)

data class OrchestratedScanRequest(
    @SerializedName("input_type") val inputType: String,
    val text: String? = null,
    val url: String? = null,
    @SerializedName("html_content") val htmlContent: String? = null,
    @SerializedName("source_channel") val sourceChannel: String = "android_native"
)

data class OrchestratedPillarState(
    val status: String? = null,
    val required: Boolean? = null,
    val details: String? = null,
    val ref: String? = null
)

data class OrchestratedPreview(
    @SerializedName("screenshot_url") val screenshotUrl: String? = null,
    @SerializedName("report_url") val reportUrl: String? = null,
    @SerializedName("final_url") val finalUrl: String? = null
)

data class OrchestratedScanResponse(
    @SerializedName("scan_id") val scanId: String,
    val status: String? = null,
    @SerializedName("status_message") val statusMessage: String? = null,
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

@Serializable
data class CommunityReport(
    val hash: String,
    @SerialName("risk_level") @SerializedName("risk_level") val riskLevel: String,
    val family: String? = null,
    @SerialName("source") @SerializedName("source") val source: String = "android"
)

interface SigurScanApi {
    @POST("v1/scan/orchestrated")
    suspend fun startOrchestratedScan(@Body request: OrchestratedScanRequest): OrchestratedScanResponse

    @GET("v1/scan/orchestrated/{scan_id}")
    suspend fun getOrchestratedScan(@Path("scan_id") scanId: String): OrchestratedScanResponse

    @POST("v1/scan/url")
    suspend fun scanUrl(@Body request: UrlScanRequest): ScanResponse

    @POST("v1/scan/text")
    suspend fun scanText(@Body request: ScanRequest): ScanResponse

    @FormUrlEncoded
    @POST("v1/scan/email")
    suspend fun scanEmailHtml(
        @Field("html_content") htmlContent: String,
        @Field("source_channel") sourceChannel: String = "android_html_share"
    ): ScanResponse

    @POST("v1/sandbox/urlscan")
    suspend fun submitUrlscanSandbox(@Body request: UrlscanSandboxSubmitRequest): UrlscanSandboxSubmitResponse

    @GET("v1/sandbox/urlscan/{uuid}")
    suspend fun getUrlscanSandboxResult(@Path("uuid") uuid: String): UrlscanSandboxResultResponse

    @retrofit2.http.Multipart
    @POST("v1/scan/image")
    suspend fun scanImage(
        @retrofit2.http.Part image: okhttp3.MultipartBody.Part,
        @retrofit2.http.Part("source_channel") sourceChannel: okhttp3.RequestBody
    ): ScanResponse

    @retrofit2.http.Multipart
    @POST("v1/scan/email")
    suspend fun scanEmail(
        @retrofit2.http.Part emailFile: okhttp3.MultipartBody.Part,
        @retrofit2.http.Part("source_channel") sourceChannel: okhttp3.RequestBody
    ): ScanResponse

    @retrofit2.http.Multipart
    @POST("v1/scan/pdf")
    suspend fun scanPdf(
        @retrofit2.http.Part pdfFile: okhttp3.MultipartBody.Part,
        @retrofit2.http.Part("source_channel") sourceChannel: okhttp3.RequestBody
    ): ScanResponse

    @POST("v1/feedback")
    suspend fun sendFeedback(@Body request: FeedbackRequest): Map<String, Any>

    @POST("v1/community/report")
    suspend fun sendCommunityReport(@Body request: CommunityReport): Map<String, Any>

    @GET("v1/community/campaigns")
    suspend fun getCampaigns(
        @Query("status") status: String = "active",
        @Query("limit") limit: Int = 50
    ): List<ScamCampaign>

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
