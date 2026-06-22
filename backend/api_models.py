"""API request/response schemas (Pydantic models) for the SigurScan backend.

Extracted verbatim from main.py to separate the HTTP API contract from the route
logic. URLSCAN defaults come from app_config to avoid a circular import with main.
"""

from typing import Optional, List, Dict, Any
from pydantic import BaseModel

from app_config import (
    URLSCAN_VISIBILITY_DEFAULT,
    URLSCAN_COUNTRY_DEFAULT,
    URLSCAN_CUSTOM_AGENT_DEFAULT,
)


class TextScanRequest(BaseModel):
    text: str
    source_channel: Optional[str] = "manual"
    consent_store_sample: Optional[bool] = False


class URLScanRequest(BaseModel):
    url: str
    source_channel: Optional[str] = "url_scan"


class UrlscanSandboxRequest(BaseModel):
    url: str
    visibility: Optional[str] = URLSCAN_VISIBILITY_DEFAULT
    country: Optional[str] = URLSCAN_COUNTRY_DEFAULT or None
    customagent: Optional[str] = URLSCAN_CUSTOM_AGENT_DEFAULT or None
    source_channel: Optional[str] = "android_native"


class OrchestratedScanRequest(BaseModel):
    input_type: str = "text"
    text: Optional[str] = None
    url: Optional[str] = None
    html_content: Optional[str] = None
    source_channel: Optional[str] = "android_native"
    visibility: Optional[str] = URLSCAN_VISIBILITY_DEFAULT
    country: Optional[str] = URLSCAN_COUNTRY_DEFAULT or None
    customagent: Optional[str] = URLSCAN_CUSTOM_AGENT_DEFAULT or None
    # Sender-authentication evidence (SPF/DKIM/DMARC + alignment) produced by
    # /v1/extract/email from the raw RFC822 headers. Threaded into the verdict so
    # email scans verify headers first, then body text, then links.
    email_auth: Optional[Dict[str, Any]] = None


class FeedbackRequest(BaseModel):
    scan_id: str
    feedback: str
    actual_is_scam: Optional[bool] = None
    predicted_is_scam: Optional[bool] = None
    predicted_risk_score: Optional[int] = None
    risk_level: Optional[str] = None
    signal_ids: Optional[List[str]] = None
    notes: Optional[str] = None


class ProvenanceRequest(BaseModel):
    claimed_brand: Optional[str] = None
    observed_channel: str = "unknown"
    observed_domain: Optional[str] = None
    observed_phone_e164: Optional[str] = None
    observed_shortcode: Optional[str] = None
    sensitive_asks: List[str] = []
    payment_method: Optional[str] = None
    final_url: Optional[str] = None


class IntelIngestRequest(BaseModel):
    title: str
    body: str
    source_url: str = ""
    source_kind: str = "press_context"
    claimed_identity: Optional[str] = None
    evidence_quality: str = "medium"
    regions_hint: Optional[List[str]] = None


class IntelModerateRequest(BaseModel):
    intel_id: str
    action: str
    approved_by: Optional[str] = None


class CampaignMatchRequest(BaseModel):
    text: str
    channel: str = "sms"
    claimed_identity: Optional[str] = None
    urls: Optional[List[str]] = None


class OneTapReportRequest(BaseModel):
    # PR-5: doar ținta REDACTATĂ ajunge la server (fără PII brut).
    target_type: str = "url"          # phone|iban|domain|url|email
    target_redacted: str = "[redactat]"
    family: Optional[str] = None
    verdict: str = "SUSPECT"
    redacted_summary: Optional[str] = None


class CirclePairRequest(BaseModel):
    protected_id: str
    verifier_id: str
    consent: str = "explicit"


class CirclePingRequest(BaseModel):
    link_id: str
    claim: str = "caller_claims_to_be_verifier"


class CircleRespondRequest(BaseModel):
    ping_id: str
    response: str  # its_me | not_me | timeout


class CircleRevokeRequest(BaseModel):
    link_id: str
    by_user: str


class GuardianSecondOpinionRequest(BaseModel):
    case_id: str
    protected_id: str
    guardian_id: str
    redacted_summary: Optional[Dict[str, Any]] = None
    share_level: Optional[str] = None  # metadata_only | redacted_excerpt | full_with_consent
    consent: bool = False


class LegalActionPlanRequest(BaseModel):
    verdict: str = "SUSPECT"
    family: Optional[str] = None
    impacts: Optional[List[str]] = None  # shared_card|shared_otp|shared_credentials|
                                         # shared_id_document|installed_remote_access|
                                         # paid_transfer|paid_crypto|clicked_link|none
    target_type: Optional[str] = None
    target_redacted: Optional[str] = None
    document_type: Optional[str] = None


class IntelStatusData(BaseModel):
    last_run_at: Optional[float] = None
    entries_ingested: int = 0
    sources_configured: int = 0
    sources_with_rss: int = 0
    sources_enabled: int = 0


class UrecheaRunRequest(BaseModel):
    sources: Optional[List[str]] = None
    max_entries_per_source: int = 5


class CommunityReportRequest(BaseModel):
    hash: str
    risk_level: str
    family: Optional[str] = None
    source: str = "ios"
    target_type: str = "unknown"
    timestamp: Optional[str] = None


class PushRegisterRequest(BaseModel):
    token: str
    platform: str = "ios"
    locale: str = "ro-RO"
