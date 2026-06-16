from __future__ import annotations

import json
import os
from dataclasses import dataclass, field, fields as dataclass_fields
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse


DATA_DIR = os.path.join(os.path.dirname(__file__), "..", "data")
DEFAULT_BTR_PATH = os.path.join(DATA_DIR, "brand_truth_registry_v1.json")
ROMANIA_OFFICIAL_RESEARCH_PATH = os.path.join(DATA_DIR, "romania_official_research_2026_06_16.json")
ACTIVE_RESEARCH_POLICIES = {"active_verified", "active_verified_for_contact_only"}
RESEARCH_MANIFEST_ID_ALIASES = {
    "bank_bt": "bt",
    "bank_bcr": "bcr",
    "bank_brd": "brd",
    "bank_ing": "ing",
    "bank_raiffeisen": "raiffeisen",
    "bank_unicredit": "unicredit",
    "bank_cec": "cec",
    "bank_revolut_ro": "revolut_ro",
    "bank_garanti": "garanti",
    "inst_anaf": "anaf",
    "inst_dnsc": "dnsc",
    "inst_politia_mai": "politia_mai",
    "inst_bnr": "bnr",
    "inst_anpc": "anpc",
    "courier_fan": "fan_courier",
    "courier_cargus": "cargus",
    "courier_dpd": "dpd_romania",
    "courier_gls": "gls_romania",
    "courier_posta_romana": "posta_romana",
    "telco_orange": "orange",
    "telco_yoxo": "yoxo",
    "telco_vodafone": "vodafone",
    "telco_digi": "digi",
    "telco_telekom_mobile": "telekom_mobile",
}
SENSITIVE_TOKEN_ALIASES = {
    "pin": ["banking_pin"],
    "bank_account": ["financial_data"],
    "banking_data_by_phone": ["financial_data"],
    "bank_data_sms_email": ["financial_data"],
    "bank_data_for_prize": ["financial_data"],
    "card_data_fake_site": ["card_number", "cvv"],
    "payment_by_email_card_transfer": ["card_number", "cvv", "financial_data"],
    "payment_details_sms_email_for_account": ["card_number", "cvv", "financial_data"],
    "personal_data_update_sms": ["personal_data"],
    "personal_data": ["id_document"],
    "cnp": ["id_document", "personal_data"],
    "app_installation": ["apk_install"],
    "external_locker_link": ["delivery_fee_sms"],
    "suspicious_payment_link": ["card_number", "cvv"],
    "login_via_link": ["password"],
    "login_via_sms_link": ["password"],
    "safe_account_transfer": ["transfer_safe_account"],
    "card_for_receiving_money": ["card_number", "cvv"],
}


@dataclass
class ManifestSourceRef:
    url: str
    publisher: str
    accessed_at: str
    confidence: str


@dataclass
class BrandManifest:
    manifest_id: str
    type: str
    display_name: str
    category: Optional[str]
    country: str
    official_domains: List[str] = field(default_factory=list)
    official_email_domains: List[str] = field(default_factory=list)
    official_shortcodes: List[str] = field(default_factory=list)
    official_shortcode_details: List[Dict[str, Any]] = field(default_factory=list)
    official_phones_e164: List[str] = field(default_factory=list)
    official_contacts: List[Dict[str, Any]] = field(default_factory=list)
    official_apps: List[Dict] = field(default_factory=list)
    official_channels: List[str] = field(default_factory=list)
    never_asks: List[str] = field(default_factory=list)
    never_does: List[str] = field(default_factory=list)
    safe_payment_channels: List[str] = field(default_factory=list)
    source_kind: str = ""
    source_refs: List[ManifestSourceRef] = field(default_factory=list)
    last_verified_at: str = ""
    confidence: str = ""
    review_status: str = "active"
    verdict_policy: str = "active_verified"
    source_dataset_id: str = ""

    @staticmethod
    def from_dict(d: Dict) -> BrandManifest:
        refs = []
        for r in d.get("source_refs", []):
            if isinstance(r, dict):
                refs.append(ManifestSourceRef(**r))
        d_copy = dict(d)
        d_copy["source_refs"] = refs
        allowed = {field.name for field in dataclass_fields(BrandManifest)}
        d_copy = {key: value for key, value in d_copy.items() if key in allowed}
        return BrandManifest(**d_copy)


@dataclass
class ProvenanceResult:
    manifest_id: Optional[str]
    provenance: str
    identity_status: str
    official_match: bool
    violated_never_asks: List[str]
    violated_never_does: List[str]
    safe_requires_failed: List[str]
    evidence_power: str
    reason_codes: List[str]
    max_effect: str


class BrandTruthRegistry:
    def __init__(self, data_path: Optional[str] = None):
        self._manifests: Dict[str, BrandManifest] = {}
        self._version: str = ""
        self._generated_at: str = ""
        if data_path is None:
            data_path = DEFAULT_BTR_PATH
        self._load(data_path)

    def _load(self, path: str) -> None:
        with open(path, "r") as f:
            raw = json.load(f)
        self._version = raw.get("btr_version", "")
        self._generated_at = raw.get("generated_at", "")
        for m in raw.get("manifests", []):
            manifest = BrandManifest.from_dict(m)
            self._manifests[manifest.manifest_id] = manifest
        if os.path.abspath(path) == os.path.abspath(DEFAULT_BTR_PATH):
            self._load_romania_official_research()

    def _load_romania_official_research(self) -> None:
        if not os.path.exists(ROMANIA_OFFICIAL_RESEARCH_PATH):
            return
        with open(ROMANIA_OFFICIAL_RESEARCH_PATH, "r", encoding="utf-8") as handle:
            raw = json.load(handle)
        metadata = raw.get("metadata") if isinstance(raw.get("metadata"), dict) else {}
        dataset_id = str(metadata.get("dataset_id") or "romania_official_research_2026_06_16")
        generated_at = str(metadata.get("generated_at") or "").strip()
        for item in raw.get("brand_manifests", []):
            if not isinstance(item, dict):
                continue
            if item.get("type") != "brand":
                continue
            policy = str(item.get("verdict_policy") or "").strip()
            if policy not in ACTIVE_RESEARCH_POLICIES:
                continue
            manifest = self._manifest_from_research(item, dataset_id, generated_at)
            if manifest:
                self._merge_manifest(manifest)
        if generated_at:
            self._generated_at = f"{generated_at}T00:00:00Z"
            self._version = "btr-ro-2026.06.16"

    def _manifest_from_research(
        self,
        item: Dict[str, Any],
        dataset_id: str,
        generated_at: str,
    ) -> Optional[BrandManifest]:
        raw_id = str(item.get("manifest_id") or "").strip()
        manifest_id = RESEARCH_MANIFEST_ID_ALIASES.get(raw_id)
        if not manifest_id:
            return None

        shortcodes = [str(detail.get("value") or "").strip() for detail in item.get("official_shortcodes", []) if isinstance(detail, dict)]
        shortcode_details = [detail for detail in item.get("official_shortcodes", []) if isinstance(detail, dict)]
        official_contacts = [detail for detail in item.get("official_contacts", []) if isinstance(detail, dict)]
        official_apps = [detail for detail in item.get("official_apps", []) if isinstance(detail, dict)]
        official_channels = ["official_website"]
        if official_apps:
            official_channels.append("official_app")
        official_channels.extend(
            str(contact.get("channel") or "").strip().lower()
            for contact in official_contacts
            if contact.get("channel")
        )
        official_channels.extend(
            str(detail.get("channel") or "").strip().lower()
            for detail in shortcode_details
            if detail.get("channel")
        )

        source_refs = []
        for ref in item.get("source_refs", []):
            if not isinstance(ref, dict):
                continue
            source_refs.append(
                ManifestSourceRef(
                    url=str(ref.get("url") or ""),
                    publisher=str(ref.get("publisher") or ""),
                    accessed_at=str(ref.get("accessed_at") or generated_at or ""),
                    confidence=str(ref.get("confidence") or item.get("confidence") or ""),
                )
            )

        return BrandManifest(
            manifest_id=manifest_id,
            type="brand",
            display_name=str(item.get("display_name") or manifest_id),
            category=str(item.get("category") or ""),
            country="RO",
            official_domains=[str(domain).strip().lower() for domain in item.get("official_domains", []) if str(domain).strip()],
            official_email_domains=[str(domain).strip().lower() for domain in item.get("official_email_domains", []) if str(domain).strip()],
            official_shortcodes=[code for code in shortcodes if code],
            official_shortcode_details=shortcode_details,
            official_phones_e164=[str(phone).strip() for phone in item.get("official_phones_e164", []) if str(phone).strip()],
            official_contacts=official_contacts,
            official_apps=official_apps,
            official_channels=self._dedupe_strings(official_channels),
            never_asks=self._research_tokens(item.get("never_asks", [])),
            never_does=self._research_tokens(item.get("never_does", [])),
            safe_payment_channels=[],
            source_kind="official_registry",
            source_refs=source_refs,
            last_verified_at=f"{generated_at}T00:00:00Z" if generated_at else "",
            confidence=str(item.get("confidence") or ""),
            review_status="active",
            verdict_policy=str(item.get("verdict_policy") or "active_verified"),
            source_dataset_id=dataset_id,
        )

    def _research_tokens(self, values: Any) -> List[str]:
        tokens: List[str] = []
        if not isinstance(values, list):
            return tokens
        for value in values:
            token = value.get("token") if isinstance(value, dict) else value
            token = str(token or "").strip()
            if not token:
                continue
            tokens.append(token)
            tokens.extend(SENSITIVE_TOKEN_ALIASES.get(token, []))
        return self._dedupe_strings(tokens)

    def _merge_manifest(self, incoming: BrandManifest) -> None:
        existing = self._manifests.get(incoming.manifest_id)
        if not existing:
            self._manifests[incoming.manifest_id] = incoming
            return
        existing.official_domains = self._dedupe_strings(existing.official_domains + incoming.official_domains)
        existing.official_email_domains = self._dedupe_strings(existing.official_email_domains + incoming.official_email_domains)
        existing.official_shortcodes = self._dedupe_strings(existing.official_shortcodes + incoming.official_shortcodes)
        existing.official_shortcode_details = self._dedupe_dicts(existing.official_shortcode_details + incoming.official_shortcode_details)
        existing.official_phones_e164 = self._dedupe_strings(existing.official_phones_e164 + incoming.official_phones_e164)
        existing.official_contacts = self._dedupe_dicts(existing.official_contacts + incoming.official_contacts)
        existing.official_apps = self._dedupe_dicts(existing.official_apps + incoming.official_apps)
        existing.official_channels = self._dedupe_strings(existing.official_channels + incoming.official_channels)
        existing.never_asks = self._dedupe_strings(existing.never_asks + incoming.never_asks)
        existing.never_does = self._dedupe_strings(existing.never_does + incoming.never_does)
        existing.source_refs = self._dedupe_refs(existing.source_refs + incoming.source_refs)
        existing.confidence = self._best_confidence(existing.confidence, incoming.confidence)
        existing.last_verified_at = incoming.last_verified_at or existing.last_verified_at
        existing.verdict_policy = incoming.verdict_policy or existing.verdict_policy
        existing.source_dataset_id = incoming.source_dataset_id or existing.source_dataset_id

    def _dedupe_strings(self, values: List[str]) -> List[str]:
        seen: set[str] = set()
        result: List[str] = []
        for value in values:
            text = str(value or "").strip()
            key = text.lower()
            if not text or key in seen:
                continue
            seen.add(key)
            result.append(text)
        return result

    def _dedupe_dicts(self, values: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        seen: set[str] = set()
        result: List[Dict[str, Any]] = []
        for value in values:
            if not isinstance(value, dict):
                continue
            key = json.dumps(value, sort_keys=True, ensure_ascii=False)
            if key in seen:
                continue
            seen.add(key)
            result.append(value)
        return result

    def _dedupe_refs(self, values: List[ManifestSourceRef]) -> List[ManifestSourceRef]:
        seen: set[Tuple[str, str]] = set()
        result: List[ManifestSourceRef] = []
        for value in values:
            key = (value.url, value.publisher)
            if key in seen:
                continue
            seen.add(key)
            result.append(value)
        return result

    def _best_confidence(self, left: str, right: str) -> str:
        order = {"": 0, "needs_confirmation": 1, "medium": 2, "high": 3}
        return right if order.get(right, 0) > order.get(left, 0) else left

    @property
    def version(self) -> str:
        return self._version

    @property
    def generated_at(self) -> str:
        return self._generated_at

    def get(self, manifest_id: str) -> Optional[BrandManifest]:
        return self._manifests.get(manifest_id)

    def all(self) -> List[BrandManifest]:
        return list(self._manifests.values())

    def brands(self) -> List[BrandManifest]:
        return [m for m in self._manifests.values() if m.type == "brand"]

    def persons(self) -> List[BrandManifest]:
        return [m for m in self._manifests.values() if m.type == "person"]

    def match_brand_by_domain(self, domain: str) -> Optional[BrandManifest]:
        domain_lower = domain.lower().strip()
        for m in self._manifests.values():
            if m.type != "brand":
                continue
            for official_domain in m.official_domains:
                od = official_domain.lower().strip()
                if domain_lower == od or domain_lower.endswith("." + od):
                    return m
        return None

    def _name_matches_manifest(self, name_lower: str, m: BrandManifest) -> bool:
        display = m.display_name.lower()
        mid = m.manifest_id.lower()
        return (
            name_lower == mid
            or name_lower == display
            or name_lower in display
            or display in name_lower
            or mid in name_lower
            or name_lower in mid
        )

    def match_brand_by_name(self, name: str) -> Optional[BrandManifest]:
        name_lower = name.lower().strip()
        best = None
        best_len = 0
        for m in self._manifests.values():
            display = m.display_name.lower()
            mid = m.manifest_id.lower()
            if name_lower == mid or name_lower == display:
                return m
            if name_lower in display or display in name_lower:
                if len(display) > best_len:
                    best = m
                    best_len = len(display)
            if mid in name_lower or name_lower in mid:
                if len(mid) > best_len:
                    best = m
                    best_len = len(mid)
        return best

    def _domain_belongs_to_brand(self, domain: str, manifest: BrandManifest) -> bool:
        domain_lower = domain.lower().strip()
        for od in manifest.official_domains:
            od = od.lower().strip()
            if domain_lower == od or domain_lower.endswith("." + od):
                return True
        return False

    def _normalize_phone_e164(self, value: str) -> str:
        raw = str(value or "").strip()
        digits = "".join(ch for ch in raw if ch.isdigit())
        if not digits:
            return ""
        if digits.startswith("0040") and len(digits) >= 6:
            return "+40" + digits[4:]
        if digits.startswith("40") and len(digits) >= 5:
            return "+" + digits
        if digits.startswith("0") and len(digits) >= 9:
            return "+40" + digits[1:]
        if raw.startswith("+"):
            return "+" + digits
        return "+" + digits

    def _phone_belongs_to_brand(self, phone: str, manifest: BrandManifest) -> bool:
        normalized = self._normalize_phone_e164(phone)
        if not normalized:
            return False
        return normalized in {self._normalize_phone_e164(p) for p in manifest.official_phones_e164}

    def _normalize_shortcode(self, shortcode: str) -> str:
        raw = str(shortcode or "").strip().upper()
        return "".join(ch for ch in raw if ch.isalnum() or ch == "*")

    def _shortcode_match_info(self, shortcode: str, manifest: BrandManifest) -> Tuple[bool, bool]:
        normalized = self._normalize_shortcode(shortcode)
        if not normalized:
            return False, False
        for detail in manifest.official_shortcode_details:
            if not isinstance(detail, dict):
                continue
            if normalized == self._normalize_shortcode(str(detail.get("value") or "")):
                return True, bool(str(detail.get("scope") or "").strip())
        for code in manifest.official_shortcodes:
            if normalized == self._normalize_shortcode(str(code or "")):
                return True, False
        return False, False

    def _extract_domain(self, url: str) -> Optional[str]:
        try:
            parsed = urlparse(url)
            return parsed.hostname
        except Exception:
            return None

    def provenance_check(
        self,
        claimed_brand: Optional[str],
        observed_channel: str,
        observed_domain: Optional[str],
        observed_phone_e164: Optional[str],
        sensitive_asks: List[str],
        payment_method: Optional[str],
        final_url: Optional[str],
        observed_shortcode: Optional[str] = None,
    ) -> ProvenanceResult:
        manifest = None
        if claimed_brand:
            manifest = self.match_brand_by_name(claimed_brand)

        if not manifest:
            manifest = self.match_brand_by_domain(observed_domain or "")

        if not manifest:
            return ProvenanceResult(
                manifest_id=None,
                provenance="unknown",
                identity_status="no_manifest_match",
                official_match=False,
                violated_never_asks=[],
                violated_never_does=[],
                safe_requires_failed=["manifest_match"],
                evidence_power="none",
                reason_codes=["BTR_NO_MANIFEST_MATCH"],
                max_effect="none",
            )

        violated_never_asks = []
        violated_never_does = []
        safe_requires_failed = []
        reason_codes = []
        normalized_channel = (observed_channel or "").strip().lower()
        if normalized_channel in {"web", "website", "site"}:
            normalized_channel = "official_website"

        domain_checked = bool(observed_domain)
        domain_match = False
        if observed_domain:
            domain_match = self._domain_belongs_to_brand(observed_domain, manifest)
            if not domain_match:
                safe_requires_failed.append("official_domain_match")
                reason_codes.append("BTR_DOMAIN_MISMATCH")
            else:
                reason_codes.append("BTR_DOMAIN_MATCH")

        phone_checked = bool(observed_phone_e164)
        phone_match = False
        if observed_phone_e164:
            phone_match = self._phone_belongs_to_brand(observed_phone_e164, manifest)
            if phone_match:
                reason_codes.append("BTR_PHONE_MATCH")
                reason_codes.append("BTR_PHONE_MATCH_SPOOFABLE")
            elif manifest.official_phones_e164:
                safe_requires_failed.append("official_phone_match")
                reason_codes.append("BTR_PHONE_MISMATCH")

        shortcode_checked = bool(observed_shortcode)
        shortcode_match = False
        shortcode_scoped = False
        if observed_shortcode:
            shortcode_match, shortcode_scoped = self._shortcode_match_info(observed_shortcode, manifest)
            if shortcode_match:
                reason_codes.append("BTR_SHORTCODE_MATCH")
                if shortcode_scoped:
                    reason_codes.append("BTR_SHORTCODE_MATCH_SCOPED")
            elif manifest.official_shortcodes:
                safe_requires_failed.append("official_shortcode_match")
                reason_codes.append("BTR_SHORTCODE_MISMATCH")

        channel_match = normalized_channel in manifest.official_channels if manifest.official_channels else False
        if not channel_match and manifest.official_channels:
            safe_requires_failed.append("official_channel_match")

        if normalized_channel not in ("official", "official_website", "official_app"):
            for ask in sensitive_asks:
                if ask in manifest.never_asks:
                    violated_never_asks.append(ask)
                    reason_codes.append(f"BTR_NEVER_ASK_{ask.upper()}_VIOLATED")

            _never_does_sensitive_map = {
                "request_otp_outside_app": ["otp"],
                "request_card_details_by_phone": ["card"],
                "request_money_transfer": ["transfer"],
                "request_bail_payment": ["transfer"],
            }
            for claim, trigger_asks in _never_does_sensitive_map.items():
                if claim in manifest.never_does and any(t in sensitive_asks for t in trigger_asks):
                    violated_never_does.append(claim)
                    reason_codes.append(f"BTR_NEVER_DOES_{claim.upper()}_VIOLATED")

        identifier_mismatch = (
            (domain_checked and not domain_match)
            or (phone_checked and manifest.official_phones_e164 and not phone_match)
            or (shortcode_checked and manifest.official_shortcodes and not shortcode_match)
        )
        positive_identifier_match = domain_match or (shortcode_match and not shortcode_scoped)

        if violated_never_asks or violated_never_does:
            evidence_power = "decisive"
        elif identifier_mismatch:
            evidence_power = "strong"
        else:
            evidence_power = "moderate"

        has_violations = bool(violated_never_asks or violated_never_does)
        if has_violations:
            identity_status = "claimed_brand_mismatch"
            provenance = "mismatch"
            official_match = False
            max_effect = "can_raise_dangerous_with_combo"
        elif identifier_mismatch:
            identity_status = "claimed_brand_official_mismatch"
            provenance = "mismatch"
            official_match = False
            max_effect = "can_raise_dangerous_with_combo"
        elif positive_identifier_match and channel_match:
            identity_status = "official_match"
            provenance = "match"
            official_match = True
            max_effect = "can_raise_safe"
        else:
            identity_status = "claimed_brand_partial"
            provenance = "partial"
            official_match = False
            max_effect = "can_raise_suspect"

        return ProvenanceResult(
            manifest_id=manifest.manifest_id,
            provenance=provenance,
            identity_status=identity_status,
            official_match=official_match,
            violated_never_asks=violated_never_asks,
            violated_never_does=violated_never_does,
            safe_requires_failed=safe_requires_failed,
            evidence_power=evidence_power,
            reason_codes=reason_codes,
            max_effect=max_effect,
        )
