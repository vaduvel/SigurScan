from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from typing import Dict, List, Optional
from urllib.parse import urlparse


DATA_DIR = os.path.join(os.path.dirname(__file__), "..", "data")


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
    official_phones_e164: List[str] = field(default_factory=list)
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

    @staticmethod
    def from_dict(d: Dict) -> BrandManifest:
        refs = []
        for r in d.get("source_refs", []):
            if isinstance(r, dict):
                refs.append(ManifestSourceRef(**r))
        d_copy = dict(d)
        d_copy["source_refs"] = refs
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
            data_path = os.path.join(DATA_DIR, "brand_truth_registry_v1.json")
        self._load(data_path)

    def _load(self, path: str) -> None:
        with open(path, "r") as f:
            raw = json.load(f)
        self._version = raw.get("btr_version", "")
        self._generated_at = raw.get("generated_at", "")
        for m in raw.get("manifests", []):
            manifest = BrandManifest.from_dict(m)
            self._manifests[manifest.manifest_id] = manifest

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

    def _shortcode_belongs_to_brand(self, shortcode: str, manifest: BrandManifest) -> bool:
        normalized = "".join(ch for ch in str(shortcode or "").strip() if ch.isdigit())
        if not normalized:
            return False
        return normalized in {
            "".join(ch for ch in str(code or "").strip() if ch.isdigit())
            for code in manifest.official_shortcodes
        }

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
            elif manifest.official_phones_e164:
                safe_requires_failed.append("official_phone_match")
                reason_codes.append("BTR_PHONE_MISMATCH")

        shortcode_checked = bool(observed_shortcode)
        shortcode_match = False
        if observed_shortcode:
            shortcode_match = self._shortcode_belongs_to_brand(observed_shortcode, manifest)
            if shortcode_match:
                reason_codes.append("BTR_SHORTCODE_MATCH")
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
        positive_identifier_match = domain_match or phone_match or shortcode_match

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
