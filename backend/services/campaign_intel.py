from __future__ import annotations

import json
import os
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


DATA_DIR = os.path.join(os.path.dirname(__file__), "..", "data")

FAMILY_TAXONOMY = {
    "IMP-01": "CONV_BANK_SAFE_ACCOUNT",
    "IMP-02": "INVESTMENT_DEEPFAKE_CELEBRITY",
    "IMP-03": "CONV_COURIER_TAX_CARD",
    "IMP-04": "CONV_FAMILY_NEW_PHONE",
    "IMP-05": "CONV_WHATSAPP_TAKEOVER",
    "IMP-06": "CONV_TECH_SUPPORT_REMOTE",
    "IMP-07": "CONV_MARKETPLACE_RECEIVE_MONEY",
    "IMP-08": "CONV_JOB_TASK_TOPUP",
    "IMP-09": "CONV_ROMANCE_ADVANCE_FEE",
    "OP-01": "DOC_BEC_IBAN_CHANGE",
    "OP-02": "DOC_OFFER_ADVANCE_PAYMENT",
    "OP-03": "QR_PARKING_GOV_PAYMENT",
}


@dataclass
class CampaignIntel:
    intel_id: str
    family: str
    skeleton: Dict[str, Any]
    iocs: Dict[str, Any]
    source: Dict[str, Any]
    evidence_quality: str
    status: str = "active"
    regions_hint: List[str] = field(default_factory=lambda: ["national"])
    moderation: Dict[str, Any] = field(default_factory=dict)
    created_at: float = 0.0
    last_seen_at: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "intel_id": self.intel_id,
            "family": self.family,
            "skeleton": self.skeleton,
            "iocs": self.iocs,
            "source": self.source,
            "evidence_quality": self.evidence_quality,
            "status": self.status,
            "regions_hint": self.regions_hint,
            "moderation": self.moderation,
            "created_at": self.created_at,
            "last_seen_at": self.last_seen_at,
        }

    @staticmethod
    def from_dict(d: Dict[str, Any]) -> CampaignIntel:
        return CampaignIntel(
            intel_id=d["intel_id"],
            family=d["family"],
            skeleton=d.get("skeleton", {}),
            iocs=d.get("iocs", {}),
            source=d.get("source", {}),
            evidence_quality=d.get("evidence_quality", "medium"),
            status=d.get("status", "active"),
            regions_hint=d.get("regions_hint", ["national"]),
            moderation=d.get("moderation", {}),
            created_at=d.get("created_at", 0.0),
            last_seen_at=d.get("last_seen_at", 0.0),
        )


class CampaignStore:
    def __init__(self, seed_path: Optional[str] = None):
        self._intels: Dict[str, CampaignIntel] = {}
        if seed_path is None:
            seed_path = os.path.join(DATA_DIR, "campaign_intel_seed_v1.json")
        self._load_seed(seed_path)

    def _load_seed(self, path: str) -> None:
        if not path or not os.path.exists(path):
            return
        with open(path, "r") as f:
            raw = json.load(f)
        for entry in raw.get("campaigns", []):
            intel = CampaignIntel.from_dict(entry)
            self._intels[intel.intel_id] = intel

    def put(self, intel: CampaignIntel) -> None:
        self._intels[intel.intel_id] = intel

    def get(self, intel_id: str) -> Optional[CampaignIntel]:
        return self._intels.get(intel_id)

    def all(self) -> List[CampaignIntel]:
        return list(self._intels.values())

    def active(self, since: float = 0) -> List[CampaignIntel]:
        now = time.time()
        return [
            i for i in self._intels.values()
            if i.status == "active"
            and i.last_seen_at >= since
            and i.moderation.get("approved") is not False
        ]

    def by_family(self, family: str) -> List[CampaignIntel]:
        return [i for i in self._intels.values() if i.family == family]

    def search(self, **kwargs) -> List[CampaignIntel]:
        results = list(self._intels.values())
        for key, value in kwargs.items():
            if key == "family":
                results = [i for i in results if i.family == value]
            elif key == "status":
                results = [i for i in results if i.status == value]
            elif key == "region":
                results = [i for i in results if value in i.regions_hint]
        return results
