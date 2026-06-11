"""Contract pentru verificările în registre publice (PR4).

Aceste obiecte sunt DOVEZI structurate, nu verdicte. Singurul judecător rămâne
verdict_gate.reduce_verdict. Niciun status de aici nu are voie să fie interpretat
direct ca SIGUR/PERICULOS.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, Optional


class RegistryStatus(str, Enum):
    MATCH = "MATCH"                  # entitatea apare în registru (context, nu „sigur")
    NO_MATCH = "NO_MATCH"            # consultat, nu apare (solo = max SUSPECT)
    INCONCLUSIVE = "INCONCLUSIVE"    # consultat, dar datele nu permit concluzie (ex. snapshot vechi)
    NOT_CONFIGURED = "NOT_CONFIGURED"  # sursa nu are adapter/snapshot configurat
    SOURCE_TIMEOUT = "SOURCE_TIMEOUT"  # sursa nu a răspuns la timp
    SOURCE_ERROR = "SOURCE_ERROR"    # sursa a răspuns invalid / snapshot corupt


@dataclass
class RegistryVerificationResult:
    source_id: str
    status: RegistryStatus
    confidence: float
    matched_entity_name: Optional[str]
    details: Dict[str, Any] = field(default_factory=dict)
    checked: bool = False

    def to_bundle_dict(self) -> Dict[str, Any]:
        """Forma minimă, deterministă, pentru Evidence Bundle v2 (fără timestamps)."""
        return {
            "source_id": self.source_id,
            "status": self.status.value,
            "confidence": round(float(self.confidence), 4),
            "matched_entity_name": self.matched_entity_name,
            "checked": self.checked,
        }
