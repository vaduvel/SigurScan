"""Stubs oneste pentru sursele fără adapter real încă.

Întorc explicit NOT_CONFIGURED (checked=False) — niciodată date inventate.
NOT_CONFIGURED nu poate coborî verdictul la SIGUR și nu e dovadă de fraudă.
"""
from __future__ import annotations

from services.registry_verification.metadata import source_metadata
from services.registry_verification.models import RegistryStatus, RegistryVerificationResult

STUB_SOURCE_IDS = (
    "situr",
    "bnr",
    "asf",
    "anpc",
    "ancpi",
    "rar_auto_pass",
    "itm",
    "anofm",
)


def verify_stub(source_id: str) -> RegistryVerificationResult:
    return RegistryVerificationResult(
        source_id=source_id,
        status=RegistryStatus.NOT_CONFIGURED,
        confidence=0.0,
        matched_entity_name=None,
        checked=False,
        details={
            "snapshot": source_metadata(source_id),
            "reason": "Adapter neimplementat încă; sursa este doar planificată.",
        },
    )
