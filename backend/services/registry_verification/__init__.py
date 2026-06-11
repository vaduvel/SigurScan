"""Registry verification (PR4) — dovezi oneste din registre publice.

Produce DOAR RegistryVerificationResult; verdictul aparține exclusiv
verdict_gate.reduce_verdict (prin offer_evidence_gate_mapper).
"""
from services.registry_verification.metadata import source_metadata
from services.registry_verification.models import RegistryStatus, RegistryVerificationResult
from services.registry_verification.router import route_sources, verify_offer_registries

__all__ = [
    "RegistryStatus",
    "RegistryVerificationResult",
    "route_sources",
    "source_metadata",
    "verify_offer_registries",
]
