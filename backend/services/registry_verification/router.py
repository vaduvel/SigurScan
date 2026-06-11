"""Router registru: alege sursele relevante pe baza familiei OP (din seed-ul
scam_atlas_offer_seed prin family_classifier) + identificatorii extrași de
offer_parser. Nu clasifică (refolosește family_code) și nu judecă (rezultatele
merg în Evidence Bundle v2 → reduce_verdict).
"""
from __future__ import annotations

import re
from typing import TYPE_CHECKING, List, Optional

from services.family_classifier import get_offer_family
from services.registry_verification.models import RegistryVerificationResult
from services.registry_verification.onrc import verify_onrc
from services.registry_verification.stubs import STUB_SOURCE_IDS, verify_stub

if TYPE_CHECKING:
    from services.offer_parser import OfferFields

# Emitentul rutează ONRC doar dacă arată a firmă (formă juridică), nu orice text
# liber pe care fallback-ul de parser l-a luat drept „emitent".
_COMPANY_HINT = re.compile(
    r"\b(srl|s\.?r\.?l\.?|sa|s\.?a\.?|s\.?c\.?|pfa|p\.?f\.?a\.?|ii|i\.?i\.?|snc|gmbh|ltd|llc)\b",
    re.IGNORECASE,
)


def _company_issuer(fields: "OfferFields") -> Optional[str]:
    issuer = fields.issuer_name or fields.emitent
    if issuer and _COMPANY_HINT.search(issuer):
        return issuer
    return None

# Cuvinte-cheie din verification_sources (seed) -> source_id local.
# SANB/DNSC/Biroul de Credit/platformele NU au adapter de registru — nu se rutează.
_SEED_KEYWORD_TO_SOURCE = (
    ("SITUR", "situr"),
    ("ANAT", "situr"),
    ("ONRC", "onrc"),
    ("ASF", "asf"),
    ("BNR", "bnr"),
    ("ANPC", "anpc"),
    ("ANCPI", "ancpi"),
    ("CARTE FUNCIARA", "ancpi"),
    ("RAR", "rar_auto_pass"),
    ("ITM", "itm"),
    ("ANOFM", "anofm"),
)

# Rutare minimă pe familie, cerută explicit de plan (independent de seed).
_FAMILY_BASE_SOURCES = {
    "OP-01": ("situr",),
    "OP-08": ("itm", "anofm"),
    "OP-09": ("bnr", "asf"),
}


def route_sources(family_code: str, fields: "OfferFields") -> List[str]:
    """Lista deterministă de surse de consultat pentru această ofertă."""
    sources: List[str] = []

    def add(source_id: str) -> None:
        if source_id not in sources:
            sources.append(source_id)

    # Firmă identificată prin CUI sau nume emitent cu formă juridică -> ONRC.
    if fields.cui or _company_issuer(fields):
        add("onrc")

    for source_id in _FAMILY_BASE_SOURCES.get(family_code or "", ()):
        add(source_id)

    family = get_offer_family(family_code or "")
    for raw in (family or {}).get("verification_sources", []):
        upper = str(raw).upper()
        for keyword, source_id in _SEED_KEYWORD_TO_SOURCE:
            if keyword in upper:
                add(source_id)

    return sources


def verify_offer_registries(fields: "OfferFields", family_code: str) -> List[RegistryVerificationResult]:
    """Rulează verificările pentru sursele rutate. Doar snapshot-uri locale/stubs —
    zero apeluri live instabile."""
    results: List[RegistryVerificationResult] = []
    issuer = fields.issuer_name or fields.emitent
    for source_id in route_sources(family_code, fields):
        if source_id == "onrc":
            results.append(verify_onrc(fields.cui, issuer))
        elif source_id in STUB_SOURCE_IDS:
            results.append(verify_stub(source_id))
    return results
