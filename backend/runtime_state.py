"""Runtime state containers for backend shared process memory."""

from typing import Any, Dict

from services.scam_atlas import ScamAtlasEngine
from services.tier1_classifier import Tier1Classifier

# Shared singletons for runtime classification/atlas services.
engine = ScamAtlasEngine()
tier1_classifier = Tier1Classifier.load_default()

# Shared in-memory caches for quick preview lookups.
_URLSCAN_PREVIEW_CACHE: Dict[str, Dict[str, Any]] = {}
_FAST_PREVIEW_CACHE: Dict[str, Dict[str, Any]] = {}
