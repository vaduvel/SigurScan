"""Shared singleton stores used by both main.py and the API routers.

Kept dependency-free (only services) so it can be imported without a circular
import. urechea_ingester wraps campaign_store, so order matters.
"""

from services.brand_truth_registry import BrandTruthRegistry
from services.campaign_intel import CampaignStore
from services.urechea_ingester import UrecheaIngester
from services.cfx_engine import CfxStore

brand_truth_registry = BrandTruthRegistry()
campaign_store = CampaignStore()
urechea_ingester = UrecheaIngester(campaign_store)
cfx_store = CfxStore()
cfx_store.seed_from_campaigns(campaign_store.all())
