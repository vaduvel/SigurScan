"""Standalone configuration constants shared between main.py and api_models.py.

Kept dependency-free so both can import it without a circular import.
"""

import os

URLSCAN_VISIBILITY_DEFAULT = os.getenv("URLSCAN_VISIBILITY_DEFAULT", "private").strip().lower() or "private"
URLSCAN_COUNTRY_DEFAULT = os.getenv("URLSCAN_COUNTRY_DEFAULT", "").strip().lower()
URLSCAN_CUSTOM_AGENT_DEFAULT = os.getenv("URLSCAN_CUSTOM_AGENT", "").strip()
