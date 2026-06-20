"""Configuration constants for the URL reputation service.

Source identifiers, weights, feed URLs, timeouts, TTLs and enable flags were extracted
verbatim from url_reputation.py to separate tunable configuration from the cache and feed
logic. Mutable feed caches and the fetcher functions stay in url_reputation.py so that test
monkeypatching of url_reputation.requests / url_reputation._fetch_* keeps working.
"""

import os
from pathlib import Path


WEB_RISK_SOURCE = "google_web_risk"
PHISHING_DATABASE_SOURCE = "phishing_database"
URLHAUS_SOURCE = "urlhaus"
SCAM_BLOCKLIST_NRD_SOURCE = "scam_blocklist_nrd"
PHISHDESTROY_SOURCE = "phishdestroy_destroylist"
ASF_INVESTOR_ALERTS_SOURCE = "asf_investor_alerts"

WEB_RISK_WEIGHT = 60
PHISHING_DATABASE_WEIGHT = 80
URLHAUS_WEIGHT = 55
SCAM_BLOCKLIST_NRD_WEIGHT = 70
PHISHDESTROY_WEIGHT = 70
ASF_INVESTOR_ALERTS_WEIGHT = 100
SOURCE_ORDER = [
    WEB_RISK_SOURCE,
    ASF_INVESTOR_ALERTS_SOURCE,
    PHISHING_DATABASE_SOURCE,
    URLHAUS_SOURCE,
    SCAM_BLOCKLIST_NRD_SOURCE,
    PHISHDESTROY_SOURCE,
]

SOURCE_WEIGHTS = {
    WEB_RISK_SOURCE: WEB_RISK_WEIGHT,
    PHISHING_DATABASE_SOURCE: PHISHING_DATABASE_WEIGHT,
    URLHAUS_SOURCE: URLHAUS_WEIGHT,
    SCAM_BLOCKLIST_NRD_SOURCE: SCAM_BLOCKLIST_NRD_WEIGHT,
    PHISHDESTROY_SOURCE: PHISHDESTROY_WEIGHT,
    ASF_INVESTOR_ALERTS_SOURCE: ASF_INVESTOR_ALERTS_WEIGHT,
}

SOURCE_STATUS_WEIGHTS = {
    "malicious": 1.0,
    "suspicious": 0.55,
    "clean": 0.0,
    "unknown": 0.0,
    "error": 0.0,
}

REPUTATION_CACHE_VERSION = 6
ASF_INVESTOR_ALERTS_URL = os.getenv(
    "ASF_INVESTOR_ALERTS_URL",
    "https://asfromania.ro/ro/a/19/alerte-investitori---informari",
)
PHISHING_DATABASE_DOMAINS_URL = os.getenv(
    "PHISHING_DATABASE_DOMAINS_URL",
    "https://raw.githubusercontent.com/Phishing-Database/Phishing.Database/master/phishing-domains-ACTIVE.txt",
)
PHISHING_DATABASE_LINKS_URL = os.getenv(
    "PHISHING_DATABASE_LINKS_URL",
    "https://phish.co.za/latest/phishing-links-ACTIVE.txt",
)
URLHAUS_API_URL = "https://urlhaus-api.abuse.ch/v1/url/"
SCAM_BLOCKLIST_NRD_URL = os.getenv(
    "SCAM_BLOCKLIST_NRD_URL",
    "https://raw.githubusercontent.com/jarelllama/Scam-Blocklist/main/lists/wildcard_domains/scams.txt",
)
SCAM_BLOCKLIST_NRD_LICENSE = "GPL-3.0"
PHISHDESTROY_URL = os.getenv(
    "PHISHDESTROY_URL",
    "https://raw.githubusercontent.com/phishdestroy/destroylist/main/rootlist/formats/primary_active/domains.txt",
)
PHISHDESTROY_API_URL = os.getenv("PHISHDESTROY_API_URL", "https://api.destroy.tools/v1")
PHISHDESTROY_LICENSE = "MIT"
PHISHING_DATABASE_TIMEOUT_SECONDS = float(os.getenv("PHISHING_DATABASE_TIMEOUT_SECONDS", "4.0"))
PHISHING_DATABASE_FEED_TTL_SECONDS = int(os.getenv("PHISHING_DATABASE_FEED_TTL_SECONDS", "3600"))
SCAM_BLOCKLIST_NRD_TIMEOUT_SECONDS = float(os.getenv("SCAM_BLOCKLIST_NRD_TIMEOUT_SECONDS", "4.0"))
SCAM_BLOCKLIST_NRD_FEED_TTL_SECONDS = int(os.getenv("SCAM_BLOCKLIST_NRD_FEED_TTL_SECONDS", "21600"))
PHISHDESTROY_TIMEOUT_SECONDS = float(os.getenv("PHISHDESTROY_TIMEOUT_SECONDS", "4.0"))
PHISHDESTROY_FEED_TTL_SECONDS = int(os.getenv("PHISHDESTROY_FEED_TTL_SECONDS", "7200"))
ASF_INVESTOR_ALERTS_TIMEOUT_SECONDS = float(os.getenv("ASF_INVESTOR_ALERTS_TIMEOUT_SECONDS", "4.0"))
ASF_INVESTOR_ALERTS_FEED_TTL_SECONDS = int(os.getenv("ASF_INVESTOR_ALERTS_FEED_TTL_SECONDS", "21600"))
URLHAUS_TIMEOUT_SECONDS = float(os.getenv("URLHAUS_TIMEOUT_SECONDS", "3.0"))
URLHAUS_AUTH_KEY = (
    os.getenv("URLHAUS_AUTH_KEY", "").strip()
    or os.getenv("URLHAUS_API_KEY", "").strip()
    or os.getenv("ABUSECH_AUTH_KEY", "").strip()
)
ENABLE_PHISHING_DATABASE = os.getenv("ENABLE_PHISHING_DATABASE", "true").strip().lower() in {
    "1",
    "true",
    "yes",
    "on",
}
ENABLE_SCAM_BLOCKLIST_NRD = os.getenv("ENABLE_SCAM_BLOCKLIST_NRD", "false").strip().lower() in {
    "1",
    "true",
    "yes",
    "on",
}
ENABLE_PHISHDESTROY = os.getenv("ENABLE_PHISHDESTROY", "false").strip().lower() in {
    "1",
    "true",
    "yes",
    "on",
}
ENABLE_ASF_INVESTOR_ALERTS = os.getenv("ENABLE_ASF_INVESTOR_ALERTS", "true").strip().lower() in {
    "1",
    "true",
    "yes",
    "on",
}
PHISHING_DATABASE_MAX_FEED_BYTES = int(os.getenv("PHISHING_DATABASE_MAX_FEED_BYTES", "20000000"))
SCAM_BLOCKLIST_NRD_MAX_FEED_BYTES = int(os.getenv("SCAM_BLOCKLIST_NRD_MAX_FEED_BYTES", "30000000"))
PHISHDESTROY_MAX_FEED_BYTES = int(os.getenv("PHISHDESTROY_MAX_FEED_BYTES", "10000000"))
ASF_INVESTOR_ALERTS_MAX_FEED_BYTES = int(os.getenv("ASF_INVESTOR_ALERTS_MAX_FEED_BYTES", "1500000"))

DEFAULT_CACHE_TTL_SECONDS = int(os.getenv("URL_REPUTATION_CACHE_TTL_SECONDS", "43200"))
MAX_REPUTATION_URLS = int(os.getenv("MAX_REPUTATION_URLS", "60"))
REPUTATION_CACHE_MAX_ITEMS = int(os.getenv("URL_REPUTATION_CACHE_MAX_ITEMS", "1000"))
DEFAULT_REPUTATION_CACHE_PATH = Path(__file__).resolve().parents[1] / "data" / "url_reputation_cache.json"
DEFAULT_LOCAL_PHISHING_LOOKALIKE_PATH = (
    Path(__file__).resolve().parents[1] / "data" / "phishing_lookalike_domains_v1.json"
)
LOCAL_PHISHING_LOOKALIKE_PATH = Path(
    os.getenv("LOCAL_PHISHING_LOOKALIKE_PATH", str(DEFAULT_LOCAL_PHISHING_LOOKALIKE_PATH)),
)
REPUTATION_CACHE_PATH = Path(
    os.getenv("URL_REPUTATION_CACHE_PATH", str(DEFAULT_REPUTATION_CACHE_PATH)),
)
REPUTATION_CACHE_TTL_SECONDS = int(
    os.getenv("URL_REPUTATION_CACHE_TTL_SECONDS", str(DEFAULT_CACHE_TTL_SECONDS)),
)
ENABLE_URL_REPUTATION = os.getenv("ENABLE_URL_REPUTATION", "true").strip().lower() in {
    "1",
    "true",
    "yes",
    "on",
}
