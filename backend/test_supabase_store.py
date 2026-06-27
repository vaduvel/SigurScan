import time

from services import supabase_store
from services.urlscan_helpers import _normalize_urlscan_preview_cache_entry


class _FakeSupabaseResponse:
    content = b"{}"

    def raise_for_status(self):
        return None

    def json(self):
        return {}


def test_scan_events_upsert_targets_scan_id_unique_constraint(monkeypatch):
    calls = []

    def fake_post(*args, **kwargs):
        calls.append({"args": args, "kwargs": kwargs})
        return _FakeSupabaseResponse()

    with monkeypatch.context() as patched:
        patched.setattr(supabase_store, "SUPABASE_URL", "https://example.supabase.co")
        patched.setattr(supabase_store, "SUPABASE_SERVICE_ROLE_KEY", "server-only-key")
        patched.setattr(supabase_store.requests, "post", fake_post)

        supabase_store.log_scan_event(
            {
                "scan_id": "scan-live-smoke-1",
                "input_type": "url",
                "risk_score": 5,
                "risk_level": "low",
                "timestamp": int(time.time()),
            }
        )

    assert calls
    assert calls[0]["kwargs"]["params"] == {"on_conflict": "scan_id"}
    assert calls[0]["kwargs"]["headers"]["Prefer"] == "resolution=merge-duplicates,return=minimal"


def test_urlscan_preview_cache_payload_matches_current_supabase_schema(monkeypatch):
    calls = []

    def fake_post(*args, **kwargs):
        calls.append({"args": args, "kwargs": kwargs})
        return _FakeSupabaseResponse()

    with monkeypatch.context() as patched:
        patched.setattr(supabase_store, "SUPABASE_URL", "https://example.supabase.co")
        patched.setattr(supabase_store, "SUPABASE_SERVICE_ROLE_KEY", "server-only-key")
        patched.setattr(supabase_store.requests, "post", fake_post)

        supabase_store.save_urlscan_preview_cache(
            {
                "url_hash": "a" * 64,
                "canonical_url": "https://example.org/menu",
                "final_url": "https://example.org/menu",
                "final_registered_domain": "example.org",
                "uuid": "urlscan-cache-1",
                "report_url": "https://urlscan.io/result/urlscan-cache-1/",
                "screenshot_url": "https://urlscan.io/screenshots/urlscan-cache-1.png",
                "screenshot_ready": True,
                "verdict": "No malicious classification",
                "severity": "low",
                "details": "urlscan preview cached",
                "expires_at": int(time.time()) + 3600,
            }
        )

    assert calls
    payload = calls[0]["kwargs"]["json"]
    assert "screenshot_ready" not in payload
    assert payload["screenshot_url"] == "https://urlscan.io/screenshots/urlscan-cache-1.png"


def test_urlscan_preview_cache_infers_ready_for_urlscan_screenshot_without_column():
    normalized = _normalize_urlscan_preview_cache_entry(
        {
            "url_hash": "urlscan-cache-1",
            "final_url": "https://example.org/menu",
            "report_url": "https://urlscan.io/result/urlscan-cache-1/",
            "screenshot_url": "https://urlscan.io/screenshots/urlscan-cache-1.png",
            "expires_at": int(time.time()) + 3600,
        }
    )

    assert normalized is not None
    assert normalized["screenshot_ready"] is True
