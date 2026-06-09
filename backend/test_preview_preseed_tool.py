import json
from pathlib import Path

from tools import preseed_urlscan_previews as preseed


class _FakeResponse:
    def __init__(self, payload):
        self._payload = payload

    def raise_for_status(self):
        return None

    def json(self):
        return self._payload


class _FakeClient:
    def __init__(self):
        self.calls = []

    def post(self, url, json=None, timeout=None):
        self.calls.append(("post", url, json, timeout))
        return _FakeResponse({"scan_id": "orch_seed_1"})

    def get(self, url, timeout=None):
        self.calls.append(("get", url, None, timeout))
        return _FakeResponse(
            {
                "status": "scanning",
                "preview": {
                    "cache_hit": True,
                    "final_url": "https://www.fancourier.ro/",
                    "report_url": "https://urlscan.io/result/fan/",
                    "screenshot_url": "https://backend/v1/sandbox/urlscan/fan/screenshot",
                },
                "result": None,
            }
        )


class _FakeClientPreviewAfterSubmit:
    def __init__(self):
        self.calls = []
        self.poll_count = 0

    def post(self, url, json=None, timeout=None):
        self.calls.append(("post", url, json, timeout))
        return _FakeResponse({"scan_id": "orch_seed_2"})

    def get(self, url, timeout=None):
        self.poll_count += 1
        self.calls.append(("get", url, None, timeout))
        if self.poll_count == 1:
            return _FakeResponse(
                {
                    "status": "scanning",
                    "preview": {
                        "cache_hit": False,
                        "cache_saved": False,
                        "final_url": "https://www.fancourier.ro/",
                        "report_url": "https://urlscan.io/result/fan-new/",
                        "screenshot_url": "https://backend/v1/sandbox/urlscan/fan-new/screenshot",
                    },
                    "result": None,
                }
            )
        return _FakeResponse(
            {
                "status": "complete",
                "preview": {
                    "cache_hit": False,
                    "cache_saved": True,
                    "final_url": "https://www.fancourier.ro/",
                    "report_url": "https://urlscan.io/result/fan-new/",
                    "screenshot_url": "https://backend/v1/sandbox/urlscan/fan-new/screenshot",
                },
                "result": {"user_risk_label": "SIGUR"},
            }
        )


class _FakeClientCompleteBeforeCacheSaved:
    def __init__(self):
        self.calls = []
        self.poll_count = 0

    def post(self, url, json=None, timeout=None):
        self.calls.append(("post", url, json, timeout))
        return _FakeResponse({"scan_id": "orch_seed_3"})

    def get(self, url, timeout=None):
        self.poll_count += 1
        self.calls.append(("get", url, None, timeout))
        if self.poll_count == 1:
            return _FakeResponse(
                {
                    "status": "complete",
                    "preview": {
                        "cache_hit": False,
                        "cache_saved": False,
                        "final_url": "https://www.orange.ro/",
                        "report_url": "https://urlscan.io/result/orange/",
                        "screenshot_url": "https://backend/v1/sandbox/urlscan/orange/screenshot",
                    },
                    "result": {"user_risk_label": "SIGUR"},
                }
            )
        return _FakeResponse(
            {
                "status": "complete",
                "preview": {
                    "cache_hit": False,
                    "cache_saved": True,
                    "final_url": "https://www.orange.ro/",
                    "report_url": "https://urlscan.io/result/orange/",
                    "screenshot_url": "https://backend/v1/sandbox/urlscan/orange/screenshot",
                },
                "result": {"user_risk_label": "SIGUR"},
            }
        )


class _FakeClientTimeoutThenCacheSaved:
    def __init__(self):
        self.calls = []
        self.poll_count = 0

    def post(self, url, json=None, timeout=None):
        self.calls.append(("post", url, json, timeout))
        return _FakeResponse({"scan_id": "orch_seed_4"})

    def get(self, url, timeout=None):
        self.poll_count += 1
        self.calls.append(("get", url, None, timeout))
        if self.poll_count == 1:
            raise preseed.requests.Timeout("poll timed out")
        return _FakeResponse(
            {
                "status": "complete",
                "preview": {
                    "cache_hit": False,
                    "cache_saved": True,
                    "final_url": "https://www.anaf.ro/",
                    "report_url": "https://urlscan.io/result/anaf/",
                    "screenshot_url": "https://backend/v1/sandbox/urlscan/anaf/screenshot",
                },
                "result": {"user_risk_label": "SIGUR"},
            }
        )


def test_load_seed_urls_filters_disabled_and_normalizes(tmp_path: Path):
    seed_path = tmp_path / "seed.json"
    seed_path.write_text(
        json.dumps(
            {
                "urls": [
                    {"label": "FAN", "url": " https://www.fancourier.ro/ ", "brand": "FAN Courier"},
                    {"label": "disabled", "url": "https://example.com", "enabled": False},
                    {"label": "empty", "url": ""},
                ]
            }
        ),
        encoding="utf-8",
    )

    urls = preseed.load_seed_urls(seed_path)

    assert urls == [
        {
            "label": "FAN",
            "url": "https://www.fancourier.ro/",
            "brand": "FAN Courier",
            "source_channel": "preview_seed",
        }
    ]


def test_run_preseed_dry_run_does_not_call_network():
    client = _FakeClient()
    result = preseed.run_preseed(
        [{"label": "FAN", "url": "https://www.fancourier.ro/"}],
        base_url="https://backend.example",
        client=client,
        dry_run=True,
    )

    assert result[0]["status"] == "dry_run"
    assert client.calls == []


def test_run_preseed_supports_offset_for_chunking():
    result = preseed.run_preseed(
        [
            {"label": "A", "url": "https://a.example"},
            {"label": "B", "url": "https://b.example"},
            {"label": "C", "url": "https://c.example"},
        ],
        base_url="https://backend.example",
        dry_run=True,
        offset=1,
        limit=1,
    )

    assert result == [{"label": "B", "url": "https://b.example", "status": "dry_run"}]


def test_preseed_one_posts_url_payload_and_stops_on_preview():
    client = _FakeClient()

    result = preseed.preseed_one(
        {"label": "FAN", "url": "https://www.fancourier.ro/"},
        base_url="https://backend.example/",
        client=client,
        timeout_seconds=20,
        poll_interval_seconds=0,
        sleep=lambda _: None,
    )

    assert result["status"] == "preview_ready"
    assert result["scan_id"] == "orch_seed_1"
    assert result["cache_hit"] is True
    assert result["screenshot_url"] == "https://backend/v1/sandbox/urlscan/fan/screenshot"
    assert client.calls[0][0] == "post"
    assert client.calls[0][1] == "https://backend.example/v1/scan/orchestrated"
    assert client.calls[0][2] == {
        "input_type": "url",
        "url": "https://www.fancourier.ro/",
        "source_channel": "preview_seed",
    }


def test_preseed_one_waits_for_complete_when_preview_is_not_cached_yet():
    client = _FakeClientPreviewAfterSubmit()

    result = preseed.preseed_one(
        {"label": "FAN", "url": "https://www.fancourier.ro/"},
        base_url="https://backend.example/",
        client=client,
        timeout_seconds=20,
        poll_interval_seconds=0,
        sleep=lambda _: None,
    )

    assert result["status"] == "preview_ready"
    assert result["cache_hit"] is False
    assert result["cache_saved"] is True
    assert client.poll_count == 2


def test_preseed_one_keeps_polling_after_complete_until_cache_saved():
    client = _FakeClientCompleteBeforeCacheSaved()

    result = preseed.preseed_one(
        {"label": "Orange", "url": "https://www.orange.ro/"},
        base_url="https://backend.example/",
        client=client,
        timeout_seconds=20,
        poll_interval_seconds=0,
        sleep=lambda _: None,
    )

    assert result["status"] == "preview_ready"
    assert result["cache_saved"] is True
    assert client.poll_count == 2


def test_preseed_one_retries_poll_timeout_until_cache_saved():
    client = _FakeClientTimeoutThenCacheSaved()

    result = preseed.preseed_one(
        {"label": "ANAF", "url": "https://www.anaf.ro/"},
        base_url="https://backend.example/",
        client=client,
        timeout_seconds=20,
        poll_interval_seconds=0,
        sleep=lambda _: None,
    )

    assert result["status"] == "preview_ready"
    assert result["cache_saved"] is True
    assert client.poll_count == 2
