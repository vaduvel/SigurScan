import json
from pathlib import Path

from services import redirect_resolver, telemetry
from services.verdict_gate import verdict


class _FakeRaw:
    def __init__(self):
        self.read_sizes = []

    def read(self, size=-1):
        self.read_sizes.append(size)
        return b"<html><body>ok</body></html>"


class _FakeResponse:
    status_code = 200
    headers = {"Content-Type": "text/html"}

    def __init__(self):
        self.raw = _FakeRaw()
        self.closed = False

    def close(self):
        self.closed = True


class _FakeSession:
    created = []

    def __init__(self):
        self.max_redirects = None
        self.calls = []
        self.response = _FakeResponse()
        _FakeSession.created.append(self)

    def get(self, url, **kwargs):
        self.calls.append((url, kwargs))
        return self.response


def _base_bundle(provider_payload):
    return {
        "resolution": {"status": "resolved", "completeness": True},
        "providers": provider_payload,
        "identity": {
            "status": "unknown",
            "tld_suspicious": False,
            "domain_age_days": 5000,
        },
        "request": {"sensitive": "none", "channel": "sms", "completeness": True},
        "semantic_review": {
            "status": "done",
            "risk_class": "unknown",
            "completeness": True,
        },
    }


def test_redirect_resolver_freeze_contract(monkeypatch):
    _FakeSession.created.clear()
    monkeypatch.setattr(redirect_resolver.requests, "Session", _FakeSession)
    monkeypatch.setattr(redirect_resolver, "check_domain_age", lambda domain: (5000, "2012-01-01"))
    monkeypatch.setattr(redirect_resolver, "check_mx_records", lambda domain: True)

    result = redirect_resolver.resolve_redirects_safely("https://example.com/start")

    session = _FakeSession.created[0]
    assert session.max_redirects == 20
    assert session.calls[0][1]["timeout"] == 4.0
    assert session.calls[0][1]["allow_redirects"] is False
    assert session.calls[0][1]["stream"] is True
    assert session.response.raw.read_sizes == [redirect_resolver.MAX_HTML_SCAN_BYTES]
    assert redirect_resolver.MAX_HTML_SCAN_BYTES == 32 * 1024
    assert len(redirect_resolver.KNOWN_SHORTENERS) >= 25
    assert {"bit.ly", "tiny.cc", "t.postis.io", "lnkd.in"}.issubset(
        redirect_resolver.KNOWN_SHORTENERS
    )
    assert result["success"] is True


def test_provider_errors_never_become_safe_with_established_domain():
    provider_cases = [
        {"verdict": "error", "completeness": True},
        {"verdict": "unknown", "completeness": True},
        {"google_web_risk": {"status": "error", "consulted": True}, "completeness": True},
        {"urlhaus": {"status": "error", "consulted": True}, "completeness": True},
    ]

    for provider_payload in provider_cases:
        result = verdict(_base_bundle(provider_payload))
        assert result["label"] == "SUSPECT"
        assert result["reason_codes"] == ["residual"]


def test_provider_pending_stays_internal_pending_not_safe():
    result = verdict(_base_bundle({"verdict": "pending", "completeness": True}))

    assert result["label"] == "PENDING"
    assert result["reason_codes"] == ["insufficient_evidence"]


def test_scan_event_logging_redacts_pii_before_any_sink(monkeypatch, tmp_path):
    captured = {}
    log_path = tmp_path / "scan_events.jsonl"
    monkeypatch.setattr(telemetry, "SCAN_EVENTS_PATH", log_path)
    monkeypatch.setattr(
        telemetry.supabase_store,
        "log_scan_event",
        lambda payload: captured.setdefault("payload", payload),
    )

    raw_text = (
        "Contact ion.popescu@example.com sau 0722 123 456. "
        "CNP 1960101223344, IBAN RO49AAAA1B31007593840000, "
        "card 4111 1111 1111 1111, cod 123456."
    )
    telemetry.log_scan_event(
        {
            "scan_id": "freeze-log-redaction",
            "risk_level": "medium",
            "redacted_text_snippet": raw_text,
            "metadata": {"raw_note": raw_text},
            "urls": [{"final_url": "https://example.com/?email=ion.popescu@example.com"}],
        }
    )

    written = log_path.read_text(encoding="utf-8")
    supabase_payload = json.dumps(captured["payload"], ensure_ascii=False)
    combined = written + supabase_payload

    assert "ion.popescu@example.com" not in combined
    assert "0722 123 456" not in combined
    assert "1960101223344" not in combined
    assert "RO49AAAA1B31007593840000" not in combined
    assert "4111 1111 1111 1111" not in combined
    assert "123456" not in combined
    assert "[EMAIL_REDACTED]" in combined
    assert "[PHONE_REDACTED]" in combined
    assert "[CNP_REDACTED]" in combined
    assert "[IBAN_REDACTED]" in combined
    assert "[CARD_REDACTED]" in combined
    assert "[OTP_REDACTED]" in combined
