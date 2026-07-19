"""Tests for the paid-provider monthly budget gates (#82)."""

from services import provider_budget
from services.paid_provider_budgets import (
    consume_gemini,
    consume_google_vision,
    consume_mistral,
    consume_web_risk,
)


def setup_function(_function):
    provider_budget.reset_memory_budgets()


def test_vision_budget_allows_until_limit(monkeypatch):
    monkeypatch.setenv("GOOGLE_VISION_MONTHLY_BUDGET", "2")
    assert consume_google_vision() is True
    assert consume_google_vision() is True
    assert consume_google_vision() is False


def test_web_risk_budget_allows_until_limit(monkeypatch):
    monkeypatch.setenv("WEB_RISK_MONTHLY_BUDGET", "1")
    assert consume_web_risk() is True
    assert consume_web_risk() is False


def test_web_risk_lookup_reports_budget_exhaustion_without_calling_api(monkeypatch):
    from services import google_web_risk

    url = "https://example.test/login"
    key = google_web_risk.hashlib.sha256(url.encode("utf-8")).hexdigest()

    monkeypatch.setenv("GOOGLE_WEB_RISK_API_KEY", "fake-key")
    monkeypatch.setenv("WEB_RISK_MONTHLY_BUDGET", "0")

    def _fail_if_called(*_args, **_kwargs):
        raise AssertionError("Web Risk API must not be called once budget is exhausted.")

    monkeypatch.setattr(google_web_risk.requests, "get", _fail_if_called)

    result = google_web_risk.check_urls_against_web_risk([url])

    assert result[key]["status"] == "error"
    assert result[key]["error"] == "budget_exhausted"
    assert result[key]["consulted"] is False
    assert result[key]["details"]["status"] == "budget_exhausted"


def test_web_risk_lookup_preserves_google_error_status(monkeypatch):
    from services import google_web_risk

    url = "https://example.test/login"
    key = google_web_risk.hashlib.sha256(url.encode("utf-8")).hexdigest()

    monkeypatch.setenv("GOOGLE_WEB_RISK_API_KEY", "fake-key")
    monkeypatch.setenv("WEB_RISK_MONTHLY_BUDGET", "10")

    class Response:
        status_code = 400

        def json(self):
            return {
                "error": {
                    "code": 400,
                    "message": "API key not valid. Please pass a valid API key.",
                    "status": "INVALID_ARGUMENT",
                    "details": [
                        {
                            "@type": "type.googleapis.com/google.rpc.ErrorInfo",
                            "reason": "API_KEY_INVALID",
                            "domain": "googleapis.com",
                        }
                    ],
                }
            }

    monkeypatch.setattr(google_web_risk.requests, "get", lambda *_args, **_kwargs: Response())

    result = google_web_risk.check_urls_against_web_risk([url])

    assert result[key]["status"] == "error"
    assert result[key]["error"] == "http_400"
    assert result[key]["consulted"] is True
    assert result[key]["details"]["status"] == "http_400"
    assert result[key]["details"]["http_status"] == 400
    assert result[key]["details"]["api_status"] == "INVALID_ARGUMENT"
    assert result[key]["details"]["api_reason"] == "API_KEY_INVALID"
    assert result[key]["details"]["api_message"].startswith("API key not valid")


def test_zero_budget_disables_provider(monkeypatch):
    monkeypatch.setenv("MISTRAL_MONTHLY_BUDGET", "0")
    assert consume_mistral() is False


def test_default_budget_allows_normal_usage(monkeypatch):
    monkeypatch.delenv("GEMINI_MONTHLY_BUDGET", raising=False)
    assert consume_gemini() is True


def test_budgets_are_tracked_per_provider(monkeypatch):
    monkeypatch.setenv("GOOGLE_VISION_MONTHLY_BUDGET", "1")
    monkeypatch.setenv("MISTRAL_MONTHLY_BUDGET", "1")
    assert consume_google_vision() is True
    # Vision exhausted must not exhaust Mistral.
    assert consume_google_vision() is False
    assert consume_mistral() is True


def test_pdf_vision_ocr_respects_budget(monkeypatch):
    """PDF OCR shares the same paid Vision quota as image OCR (#82 follow-up)."""
    from services import google_vision_ocr

    monkeypatch.setenv("GOOGLE_VISION_MONTHLY_BUDGET", "0")
    monkeypatch.setattr(google_vision_ocr, "GOOGLE_CLOUD_VISION_API_KEY", "fake-key")

    def _fail_if_called(*_args, **_kwargs):
        raise AssertionError("Vision API must not be called once budget is exhausted.")

    monkeypatch.setattr(google_vision_ocr.requests, "post", _fail_if_called)

    try:
        google_vision_ocr.extract_text_from_pdf_with_vision(b"%PDF-1.4 fake")
        assert False, "expected RuntimeError on exhausted budget"
    except RuntimeError as exc:
        assert "budget" in str(exc).lower()


def test_shadow_adjudication_respects_mistral_budget(monkeypatch):
    """Shadow adjudicator shares the Mistral budget with the explainer (#82 follow-up)."""
    from services import mistral_shadow_adjudicator as shadow

    monkeypatch.setattr(shadow, "SHADOW_ENABLED", True)
    monkeypatch.setattr(shadow, "MISTRAL_API_KEY", "fake-key")
    monkeypatch.setenv("MISTRAL_MONTHLY_BUDGET", "0")
    shadow._CACHE.clear()

    def _fail_if_called(*_args, **_kwargs):
        raise AssertionError("Mistral must not be called once budget is exhausted.")

    monkeypatch.setattr(shadow, "_call_mistral", _fail_if_called)
    monkeypatch.setattr(shadow, "log_scan_event", lambda event: None)

    event = shadow.maybe_run_shadow_adjudication(
        scan_id="scan-1",
        input_type="text",
        source_channel="share",
        evidence={"gate": {"user_risk_label": "SUSPECT"}, "evidence_hash": "sha256:abc"},
    )

    assert event["evidence"]["fallback_reason"] == "mistral_budget_exhausted"
    assert event["evidence"]["valid"] is False
