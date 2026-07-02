"""Tests for the signed screenshot proxy tokens (#80)."""

import time

from core.screenshot_token import (
    enforcement_enabled,
    mint_screenshot_token,
    secret_configured,
    verify_screenshot_token,
)


def test_token_roundtrip(monkeypatch):
    monkeypatch.setenv("SCREENSHOT_PROXY_HMAC_KEY", "test-secret")
    token = mint_screenshot_token("abc-123")
    assert verify_screenshot_token("abc-123", token) is True


def test_token_bound_to_uuid(monkeypatch):
    monkeypatch.setenv("SCREENSHOT_PROXY_HMAC_KEY", "test-secret")
    token = mint_screenshot_token("abc-123")
    assert verify_screenshot_token("other-uuid", token) is False


def test_expired_token_rejected(monkeypatch):
    monkeypatch.setenv("SCREENSHOT_PROXY_HMAC_KEY", "test-secret")
    monkeypatch.delenv("SCREENSHOT_PROXY_TOKEN_TTL_SECONDS", raising=False)
    stale_now = int(time.time()) - 200000  # expiry lands well in the past
    token = mint_screenshot_token("abc-123", now=stale_now)
    assert verify_screenshot_token("abc-123", token) is False


def test_garbage_tokens_rejected(monkeypatch):
    monkeypatch.setenv("SCREENSHOT_PROXY_HMAC_KEY", "test-secret")
    assert verify_screenshot_token("abc-123", "") is False
    assert verify_screenshot_token("abc-123", "not-a-token") is False
    assert verify_screenshot_token("abc-123", "123456.") is False
    assert verify_screenshot_token("abc-123", None) is False


def test_missing_secret_fails_verification(monkeypatch):
    monkeypatch.delenv("SCREENSHOT_PROXY_HMAC_KEY", raising=False)
    monkeypatch.delenv("INVOICE_CACHE_HMAC_KEY", raising=False)
    assert secret_configured() is False
    assert verify_screenshot_token("abc-123", "1.deadbeef") is False


def test_enforcement_flag_default_on(monkeypatch):
    monkeypatch.delenv("SCREENSHOT_PROXY_REQUIRE_TOKEN", raising=False)
    assert enforcement_enabled() is True
    monkeypatch.setenv("SCREENSHOT_PROXY_REQUIRE_TOKEN", "false")
    assert enforcement_enabled() is False
