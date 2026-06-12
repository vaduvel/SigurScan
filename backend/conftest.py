import pytest


@pytest.fixture(autouse=True)
def _default_test_invoice_hmac_key(monkeypatch):
    monkeypatch.setenv("INVOICE_CACHE_HMAC_KEY", "test-invoice-cache-hmac-key")
