import pytest


@pytest.fixture(autouse=True)
def _default_test_invoice_hmac_key(monkeypatch):
    monkeypatch.setenv("INVOICE_CACHE_HMAC_KEY", "test-invoice-cache-hmac-key")


@pytest.fixture(autouse=True)
def _clear_invoice_caches():
    # Cache-urile CUI/verdict din invoice_orchestrator sunt globale (process-wide)
    # cu TTL 12h. Fără reset per-test, rezultate cu aceeași cheie (CUI+IBAN+...)
    # se scurg între teste și otrăvesc verdictul (vezi bug#3). Curăță înainte ȘI
    # după fiecare test ca să garantăm izolarea deterministă.
    try:
        from services import invoice_orchestrator as _io
    except Exception:
        yield
        return
    _io._cui_cache.clear()
    _io._verdict_cache.clear()
    yield
    _io._cui_cache.clear()
    _io._verdict_cache.clear()
