import importlib.util
import json
import sys
from pathlib import Path


BACKEND_DIR = Path(__file__).resolve().parent


def _load_tool():
    path = BACKEND_DIR / "tools" / "crawl_public_payment_destinations.py"
    spec = importlib.util.spec_from_file_location("public_payment_destination_crawler_tool_test", path)
    module = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    sys.modules["public_payment_destination_crawler_tool_test"] = module
    spec.loader.exec_module(module)
    return module


def test_extractor_finds_valid_iban_cui_and_masks_client_display():
    from services.public_payment_destination_crawler import extract_candidates_from_text

    text = """
    Modalitati de plata factura
    Furnizor: Compania Exemplu S.R.L.
    CUI: 1096128
    Cont plata clienti: RO78 BACX 0000 0006 4257 9002
    Beneficiar: Compania Exemplu S.R.L.
    """
    source = {
        "url": "https://exemplu.ro/plata",
        "publisher": "Compania Exemplu",
        "brand_id": "compania_exemplu",
        "display_name": "Compania Exemplu",
        "legal_name": "Compania Exemplu S.R.L.",
        "cui": "1096128",
        "source_kind": "official_webpage",
        "trust_tier": "T1_PUBLIC_OFFICIAL",
        "scope": "invoice_payment",
    }

    candidates = extract_candidates_from_text(text, source)

    assert len(candidates) == 1
    candidate = candidates[0]
    assert candidate["iban_normalized"] == "RO78BACX0000000642579002"
    assert candidate["iban_masked_for_client"] == "RO78 BACX **** **** **** 9002"
    assert candidate["cui"] == "1096128"
    assert candidate["source_refs"][0]["url"] == "https://exemplu.ro/plata"
    assert candidate["can_contribute_to_safe"] is False
    assert candidate["review_status"] == "needs_review"


def test_extractor_rejects_invalid_and_masked_ibans():
    from services.public_payment_destination_crawler import extract_candidates_from_text

    text = """
    CUI: 1096128
    IBAN mascat: RO63 TREZ 1315 069X XX00 0650
    IBAN invalid: RO78 BACX 0000 0006 4257 9003
    """

    candidates = extract_candidates_from_text(text, {"url": "https://example.ro"})

    assert candidates == []


def test_registry_delta_keeps_crawled_candidates_review_only_by_default():
    from services.public_payment_destination_crawler import (
        build_payment_destination_registry_delta,
        extract_candidates_from_text,
    )

    source = {
        "url": "https://exemplu.ro/plata",
        "publisher": "Compania Exemplu",
        "brand_id": "compania_exemplu",
        "display_name": "Compania Exemplu",
        "legal_name": "Compania Exemplu S.R.L.",
        "cui": "1096128",
        "source_kind": "official_webpage",
        "trust_tier": "T1_PUBLIC_OFFICIAL",
        "scope": "invoice_payment",
    }
    candidates = extract_candidates_from_text("CUI 1096128 IBAN RO78 BACX 0000 0006 4257 9002", source)

    payload = build_payment_destination_registry_delta(candidates, version="test-version")

    destination = payload["entries"][0]["payment_destinations"][0]
    assert payload["version"] == "test-version"
    assert destination["review_status"] == "needs_review"
    assert destination["can_contribute_to_safe"] is False
    assert destination["trust_tier"] == "T1_PUBLIC_OFFICIAL"


def test_official_manifest_can_explicitly_activate_safe_contribution():
    from services.public_payment_destination_crawler import (
        build_payment_destination_registry_delta,
        extract_candidates_from_text,
    )

    source = {
        "url": "https://exemplu.ro/plata",
        "publisher": "Compania Exemplu",
        "brand_id": "compania_exemplu",
        "display_name": "Compania Exemplu",
        "legal_name": "Compania Exemplu S.R.L.",
        "cui": "1096128",
        "source_kind": "official_webpage",
        "trust_tier": "T1_PUBLIC_OFFICIAL",
        "scope": "invoice_payment",
        "allow_safe_contribution": True,
    }
    candidates = extract_candidates_from_text("CUI: 1096128\nIBAN: RO78 BACX 0000 0006 4257 9002", source)

    payload = build_payment_destination_registry_delta(candidates, version="test-version")

    destination = payload["entries"][0]["payment_destinations"][0]
    assert destination["review_status"] == "active"
    assert destination["can_contribute_to_safe"] is True


def test_cli_crawls_manifest_with_injected_fetcher(tmp_path):
    tool = _load_tool()
    manifest = {
        "sources": [
            {
                "url": "https://exemplu.ro/plata",
                "publisher": "Compania Exemplu",
                "brand_id": "compania_exemplu",
                "display_name": "Compania Exemplu",
                "legal_name": "Compania Exemplu S.R.L.",
                "cui": "1096128",
                "source_kind": "official_webpage",
                "trust_tier": "T1_PUBLIC_OFFICIAL",
                "scope": "invoice_payment",
            }
        ]
    }
    manifest_path = tmp_path / "manifest.json"
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

    class Response:
        status_code = 200
        content = b"<html><body>CUI: 1096128 IBAN RO78 BACX 0000 0006 4257 9002</body></html>"
        text = content.decode("utf-8")
        headers = {"content-type": "text/html"}

    result = tool.run_crawl(manifest_path, fetcher=lambda url, **kwargs: Response())

    assert result["summary"]["sources_read"] == 1
    assert result["summary"]["candidates"] == 1
    assert result["registry_delta"]["entries"][0]["brand_id"] == "compania_exemplu"


def test_crawler_discovers_ckan_resource_urls_when_enabled():
    from services.public_payment_destination_crawler import crawl_public_payment_sources

    manifest_source = {
        "url": "https://data.gov.ro/api/3/action/package_show?id=test",
        "publisher": "data.gov.ro",
        "brand_id": "data_gov_test",
        "display_name": "data.gov test",
        "source_kind": "public_dataset_catalog",
        "trust_tier": "T4_STRUCTURALLY_VALID_UNKNOWN",
        "discover_resources": True,
        "max_resource_urls": 2,
    }
    calls = []

    class Response:
        def __init__(self, payload: bytes, content_type: str = "application/json"):
            self.status_code = 200
            self.content = payload
            self.text = payload.decode("utf-8")
            self.headers = {"content-type": content_type}

    def fetcher(url, **kwargs):
        calls.append(url)
        if "package_show" in url:
            return Response(
                json.dumps(
                    {
                        "success": True,
                        "result": {
                            "resources": [
                                {"url": "https://example.ro/contract-1.txt", "name": "Contract 1"},
                                {"url": "https://example.ro/contract-2.txt", "name": "Contract 2"},
                            ]
                        },
                    }
                ).encode("utf-8")
            )
        return Response(b"CUI 1096128 IBAN RO78 BACX 0000 0006 4257 9002", "text/plain")

    result = crawl_public_payment_sources([manifest_source], fetcher=fetcher)

    assert calls == [
        "https://data.gov.ro/api/3/action/package_show?id=test",
        "https://example.ro/contract-1.txt",
        "https://example.ro/contract-2.txt",
    ]
    assert result["summary"]["sources_read"] == 3
    assert result["summary"]["candidates"] == 2
    assert all(candidate["can_contribute_to_safe"] is False for candidate in result["candidates"])
