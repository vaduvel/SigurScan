from __future__ import annotations

from eval.live_provider_smoke_runner import LiveSmokeCase, _load_cases_from_file, _post_scan


class _FakeResponse:
    def raise_for_status(self) -> None:
        return None

    def json(self) -> dict:
        return {"scan_id": "scan-test"}


def test_live_smoke_posts_url_payload(monkeypatch) -> None:
    captured = {}

    def fake_post(url, *, headers, json, timeout):
        captured["url"] = url
        captured["json"] = json
        return _FakeResponse()

    monkeypatch.setattr("eval.live_provider_smoke_runner.requests.post", fake_post)

    result = _post_scan(
        "https://api.sigurscan.com",
        LiveSmokeCase(
            case_id="qr-menu",
            title="QR menu",
            text="https://www.smart-menu.ro/qr/eomsi6XuN7",
            url="https://www.smart-menu.ro/qr/eomsi6XuN7",
            input_type="url",
            source_channel="android_url_scan",
            visibility="unlisted",
            expected_labels=["SAFE"],
        ),
        timeout=5,
    )

    assert result["scan_id"] == "scan-test"
    assert captured["json"]["input_type"] == "url"
    assert captured["json"]["url"] == "https://www.smart-menu.ro/qr/eomsi6XuN7"
    assert captured["json"]["source_channel"] == "android_url_scan"
    assert captured["json"]["visibility"] == "unlisted"


def test_load_cases_file_preserves_input_type_url_and_source_channel(tmp_path) -> None:
    path = tmp_path / "cases.json"
    path.write_text(
        """
        [
          {
            "case_id": "invoice-1",
            "title": "Invoice",
            "input_type": "invoice",
            "source_channel": "android_invoice_scan",
            "text": "Factura nr. F-1 CUI RO12345678 IBAN RO49AAAA1B31007593840000 total 120 RON",
            "expected_labels": ["UNVERIFIED"]
          }
        ]
        """,
        encoding="utf-8",
    )

    cases = _load_cases_from_file(str(path))

    assert len(cases) == 1
    assert cases[0].input_type == "invoice"
    assert cases[0].source_channel == "android_invoice_scan"
    assert cases[0].expected_labels == ["UNVERIFIED"]
