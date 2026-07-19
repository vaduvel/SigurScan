import json
import asyncio

import pytest
from fastapi.testclient import TestClient

from api_models import OrchestratedScanRequest
from app import app
from services.payment_case import build_payment_case_facts
from services import payment_case_store
from services.orchestrated_scan import orchestrated_engine


CLIENT_A = "android-payment-case-a"
CLIENT_B = "android-payment-case-b"
RAW_IBAN = "RO49AAAA1B31007593840000"
INVOICE_TEXT = f"""
Factura ALFA 1001
Furnizor: ALFA DISTRIBUTIE SRL
IBAN: {RAW_IBAN}
Total de plata: 520.65 RON
"""


@pytest.fixture(autouse=True)
def _reset_payment_case_store(monkeypatch):
    monkeypatch.setenv("INVOICE_CACHE_HMAC_KEY", "payment-case-api-test-key")
    payment_case_store.reset_local_payment_case_store_for_tests()
    yield
    payment_case_store.reset_local_payment_case_store_for_tests()


def _headers(client_id: str) -> dict[str, str]:
    return {"X-SigurScan-Client-Instance": client_id}


def _registered_artifact(*, owner: str = CLIENT_A, verdict: str = "SAFE", final: bool = True) -> str:
    facts = build_payment_case_facts(
        artifact_type="invoice",
        pre_redaction_evidence={
            "identifiers": {"ibans": [{"value": RAW_IBAN}], "cuis": ["12345678"]},
            "payment": {"beneficiary": "ALFA DISTRIBUTIE SRL"},
        },
        entity_name="ALFA DISTRIBUTIE SRL",
        amount="520.65",
        currency="RON",
        requested_actions=["pay_invoice"],
        evidence_provenance="server_extracted",
    )
    return payment_case_store.register_server_artifact(
        client_instance_id=owner,
        artifact_type="invoice",
        verdict=verdict,
        is_final=final,
        reason_codes=[],
        facts=facts,
    )["artifact_ref"]


def test_create_payment_case_requires_client_instance_header():
    response = TestClient(app).post("/v1/payment-cases")

    assert response.status_code == 400
    assert "instan" in response.json()["detail"].lower()


def test_case_owner_can_attach_server_artifact_and_attach_is_idempotent():
    client = TestClient(app)
    case_id = client.post("/v1/payment-cases", headers=_headers(CLIENT_A)).json()["case_id"]
    artifact_ref = _registered_artifact()

    first = client.post(
        f"/v1/payment-cases/{case_id}/artifacts",
        headers=_headers(CLIENT_A),
        json={"artifact_ref": artifact_ref},
    )
    second = client.post(
        f"/v1/payment-cases/{case_id}/artifacts",
        headers=_headers(CLIENT_A),
        json={"artifact_ref": artifact_ref},
    )

    assert first.status_code == 200
    assert second.status_code == 200
    assert second.json()["schema"] == "sigurscan_payment_case_v1"
    assert second.json()["artifact_count"] == 1
    assert second.json()["verdict"] == "SAFE"


def test_persisted_evidence_is_detached_from_caller_mutations():
    facts = build_payment_case_facts(
        artifact_type="invoice",
        pre_redaction_evidence={"identifiers": {"ibans": [{"value": RAW_IBAN}]}},
        requested_actions=["pay_invoice"],
    )
    artifact = payment_case_store.register_server_artifact(
        client_instance_id=CLIENT_A,
        artifact_type="invoice",
        verdict="SAFE",
        is_final=True,
        reason_codes=[],
        facts=facts,
    )

    facts["payment"]["amount"] = "999999.00"
    stored = payment_case_store.load_case_for_tests(artifact["artifact_ref"])

    assert stored["artifact"]["facts"]["payment"]["amount"] is None


def test_other_client_cannot_read_case_or_attach_artifact():
    client = TestClient(app)
    case_id = client.post("/v1/payment-cases", headers=_headers(CLIENT_A)).json()["case_id"]
    artifact_ref = _registered_artifact()

    read = client.get(f"/v1/payment-cases/{case_id}", headers=_headers(CLIENT_B))
    attach = client.post(
        f"/v1/payment-cases/{case_id}/artifacts",
        headers=_headers(CLIENT_B),
        json={"artifact_ref": artifact_ref},
    )

    assert read.status_code == 404
    assert attach.status_code == 404


def test_unfinished_artifact_cannot_be_attached_as_evidence():
    client = TestClient(app)
    case_id = client.post("/v1/payment-cases", headers=_headers(CLIENT_A)).json()["case_id"]
    artifact_ref = _registered_artifact(final=False)

    response = client.post(
        f"/v1/payment-cases/{case_id}/artifacts",
        headers=_headers(CLIENT_A),
        json={"artifact_ref": artifact_ref},
    )

    assert response.status_code == 409


def test_payment_case_response_and_persisted_payload_do_not_contain_raw_iban():
    client = TestClient(app)
    case_id = client.post("/v1/payment-cases", headers=_headers(CLIENT_A)).json()["case_id"]
    artifact_ref = _registered_artifact()

    response = client.post(
        f"/v1/payment-cases/{case_id}/artifacts",
        headers=_headers(CLIENT_A),
        json={"artifact_ref": artifact_ref},
    )
    stored = payment_case_store.load_case_for_tests(case_id)

    assert response.status_code == 200
    assert RAW_IBAN not in json.dumps(response.json(), ensure_ascii=False)
    assert RAW_IBAN not in json.dumps(stored, ensure_ascii=False)


def test_case_owner_can_delete_case():
    client = TestClient(app)
    case_id = client.post("/v1/payment-cases", headers=_headers(CLIENT_A)).json()["case_id"]
    artifact_ref = _registered_artifact()
    attached = client.post(
        f"/v1/payment-cases/{case_id}/artifacts",
        headers=_headers(CLIENT_A),
        json={"artifact_ref": artifact_ref},
    )

    response = client.delete(f"/v1/payment-cases/{case_id}", headers=_headers(CLIENT_A))
    read = client.get(f"/v1/payment-cases/{case_id}", headers=_headers(CLIENT_A))

    assert attached.status_code == 200
    assert response.status_code == 204
    assert read.status_code == 404
    assert payment_case_store.load_case_for_tests(artifact_ref) is None


def test_payment_case_rejects_more_than_its_bounded_artifact_capacity(monkeypatch):
    monkeypatch.setattr(payment_case_store, "PAYMENT_CASE_MAX_ARTIFACTS", 1)
    client = TestClient(app)
    case_id = client.post("/v1/payment-cases", headers=_headers(CLIENT_A)).json()["case_id"]
    first_ref = _registered_artifact()
    second_ref = _registered_artifact(verdict="SUSPECT")

    first = client.post(
        f"/v1/payment-cases/{case_id}/artifacts",
        headers=_headers(CLIENT_A),
        json={"artifact_ref": first_ref},
    )
    second = client.post(
        f"/v1/payment-cases/{case_id}/artifacts",
        headers=_headers(CLIENT_A),
        json={"artifact_ref": second_ref},
    )

    assert first.status_code == 200
    assert second.status_code == 409
    assert "maximum" in second.json()["detail"].lower()


def test_invoice_scan_emits_server_artifact_attachable_only_by_same_client(monkeypatch):
    async def fake_extract_text_for_scan(filename, file_bytes, extract_fn):
        return INVOICE_TEXT, None

    monkeypatch.setattr("services.scan_pipeline.extract_text_for_scan", fake_extract_text_for_scan)
    client = TestClient(app)
    scan = client.post(
        "/v1/scan/invoice",
        headers=_headers(CLIENT_A),
        files={"pdf_file": ("invoice.pdf", b"%PDF-1.4\n%%EOF", "application/pdf")},
        data={"source_channel": "android_native", "payment_case_active": "true"},
    )

    assert scan.status_code == 200
    artifact_ref = scan.json()["payment_case_artifact_ref"]
    assert artifact_ref.startswith("pc-art-")

    case_id = client.post("/v1/payment-cases", headers=_headers(CLIENT_A)).json()["case_id"]
    attached = client.post(
        f"/v1/payment-cases/{case_id}/artifacts",
        headers=_headers(CLIENT_A),
        json={"artifact_ref": artifact_ref},
    )
    stolen = client.post(
        f"/v1/payment-cases/{case_id}/artifacts",
        headers=_headers(CLIENT_B),
        json={"artifact_ref": artifact_ref},
    )
    stored_artifact = payment_case_store.load_case_for_tests(artifact_ref)

    assert attached.status_code == 200
    assert attached.json()["artifact_count"] == 1
    assert stolen.status_code == 404
    assert RAW_IBAN not in json.dumps(stored_artifact, ensure_ascii=False)
    assert CLIENT_A not in json.dumps(stored_artifact, ensure_ascii=False)


def test_orchestrated_scan_registers_artifact_only_after_final_verdict(monkeypatch):
    monkeypatch.setattr(orchestrated_engine, "_persist_orchestrated_job", lambda candidate: candidate)
    monkeypatch.setattr(orchestrated_engine, "_emit_orchestrated_telemetry", lambda *args, **kwargs: None)
    job = asyncio.run(
        orchestrated_engine._create_orchestrated_job(
            OrchestratedScanRequest(
                input_type="offer",
                text=f"Plătește factura astăzi în contul {RAW_IBAN}.",
                source_channel="share_text",
                payment_case_active=True,
            ),
            client_instance_id=CLIENT_A,
        )
    )
    gate = {"label": "SUSPECT", "reason_codes": ["payment_needs_verification"]}
    provisional = {"is_final": False, "user_risk_label": "UNVERIFIED"}
    final = {"is_final": True, "user_risk_label": "SUSPECT"}

    orchestrated_engine._attach_payment_case_artifact_ref(job, provisional, gate)
    assert "payment_case_artifact_ref" not in provisional

    orchestrated_engine._attach_payment_case_artifact_ref(job, final, gate)
    artifact_ref = final["payment_case_artifact_ref"]
    job["result"] = final
    public_status = orchestrated_engine._orchestrated_status_payload(job)
    stored = payment_case_store.load_case_for_tests(artifact_ref)
    serialized_job = json.dumps(job, ensure_ascii=False)

    assert artifact_ref.startswith("pc-art-")
    assert public_status["result"]["payment_case_artifact_ref"] == artifact_ref
    assert stored["artifact"]["verdict"] == "SUSPECT"
    assert stored["artifact"]["is_final"] is True
    assert RAW_IBAN not in json.dumps(stored, ensure_ascii=False)
    assert CLIENT_A not in serialized_job
    assert job["payment_case_owner_fingerprint"].startswith("hmac-sha256:")


def test_orchestrated_api_binds_active_payment_case_to_hashed_client_identity(monkeypatch):
    monkeypatch.setattr(orchestrated_engine, "_enqueue_orchestrated_worker_task", lambda *args, **kwargs: False)
    client = TestClient(app)

    response = client.post(
        "/v1/scan/orchestrated",
        headers=_headers(CLIENT_A),
        json={
            "input_type": "offer",
            "text": f"Plătește factura în contul {RAW_IBAN}.",
            "source_channel": "android_offer_scan",
            "payment_case_active": True,
        },
    )
    assert response.status_code == 200

    job = orchestrated_engine._load_orchestrated_job(response.json()["scan_id"])
    assert job["payment_case_owner_fingerprint"].startswith("hmac-sha256:")
    assert job["payment_case_facts"]["privacy"]["raw_artifact_text_persisted"] is False
    assert CLIENT_A not in json.dumps(job, ensure_ascii=False)
    assert RAW_IBAN not in json.dumps(job["payment_case_facts"], ensure_ascii=False)


def test_normal_scans_do_not_create_payment_case_artifacts(monkeypatch):
    async def fake_extract_text_for_scan(filename, file_bytes, extract_fn):
        return INVOICE_TEXT, None

    monkeypatch.setattr("services.scan_pipeline.extract_text_for_scan", fake_extract_text_for_scan)
    client = TestClient(app)
    invoice = client.post(
        "/v1/scan/invoice",
        headers=_headers(CLIENT_A),
        files={"pdf_file": ("invoice.pdf", b"%PDF-1.4\n%%EOF", "application/pdf")},
        data={"source_channel": "android_native"},
    )
    job = asyncio.run(
        orchestrated_engine._create_orchestrated_job(
            OrchestratedScanRequest(input_type="text", text="Mesaj informativ."),
            client_instance_id=CLIENT_A,
        )
    )

    assert invoice.status_code == 200
    assert "payment_case_artifact_ref" not in invoice.json()
    assert job.get("payment_case_owner_fingerprint") is None
    assert job.get("payment_case_facts") is None


def test_payment_case_opt_in_without_client_identity_does_not_retain_case_facts(monkeypatch):
    monkeypatch.setattr(orchestrated_engine, "_persist_orchestrated_job", lambda candidate: candidate)

    job = asyncio.run(
        orchestrated_engine._create_orchestrated_job(
            OrchestratedScanRequest(
                input_type="text",
                text=f"Plătește în contul {RAW_IBAN}.",
                payment_case_active=True,
            )
        )
    )

    assert job.get("payment_case_owner_fingerprint") is None
    assert job.get("payment_case_facts") is None
