"""Scan/orchestration/extraction endpoints extracted from main.py."""

import main
from fastapi import APIRouter, Request, UploadFile, File, Form

from api_models import OrchestratedScanRequest, TextScanRequest, UrlscanSandboxRequest, URLScanRequest

router = APIRouter()


@router.post("/internal/orchestrated/{scan_id}/advance")
async def advance_orchestrated_scan_worker(scan_id: str, request: Request, max_steps: int = 1):
    return await main.advance_orchestrated_scan_worker(scan_id, request, max_steps=max_steps)


@router.post("/v1/scan/orchestrated")
async def start_orchestrated_scan(payload: OrchestratedScanRequest, request: Request):
    return await main.start_orchestrated_scan(payload, request)


@router.get("/v1/scan/orchestrated/{scan_id}/status")
async def get_orchestrated_scan_status(
    scan_id: str,
    after_revision: int | None = None,
    wait: float = 0.0,
):
    return await main.get_orchestrated_scan_status(scan_id, after_revision=after_revision, wait=wait)


@router.get("/v1/scan/orchestrated/{scan_id}")
async def get_orchestrated_scan(scan_id: str, request: Request):
    return await main.get_orchestrated_scan(scan_id, request)


@router.post("/v1/sandbox/urlscan")
async def submit_urlscan_sandbox(payload: UrlscanSandboxRequest, request: Request):
    return await main.submit_urlscan_sandbox(payload, request)


@router.get("/v1/sandbox/urlscan/{uuid}", name="get_urlscan_result")
async def get_urlscan_result(uuid: str, request: Request):
    return await main.get_urlscan_result(uuid, request)


@router.get("/v1/sandbox/urlscan/{uuid}/screenshot", name="urlscan_screenshot")
async def urlscan_screenshot(uuid: str):
    return await main.urlscan_screenshot(uuid)


@router.post("/v1/extract/image")
async def extract_image_for_orchestration(
    image_file: UploadFile = File(...),
    source_channel: str | None = Form("image_upload"),
):
    return await main.extract_image_for_orchestration(image_file=image_file, source_channel=source_channel)


@router.post("/v1/extract/pdf")
async def extract_pdf_for_orchestration(
    pdf_file: UploadFile = File(...),
    source_channel: str | None = Form("pdf_upload"),
):
    return await main.extract_pdf_for_orchestration(pdf_file=pdf_file, source_channel=source_channel)


@router.post("/v1/extract/email")
async def extract_email_for_orchestration(
    email_file: UploadFile | None = File(None),
    html_content: str | None = Form(None),
    source_channel: str | None = Form("email"),
):
    return await main.extract_email_for_orchestration(
        email_file=email_file,
        html_content=html_content,
        source_channel=source_channel,
    )


@router.post("/v1/scan/text")
async def scan_text(request: TextScanRequest):
    return await main.scan_text(request)


@router.post("/v1/scan/url")
async def scan_url(request: URLScanRequest):
    return await main.scan_url(request)


@router.post("/v1/scan/email")
async def scan_email(
    email_file: UploadFile | None = File(None),
    html_content: str | None = Form(None),
    source_channel: str | None = Form("email"),
):
    return await main.scan_email(
        email_file=email_file,
        html_content=html_content,
        source_channel=source_channel,
    )


@router.post("/v1/scan/image")
async def scan_image(
    image_file: UploadFile = File(...),
    source_channel: str | None = Form("image_upload"),
):
    return await main.scan_image(image_file=image_file, source_channel=source_channel)


@router.post("/v1/scan/pdf")
async def scan_pdf(
    pdf_file: UploadFile = File(...),
    source_channel: str | None = Form("pdf_upload"),
):
    return await main.scan_pdf(pdf_file=pdf_file, source_channel=source_channel)


@router.post("/v1/scan/invoice")
async def scan_invoice_endpoint(
    image_file: UploadFile | None = File(None),
    pdf_file: UploadFile | None = File(None),
    official_xml_file: UploadFile | None = File(None),
    source_channel: str | None = Form("android_native"),
    sanb_attestation: str | None = Form(None),
):
    return await main.scan_invoice_endpoint(
        image_file=image_file,
        pdf_file=pdf_file,
        official_xml_file=official_xml_file,
        source_channel=source_channel,
        sanb_attestation=sanb_attestation,
    )
