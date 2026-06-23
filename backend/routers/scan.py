"""Scan/orchestration/extraction endpoints extracted from main.py."""

from fastapi import APIRouter, Request, UploadFile, File, Form

from api_models import OrchestratedScanRequest, TextScanRequest, UrlscanSandboxRequest, URLScanRequest
from services.extract_pipeline import (
    extract_email_for_orchestration as extract_email_for_orchestration_handler,
    extract_image_for_orchestration as extract_image_for_orchestration_handler,
    extract_pdf_for_orchestration as extract_pdf_for_orchestration_handler,
)
from services.orchestrated_pipeline import (
    advance_orchestrated_scan_worker as advance_orchestrated_scan_worker_handler,
    get_orchestrated_scan as get_orchestrated_scan_handler,
    get_orchestrated_scan_status as get_orchestrated_scan_status_handler,
    start_orchestrated_scan as start_orchestrated_scan_handler,
)
from services.scan_pipeline import (
    scan_email as scan_email_handler,
    scan_image as scan_image_handler,
    scan_invoice_endpoint as scan_invoice_endpoint_handler,
    scan_pdf as scan_pdf_handler,
    scan_text as scan_text_handler,
    scan_url as scan_url_handler,
)
from services.urlscan_pipeline import (
    get_urlscan_result as get_urlscan_result_handler,
    submit_urlscan_sandbox as submit_urlscan_sandbox_handler,
    urlscan_screenshot as urlscan_screenshot_handler,
)

router = APIRouter()


@router.post("/internal/orchestrated/{scan_id}/advance")
async def advance_orchestrated_scan_worker(scan_id: str, request: Request, max_steps: int = 1):
    return await advance_orchestrated_scan_worker_handler(scan_id, request, max_steps=max_steps)


@router.post("/v1/scan/orchestrated")
async def start_orchestrated_scan(payload: OrchestratedScanRequest, request: Request):
    return await start_orchestrated_scan_handler(payload, request)


@router.get("/v1/scan/orchestrated/{scan_id}/status")
async def get_orchestrated_scan_status(
    scan_id: str,
    after_revision: int | None = None,
    wait: float = 0.0,
):
    return await get_orchestrated_scan_status_handler(scan_id, after_revision=after_revision, wait=wait)


@router.get("/v1/scan/orchestrated/{scan_id}")
async def get_orchestrated_scan(scan_id: str, request: Request):
    return await get_orchestrated_scan_handler(scan_id, request)


@router.post("/v1/sandbox/urlscan")
async def submit_urlscan_sandbox(payload: UrlscanSandboxRequest, request: Request):
    return await submit_urlscan_sandbox_handler(payload, request)


@router.get("/v1/sandbox/urlscan/{uuid}", name="get_urlscan_result")
async def get_urlscan_result(uuid: str, request: Request):
    return await get_urlscan_result_handler(uuid, request)


@router.get("/v1/sandbox/urlscan/{uuid}/screenshot", name="urlscan_screenshot")
async def urlscan_screenshot(uuid: str):
    return await urlscan_screenshot_handler(uuid)


@router.post("/v1/extract/image")
async def extract_image_for_orchestration(
    image_file: UploadFile = File(...),
    source_channel: str | None = Form("image_upload"),
):
    return await extract_image_for_orchestration_handler(
        image_file=image_file,
        source_channel=source_channel,
    )


@router.post("/v1/extract/pdf")
async def extract_pdf_for_orchestration(
    pdf_file: UploadFile = File(...),
    source_channel: str | None = Form("pdf_upload"),
):
    return await extract_pdf_for_orchestration_handler(pdf_file=pdf_file, source_channel=source_channel)


@router.post("/v1/extract/email")
async def extract_email_for_orchestration(
    email_file: UploadFile | None = File(None),
    html_content: str | None = Form(None),
    source_channel: str | None = Form("email"),
):
    return await extract_email_for_orchestration_handler(
        email_file=email_file,
        html_content=html_content,
        source_channel=source_channel,
    )


@router.post("/v1/scan/text")
async def scan_text(request: TextScanRequest):
    return await scan_text_handler(request)


@router.post("/v1/scan/url")
async def scan_url(request: URLScanRequest):
    return await scan_url_handler(request)


@router.post("/v1/scan/email")
async def scan_email(
    email_file: UploadFile | None = File(None),
    html_content: str | None = Form(None),
    source_channel: str | None = Form("email"),
):
    return await scan_email_handler(
        email_file=email_file,
        html_content=html_content,
        source_channel=source_channel,
    )


@router.post("/v1/scan/image")
async def scan_image(
    image_file: UploadFile = File(...),
    source_channel: str | None = Form("image_upload"),
):
    return await scan_image_handler(image_file=image_file, source_channel=source_channel)


@router.post("/v1/scan/pdf")
async def scan_pdf(
    pdf_file: UploadFile = File(...),
    source_channel: str | None = Form("pdf_upload"),
):
    return await scan_pdf_handler(pdf_file=pdf_file, source_channel=source_channel)


@router.post("/v1/scan/invoice")
async def scan_invoice_endpoint(
    image_file: UploadFile | None = File(None),
    pdf_file: UploadFile | None = File(None),
    official_xml_file: UploadFile | None = File(None),
    source_channel: str | None = Form("android_native"),
    sanb_attestation: str | None = Form(None),
):
    return await scan_invoice_endpoint_handler(
        image_file=image_file,
        pdf_file=pdf_file,
        official_xml_file=official_xml_file,
        source_channel=source_channel,
        sanb_attestation=sanb_attestation,
    )
