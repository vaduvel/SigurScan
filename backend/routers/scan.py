"""Public scan endpoints — `/v1/scan/text|url|email|image|pdf|invoice`."""

from fastapi import APIRouter, File, Form, Request, UploadFile

from api_models import TextScanRequest, URLScanRequest
from core.request_security import _extract_client_instance_id
from services.scan_pipeline import (
    scan_email as scan_email_handler,
    scan_image as scan_image_handler,
    scan_invoice_endpoint as scan_invoice_endpoint_handler,
    scan_pdf as scan_pdf_handler,
    scan_text as scan_text_handler,
    scan_url as scan_url_handler,
)

router = APIRouter()


@router.post("/v1/scan/text")
async def scan_text(payload: TextScanRequest):
    return await scan_text_handler(payload)


@router.post("/v1/scan/url")
async def scan_url(payload: URLScanRequest):
    return await scan_url_handler(payload)


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
    return await scan_image_handler(
        image_file=image_file,
        source_channel=source_channel,
    )


@router.post("/v1/scan/pdf")
async def scan_pdf(
    pdf_file: UploadFile = File(...),
    source_channel: str | None = Form("pdf_upload"),
):
    return await scan_pdf_handler(
        pdf_file=pdf_file,
        source_channel=source_channel,
    )


@router.post("/v1/scan/invoice")
async def scan_invoice_endpoint(
    request: Request,
    image_file: UploadFile | None = File(None),
    pdf_file: UploadFile | None = File(None),
    official_xml_file: UploadFile | None = File(None),
    source_channel: str | None = Form("android_native"),
    sanb_attestation: str | None = Form(None),
    payment_case_active: bool = Form(False),
):
    return await scan_invoice_endpoint_handler(
        image_file=image_file,
        pdf_file=pdf_file,
        official_xml_file=official_xml_file,
        source_channel=source_channel,
        sanb_attestation=sanb_attestation,
        client_instance_id=_extract_client_instance_id(request),
        payment_case_active=payment_case_active,
    )
