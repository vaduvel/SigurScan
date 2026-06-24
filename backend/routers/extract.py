"""OCR/extraction endpoints extracted from ``scan.py``."""

from fastapi import APIRouter, File, Form, UploadFile

from services.extract_pipeline import (
    extract_email_for_orchestration as extract_email_for_orchestration_handler,
    extract_image_for_orchestration as extract_image_for_orchestration_handler,
    extract_pdf_for_orchestration as extract_pdf_for_orchestration_handler,
)

router = APIRouter()


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
