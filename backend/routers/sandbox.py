"""URLscan sandbox endpoints extracted from ``scan.py``."""

from fastapi import APIRouter, Request

from api_models import UrlscanSandboxRequest
from services.urlscan_pipeline import (
    get_urlscan_result as get_urlscan_result_handler,
    submit_urlscan_sandbox as submit_urlscan_sandbox_handler,
    urlscan_screenshot as urlscan_screenshot_handler,
)

router = APIRouter()


@router.post("/v1/sandbox/urlscan")
async def submit_urlscan_sandbox(payload: UrlscanSandboxRequest, request: Request):
    return await submit_urlscan_sandbox_handler(payload, request)


@router.get("/v1/sandbox/urlscan/{uuid}", name="get_urlscan_result")
async def get_urlscan_result(uuid: str, request: Request):
    return await get_urlscan_result_handler(uuid, request)


@router.get("/v1/sandbox/urlscan/{uuid}/screenshot", name="urlscan_screenshot")
async def urlscan_screenshot(uuid: str):
    return await urlscan_screenshot_handler(uuid)

