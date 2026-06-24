"""Orchestrated scan endpoints extracted from ``scan.py``."""

from fastapi import APIRouter, Request

from api_models import OrchestratedScanRequest
from services.orchestrated_pipeline import (
    advance_orchestrated_scan_worker as advance_orchestrated_scan_worker_handler,
    get_orchestrated_scan as get_orchestrated_scan_handler,
    get_orchestrated_scan_status as get_orchestrated_scan_status_handler,
    start_orchestrated_scan as start_orchestrated_scan_handler,
)

router = APIRouter()


@router.post("/v1/scan/orchestrated")
async def start_orchestrated_scan(payload: OrchestratedScanRequest, request: Request):
    return await start_orchestrated_scan_handler(payload, request)


@router.get("/v1/scan/orchestrated/{scan_id}")
async def get_orchestrated_scan(scan_id: str, request: Request):
    return await get_orchestrated_scan_handler(scan_id, request)


@router.get("/v1/scan/orchestrated/{scan_id}/status")
async def get_orchestrated_scan_status(
    scan_id: str,
    after_revision: int | None = None,
    wait: float = 0.0,
):
    return await get_orchestrated_scan_status_handler(
        scan_id,
        after_revision=after_revision,
        wait=wait,
    )


@router.post("/internal/orchestrated/{scan_id}/advance")
async def advance_orchestrated_scan_worker(scan_id: str, request: Request, max_steps: int = 1):
    return await advance_orchestrated_scan_worker_handler(scan_id, request, max_steps=max_steps)

