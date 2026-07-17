"""Orchestrated scan endpoint handlers extracted from runtime.py."""

from __future__ import annotations

import asyncio

from fastapi import HTTPException, Request
from config import ORCHESTRATED_CLOUD_TASKS_CONTINUE_DELAY_SECONDS
from core.request_security import _require_internal_worker_auth

from services.orchestrated_scan import orchestrated_engine


async def advance_orchestrated_scan_worker(scan_id: str, request: Request, max_steps: int = 1):
    _require_internal_worker_auth(request)
    orchestrated_engine._prune_orchestrated_jobs()
    orchestrated_engine._cleanup_expired_orchestrated_jobs()
    step_budget = max(1, min(int(max_steps or 1), 3))
    steps = 0
    worker_state = "idle"
    job = None
    lock = orchestrated_engine._ORCHESTRATED_SCAN_LOCKS.setdefault(scan_id, asyncio.Lock())
    async with lock:
        job = orchestrated_engine._load_orchestrated_job(scan_id)
        if not isinstance(job, dict):
            raise HTTPException(status_code=404, detail="Scanarea nu a fost gasita sau a expirat.")
        for _ in range(step_budget):
            if isinstance(job.get("_storage_revision"), int):
                claimed_job = orchestrated_engine._claim_distributed_orchestrated_refresh(job)
                if claimed_job is None:
                    latest = orchestrated_engine._load_orchestrated_job(scan_id)
                    if isinstance(latest, dict):
                        job = latest
                    worker_state = "locked"
                    break
                job = claimed_job
            job = await orchestrated_engine._refresh_orchestrated_job(job, request)
            status_payload = orchestrated_engine._orchestrated_status_payload(job)
            job = orchestrated_engine._persist_orchestrated_job(job)
            steps += 1
            worker_state = "advanced"
            read_payload = orchestrated_engine._orchestrated_read_status_payload(job, changed=True)
            if orchestrated_engine._orchestrated_worker_can_stop(read_payload):
                break

    if not isinstance(job, dict):
        raise HTTPException(status_code=404, detail="Scanarea nu a fost gasita sau a expirat.")
    payload = orchestrated_engine._orchestrated_read_status_payload(job, changed=True)
    requeued = False
    if worker_state == "advanced" and not orchestrated_engine._orchestrated_worker_can_stop(payload):
        requeued = orchestrated_engine._enqueue_orchestrated_worker_task(
            scan_id,
            request,
            delay_seconds=ORCHESTRATED_CLOUD_TASKS_CONTINUE_DELAY_SECONDS,
            max_steps=1,
        )
    payload["worker"] = {
        "state": worker_state,
        "steps": steps,
        "max_steps": step_budget,
        "requeued": requeued,
    }
    return payload


async def start_orchestrated_scan(payload, request: Request):
    """
    Starts the product-grade scan pipeline:
    intake -> persistent queued scan_id. Provider work is advanced idempotently by GET polling.
    """
    orchestrated_engine._prune_orchestrated_jobs()
    job = await orchestrated_engine._create_orchestrated_job(payload)
    response = orchestrated_engine._orchestrated_status_payload(job)
    job = orchestrated_engine._persist_orchestrated_job(job)
    orchestrated_engine._enqueue_orchestrated_worker_task(job["scan_id"], request, delay_seconds=0, max_steps=1)
    return response


async def get_orchestrated_scan_status(
    scan_id: str,
    after_revision=None,
    wait: float = 0.0,
):
    orchestrated_engine._prune_orchestrated_jobs()
    job, changed = await orchestrated_engine._wait_for_orchestrated_status_read(
        scan_id,
        after_revision=after_revision,
        wait_seconds=wait,
    )
    if not isinstance(job, dict):
        raise HTTPException(status_code=404, detail="Scanarea nu a fost gasita sau a expirat.")
    return orchestrated_engine._orchestrated_read_status_payload(job, changed=changed)


async def get_orchestrated_scan(scan_id: str, request: Request):
    orchestrated_engine._prune_orchestrated_jobs()
    lock = orchestrated_engine._ORCHESTRATED_SCAN_LOCKS.setdefault(scan_id, asyncio.Lock())
    async with lock:
        job = orchestrated_engine._load_orchestrated_job(scan_id)
        if not job:
            raise HTTPException(status_code=404, detail="Scanarea nu a fost gasita sau a expirat.")
        if isinstance(job.get("_storage_revision"), int):
            claimed_job = orchestrated_engine._claim_distributed_orchestrated_refresh(job)
            if claimed_job is None:
                latest = orchestrated_engine._load_orchestrated_job(scan_id)
                if isinstance(latest, dict):
                    job = latest
                return orchestrated_engine._orchestrated_status_payload(job)
            job = claimed_job
        job = await orchestrated_engine._refresh_orchestrated_job(job, request)
        response = orchestrated_engine._orchestrated_status_payload(job)
        job = orchestrated_engine._persist_orchestrated_job(job)
        return response
