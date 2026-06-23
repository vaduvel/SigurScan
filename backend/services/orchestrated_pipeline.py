"""Orchestrated scan endpoint handlers extracted from runtime.py."""

from __future__ import annotations

import importlib
import sys

from fastapi import HTTPException, Request


def _runtime():
    runtime = sys.modules.get("main")
    if runtime is None:
        runtime = importlib.import_module("app")
    return runtime


async def advance_orchestrated_scan_worker(scan_id: str, request: Request, max_steps: int = 1):
    runtime = _runtime()
    runtime._require_internal_worker_auth(request)
    runtime.orchestrated_engine._prune_orchestrated_jobs()
    step_budget = max(1, min(int(max_steps or 1), 3))
    steps = 0
    worker_state = "idle"
    job = None
    lock = runtime.orchestrated_engine._ORCHESTRATED_SCAN_LOCKS.setdefault(scan_id, runtime.asyncio.Lock())
    async with lock:
        job = runtime.orchestrated_engine._load_orchestrated_job(scan_id)
        if not isinstance(job, dict):
            raise HTTPException(status_code=404, detail="Scanarea nu a fost gasita sau a expirat.")
        for _ in range(step_budget):
            if isinstance(job.get("_storage_revision"), int):
                claimed_job = runtime.orchestrated_engine._claim_distributed_orchestrated_refresh(job)
                if claimed_job is None:
                    latest = runtime.orchestrated_engine._load_orchestrated_job(scan_id)
                    if isinstance(latest, dict):
                        job = latest
                    worker_state = "locked"
                    break
                job = claimed_job
            job = await runtime.orchestrated_engine._refresh_orchestrated_job(job, request)
            status_payload = runtime.orchestrated_engine._orchestrated_status_payload(job)
            job = runtime.orchestrated_engine._persist_orchestrated_job(job)
            steps += 1
            worker_state = "advanced"
            read_payload = runtime.orchestrated_engine._orchestrated_read_status_payload(job, changed=True)
            if runtime.orchestrated_engine._orchestrated_worker_can_stop(read_payload):
                break

    if not isinstance(job, dict):
        raise HTTPException(status_code=404, detail="Scanarea nu a fost gasita sau a expirat.")
    payload = runtime.orchestrated_engine._orchestrated_read_status_payload(job, changed=True)
    requeued = False
    if worker_state == "advanced" and not runtime.orchestrated_engine._orchestrated_worker_can_stop(payload):
        requeued = runtime.orchestrated_engine._enqueue_orchestrated_worker_task(
            scan_id,
            request,
            delay_seconds=runtime.ORCHESTRATED_CLOUD_TASKS_CONTINUE_DELAY_SECONDS,
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
    runtime = _runtime()
    runtime.orchestrated_engine._prune_orchestrated_jobs()
    job = await runtime.orchestrated_engine._create_orchestrated_job(payload)
    response = runtime.orchestrated_engine._orchestrated_status_payload(job)
    job = runtime.orchestrated_engine._persist_orchestrated_job(job)
    runtime.orchestrated_engine._enqueue_orchestrated_worker_task(job["scan_id"], request, delay_seconds=0, max_steps=1)
    return response


async def get_orchestrated_scan_status(
    scan_id: str,
    after_revision=None,
    wait: float = 0.0,
):
    runtime = _runtime()
    runtime.orchestrated_engine._prune_orchestrated_jobs()
    job, changed = await runtime.orchestrated_engine._wait_for_orchestrated_status_read(
        scan_id,
        after_revision=after_revision,
        wait_seconds=wait,
    )
    if not isinstance(job, dict):
        raise HTTPException(status_code=404, detail="Scanarea nu a fost gasita sau a expirat.")
    return runtime.orchestrated_engine._orchestrated_read_status_payload(job, changed=changed)


async def get_orchestrated_scan(scan_id: str, request: Request):
    runtime = _runtime()
    runtime.orchestrated_engine._prune_orchestrated_jobs()
    lock = runtime.orchestrated_engine._ORCHESTRATED_SCAN_LOCKS.setdefault(scan_id, runtime.asyncio.Lock())
    async with lock:
        job = runtime.orchestrated_engine._load_orchestrated_job(scan_id)
        if not job:
            raise HTTPException(status_code=404, detail="Scanarea nu a fost gasita sau a expirat.")
        if isinstance(job.get("_storage_revision"), int):
            claimed_job = runtime.orchestrated_engine._claim_distributed_orchestrated_refresh(job)
            if claimed_job is None:
                latest = runtime.orchestrated_engine._load_orchestrated_job(scan_id)
                if isinstance(latest, dict):
                    job = latest
                return runtime.orchestrated_engine._orchestrated_status_payload(job)
            job = claimed_job
        job = await runtime.orchestrated_engine._refresh_orchestrated_job(job, request)
        response = runtime.orchestrated_engine._orchestrated_status_payload(job)
        job = runtime.orchestrated_engine._persist_orchestrated_job(job)
        return response
