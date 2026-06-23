"""Orchestrated scan endpoint handlers extracted from main.py."""

from __future__ import annotations

from fastapi import HTTPException, Request


def _main_module():
    import main as _main

    return _main


async def advance_orchestrated_scan_worker(scan_id: str, request: Request, max_steps: int = 1):
    _main = _main_module()
    _main._require_internal_worker_auth(request)
    _main.orchestrated_engine._prune_orchestrated_jobs()
    step_budget = max(1, min(int(max_steps or 1), 3))
    steps = 0
    worker_state = "idle"
    job = None
    lock = _main.orchestrated_engine._ORCHESTRATED_SCAN_LOCKS.setdefault(scan_id, _main.asyncio.Lock())
    async with lock:
        job = _main.orchestrated_engine._load_orchestrated_job(scan_id)
        if not isinstance(job, dict):
            raise HTTPException(status_code=404, detail="Scanarea nu a fost gasita sau a expirat.")
        for _ in range(step_budget):
            if isinstance(job.get("_storage_revision"), int):
                claimed_job = _main.orchestrated_engine._claim_distributed_orchestrated_refresh(job)
                if claimed_job is None:
                    latest = _main.orchestrated_engine._load_orchestrated_job(scan_id)
                    if isinstance(latest, dict):
                        job = latest
                    worker_state = "locked"
                    break
                job = claimed_job
            job = await _main.orchestrated_engine._refresh_orchestrated_job(job, request)
            status_payload = _main.orchestrated_engine._orchestrated_status_payload(job)
            job = _main.orchestrated_engine._persist_orchestrated_job(job)
            steps += 1
            worker_state = "advanced"
            read_payload = _main.orchestrated_engine._orchestrated_read_status_payload(job, changed=True)
            if _main.orchestrated_engine._orchestrated_worker_can_stop(read_payload):
                break

    if not isinstance(job, dict):
        raise HTTPException(status_code=404, detail="Scanarea nu a fost gasita sau a expirat.")
    payload = _main.orchestrated_engine._orchestrated_read_status_payload(job, changed=True)
    requeued = False
    if worker_state == "advanced" and not _main.orchestrated_engine._orchestrated_worker_can_stop(payload):
        requeued = _main.orchestrated_engine._enqueue_orchestrated_worker_task(
            scan_id,
            request,
            delay_seconds=_main.ORCHESTRATED_CLOUD_TASKS_CONTINUE_DELAY_SECONDS,
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

    _main = _main_module()
    _main.orchestrated_engine._prune_orchestrated_jobs()
    job = await _main.orchestrated_engine._create_orchestrated_job(payload)
    response = _main.orchestrated_engine._orchestrated_status_payload(job)
    job = _main.orchestrated_engine._persist_orchestrated_job(job)
    _main.orchestrated_engine._enqueue_orchestrated_worker_task(job["scan_id"], request, delay_seconds=0, max_steps=1)
    return response


async def get_orchestrated_scan_status(
    scan_id: str,
    after_revision=None,
    wait: float = 0.0,
):
    _main = _main_module()
    _main.orchestrated_engine._prune_orchestrated_jobs()
    job, changed = await _main.orchestrated_engine._wait_for_orchestrated_status_read(
        scan_id,
        after_revision=after_revision,
        wait_seconds=wait,
    )
    if not isinstance(job, dict):
        raise HTTPException(status_code=404, detail="Scanarea nu a fost gasita sau a expirat.")
    return _main.orchestrated_engine._orchestrated_read_status_payload(job, changed=changed)


async def get_orchestrated_scan(scan_id: str, request: Request):
    _main = _main_module()
    _main.orchestrated_engine._prune_orchestrated_jobs()
    lock = _main.orchestrated_engine._ORCHESTRATED_SCAN_LOCKS.setdefault(scan_id, _main.asyncio.Lock())
    async with lock:
        job = _main.orchestrated_engine._load_orchestrated_job(scan_id)
        if not job:
            raise HTTPException(status_code=404, detail="Scanarea nu a fost gasita sau a expirat.")
        if isinstance(job.get("_storage_revision"), int):
            claimed_job = _main.orchestrated_engine._claim_distributed_orchestrated_refresh(job)
            if claimed_job is None:
                latest = _main.orchestrated_engine._load_orchestrated_job(scan_id)
                if isinstance(latest, dict):
                    job = latest
                return _main.orchestrated_engine._orchestrated_status_payload(job)
            job = claimed_job
        job = await _main.orchestrated_engine._refresh_orchestrated_job(job, request)
        response = _main.orchestrated_engine._orchestrated_status_payload(job)
        job = _main.orchestrated_engine._persist_orchestrated_job(job)
        return response
