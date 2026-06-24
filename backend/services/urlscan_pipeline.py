"""URLscan sandbox endpoint handlers extracted from runtime.py."""

from __future__ import annotations

import re
import requests

from fastapi import HTTPException, Request
from fastapi.responses import Response
from starlette.concurrency import run_in_threadpool

from config import (
    URLSCAN_API_KEY,
    URLSCAN_COUNTRY_DEFAULT,
    URLSCAN_CUSTOM_AGENT_DEFAULT,
    URLSCAN_TIMEOUT_SECONDS,
)
from services.urlscan_helpers import (
    _public_route_url,
    _safe_urlscan_visibility,
    _summarize_urlscan_payload,
    _urlscan_error_detail,
    _urlscan_headers,
    _urlscan_report_url,
    _urlscan_tags,
    _require_urlscan_key,
    _validate_sandbox_url,
)


async def submit_urlscan_sandbox(payload, request: Request):
    _require_urlscan_key()
    url = _validate_sandbox_url(payload.url)
    visibility = _safe_urlscan_visibility(payload.visibility)

    def build_submit_payload(selected_visibility: str, include_persona: bool = True):
        submit_payload = {
            "url": url,
            "visibility": selected_visibility,
            "tags": _urlscan_tags(payload.source_channel),
        }
        if include_persona:
            country = (payload.country or URLSCAN_COUNTRY_DEFAULT or "").strip().lower()
            customagent = (payload.customagent or URLSCAN_CUSTOM_AGENT_DEFAULT or "").strip()
            if country:
                submit_payload["country"] = country[:2]
            if customagent:
                submit_payload["customagent"] = customagent[:512]
        return submit_payload

    def submit(selected_visibility: str, include_persona: bool = True):
        return requests.post(
            "https://urlscan.io/api/v1/scan/",
            headers=_urlscan_headers(),
            json=build_submit_payload(selected_visibility, include_persona=include_persona),
            timeout=URLSCAN_TIMEOUT_SECONDS,
        )

    include_persona = True
    response = await run_in_threadpool(submit, visibility, include_persona)
    if response.status_code in {400, 422} and (
        payload.country
        or payload.customagent
        or URLSCAN_COUNTRY_DEFAULT
        or URLSCAN_CUSTOM_AGENT_DEFAULT
    ):
        include_persona = False
        response = await run_in_threadpool(submit, visibility, include_persona)
    if response.status_code in {400, 403, 422} and visibility == "private":
        response = await run_in_threadpool(submit, "unlisted", include_persona)

    if response.status_code >= 400:
        raise HTTPException(
            status_code=502,
            detail=_urlscan_error_detail(response),
        )

    body = response.json()
    uuid = body.get("uuid")
    if not uuid:
        raise HTTPException(status_code=502, detail="urlscan.io nu a returnat uuid.")

    return {
        "uuid": uuid,
        "status": "pending",
        "report_url": _urlscan_report_url(uuid),
        "result_url": _public_route_url(request, "get_urlscan_result", uuid=uuid),
        "screenshot_url": _public_route_url(request, "urlscan_screenshot", uuid=uuid),
        "submitted_url": url,
    }


async def get_urlscan_result(uuid: str, request: Request):
    _require_urlscan_key()
    safe_uuid = re.sub(r"[^A-Za-z0-9._-]", "", uuid or "")
    if not safe_uuid:
        raise HTTPException(status_code=400, detail="uuid invalid.")

    def fetch_result():
        return requests.get(
            f"https://urlscan.io/api/v1/result/{safe_uuid}/",
            headers=_urlscan_headers(),
            timeout=URLSCAN_TIMEOUT_SECONDS,
        )

    response = await run_in_threadpool(fetch_result)
    if response.status_code == 404:
        return {
            "uuid": safe_uuid,
            "status": "pending",
            "verdict": "Pending",
            "severity": "unknown",
            "details": "urlscan.io sandbox inca proceseaza rezultatul.",
            "report_url": _urlscan_report_url(safe_uuid),
            "screenshot_url": _public_route_url(request, "urlscan_screenshot", uuid=safe_uuid),
        }
    if response.status_code >= 400:
        raise HTTPException(
            status_code=502,
            detail=f"urlscan.io result failed: HTTP {response.status_code}",
        )

    payload = response.json()
    return _summarize_urlscan_payload(payload, safe_uuid, request)


async def urlscan_screenshot(uuid: str):
    _require_urlscan_key()
    safe_uuid = re.sub(r"[^A-Za-z0-9._-]", "", uuid or "")
    if not safe_uuid:
        raise HTTPException(status_code=400, detail="uuid invalid.")

    def fetch_screenshot():
        return requests.get(
            f"https://urlscan.io/screenshots/{safe_uuid}.png",
            headers={"api-key": URLSCAN_API_KEY},
            timeout=URLSCAN_TIMEOUT_SECONDS,
        )

    response = await run_in_threadpool(fetch_screenshot)
    if response.status_code >= 400:
        raise HTTPException(
            status_code=502,
            detail=f"urlscan.io screenshot failed: HTTP {response.status_code}",
        )
    return Response(
        content=response.content,
        media_type=response.headers.get("content-type") or "image/png",
        headers={"Cache-Control": "private, max-age=300"},
    )
