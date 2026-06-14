import os
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

import requests


SUPABASE_URL = (os.getenv("SUPABASE_URL") or "").strip().rstrip("/")
SUPABASE_SERVICE_ROLE_KEY = (os.getenv("SUPABASE_SERVICE_ROLE_KEY") or "").strip()
SUPABASE_TIMEOUT_SECONDS = float(os.getenv("SUPABASE_TIMEOUT_SECONDS") or "4.0")


def is_supabase_enabled() -> bool:
    return bool(SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY)


def _headers(prefer: Optional[str] = None) -> Dict[str, str]:
    headers = {
        "apikey": SUPABASE_SERVICE_ROLE_KEY,
        "Authorization": f"Bearer {SUPABASE_SERVICE_ROLE_KEY}",
        "Content-Type": "application/json",
    }
    if prefer:
        headers["Prefer"] = prefer
    return headers


def _table_url(table: str) -> str:
    return f"{SUPABASE_URL}/rest/v1/{table}"


def _ts_to_iso(value: Any) -> Optional[str]:
    try:
        ts = int(value)
    except Exception:
        return None
    if ts <= 0:
        return None
    return datetime.fromtimestamp(ts, tz=timezone.utc).isoformat()


def _iso_to_ts(value: Any) -> Optional[int]:
    if not isinstance(value, str) or not value.strip():
        return None
    try:
        normalized = value.replace("Z", "+00:00")
        return int(datetime.fromisoformat(normalized).timestamp())
    except Exception:
        return None


def _post_json(table: str, payload: Dict[str, Any], prefer: str = "return=minimal") -> None:
    if not is_supabase_enabled():
        return
    try:
        requests.post(
            _table_url(table),
            headers=_headers(prefer),
            json=payload,
            timeout=SUPABASE_TIMEOUT_SECONDS,
        ).raise_for_status()
    except Exception:
        return


def _patch_json(
    table: str,
    payload: Dict[str, Any],
    params: Dict[str, Any],
    prefer: str = "return=minimal",
) -> List[Dict[str, Any]]:
    if not is_supabase_enabled():
        return []
    try:
        response = requests.patch(
            _table_url(table),
            headers=_headers(prefer),
            params=params,
            json=payload,
            timeout=SUPABASE_TIMEOUT_SECONDS,
        )
        response.raise_for_status()
        if not response.content:
            return []
        data = response.json()
    except Exception:
        return []
    return data if isinstance(data, list) else []


def _get_json(table: str, params: Dict[str, Any]) -> List[Dict[str, Any]]:
    if not is_supabase_enabled():
        return []
    try:
        response = requests.get(
            _table_url(table),
            headers=_headers(),
            params=params,
            timeout=SUPABASE_TIMEOUT_SECONDS,
        )
        response.raise_for_status()
        data = response.json()
    except Exception:
        return []
    return data if isinstance(data, list) else []


def log_scan_event(payload: Dict[str, Any]) -> None:
    row = {
        "scan_id": payload.get("scan_id"),
        "event_type": payload.get("event_type", "scan_completed"),
        "input_type": payload.get("input_type", "unknown"),
        "source_channel": payload.get("source_channel"),
        "risk_score": payload.get("risk_score", 0),
        "risk_level": payload.get("risk_level"),
        "user_risk_level": payload.get("user_risk_level"),
        "user_risk_label": payload.get("user_risk_label"),
        "detected_family_id": payload.get("detected_family_id"),
        "detected_family": payload.get("detected_family"),
        "claimed_brand": payload.get("claimed_brand"),
        "predicted_is_scam": payload.get("predicted_is_scam"),
        "signal_ids": payload.get("signal_ids") or [],
        "url_count": payload.get("url_count", 0),
        "urls": payload.get("urls") or [],
        "redacted_text_snippet": payload.get("redacted_text_snippet"),
        "evidence": payload.get("evidence") or {},
        "metadata": payload.get("metadata") or {},
    }
    created_at = _ts_to_iso(payload.get("timestamp"))
    if created_at:
        row["created_at"] = created_at
    if row["scan_id"]:
        _post_json("scan_events", row, "resolution=merge-duplicates,return=minimal")


def log_feedback_event(payload: Dict[str, Any]) -> None:
    row = {
        "scan_id": payload.get("scan_id"),
        "feedback": payload.get("feedback"),
        "actual_is_scam": payload.get("actual_is_scam"),
        "predicted_is_scam": payload.get("predicted_is_scam"),
        "predicted_risk_score": payload.get("predicted_risk_score"),
        "risk_level": payload.get("risk_level"),
        "signal_ids": payload.get("signal_ids") or [],
        "source_channel": payload.get("source_channel"),
        "notes": payload.get("notes"),
        "metadata": payload.get("metadata") or {},
    }
    created_at = _ts_to_iso(payload.get("timestamp"))
    if created_at:
        row["created_at"] = created_at
    if row["scan_id"] and row["feedback"]:
        _post_json("scan_feedback", row)


def load_scan_records(limit: Optional[int] = None) -> List[Dict[str, Any]]:
    params: Dict[str, Any] = {"select": "*", "order": "created_at.desc"}
    if isinstance(limit, int) and limit > 0:
        params["limit"] = str(limit)
    rows = _get_json("scan_events", params)
    output = []
    for row in reversed(rows):
        normalized = dict(row)
        normalized.setdefault("event_type", "scan_completed")
        ts = _iso_to_ts(normalized.get("created_at"))
        if ts:
            normalized["timestamp"] = ts
        output.append(normalized)
    return output


def load_feedback_records() -> List[Dict[str, Any]]:
    rows = _get_json("scan_feedback", {"select": "*", "order": "created_at.asc"})
    output = []
    for row in rows:
        normalized = dict(row)
        normalized.setdefault("event_type", "scan_feedback")
        ts = _iso_to_ts(normalized.get("created_at"))
        if ts:
            normalized["timestamp"] = ts
        output.append(normalized)
    return output


def save_campaign_intel(entry: Dict[str, Any]) -> None:
    if not is_supabase_enabled() or not isinstance(entry, dict):
        return
    intel_id = entry.get("intel_id")
    family = entry.get("family")
    if not intel_id or not family:
        return
    row = {
        "intel_id": intel_id,
        "family": family,
        "skeleton": entry.get("skeleton") or {},
        "iocs": entry.get("iocs") or {},
        "source": entry.get("source") or {},
        "evidence_quality": entry.get("evidence_quality") or "medium",
        "status": entry.get("status") or "active",
        "regions_hint": entry.get("regions_hint") or ["national"],
        "moderation": entry.get("moderation") or {},
    }
    created_at = _ts_to_iso(entry.get("created_at"))
    last_seen_at = _ts_to_iso(entry.get("last_seen_at"))
    if created_at:
        row["created_at"] = created_at
    if last_seen_at:
        row["last_seen_at"] = last_seen_at
    _post_json("campaign_intel", row, "resolution=merge-duplicates,return=minimal")


def load_campaign_intel() -> List[Dict[str, Any]]:
    rows = _get_json("campaign_intel", {"select": "*", "order": "last_seen_at.desc"})
    output: List[Dict[str, Any]] = []
    for row in rows:
        normalized = dict(row)
        for key in ("created_at", "last_seen_at"):
            ts = _iso_to_ts(normalized.get(key))
            if ts:
                normalized[key] = ts
        output.append(normalized)
    return output


def save_campaign_fingerprint(entry: Dict[str, Any]) -> None:
    if not is_supabase_enabled() or not isinstance(entry, dict):
        return
    fingerprint_id = entry.get("fingerprint_id")
    if not fingerprint_id:
        return
    row = {
        "fingerprint_id": fingerprint_id,
        "locale": entry.get("locale") or "ro-RO",
        "channel_class": entry.get("channel_class") or "sms",
        "arc_family": entry.get("arc_family") or "",
        "ask_sequence_sig": entry.get("ask_sequence_sig") or "",
        "cta_pattern_sig": entry.get("cta_pattern_sig") or "",
        "identity_claim_sig": entry.get("identity_claim_sig") or "",
        "payment_rail_sig": entry.get("payment_rail_sig") or "",
        "sensitive_request_sig": entry.get("sensitive_request_sig") or [],
        "text_skeleton_hash": entry.get("text_skeleton_hash") or "",
        "url_shape_sig": entry.get("url_shape_sig") or "no-url",
        "no_raw_iocs": bool(entry.get("no_raw_iocs", True)),
    }
    created_at = _ts_to_iso(entry.get("created_at"))
    if created_at:
        row["created_at"] = created_at
    _post_json("campaign_fingerprint", row, "resolution=merge-duplicates,return=minimal")


def delete_campaign_fingerprint(fingerprint_id: str) -> None:
    if not is_supabase_enabled() or not fingerprint_id:
        return
    try:
        requests.delete(
            _table_url("campaign_fingerprint"),
            headers=_headers(),
            params={"fingerprint_id": f"eq.{fingerprint_id}"},
            timeout=SUPABASE_TIMEOUT_SECONDS,
        ).raise_for_status()
    except Exception:
        return


def load_campaign_fingerprints() -> List[Dict[str, Any]]:
    rows = _get_json("campaign_fingerprint", {"select": "*", "order": "created_at.desc"})
    output: List[Dict[str, Any]] = []
    for row in rows:
        normalized = dict(row)
        ts = _iso_to_ts(normalized.get("created_at"))
        if ts:
            normalized["created_at"] = ts
        output.append(normalized)
    return output


def load_reputation_cache() -> Dict[str, Any]:
    rows = _get_json("url_reputation_cache", {"select": "*"})
    cache: Dict[str, Any] = {}
    now = int(time.time())
    for row in rows:
        url_hash = row.get("url_hash")
        details = row.get("details") if isinstance(row.get("details"), dict) else {}
        if not url_hash or not details:
            continue
        cache[url_hash] = details
        cache[url_hash].setdefault("cached_at", now)
    return cache


def save_reputation_cache(cache: Dict[str, Any]) -> None:
    if not is_supabase_enabled() or not isinstance(cache, dict):
        return
    rows: List[Dict[str, Any]] = []
    for url_hash, entry in cache.items():
        if not isinstance(entry, dict):
            continue
        expires_at = _ts_to_iso(entry.get("expires_at"))
        row = {
            "url_hash": url_hash,
            "canonical_url": entry.get("url"),
            "registered_domain": entry.get("registered_domain"),
            "verdict": entry.get("verdict", "unknown"),
            "risk_score": entry.get("risk_score", 0),
            "confidence": entry.get("confidence", 0),
            "sources": entry.get("sources") or {},
            "details": entry,
        }
        if expires_at:
            row["expires_at"] = expires_at
        rows.append(row)
    if not rows:
        return
    try:
        requests.post(
            _table_url("url_reputation_cache"),
            headers=_headers("resolution=merge-duplicates,return=minimal"),
            json=rows,
            timeout=SUPABASE_TIMEOUT_SECONDS,
        ).raise_for_status()
    except Exception:
        return


def load_urlscan_preview_cache(url_hash: str) -> Optional[Dict[str, Any]]:
    if not url_hash or not is_supabase_enabled():
        return None
    rows = _get_json(
        "urlscan_preview_cache",
        {
            "select": "*",
            "url_hash": f"eq.{url_hash}",
            "limit": "1",
        },
    )
    if not rows:
        return None
    row = dict(rows[0])
    expires_ts = _iso_to_ts(row.get("expires_at"))
    if expires_ts is not None and expires_ts <= int(time.time()):
        return None
    row.setdefault("status", "finished")
    return row


def load_fast_preview_cache(url_hash: str) -> Optional[Dict[str, Any]]:
    if not url_hash or not is_supabase_enabled():
        return None
    rows = _get_json(
        "fast_preview_cache",
        {
            "select": "*",
            "url_hash": f"eq.{url_hash}",
            "limit": "1",
        },
    )
    if not rows:
        return None
    row = dict(rows[0])
    expires_ts = _iso_to_ts(row.get("expires_at"))
    if expires_ts is not None and expires_ts <= int(time.time()):
        return None
    return row


def load_fast_preview_alias_cache(alias_hash: str) -> Optional[Dict[str, Any]]:
    if not alias_hash or not is_supabase_enabled():
        return None
    rows = _get_json(
        "fast_preview_alias_cache",
        {
            "select": "*",
            "alias_hash": f"eq.{alias_hash}",
            "limit": "1",
        },
    )
    if not rows:
        return None
    row = dict(rows[0])
    expires_ts = _iso_to_ts(row.get("expires_at"))
    if expires_ts is not None and expires_ts <= int(time.time()):
        return None
    return row


def create_preview_signed_url(
    object_path: str,
    bucket: str = "previews",
    expires_in_seconds: int = 900,
) -> Optional[str]:
    if not object_path or not bucket or not is_supabase_enabled():
        return None
    clean_path = str(object_path).strip().lstrip("/")
    bucket_prefix = f"{bucket}/"
    if clean_path.startswith(bucket_prefix):
        clean_path = clean_path[len(bucket_prefix):]
    try:
        response = requests.post(
            f"{SUPABASE_URL}/storage/v1/object/sign/{bucket}/{clean_path}",
            headers=_headers(),
            json={"expiresIn": int(expires_in_seconds)},
            timeout=SUPABASE_TIMEOUT_SECONDS,
        )
        response.raise_for_status()
        payload = response.json() if response.content else {}
        signed_url = payload.get("signedURL") or payload.get("signedUrl") or payload.get("signed_url")
        if not isinstance(signed_url, str) or not signed_url.strip():
            return None
        signed_url = signed_url.strip()
        if signed_url.startswith("http://") or signed_url.startswith("https://"):
            return signed_url
        if signed_url.startswith("/"):
            return f"{SUPABASE_URL}/storage/v1{signed_url}"
        return f"{SUPABASE_URL}/storage/v1/{signed_url.lstrip('/')}"
    except Exception:
        return None


def save_urlscan_preview_cache(entry: Dict[str, Any]) -> None:
    if not is_supabase_enabled() or not isinstance(entry, dict):
        return
    url_hash = entry.get("url_hash")
    final_url = entry.get("final_url")
    if not url_hash or not final_url:
        return
    row = {
        "url_hash": url_hash,
        "canonical_url": entry.get("canonical_url") or final_url,
        "final_url": final_url,
        "final_registered_domain": entry.get("final_registered_domain"),
        "uuid": entry.get("uuid"),
        "report_url": entry.get("report_url"),
        "screenshot_url": entry.get("screenshot_url"),
        "verdict": entry.get("verdict"),
        "severity": entry.get("severity"),
        "details": entry.get("details"),
        "score": entry.get("score") or 0,
        "categories": entry.get("categories") or [],
        "brands": entry.get("brands") or [],
    }
    expires_at = _ts_to_iso(entry.get("expires_at"))
    if expires_at:
        row["expires_at"] = expires_at
    _post_json("urlscan_preview_cache", row, "resolution=merge-duplicates,return=minimal")


def save_scan_job(job: Dict[str, Any]) -> bool:
    if not is_supabase_enabled() or not isinstance(job, dict):
        return True
    scan_id = job.get("scan_id")
    if not scan_id:
        return False
    storage_updated_at = job.get("_storage_updated_at")
    persisted_payload = dict(job)
    persisted_payload.pop("_storage_updated_at", None)
    expires_at = _ts_to_iso(job.get("expires_at"))
    row = {
        "scan_id": scan_id,
        "status": job.get("status", "scanning"),
        "input_type": job.get("input_type", "unknown"),
        "source_channel": job.get("source_channel"),
        "payload": persisted_payload,
    }
    if expires_at:
        row["expires_at"] = expires_at
    if isinstance(storage_updated_at, str) and storage_updated_at.strip():
        rows = _patch_json(
            "scan_jobs",
            row,
            {
                "scan_id": f"eq.{scan_id}",
                "updated_at": f"eq.{storage_updated_at}",
            },
            "return=representation",
        )
        if not rows:
            return False
        updated_at = rows[0].get("updated_at")
        if isinstance(updated_at, str):
            job["_storage_updated_at"] = updated_at
        return True

    try:
        response = requests.post(
            _table_url("scan_jobs"),
            headers=_headers("resolution=merge-duplicates,return=representation"),
            json=row,
            timeout=SUPABASE_TIMEOUT_SECONDS,
        )
        response.raise_for_status()
        data = response.json() if response.content else []
        if isinstance(data, list) and data:
            updated_at = data[0].get("updated_at")
            if isinstance(updated_at, str):
                job["_storage_updated_at"] = updated_at
        return True
    except Exception:
        return False


def load_scan_job(scan_id: str) -> Optional[Dict[str, Any]]:
    if not scan_id or not is_supabase_enabled():
        return None
    rows = _get_json(
        "scan_jobs",
        {
            "select": "payload,updated_at",
            "scan_id": f"eq.{scan_id}",
            "limit": "1",
        },
    )
    if not rows:
        return None
    payload = rows[0].get("payload")
    if not isinstance(payload, dict):
        return None
    updated_at = rows[0].get("updated_at")
    if isinstance(updated_at, str):
        payload["_storage_updated_at"] = updated_at
    return payload


# ─── PR-6 — Cercul: persistență durabilă (write-through, best-effort) ─────────
# Toate funcțiile sunt no-op fără SUPABASE_URL/SERVICE_ROLE_KEY (vezi _post_json/
# _patch_json). Backend-ul rulează identic cu sau fără Supabase; când Codex pune
# cheile + aplică migrarea, datele Cercului devin durabile (audit + cross-instance).

def save_circle_link(link: Dict[str, Any]) -> None:
    if not link.get("link_id"):
        return
    row = {
        "link_id": link.get("link_id"),
        "protected_user_id": link.get("protected_user_id"),
        "verifier_user_id": link.get("verifier_user_id"),
        "consent": link.get("consent") or "explicit",
        "revocable": bool(link.get("revocable", True)),
        "active": bool(link.get("active", True)),
    }
    _post_json("circle_links", row, "resolution=merge-duplicates,return=minimal")


def load_circle_link(link_id: str) -> Optional[Dict[str, Any]]:
    if not link_id:
        return None
    rows = _get_json(
        "circle_links",
        {"select": "*", "link_id": f"eq.{link_id}", "limit": "1"},
    )
    if not rows:
        return None
    row = dict(rows[0])
    created_ts = _iso_to_ts(row.get("created_at"))
    revoked_ts = _iso_to_ts(row.get("revoked_at"))
    return {
        "link_id": row.get("link_id"),
        "protected_user_id": row.get("protected_user_id"),
        "verifier_user_id": row.get("verifier_user_id"),
        "consent": row.get("consent") or "explicit",
        "revocable": bool(row.get("revocable", True)),
        "active": bool(row.get("active", True)),
        "created_at": created_ts or int(time.time()),
        "revoked_at": revoked_ts,
    }


def mark_circle_link_revoked(link_id: str) -> None:
    if not link_id:
        return
    _patch_json(
        "circle_links",
        {"active": False, "revoked_at": _ts_to_iso(int(time.time()))},
        {"link_id": f"eq.{link_id}"},
    )


def save_verification_ping(ping: Dict[str, Any]) -> None:
    if not ping.get("ping_id"):
        return
    row = {
        "ping_id": ping.get("ping_id"),
        "link_id": ping.get("link_id"),
        "claim": ping.get("claim") or "caller_claims_to_be_verifier",
        "payload_class": ping.get("payload_class") or "metadata_only",
        "default_on_timeout": ping.get("default_on_timeout") or "PRECAUTIE",
        "latency_target_s": int(ping.get("latency_target_s") or 10),
        "status": ping.get("status") or "pending",
    }
    _post_json("verification_pings", row, "resolution=merge-duplicates,return=minimal")


def load_verification_ping(ping_id: str) -> Optional[Dict[str, Any]]:
    if not ping_id:
        return None
    rows = _get_json(
        "verification_pings",
        {"select": "*", "ping_id": f"eq.{ping_id}", "limit": "1"},
    )
    if not rows:
        return None
    row = dict(rows[0])
    created_ts = _iso_to_ts(row.get("created_at"))
    resolved_ts = _iso_to_ts(row.get("resolved_at"))
    return {
        "ping_id": row.get("ping_id"),
        "link_id": row.get("link_id"),
        "claim": row.get("claim") or "caller_claims_to_be_verifier",
        "payload_class": row.get("payload_class") or "metadata_only",
        "default_on_timeout": row.get("default_on_timeout") or "PRECAUTIE",
        "latency_target_s": int(row.get("latency_target_s") or 10),
        "status": row.get("status") or "pending",
        "verifier_response": row.get("verifier_response"),
        "created_at": created_ts or int(time.time()),
        "resolved_at": resolved_ts,
    }


def update_verification_ping(ping_id: str, response: str, status: str = "resolved") -> None:
    if not ping_id:
        return
    _patch_json(
        "verification_pings",
        {"verifier_response": response, "status": status,
         "resolved_at": _ts_to_iso(int(time.time()))},
        {"ping_id": f"eq.{ping_id}"},
    )


def save_guardian_second_opinion(opinion: Dict[str, Any]) -> None:
    if not opinion.get("request_id"):
        return
    row = {
        "request_id": opinion.get("request_id"),
        "case_id": opinion.get("case_id"),
        "protected_user_id": opinion.get("protected_user_id"),
        "guardian_user_id": opinion.get("guardian_user_id"),
        "share_level": opinion.get("share_level") or "metadata_only",
        "share_downgraded": bool(opinion.get("share_downgraded", False)),
        "redacted_summary": opinion.get("redacted_summary") or {},
        "status": opinion.get("status") or "pending",
    }
    _post_json("guardian_second_opinion", row, "resolution=merge-duplicates,return=minimal")
