import os
import re
import time
import uuid
import logging
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

import requests


SUPABASE_URL = (os.getenv("SUPABASE_URL") or "").strip().rstrip("/")
SUPABASE_SERVICE_ROLE_KEY = (
    os.getenv("SUPABASE_SERVICE_ROLE_KEY")
    or os.getenv("SUPABASE_SERVICE_KEY")
    or ""
).strip()
SUPABASE_TIMEOUT_SECONDS = float(os.getenv("SUPABASE_TIMEOUT_SECONDS") or "4.0")
SUPABASE_SUPPRESS_LOGS = os.getenv("SUPABASE_SUPPRESS_LOGS", "").lower() in {"1", "true", "yes"}
_LOGGER = logging.getLogger(__name__)

_SCAN_JOB_STORAGE_KEYS = {
    "_storage_updated_at",
    "_storage_revision",
    "_storage_locked_until",
    "_storage_active_step",
    "_storage_lock_owner",
    "_storage_lock_acquired_at",
}

_REPUTATION_TARGET_TYPES = {"phone", "domain", "url", "iban", "email", "wallet", "text", "unknown"}
_REPUTATION_EDGE_RELATIONS = {"pays_to", "co_occurred_in_case", "same_campaign", "claimed_by", "redirects_to"}
_SHA256_HEX_RE = re.compile(r"^[0-9a-f]{64}$", re.IGNORECASE)


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


def _rpc_url(function_name: str) -> str:
    return f"{SUPABASE_URL}/rest/v1/rpc/{function_name}"


def _ts_to_iso(value: Any) -> Optional[str]:
    try:
        ts = int(value)
    except Exception as exc:
        if not SUPABASE_SUPPRESS_LOGS:
            _LOGGER.debug("Failed to convert timestamp to ISO: %r", value, exc_info=exc)
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
    except Exception as exc:
        if not SUPABASE_SUPPRESS_LOGS:
            _LOGGER.debug("Failed to parse ISO timestamp: %r", value, exc_info=exc)
        return None


def _utc_iso(value: Optional[datetime] = None) -> str:
    candidate = value or datetime.now(timezone.utc)
    if candidate.tzinfo is None:
        candidate = candidate.replace(tzinfo=timezone.utc)
    return candidate.astimezone(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _post_json(
    table: str,
    payload: Dict[str, Any],
    prefer: str = "return=minimal",
    params: Optional[Dict[str, Any]] = None,
) -> None:
    if not is_supabase_enabled():
        return
    try:
        requests.post(
            _table_url(table),
            headers=_headers(prefer),
            params=params,
            json=payload,
            timeout=SUPABASE_TIMEOUT_SECONDS,
        ).raise_for_status()
    except Exception as exc:
        if not SUPABASE_SUPPRESS_LOGS:
            _LOGGER.warning("Supabase post_json failed for table=%s", table, exc_info=exc)
        return


def _rpc_json(function_name: str, payload: Dict[str, Any]) -> bool:
    if not is_supabase_enabled():
        return False
    try:
        requests.post(
            _rpc_url(function_name),
            headers=_headers(),
            json=payload,
            timeout=SUPABASE_TIMEOUT_SECONDS,
        ).raise_for_status()
        return True
    except Exception as exc:
        if not SUPABASE_SUPPRESS_LOGS:
            _LOGGER.warning("Supabase rpc_json failed for function=%s", function_name, exc_info=exc)
        return False


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
    except Exception as exc:
        if not SUPABASE_SUPPRESS_LOGS:
            _LOGGER.warning(
                "Supabase patch_json failed for table=%s params=%s",
                table,
                params,
                exc_info=exc,
            )
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
    except Exception as exc:
        if not SUPABASE_SUPPRESS_LOGS:
            _LOGGER.warning(
                "Supabase get_json failed for table=%s params=%s",
                table,
                params,
                exc_info=exc,
            )
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
        _post_json(
            "scan_events",
            row,
            "resolution=merge-duplicates,return=minimal",
            params={"on_conflict": "scan_id"},
        )


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


def save_negative_iban(iban: str, *, source: str = "manual", family: Optional[str] = None) -> None:
    if not iban:
        return
    row = {
        "iban": iban,
        "source": source or "manual",
        "family": family,
        "report_count": 1,
    }
    _post_json("negative_iban_registry", row, "resolution=merge-duplicates,return=minimal")


def load_negative_ibans() -> List[str]:
    rows = _get_json("negative_iban_registry", {"select": "iban"})
    return [str(row.get("iban") or "") for row in rows if row.get("iban")]


# ─── Reputation Graph v1 — cross-surface hashed intel ────────────────────────

def _valid_reputation_target_type(value: Any) -> str:
    target_type = str(value or "unknown").strip().lower()
    if target_type not in _REPUTATION_TARGET_TYPES:
        raise ValueError(f"invalid reputation target_type: {target_type}")
    return target_type


def _valid_reputation_hash(value: Any) -> str:
    digest = str(value or "").strip().lower()
    if not _SHA256_HEX_RE.fullmatch(digest):
        raise ValueError("reputation graph values must be SHA-256 hex digests")
    return digest


def save_reputation_observation(entry: Dict[str, Any]) -> None:
    if not isinstance(entry, dict):
        return
    row = {
        "target_type": _valid_reputation_target_type(entry.get("target_type")),
        "target_hash": _valid_reputation_hash(entry.get("target_hash") or entry.get("hash")),
        "source": str(entry.get("source") or "unknown").strip().lower() or "unknown",
        "risk_level": str(entry.get("risk_level") or "medium").strip().lower() or "medium",
        "family": entry.get("family"),
        "report_count": max(1, int(entry.get("report_count") or 1)),
        "evidence_quality": str(entry.get("evidence_quality") or "medium").strip().lower() or "medium",
    }
    observed_at = _ts_to_iso(entry.get("observed_at") or entry.get("timestamp"))
    if observed_at:
        row["observed_at"] = observed_at
    _post_json("reputation_observations", row, "return=minimal")


def save_reputation_edge(entry: Dict[str, Any]) -> None:
    if not isinstance(entry, dict):
        return
    relation = str(entry.get("relation") or "").strip().lower()
    if relation not in _REPUTATION_EDGE_RELATIONS:
        raise ValueError(f"invalid reputation edge relation: {relation}")
    row = {
        "source_type": _valid_reputation_target_type(entry.get("source_type")),
        "source_hash": _valid_reputation_hash(entry.get("source_hash")),
        "target_type": _valid_reputation_target_type(entry.get("target_type")),
        "target_hash": _valid_reputation_hash(entry.get("target_hash")),
        "relation": relation,
        "source": str(entry.get("source") or "case_correlation").strip().lower() or "case_correlation",
        "family": entry.get("family"),
        "evidence_quality": str(entry.get("evidence_quality") or "medium").strip().lower() or "medium",
    }
    observed_at = _ts_to_iso(entry.get("observed_at") or entry.get("timestamp"))
    if observed_at:
        row["observed_at"] = observed_at
    _post_json("reputation_edges", row, "return=minimal")


# Stable namespace for deterministic reputation-edge ids (D6). Never change it:
# the id is what makes an upsert idempotent, so the same logical edge always maps
# to the same row.
_REPUTATION_EDGE_NAMESPACE = uuid.UUID("6d36b0f2-0d6e-5e6a-9c4d-000000000006")


def _reputation_edge_id(row: Dict[str, Any]) -> str:
    key = "|".join([
        row["source_type"], row["source_hash"],
        row["target_type"], row["target_hash"],
        row["relation"],
    ])
    return str(uuid.uuid5(_REPUTATION_EDGE_NAMESPACE, key))


def upsert_reputation_edge(entry: Dict[str, Any]) -> None:
    """Idempotent variant of save_reputation_edge (D6).

    Derives a deterministic id from (source, target, relation) and upserts on the
    primary key via PostgREST merge-duplicates, so persisting the same seller
    edge across scans collapses to a single row instead of accumulating dupes.
    """
    if not isinstance(entry, dict):
        return
    relation = str(entry.get("relation") or "").strip().lower()
    if relation not in _REPUTATION_EDGE_RELATIONS:
        raise ValueError(f"invalid reputation edge relation: {relation}")
    row = {
        "source_type": _valid_reputation_target_type(entry.get("source_type")),
        "source_hash": _valid_reputation_hash(entry.get("source_hash")),
        "target_type": _valid_reputation_target_type(entry.get("target_type")),
        "target_hash": _valid_reputation_hash(entry.get("target_hash")),
        "relation": relation,
        "source": str(entry.get("source") or "case_correlation").strip().lower() or "case_correlation",
        "family": entry.get("family"),
        "evidence_quality": str(entry.get("evidence_quality") or "medium").strip().lower() or "medium",
    }
    row["id"] = _reputation_edge_id(row)
    observed_at = _ts_to_iso(entry.get("observed_at") or entry.get("timestamp"))
    if observed_at:
        row["observed_at"] = observed_at
    _post_json("reputation_edges", row, "resolution=merge-duplicates,return=minimal")


def save_reputation_allowlist(entry: Dict[str, Any]) -> None:
    if not isinstance(entry, dict):
        return
    row = {
        "target_type": _valid_reputation_target_type(entry.get("target_type")),
        "target_hash": _valid_reputation_hash(entry.get("target_hash") or entry.get("hash")),
        "source": str(entry.get("source") or "unknown").strip().lower() or "unknown",
        "reason": str(entry.get("reason") or "official").strip().lower() or "official",
    }
    observed_at = _ts_to_iso(entry.get("observed_at") or entry.get("timestamp"))
    if observed_at:
        row["observed_at"] = observed_at
    _post_json("reputation_allowlist", row, "resolution=merge-duplicates,return=minimal")


def load_reputation_graph_rows(limit: int = 1000) -> Dict[str, List[Dict[str, Any]]]:
    capped_limit = str(max(1, min(int(limit or 1000), 5000)))
    observations = _get_json(
        "reputation_observations",
        {
            "select": "target_type,target_hash,source,risk_level,family,report_count,evidence_quality,observed_at",
            "order": "observed_at.desc",
            "limit": capped_limit,
        },
    )
    edges = _get_json(
        "reputation_edges",
        {
            "select": "source_type,source_hash,target_type,target_hash,relation,source,family,evidence_quality,observed_at",
            "order": "observed_at.desc",
            "limit": capped_limit,
        },
    )
    allowlist = _get_json(
        "reputation_allowlist",
        {
            "select": "target_type,target_hash,source,reason,observed_at",
            "order": "observed_at.desc",
            "limit": capped_limit,
        },
    )
    return {"observations": observations, "edges": edges, "allowlist": allowlist}


def save_vendor_iban(cui: str, iban: str) -> None:
    if not cui or not iban:
        return
    if _rpc_json("remember_vendor_iban", {"p_cui": cui, "p_iban": iban}):
        return
    row = {
        "cui": cui,
        "iban": iban,
        "seen_count": 1,
    }
    _post_json("vendor_iban_memory", row, "resolution=merge-duplicates,return=minimal")


def load_vendor_ibans() -> List[Dict[str, Any]]:
    return _get_json("vendor_iban_memory", {"select": "cui,iban"})


def try_consume_provider_budget(provider: str, month_key: str, monthly_limit: int) -> Optional[bool]:
    if not is_supabase_enabled():
        return None
    try:
        response = requests.post(
            _rpc_url("try_consume_provider_budget"),
            headers=_headers(),
            json={
                "p_provider": provider,
                "p_month_key": month_key,
                "p_monthly_limit": int(monthly_limit),
            },
            timeout=SUPABASE_TIMEOUT_SECONDS,
        )
        response.raise_for_status()
        if not response.content:
            return None
        data = response.json()
        if isinstance(data, bool):
            return data
        if isinstance(data, list) and data and isinstance(data[0], bool):
            return data[0]
    except Exception as exc:
        if not SUPABASE_SUPPRESS_LOGS:
            _LOGGER.warning("Supabase try_consume_provider_budget failed", exc_info=exc)
        return None
    return None


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
    except Exception as exc:
        if not SUPABASE_SUPPRESS_LOGS:
            _LOGGER.warning("Supabase delete_campaign_fingerprint failed", exc_info=exc)
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
    except Exception as exc:
        if not SUPABASE_SUPPRESS_LOGS:
            _LOGGER.warning("Supabase save_reputation_cache failed", exc_info=exc)
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
    except Exception as exc:
        if not SUPABASE_SUPPRESS_LOGS:
            _LOGGER.warning("Supabase create_preview_signed_url failed", exc_info=exc)
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
    storage_revision = job.get("_storage_revision")
    persisted_payload = dict(job)
    for key in _SCAN_JOB_STORAGE_KEYS:
        persisted_payload.pop(key, None)
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
    if isinstance(storage_revision, int):
        row.update(
            {
                "revision": storage_revision + 1,
                "locked_until": None,
                "active_step": None,
                "lock_owner": None,
                "lock_acquired_at": None,
            }
        )
        rows = _patch_json(
            "scan_jobs",
            row,
            {
                "scan_id": f"eq.{scan_id}",
                "revision": f"eq.{storage_revision}",
            },
            "return=representation",
        )
        if not rows:
            return False
        _attach_scan_job_storage_metadata(job, rows[0])
        return True
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
        _attach_scan_job_storage_metadata(job, rows[0])
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
            _attach_scan_job_storage_metadata(job, data[0])
        return True
    except Exception as exc:
        if not SUPABASE_SUPPRESS_LOGS:
            _LOGGER.warning("Supabase save_scan_job failed for scan_id=%s", scan_id, exc_info=exc)
        return False


def _attach_scan_job_storage_metadata(job: Dict[str, Any], row: Dict[str, Any]) -> Dict[str, Any]:
    updated_at = row.get("updated_at")
    if isinstance(updated_at, str):
        job["_storage_updated_at"] = updated_at
    revision = row.get("revision")
    if isinstance(revision, int):
        job["_storage_revision"] = revision
    locked_until = row.get("locked_until")
    if isinstance(locked_until, str):
        job["_storage_locked_until"] = locked_until
    active_step = row.get("active_step")
    if isinstance(active_step, str):
        job["_storage_active_step"] = active_step
    lock_owner = row.get("lock_owner")
    if isinstance(lock_owner, str):
        job["_storage_lock_owner"] = lock_owner
    lock_acquired_at = row.get("lock_acquired_at")
    if isinstance(lock_acquired_at, str):
        job["_storage_lock_acquired_at"] = lock_acquired_at
    return job


def scan_job_from_record(row: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    payload = row.get("payload") if isinstance(row, dict) else None
    if not isinstance(payload, dict):
        return None
    job = dict(payload)
    return _attach_scan_job_storage_metadata(job, row)


def load_scan_job_record(scan_id: str) -> Optional[Dict[str, Any]]:
    if not scan_id or not is_supabase_enabled():
        return None
    rows = _get_json(
        "scan_jobs",
        {
            "select": "payload,updated_at,revision,locked_until,active_step,lock_owner,lock_acquired_at",
            "scan_id": f"eq.{scan_id}",
            "limit": "1",
        },
    )
    if not rows:
        return None
    return rows[0]


def load_scan_job(scan_id: str) -> Optional[Dict[str, Any]]:
    if not scan_id or not is_supabase_enabled():
        return None
    record = load_scan_job_record(scan_id)
    job = scan_job_from_record(record) if isinstance(record, dict) else None
    if isinstance(job, dict):
        return job

    # Backward-compatible fallback for projects where the CAS migration has not
    # been applied yet. Once the migration is live, load_scan_job_record handles
    # the normal path and includes revision/lock metadata.
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
    return scan_job_from_record(rows[0])


def claim_scan_job(
    scan_id: str,
    *,
    expected_revision: int,
    owner: str,
    active_step: str,
    lock_seconds: int = 90,
) -> Optional[Dict[str, Any]]:
    if not scan_id or not is_supabase_enabled() or not isinstance(expected_revision, int):
        return None
    now_iso = _utc_iso()
    locked_until = _utc_iso(datetime.now(timezone.utc) + timedelta(seconds=max(5, int(lock_seconds))))
    rows = _patch_json(
        "scan_jobs",
        {
            "revision": expected_revision + 1,
            "locked_until": locked_until,
            "active_step": str(active_step or "polling")[:80],
            "lock_owner": str(owner or "unknown")[:120],
            "lock_acquired_at": now_iso,
        },
        {
            "scan_id": f"eq.{scan_id}",
            "revision": f"eq.{expected_revision}",
            "or": f"(locked_until.is.null,locked_until.lt.{now_iso})",
        },
        "return=representation",
    )
    return rows[0] if rows else None


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


def save_circle_delivery_event(event: Dict[str, Any]) -> None:
    if not isinstance(event, dict):
        return
    if event.get("raw_content_shared") is not False:
        return
    row = {
        "event_type": event.get("type") or "push_deeplink",
        "target_user_id": event.get("target_user_id"),
        "deeplink": event.get("deeplink"),
        "payload_class": event.get("payload_class") or "metadata_only",
        "raw_content_shared": False,
        "status": event.get("status") or "pending",
        "metadata": {
            "ping_id": event.get("ping_id"),
            "link_id": event.get("link_id"),
        },
    }
    if not row["target_user_id"] or not row["deeplink"]:
        return
    _post_json("circle_delivery_outbox", row, "return=minimal")


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
