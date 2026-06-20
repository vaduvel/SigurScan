import json
import os
from datetime import datetime, timezone
from collections import Counter
import threading
import time
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

from services import supabase_store
from services.pii_redactor import redact_pii


_LOCK = threading.Lock()


def _resolve_path(env_name: str, default_rel_path: str) -> Path:
    return Path(os.getenv(env_name, str(Path(__file__).resolve().parents[1] / default_rel_path)))


SCAN_EVENTS_PATH = _resolve_path("SCAN_EVENTS_LOG_PATH", "data/scan_events.jsonl")
FEEDBACK_LOG_PATH = _resolve_path("SCAN_FEEDBACK_LOG_PATH", "data/scan_feedback.jsonl")


def _append_jsonl(path: Path, payload: Dict[str, Any]) -> None:
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        with _LOCK:
            with path.open("a", encoding="utf-8") as f:
                f.write(json.dumps(payload, ensure_ascii=False))
                f.write("\n")
    except Exception:
        # Telemetry is non-blocking.
        return


def _redact_log_value(value: Any) -> Any:
    """Best-effort final guard before telemetry reaches any persistence sink."""
    if isinstance(value, str):
        return redact_pii(value)
    if isinstance(value, list):
        return [_redact_log_value(item) for item in value]
    if isinstance(value, dict):
        return {key: _redact_log_value(item) for key, item in value.items()}
    return value


def log_scan_event(payload: Dict[str, Any]) -> None:
    if not isinstance(payload, dict):
        return

    base_payload = _redact_log_value(dict(payload))
    base_payload.setdefault("event_type", "scan_completed")
    base_payload.setdefault("timestamp", int(time.time()))
    supabase_store.log_scan_event(base_payload)
    _append_jsonl(SCAN_EVENTS_PATH, base_payload)


def log_feedback_event(payload: Dict[str, Any]) -> None:
    if not isinstance(payload, dict):
        return

    base_payload = _redact_log_value(dict(payload))
    base_payload.setdefault("event_type", "scan_feedback")
    base_payload.setdefault("timestamp", int(time.time()))
    supabase_store.log_feedback_event(base_payload)
    _append_jsonl(FEEDBACK_LOG_PATH, base_payload)


def _iter_jsonl(path: Path) -> Iterable[Dict[str, Any]]:
    if not path.exists():
        return []
    with path.open("r", encoding="utf-8") as f:
        for line in f:
            try:
                obj = json.loads(line.strip())
                if isinstance(obj, dict):
                    yield obj
            except Exception:
                continue


def load_feedback_records() -> List[Dict[str, Any]]:
    remote_records = supabase_store.load_feedback_records()
    if remote_records:
        return remote_records
    return list(_iter_jsonl(FEEDBACK_LOG_PATH))


def load_scan_records(limit: int | None = None) -> List[Dict[str, Any]]:
    remote_records = supabase_store.load_scan_records(limit)
    if remote_records:
        return remote_records
    records = list(_iter_jsonl(SCAN_EVENTS_PATH))
    if isinstance(limit, int) and limit > 0:
        return records[-limit:]
    return records


def find_scan_record_by_id(scan_id: str) -> Dict[str, Any] | None:
    if not scan_id:
        return None

    for row in reversed(load_scan_records()):
        if not isinstance(row, dict):
            continue
        if row.get("scan_id") == scan_id and row.get("event_type", "scan_completed") == "scan_completed":
            return row
    return None


# Feedback evaluation / trend logic lives in telemetry_feedback.py; re-export the public
# API here so existing `from services.telemetry import ...` call sites keep working.
from services.telemetry_feedback import (  # noqa: E402
    build_feedback_evaluation_rows,
    run_feedback_threshold_sweep,
    summarize_feedback_records,
    summarize_feedback_trend,
)
