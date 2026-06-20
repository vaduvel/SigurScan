"""Pure value-coercion helpers for telemetry feedback evaluation.

Extracted from telemetry.py; no module state, safe to import anywhere.
"""

import json
import os
from datetime import datetime, timezone
from collections import Counter
import threading
import time
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional


def _coerce_optional_bool(value: Any) -> Optional[bool]:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        normalized = value.strip().lower()
        if normalized in {"true", "1", "yes", "y", "on"}:
            return True
        if normalized in {"false", "0", "no", "n", "off"}:
            return False
    return None


def _safe_div(num: int, denom: int) -> float:
    return num / denom if denom else 0.0


def _coerce_feedback_ts(value: Any) -> int | None:
    if value is None:
        return None
    try:
        ts = int(value)
    except Exception:
        return None
    if ts <= 0:
        return None
    return ts


def _coerce_feedback_bool(value: Any) -> bool | None:
    if isinstance(value, bool):
        return value
    if isinstance(value, int):
        return bool(value)
    if isinstance(value, str):
        normalized = value.strip().lower()
        if normalized in {"true", "1", "yes", "y", "on"}:
            return True
        if normalized in {"false", "0", "no", "n", "off"}:
            return False
    return None


def _coerce_signal_list(value: Any) -> List[str]:
    if not isinstance(value, list):
        return []
    signal_ids: List[str] = []
    for raw_signal in value:
        if not isinstance(raw_signal, str):
            continue
        signal = raw_signal.strip()
        if signal:
            signal_ids.append(signal)
    return signal_ids


def _coerce_positive_int(value: Any, default: int = 0) -> int:
    try:
        int_value = int(value)
    except Exception:
        return default
    return int_value if int_value >= 0 else default


def _coerce_str(value: Any) -> str:
    if value is None:
        return ""
    return str(value).strip()


def _slice_list(values: List[Any], limit: int = 5) -> List[Any]:
    if limit <= 0:
        return []
    if len(values) <= limit:
        return values
    return list(values[:limit])
