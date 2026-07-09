"""P-RULES Felia 1 — versioned semantic-rules manifest (backend loader).

Rules-as-data: the scam-keyword pattern groups (OTP, payment, remote-access,
urgency, ...) live in a versioned JSON manifest instead of only as hardcoded
Python. This is the backend half of unifying the rules across backend + Android
(P-DUP / P-PORT) and enabling rule updates without an app release, reusing the
BTR-style version-gated sync pattern.

Felia 1 scope: load + compile the manifest, and prove (test_rules_manifest) that
it is byte-for-byte equivalent to the current `scam_atlas_patterns` constants.
The manifest is NOT yet consumed by the detectors (that is a later, gated slice),
so this module changes no verdict behavior. `is_enabled()` gates that future
consumption; it defaults OFF.
"""
from __future__ import annotations

import json
import os
import re
from functools import lru_cache
from pathlib import Path
from typing import Any, Dict, List, Optional

_BACKEND_DIR = Path(__file__).resolve().parents[1]
DEFAULT_MANIFEST_PATH = _BACKEND_DIR / "data" / "rules" / "scam_rules_manifest_v1.json"

_FLAG_MAP = {
    "IGNORECASE": re.IGNORECASE,
    "DOTALL": re.DOTALL,
    "MULTILINE": re.MULTILINE,
}


def is_enabled() -> bool:
    """Gate for future manifest-driven consumption. Default OFF: until this is on
    (and parity is proven), the hardcoded `scam_atlas_patterns` stay the source of
    truth."""
    return os.getenv("RULES_MANIFEST", "0").strip().lower() in {"1", "true", "yes", "on"}


def _manifest_path() -> Path:
    override = os.getenv("RULES_MANIFEST_PATH")
    return Path(override) if override else DEFAULT_MANIFEST_PATH


@lru_cache(maxsize=4)
def _load_raw(path_str: str) -> dict:
    return json.loads(Path(path_str).read_text(encoding="utf-8"))


def manifest_version() -> str:
    return str(_load_raw(str(_manifest_path())).get("version") or "")


def _compile_flags(names: List[str]) -> int:
    flags = 0
    for name in names or []:
        flags |= _FLAG_MAP.get(str(name).upper(), 0)
    return flags


def load_pattern_groups() -> Dict[str, List[re.Pattern]]:
    """Return {group_name: [compiled patterns]} from the manifest."""
    raw = _load_raw(str(_manifest_path()))
    groups: Dict[str, List[re.Pattern]] = {}
    for name, entries in (raw.get("groups") or {}).items():
        compiled: List[re.Pattern] = []
        for entry in entries or []:
            compiled.append(re.compile(entry["pattern"], _compile_flags(entry.get("flags"))))
        groups[name] = compiled
    return groups


def rules_sync_payload(client_version: Optional[str] = None) -> Dict[str, Any]:
    """P-RULES Felia 2 — device/backend pull of the semantic-rules manifest.

    Mirrors btr_sync_payload: version-gated. If the caller's version matches the
    current one -> no-op (changed=False). Otherwise returns the full manifest so
    a consumer can rebuild its rules. Read-only, no message content, just rules.
    """
    raw = _load_raw(str(_manifest_path()))
    current = str(raw.get("version") or "")
    if client_version and client_version == current:
        return {"changed": False, "version": current, "manifest": None, "count": 0}
    return {
        "changed": True,
        "version": current,
        "manifest": raw,
        "count": sum(len(v or []) for v in (raw.get("groups") or {}).values()),
    }
