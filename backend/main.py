"""Backward-compatibility module for legacy ``main`` imports."""

from __future__ import annotations

from typing import Any
import importlib

from config import RISK_THRESHOLD
from app import app, create_app

_runtime_module: Any | None = None


def _legacy_runtime() -> Any:
    global _runtime_module
    if _runtime_module is None:
        _runtime_module = importlib.import_module("main_runtime")
    return _runtime_module


def __getattr__(name: str) -> Any:
    if name in {"app", "create_app"}:
        return globals()[name]
    try:
        return getattr(app, name)
    except AttributeError:
        return getattr(_legacy_runtime(), name)


def __dir__():
    return sorted(set(globals()) | set(dir(_legacy_runtime())))

__all__ = ["app", "create_app"]
