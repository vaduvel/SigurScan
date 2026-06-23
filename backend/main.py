"""Backward-compatibility façade for legacy ``main`` imports."""

from __future__ import annotations

from typing import Any

try:
    from . import app as _runtime
except Exception:
    import importlib

    _fallback_module = importlib.import_module("app")
    if hasattr(_fallback_module, "app") and hasattr(_fallback_module, "create_app"):
        _runtime = _fallback_module
    else:
        from . import app as _runtime


def __getattr__(name: str) -> Any:
    return getattr(_runtime, name)


app = _runtime.app
__all__ = ["app", "create_app"]
create_app = _runtime.create_app
