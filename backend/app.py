"""Application entrypoint and runtime façade.

The concrete implementation still lives in ``main_runtime``. This module exposes:
- ``app`` and ``create_app`` for ASGI launchers
- a legacy-compatible runtime surface via module attributes (e.g. ``_new_scan_id``)

Keeping imports here lazy avoids import-time cycles when ``main_runtime`` loads
its services, which now reference ``app`` for compatibility access.
"""

from __future__ import annotations

import importlib
import sys
from typing import Any
from pathlib import Path

from fastapi import FastAPI

_runtime = None
_app_instance = None
_RUNTIME_FILE = Path(__file__).resolve().parent / "main_runtime.py"


def _runtime_module():
    global _runtime
    if _runtime is None:
        for module_name in ("main_runtime", "backend.main_runtime"):
            try:
                _runtime = importlib.import_module(module_name)
                break
            except ModuleNotFoundError:
                _runtime = None
                continue
        if _runtime is None and _RUNTIME_FILE.exists():
            runtime_dir = str(_RUNTIME_FILE.parent)
            inserted = False
            if runtime_dir not in sys.path:
                sys.path.insert(0, runtime_dir)
                inserted = True
            try:
                _runtime = importlib.import_module("main_runtime")
            except ModuleNotFoundError:
                _runtime = None
            finally:
                if inserted:
                    try:
                        sys.path.remove(runtime_dir)
                    except ValueError:
                        pass
        if _runtime is None:
            raise ModuleNotFoundError("Unable to import main runtime module as 'main_runtime' or 'backend.main_runtime'.")
    return _runtime


def __getattr__(name: str) -> Any:
    if name == "app":
        return create_app()
    if name == "create_app":
        return create_app
    return getattr(_runtime_module(), name)


def __dir__():
    try:
        runtime = _runtime_module()
        return sorted(set(globals()) | set(dir(runtime)))
    except Exception:
        return sorted(set(globals()))


def create_app() -> FastAPI:
    """Create a FastAPI application using the runtime factory."""

    global _app_instance
    if _app_instance is None:
        _app_instance = _runtime_module().create_app()
    return _app_instance
    

# Backward-compatible module-level app object expected by ASGI runners.
# The object is provided lazily via ``__getattr__`` to avoid import-time cycles
# when loading this module from contexts that re-import services referencing it.
