"""FastAPI application entrypoint."""

from __future__ import annotations

from typing import Any
import importlib
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

import config
from core.request_security import security_guard

RISK_THRESHOLD = config.RISK_THRESHOLD

from routers import pages, circle, community, intel, analytics, extract, orchestrated, sandbox

_RUNTIME_MODULE: Any | None = None

def _main_runtime() -> Any:
    global _RUNTIME_MODULE
    if _RUNTIME_MODULE is None:
        _RUNTIME_MODULE = importlib.import_module("main_runtime")
    return _RUNTIME_MODULE


def create_app() -> FastAPI:
    app = FastAPI(
        title="SigurScan API",
        description="Anti-scam detection engine localized for Romania (2025-2026)",
        version="1.0",
        docs_url="/docs" if config.EXPOSE_API_DOCS else None,
        redoc_url="/redoc" if config.EXPOSE_API_DOCS else None,
        openapi_url="/openapi.json" if config.EXPOSE_API_DOCS else None,
    )

    app.add_middleware(
        CORSMiddleware,
        allow_origins=config.ALLOWED_ORIGINS,
        allow_credentials="*" not in config.ALLOWED_ORIGINS,
        allow_methods=config.ALLOWED_CORS_METHODS,
        allow_headers=config.ALLOWED_CORS_HEADERS,
    )
    app.middleware("http")(security_guard)

    # Register route modules.
    for mod in (pages, circle, community, intel, analytics, extract, orchestrated, sandbox):
        app.include_router(mod.router)

    return app


app = create_app()


def __getattr__(name: str) -> Any:
    if name == "create_app":
        return create_app
    if name == "app":
        return app
    return getattr(_main_runtime(), name)


def __dir__():
    return sorted(set(globals()) | set(dir(_main_runtime())))
