"""FastAPI application entrypoint."""

from __future__ import annotations

import config
from core.request_security import security_guard
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from routers import analytics, audio, circle, community, extract, intel, orchestrated, pages, scan, sandbox, twilio_voice



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
    for mod in (
        pages,
        audio,
        twilio_voice,
        circle,
        community,
        intel,
        analytics,
        extract,
        orchestrated,
        sandbox,
        scan,
    ):
        app.include_router(mod.router)

    return app


app = create_app()
