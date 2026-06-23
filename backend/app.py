"""Application entrypoint.

The runtime object is built in `main_runtime` and re-exported here so deployment
entrypoints can keep using `app:app`.
"""

from __future__ import annotations

from fastapi import FastAPI

from main_runtime import app as app
from main_runtime import create_app as _create_app


def create_app() -> FastAPI:
    """Factory wrapper for compatibility with factory-based startup tools."""

    return _create_app()
