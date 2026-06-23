"""Backward-compatibility module for legacy ``main`` imports."""

from __future__ import annotations

from app import app, create_app
import importlib

__all__ = ["app", "create_app"]


def _runtime_module():
    return importlib.import_module("main_runtime")


def __getattr__(name: str):
    if name in {"app", "create_app"}:
        return globals()[name]
    return getattr(_runtime_module(), name)


def __dir__():
    return sorted(set(__all__) | set(dir(_runtime_module())))
