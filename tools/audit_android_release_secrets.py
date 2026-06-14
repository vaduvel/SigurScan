#!/usr/bin/env python3
"""Audit Android release artifacts for embedded local/backend secrets.

The script intentionally prints only variable names and categories, never values.
Provider/admin/service secrets are treated as failures. The app client API key is
reported separately because the current private-client build still embeds it as
an anti-abuse barrier until Play Integrity/backend-issued tokens replace it.
"""

from __future__ import annotations

import argparse
import shutil
import sys
import tempfile
import zipfile
from pathlib import Path


CLIENT_OR_PUBLIC_NAMES = {
    "SIGURSCAN_BACKEND_BASE_URL",
    "SIGURSCAN_RELEASE_BACKEND_BASE_URL",
    "SIGURSCAN_PRIVACY_URL",
    "SIGURSCAN_RELEASE_PRIVACY_URL",
    "SIGURSCAN_API_KEY",
    "SIGURSCAN_RELEASE_API_KEY",
}

SENSITIVE_MARKERS = ("KEY", "TOKEN", "SECRET", "URL", "API")


def _read_properties(path: Path) -> dict[str, str]:
    if not path.exists():
        return {}
    values: dict[str, str] = {}
    for raw_line in path.read_text(errors="ignore").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        value = value.strip().strip('"').strip("'")
        if value:
            values[key.strip()] = value
    return values


def _artifact_blob(artifact: Path) -> bytes:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp) / "artifact"
        root.mkdir(parents=True, exist_ok=True)
        with zipfile.ZipFile(artifact) as archive:
            archive.extractall(root)
        chunks: list[bytes] = []
        for file_path in root.rglob("*"):
            if not file_path.is_file():
                continue
            try:
                chunks.append(file_path.read_bytes())
            except OSError:
                continue
        return b"\n".join(chunks)


def _category(name: str) -> str:
    if name in CLIENT_OR_PUBLIC_NAMES:
        return "client_or_public"
    return "secret_candidate"


def audit(artifact: Path, property_files: list[Path], fail_on_client_key: bool = False) -> int:
    if not artifact.exists():
        print(f"artifact_missing: {artifact}")
        return 2
    if shutil.which("unzip") is None:
        # zipfile does the extraction, but this keeps the environment expectation explicit.
        print("note: unzip command not found; using Python zipfile extraction")

    blob = _artifact_blob(artifact)
    checked = 0
    failures: list[str] = []
    warnings: list[str] = []

    for props_path in property_files:
        for name, value in _read_properties(props_path).items():
            if len(value) < 8 or not any(marker in name for marker in SENSITIVE_MARKERS):
                continue
            checked += 1
            embedded = value.encode() in blob
            category = _category(name)
            if embedded and category == "secret_candidate":
                failures.append(f"{props_path}:{name}")
            elif embedded and name in {"SIGURSCAN_API_KEY", "SIGURSCAN_RELEASE_API_KEY"}:
                warnings.append(f"{props_path}:{name}")
            print(f"{props_path}:{name} category={category} embedded={str(embedded).lower()}")

    print(f"checked_values={checked}")
    if warnings:
        print("client_key_embedded_warning=" + ",".join(warnings))
    if failures:
        print("secret_embedding_failures=" + ",".join(failures))
        return 1
    if fail_on_client_key and warnings:
        return 1
    return 0


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "artifact",
        nargs="?",
        default="app/build/outputs/apk/release/app-release.apk",
        help="APK/AAB artifact to inspect",
    )
    parser.add_argument(
        "--props",
        action="append",
        default=["local.properties", "backend/.env.vercel"],
        help="Properties/env file to compare against. Can be provided multiple times.",
    )
    parser.add_argument(
        "--fail-on-client-key",
        action="store_true",
        help="Treat embedded SIGURSCAN_API_KEY/SIGURSCAN_RELEASE_API_KEY as a failure.",
    )
    args = parser.parse_args(argv)
    return audit(Path(args.artifact), [Path(item) for item in args.props], args.fail_on_client_key)


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
