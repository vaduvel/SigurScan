from pathlib import Path


BACKEND_DIR = Path(__file__).resolve().parent
DOCKERFILE = BACKEND_DIR / "Dockerfile"
LOCKFILE = BACKEND_DIR / "requirements.lock"
REQUIREMENTS = BACKEND_DIR / "requirements.txt"


def test_cloud_run_container_build_is_reproducible_and_warning_free():
    dockerfile = DOCKERFILE.read_text(encoding="utf-8")

    assert dockerfile.startswith(
        "FROM python:3.12.13-slim-trixie@sha256:"
    ), "Cloud Run base image must pin both the Python patch version and image digest"
    assert "pip install --upgrade pip" not in dockerfile
    assert "requirements.lock" in dockerfile
    assert "--require-hashes" in dockerfile
    assert "--root-user-action=ignore" in dockerfile

    lockfile = LOCKFILE.read_text(encoding="utf-8")
    assert "--hash=sha256:" in lockfile


def test_cloud_run_image_includes_backend_modules_imported_by_main():
    dockerfile = DOCKERFILE.read_text(encoding="utf-8")

    # Top-level modules imported at runtime by `uvicorn app:app` (app.py imports
    # `config` and `core.request_security`; main.py/the engine import
    # `runtime_state`). All of these must be copied into the image or it crashes
    # on boot with ModuleNotFoundError -- a failure pytest cannot catch since it
    # runs in the full source tree, not the built image (refactor #62 regression).
    for module_file in (
        "main.py",
        "app.py",
        "api_models.py",
        "app_config.py",
        "app_stores.py",
        "config.py",
        "runtime_state.py",
    ):
        assert module_file in dockerfile, f"Dockerfile must COPY {module_file} into the image"

    for package_dir in ("core", "routers", "services"):
        assert f"COPY {package_dir} ./{package_dir}" in dockerfile, (
            f"Dockerfile must COPY the {package_dir}/ package into the image"
        )


def test_cloud_run_lockfile_covers_declared_requirements():
    requirements = REQUIREMENTS.read_text(encoding="utf-8")
    lockfile = LOCKFILE.read_text(encoding="utf-8")

    declared = []
    for raw_line in requirements.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        package = line.split("==", 1)[0].strip().lower().replace("_", "-")
        declared.append(package)

    missing = [
        package
        for package in declared
        if f"{package}==" not in lockfile.lower().replace("_", "-")
    ]
    assert missing == []
