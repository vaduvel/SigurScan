import json
from pathlib import Path
from urllib.parse import urlparse


ROOT = Path(__file__).resolve().parents[1]


def _load(path: str):
    return json.loads((ROOT / path).read_text(encoding="utf-8"))


def _normalized_urls(items):
    urls = set()
    for item in items:
        url = item.get("url")
        if not url:
            continue
        parsed = urlparse(url)
        host = (parsed.hostname or "").lower()
        path = (parsed.path or "/").rstrip("/") or "/"
        urls.add(f"https://{host}{'' if path == '/' else path}")
    return urls


def test_official_url_patch_shape_and_counts():
    patch = _load("backend/data/knowledge/official_url_patch_2026_06_14.json")

    assert patch["schema"] == "sigurscan_official_url_patch_v1"
    assert patch["entry_count"] == 72
    assert patch["preview_seed_count"] == 51
    assert patch["registry_only_count"] == 21
    assert len(patch["needs_human_review"]) == 11
    assert all(entry["registry_include"] is True for entry in patch["entries"])


def test_registry_only_urls_do_not_enter_preview_seeds():
    patch = _load("backend/data/knowledge/official_url_patch_2026_06_14.json")
    backend_seed = _load("backend/data/preview_seed_urls_ro.json")
    worker_seed = _load("workers/precapture/samples/official_preview_targets.ro.json")

    registry_only = [
        entry for entry in patch["entries"]
        if entry["registry_include"] is True and entry["preview_seed_include"] is not True
    ]
    backend_urls = _normalized_urls(backend_seed["urls"])
    worker_urls = _normalized_urls(worker_seed["targets"])

    for entry in registry_only:
        parsed = urlparse(entry["url"])
        normalized = f"https://{(parsed.hostname or '').lower()}{(parsed.path or '/').rstrip('/') if (parsed.path or '/') != '/' else ''}"
        assert normalized not in backend_urls
        assert normalized not in worker_urls


def test_preview_patch_urls_are_seeded_and_safe_for_capture():
    patch = _load("backend/data/knowledge/official_url_patch_2026_06_14.json")
    backend_seed = _load("backend/data/preview_seed_urls_ro.json")
    worker_seed = _load("workers/precapture/samples/official_preview_targets.ro.json")

    backend_urls = _normalized_urls(backend_seed["urls"])
    worker_urls = _normalized_urls(worker_seed["targets"])
    preview_urls = [
        entry["url"] for entry in patch["entries"]
        if entry["preview_seed_include"] is True
    ]

    missing_backend = []
    missing_worker = []
    for url in preview_urls:
        parsed = urlparse(url)
        normalized = f"https://{(parsed.hostname or '').lower()}{(parsed.path or '/').rstrip('/') if (parsed.path or '/') != '/' else ''}"
        if normalized not in backend_urls:
            missing_backend.append(normalized)
        if normalized not in worker_urls:
            missing_worker.append(normalized)

    assert missing_backend == []
    assert missing_worker == []
    assert not any("needs_exact_url" in url for url in backend_urls | worker_urls)
    assert not any(url.endswith((".test", ".invalid", ".example", ".localhost")) for url in backend_urls | worker_urls)
