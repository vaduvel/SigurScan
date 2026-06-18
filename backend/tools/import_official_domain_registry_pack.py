#!/usr/bin/env python3
"""Import official-domain registry research packs into brand_knowledge_pack.json.

The importer is deliberately conservative:
- all entities enter official_registry_updates as provenance/policy evidence;
- only non-shared registrable-domain entities enter the legacy brand_registry;
- exact-host and path-scoped entities stay policy-only, handled by scam_atlas.py;
- critical corrections remove unsafe legacy whitelist domains.
"""

from __future__ import annotations

import argparse
import json
import re
import zipfile
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
DEFAULT_BRAND_PACK_PATH = ROOT / "backend" / "data" / "brand_knowledge_pack.json"

PATH_SCOPED_POLICIES = {
    "exact_host",
    "path_scoped",
    "shared_host_plus_path_prefix",
    "shared_host_plus_entity_context",
    "brand_scoped_shared_host",
}


def _coerce_str_list(values: Any) -> list[str]:
    if not values:
        return []
    if isinstance(values, (str, int, float)):
        values = [values]
    output: list[str] = []
    for value in values:
        text = str(value or "").strip()
        if text:
            output.append(text)
    return output


def _dedupe_preserve_order(values: list[str]) -> list[str]:
    seen: set[str] = set()
    output: list[str] = []
    for value in values:
        normalized = str(value or "").strip()
        if not normalized:
            continue
        fingerprint = normalized.lower()
        if fingerprint in seen:
            continue
        seen.add(fingerprint)
        output.append(normalized)
    return output


def _normalise_host(value: Any) -> str:
    return str(value or "").strip().lower().strip(".")


def _fingerprint_host(value: Any) -> str:
    host = _normalise_host(value)
    if host.startswith("www."):
        host = host[4:]
    return host


def _normalise_path(value: Any) -> str:
    path = str(value or "").strip()
    if not path:
        return ""
    if not path.startswith("/"):
        path = f"/{path}"
    if len(path) > 1:
        path = path.rstrip("/")
    return path.lower()


def _record_key(record: dict[str, Any], index: int) -> str:
    brand_id = str(record.get("brand_id") or "").strip()
    if brand_id:
        return f"brand_id:{brand_id}"
    display_name = str(record.get("display_name") or "").strip()
    if display_name:
        return f"display_name:{display_name.lower()}"
    return f"index:{index}"


def _record_fingerprints(record: dict[str, Any], index: int) -> set[str]:
    fingerprints = {_record_key(record, index)}
    display_name = str(record.get("display_name") or "").strip()
    if display_name:
        fingerprints.add(f"display_name:{display_name.lower()}")

    hosts = _dedupe_preserve_order(
        [
            _fingerprint_host(value)
            for value in (
                _coerce_str_list(record.get("official_domains"))
                + _coerce_str_list(record.get("exact_hosts"))
                + _coerce_str_list(record.get("subdomains"))
                + _coerce_str_list(record.get("delegated_domains"))
            )
            if _fingerprint_host(value)
        ]
    )
    paths = _dedupe_preserve_order(
        [_normalise_path(value) for value in _coerce_str_list(record.get("path_prefixes")) if _normalise_path(value)]
    )
    match_policy = _norm_policy(record.get("match_policy"))
    shared_host = bool(record.get("shared_host"))

    if hosts and (not shared_host or match_policy == "exact_host" or paths):
        fingerprints.add(
            "technical:"
            + match_policy
            + "|"
            + ",".join(sorted(hosts))
            + "|"
            + ",".join(sorted(paths))
        )
    return fingerprints


def _norm_policy(value: Any) -> str:
    return str(value or "").strip().lower()


def _load_json_from_zip(zip_path: Path) -> tuple[dict[str, Any], str]:
    best_payload: dict[str, Any] | None = None
    best_name = ""
    best_score = -1
    with zipfile.ZipFile(zip_path) as archive:
        for name in archive.namelist():
            if not name.endswith(".json"):
                continue
            try:
                payload = json.loads(archive.read(name).decode("utf-8"))
            except Exception:
                continue
            if not isinstance(payload, dict):
                continue
            entities = payload.get("entities")
            if not isinstance(entities, list):
                continue
            score = len(entities)
            if isinstance(payload.get("metadata"), dict):
                score += 10_000
            if payload.get("critical_corrections"):
                score += 500
            if score > best_score:
                best_payload = payload
                best_name = name
                best_score = score
    if best_payload is None:
        raise ValueError(f"No importable registry JSON with entities found in {zip_path}")
    return best_payload, best_name


def _normalise_registry_payload(payload: dict[str, Any], *, source_label: str) -> dict[str, Any]:
    if isinstance(payload.get("entities"), list):
        return payload
    if isinstance(payload.get("high_confidence"), list):
        metadata = {
            "pack_id": Path(source_label).stem,
            "version": payload.get("version"),
            "research_scope": payload.get("research_scope"),
        }
        if isinstance(payload.get("metadata"), dict):
            metadata.update(payload["metadata"])
        return {
            "metadata": metadata,
            "entities": payload.get("high_confidence") or [],
            "security_review_queue": payload.get("review_queue") or [],
            "negative_or_warning_sources": payload.get("negative_or_warning_sources") or [],
        }
    return payload


def _corrections_from_payload(payload: Any) -> list[dict[str, Any]]:
    if isinstance(payload, list):
        return [correction for correction in payload if isinstance(correction, dict)]
    if isinstance(payload, dict):
        return [
            correction
            for correction in payload.get("critical_corrections", [])
            if isinstance(correction, dict)
        ]
    return []


def _load_registry_payload(path: Path) -> tuple[dict[str, Any], str, list[dict[str, Any]]]:
    if path.suffix.lower() == ".zip":
        payload, selected_name = _load_json_from_zip(path)
        return (
            _normalise_registry_payload(payload, source_label=selected_name),
            selected_name,
            _load_extra_critical_corrections(path),
        )
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError(f"No importable registry JSON object found in {path}")
    normalized = _normalise_registry_payload(payload, source_label=str(path))
    if not isinstance(normalized.get("entities"), list):
        raise ValueError(f"No importable registry entities found in {path}")
    return normalized, str(path), _corrections_from_payload(payload)


def _load_extra_critical_corrections(zip_path: Path) -> list[dict[str, Any]]:
    corrections: list[dict[str, Any]] = []
    with zipfile.ZipFile(zip_path) as archive:
        for name in archive.namelist():
            if "critical_corrections" not in name or not name.endswith(".json"):
                continue
            try:
                payload = json.loads(archive.read(name).decode("utf-8"))
            except Exception:
                continue
            corrections.extend(_corrections_from_payload(payload))
    return corrections


def _domain_tokens_from_correction(correction: dict[str, Any]) -> list[str]:
    tokens: list[str] = []
    tokens.extend(_coerce_str_list(correction.get("legacy_or_old_candidates")))
    existing = str(correction.get("existing_value") or "")
    tokens.extend(re.findall(r"\b(?:[a-z0-9-]+\.)+[a-z]{2,}\b", existing.lower()))
    action = str(correction.get("action") or "").lower()
    if action in {"do_not_whitelist", "remove_and_replace"}:
        tokens.extend(_coerce_str_list(correction.get("existing_value")))
    return [_normalise_host(token) for token in _dedupe_preserve_order(tokens) if _normalise_host(token)]


def _remove_domains_from_legacy_registry(pack: dict[str, Any], domains: list[str]) -> int:
    if not domains:
        return 0
    remove_set = {_normalise_host(domain) for domain in domains if _normalise_host(domain)}
    removed = 0
    registry = pack.setdefault("brand_registry", {})
    for brand, values in list(registry.items()):
        kept = []
        for value in _coerce_str_list(values):
            normalized = _normalise_host(value)
            if normalized in remove_set:
                removed += 1
                continue
            kept.append(value)
        registry[brand] = kept
    trusted = pack.setdefault("trusted_base_names", {})
    remove_tokens = set(remove_set)
    remove_tokens.update(domain.split(".", 1)[0] for domain in remove_set if "." in domain)
    for token, brand in list(trusted.items()):
        if _normalise_host(token) in remove_tokens:
            trusted.pop(token, None)
    return removed


def _entity_domains_for_legacy_registry(entity: dict[str, Any]) -> list[str]:
    if bool(entity.get("shared_host")):
        return []
    if str(entity.get("match_policy") or "").strip().lower() in PATH_SCOPED_POLICIES:
        return []
    if entity.get("can_contribute_to_safe") is False:
        return []
    domains = []
    domains.extend(_coerce_str_list(entity.get("official_domains")))
    domains.extend(_coerce_str_list(entity.get("subdomains")))
    domains.extend(_coerce_str_list(entity.get("delegated_domains")))
    return [_normalise_host(domain) for domain in _dedupe_preserve_order(domains) if _normalise_host(domain)]


def _trusted_base_for_domain(domain: str) -> str:
    host = _normalise_host(domain)
    if not host:
        return ""
    return host.split(".", 1)[0]


def import_pack_payload(
    brand_pack: dict[str, Any],
    registry_payload: dict[str, Any],
    *,
    source_label: str,
    critical_corrections: list[dict[str, Any]] | None = None,
) -> tuple[dict[str, Any], dict[str, Any]]:
    pack = json.loads(json.dumps(brand_pack, ensure_ascii=False))
    entities = [entity for entity in registry_payload.get("entities", []) if isinstance(entity, dict)]
    corrections = list(registry_payload.get("critical_corrections") or [])
    corrections.extend(critical_corrections or [])

    metadata = pack.setdefault("metadata", {})
    pack_id = (
        (registry_payload.get("metadata") or {}).get("pack_id")
        or Path(source_label).stem
    )
    removed_domains: list[str] = []
    for correction in corrections:
        removed_domains.extend(_domain_tokens_from_correction(correction))
    removed_domains = _dedupe_preserve_order(removed_domains)
    correction_domain_set = {_normalise_host(domain) for domain in removed_domains if _normalise_host(domain)}

    sources = metadata.setdefault("official_domain_registry_sources", [])
    if source_label not in sources:
        sources.append(source_label)

    updates = pack.setdefault("official_registry_updates", [])
    existing_update_fingerprints: set[str] = set()
    for index, update in enumerate(updates):
        if isinstance(update, dict):
            existing_update_fingerprints.update(_record_fingerprints(update, index))

    updates_added = 0
    registry_domains_added = 0
    registry_entities_added = 0
    trusted_tokens_added = 0
    policy_only_entities = 0
    legacy_registry_eligible_entities = 0

    for index, entity in enumerate(entities):
        display_name = str(entity.get("display_name") or entity.get("brand_id") or "").strip()
        fingerprints = _record_fingerprints(entity, index)
        if not (fingerprints & existing_update_fingerprints):
            row = dict(entity)
            row.setdefault("source_pack", pack_id)
            row.setdefault("safe_effect", "positive_provenance_only_never_safe_alone")
            updates.append(row)
            existing_update_fingerprints.update(_record_fingerprints(row, len(updates) - 1))
            updates_added += 1

        legacy_domains = [
            domain
            for domain in _entity_domains_for_legacy_registry(entity)
            if _normalise_host(domain) not in correction_domain_set
        ]
        if legacy_domains:
            legacy_registry_eligible_entities += 1
        else:
            policy_only_entities += 1
        if display_name and legacy_domains:
            bucket = pack.setdefault("brand_registry", {}).setdefault(display_name, [])
            before = len(bucket)
            bucket[:] = _dedupe_preserve_order(bucket + legacy_domains)
            added = len(bucket) - before
            if added:
                registry_entities_added += 1
                registry_domains_added += added
                for domain in legacy_domains:
                    token = _trusted_base_for_domain(domain)
                    if len(token) >= 4 and token not in pack.setdefault("trusted_base_names", {}):
                        pack["trusted_base_names"][token] = display_name
                        trusted_tokens_added += 1

    removed_count = _remove_domains_from_legacy_registry(pack, removed_domains)

    summary = metadata.setdefault("official_domain_registry_import_summary", {})
    summary["entities_read"] = int(summary.get("entities_read") or 0) + len(entities)
    summary["critical_corrections_read"] = int(summary.get("critical_corrections_read") or 0) + len(corrections)
    summary["updates_added"] = int(summary.get("updates_added") or 0) + updates_added
    summary["safe_entities_with_domains_added"] = int(summary.get("safe_entities_with_domains_added") or 0) + registry_entities_added
    summary["domains_added_to_brand_registry"] = int(summary.get("domains_added_to_brand_registry") or 0) + registry_domains_added
    summary["trusted_base_tokens_added"] = int(summary.get("trusted_base_tokens_added") or 0) + trusted_tokens_added
    summary["domains_removed_by_corrections"] = _dedupe_preserve_order(
        _coerce_str_list(summary.get("domains_removed_by_corrections")) + removed_domains
    )
    summary.setdefault("packs", {})
    summary["packs"][pack_id] = {
        "source": source_label,
        "entities_read": len(entities),
        "updates_added": updates_added,
        "legacy_registry_domains_added": registry_domains_added,
        "legacy_registry_eligible_entities": legacy_registry_eligible_entities,
        "policy_only_entities": policy_only_entities,
        "domains_removed_by_corrections": removed_domains,
        "legacy_registry_domain_removals": removed_count,
    }
    metadata["official_domain_registry_imported_at"] = "2026-06-18"

    return pack, summary["packs"][pack_id]


def import_pack_file(brand_pack_path: Path, zip_path: Path, *, write: bool = False) -> dict[str, Any]:
    brand_pack = json.loads(brand_pack_path.read_text(encoding="utf-8"))
    registry_payload, selected_json, extra_corrections = _load_registry_payload(zip_path)
    source_label = zip_path.name
    imported_pack, result = import_pack_payload(
        brand_pack,
        registry_payload,
        source_label=source_label,
        critical_corrections=extra_corrections,
    )
    result = dict(result)
    result["selected_json"] = selected_json
    result["write"] = write
    if write:
        brand_pack_path.write_text(json.dumps(imported_pack, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return result


def main() -> None:
    parser = argparse.ArgumentParser(description="Import an official-domain registry research pack.")
    parser.add_argument("zip_path", type=Path)
    parser.add_argument("--brand-pack", type=Path, default=DEFAULT_BRAND_PACK_PATH)
    parser.add_argument("--write", action="store_true", help="Persist changes. Default is dry-run.")
    args = parser.parse_args()

    result = import_pack_file(args.brand_pack, args.zip_path, write=args.write)
    print(json.dumps(result, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
