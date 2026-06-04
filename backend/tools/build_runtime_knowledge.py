import json
import re
import unicodedata
import urllib.parse
from pathlib import Path

import tldextract


ROOT = Path(__file__).resolve().parents[2]
ANDROID_KNOWLEDGE_PATH = ROOT / "app" / "src" / "main" / "assets" / "knowledge" / "romania_knowledge_layer_compact.json"
SEED_OUTPUT_PATH = ROOT / "backend" / "data" / "scam_atlas_ro_2025_2026_seed.json"
BRAND_PACK_OUTPUT_PATH = ROOT / "backend" / "data" / "brand_knowledge_pack.json"


REQUESTED_ASSET_TERMS = {
    "card": ["card", "numar card", "număr card", "date card"],
    "cvv": ["cvv", "cvc", "cod cvv"],
    "otp": ["otp", "cod otp", "cod sms"],
    "whatsapp_code": ["whatsapp", "cod whatsapp"],
    "banking_pin": ["pin", "pin bancar"],
    "cnp": ["cnp"],
    "iban": ["iban"],
    "password": ["parola", "parolă", "password"],
    "remote_access": ["anydesk", "teamviewer", "control la distanta", "control la distanță"],
    "apk_install": ["apk", "instaleaza apk", "instalează apk"],
    "safe_account_transfer": ["cont sigur", "transfer sigur"],
}


def _load_android_knowledge() -> dict:
    with ANDROID_KNOWLEDGE_PATH.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def _load_existing_brand_pack() -> dict:
    if not BRAND_PACK_OUTPUT_PATH.exists():
        return {}
    with BRAND_PACK_OUTPUT_PATH.open("r", encoding="utf-8") as handle:
        data = json.load(handle)
        return data if isinstance(data, dict) else {}


def _coerce_str_list(values) -> list[str]:
    if not values:
        return []
    output: list[str] = []
    for item in values:
        raw = str(item or "").strip()
        if raw:
            output.append(raw)
    return output


def _dedupe_preserve_order(values: list[str]) -> list[str]:
    seen = set()
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


def _merge_map_of_lists(*items: dict[str, list[str]]) -> dict[str, list[str]]:
    merged: dict[str, list[str]] = {}
    for source in items:
        for key, values in source.items():
            bucket = merged.setdefault(key, [])
            bucket.extend(_coerce_str_list(values))
            merged[key] = _dedupe_preserve_order(bucket)
    return merged


def _merge_map_of_strings(*items: dict[str, str]) -> dict[str, str]:
    merged: dict[str, str] = {}
    for source in items:
        for key, value in source.items():
            raw = str(value or "").strip()
            if raw:
                merged[str(key)] = raw
    return merged


def _ascii_fold(value: str) -> str:
    folded = unicodedata.normalize("NFKD", value or "")
    return "".join(char for char in folded if not unicodedata.combining(char))


def _normalize_host(raw: str) -> str:
    text = str(raw or "").strip()
    if not text:
        return ""
    if "://" in text:
        text = urllib.parse.urlparse(text).hostname or ""
    text = text.lower().strip().strip(".")
    if text.startswith("www."):
        text = text[4:]
    return text


def _base_label_for_host(host: str) -> str:
    normalized = _normalize_host(host)
    if not normalized:
        return ""
    extracted = tldextract.extract(normalized)
    return (extracted.domain or normalized.split(".")[0]).strip().lower()


def _alias_candidates(
    brand_id: str,
    display_name: str,
    official_domains: list[str],
    partner_domains: list[str],
) -> list[str]:
    aliases = [
        display_name,
        _ascii_fold(display_name),
        brand_id.replace("_", " "),
        _ascii_fold(brand_id.replace("_", " ")),
    ]

    for separator in ("/", "|"):
        if separator in display_name:
            aliases.extend(part.strip() for part in display_name.split(separator) if part.strip())
            aliases.extend(_ascii_fold(part.strip()) for part in display_name.split(separator) if part.strip())

    for host in official_domains + partner_domains:
        base = _base_label_for_host(host)
        if base:
            aliases.append(base)

    cleaned_aliases = []
    for alias in aliases:
        raw = re.sub(r"\s+", " ", str(alias or "").strip())
        if raw:
            cleaned_aliases.append(raw)
    return _dedupe_preserve_order(cleaned_aliases)


def _trusted_labels_for_domains(domains: list[str], aliases: list[str]) -> list[str]:
    labels = []
    for host in domains:
        base = _base_label_for_host(host)
        if base:
            labels.append(base)
    for alias in aliases:
        normalized = re.sub(r"[^0-9a-z]+", "", _ascii_fold(alias).lower())
        if normalized and len(normalized) >= 3:
            labels.append(normalized)
        if " " not in alias:
            lowered = _ascii_fold(alias).lower().strip()
            if lowered and len(lowered) >= 3:
                labels.append(lowered)
    return _dedupe_preserve_order(labels)


def _hook_for(entry: dict) -> str:
    parts = []
    parts.extend(entry.get("names_used_in_romania") or [])
    parts.extend(entry.get("typical_text_patterns") or [])
    parts.append(entry.get("claimed_brand_or_role") or "")
    return " | ".join(part.strip() for part in parts if str(part).strip())


def _asks_for_for(entry: dict) -> list[str]:
    asks = []
    for asset in entry.get("requested_asset") or []:
        key = str(asset).strip().lower()
        mapped = REQUESTED_ASSET_TERMS.get(key)
        if mapped:
            asks.extend(mapped)
        elif key:
            asks.append(key.replace("_", " "))
    deduped = []
    seen = set()
    for ask in asks:
        normalized = ask.strip().lower()
        if normalized and normalized not in seen:
            seen.add(normalized)
            deduped.append(ask)
    return deduped


def _safe_actions_for(entry: dict) -> list[str]:
    brand = entry.get("claimed_brand_or_role") or "instituția invocată"
    requested = {str(asset).strip().lower() for asset in (entry.get("requested_asset") or [])}
    actions = [
        "Nu accesați linkul și nu răspundeți înainte de verificare.",
        f"Contactați {brand} doar pe canalul oficial, introdus manual.",
    ]
    if requested.intersection({"card", "cvv", "otp", "banking_pin", "password", "cnp", "iban"}):
        actions.insert(1, "Nu introduceți date bancare, parole, coduri OTP sau date personale.")
    if requested.intersection({"remote_access", "apk_install"}):
        actions.insert(1, "Nu instalați aplicații și nu permiteți control la distanță.")
    return actions


def build_seed_payload(knowledge: dict) -> dict:
    families = []
    for entry in knowledge.get("scenario_corpus", []):
        families.append(
            {
                "id": entry.get("scenario_id"),
                "family": f"{entry.get('family', 'unknown')} / {entry.get('claimed_brand_or_role', 'unknown')}",
                "hook": _hook_for(entry),
                "asks_for": _asks_for_for(entry),
                "safe_actions": _safe_actions_for(entry),
                "channels": entry.get("channels") or [],
                "claimed_brand_or_role": entry.get("claimed_brand_or_role"),
                "acceptance_test_idea": entry.get("acceptance_test_idea"),
            }
        )
    return {
        "metadata": {
            "generated_from": str(ANDROID_KNOWLEDGE_PATH.relative_to(ROOT)),
            "generator": "backend/tools/build_runtime_knowledge.py",
        },
        "scam_families": families,
    }


def build_brand_pack_payload(knowledge: dict, existing_pack: dict) -> dict:
    generated_registry: dict[str, list[str]] = {}
    generated_exceptions: dict[str, list[str]] = {}
    generated_aliases: dict[str, list[str]] = {}
    generated_trusted: dict[str, str] = {}

    for entry in knowledge.get("official_registry_updates", []):
        brand_id = str(entry.get("brand_id") or "").strip()
        display_name = str(entry.get("display_name") or brand_id or "").strip()
        if not display_name:
            continue

        official_domains = _dedupe_preserve_order(
            [_normalize_host(host) for host in entry.get("official_domains") or [] if _normalize_host(host)]
        )
        partner_domains = _dedupe_preserve_order(
            [_normalize_host(host) for host in entry.get("approved_tracking_or_partner_domains") or [] if _normalize_host(host)]
        )

        generated_registry[display_name] = official_domains
        if partner_domains:
            generated_exceptions[display_name] = partner_domains

        aliases = _alias_candidates(brand_id, display_name, official_domains, partner_domains)
        generated_aliases[display_name] = aliases

        for label in _trusted_labels_for_domains(official_domains + partner_domains, aliases):
            generated_trusted[label] = display_name

    metadata = {
        "pack": "sigurscan_runtime_knowledge_v2",
        "generated_from": str(ANDROID_KNOWLEDGE_PATH.relative_to(ROOT)),
        "generator": "backend/tools/build_runtime_knowledge.py",
        "preserves_existing_operational_entries": True,
    }

    return {
        "metadata": metadata,
        "brand_registry": _merge_map_of_lists(
            generated_registry,
            existing_pack.get("brand_registry", {}),
        ),
        "brand_domain_exceptions": _merge_map_of_lists(
            generated_exceptions,
            existing_pack.get("brand_domain_exceptions", {}),
        ),
        "trusted_base_names": _merge_map_of_strings(
            generated_trusted,
            existing_pack.get("trusted_base_names", {}),
        ),
        "brand_aliases": _merge_map_of_lists(
            generated_aliases,
            existing_pack.get("brand_aliases", {}),
        ),
        "brand_warnings": knowledge.get("brand_warnings", []),
        "claim_verifier_targets": knowledge.get("claim_verifier_targets", []),
        "official_registry_updates": knowledge.get("official_registry_updates", []),
    }


def _write_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        json.dump(payload, handle, ensure_ascii=False, indent=2)
        handle.write("\n")


def main() -> None:
    knowledge = _load_android_knowledge()
    existing_pack = _load_existing_brand_pack()

    seed_payload = build_seed_payload(knowledge)
    brand_pack_payload = build_brand_pack_payload(knowledge, existing_pack)

    _write_json(SEED_OUTPUT_PATH, seed_payload)
    _write_json(BRAND_PACK_OUTPUT_PATH, brand_pack_payload)

    print(f"Wrote {SEED_OUTPUT_PATH} with {len(seed_payload['scam_families'])} scam families")
    print(
        f"Wrote {BRAND_PACK_OUTPUT_PATH} with "
        f"{len(brand_pack_payload['brand_registry'])} brands, "
        f"{len(brand_pack_payload.get('brand_warnings', []))} warnings and "
        f"{len(brand_pack_payload.get('claim_verifier_targets', []))} claim targets"
    )


if __name__ == "__main__":
    main()
