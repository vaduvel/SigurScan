"""Build the runtime impersonation atlas from the approved research packs.

The research contains semantic evidence, source references, test fixtures and
verdict oracles. Only semantic evidence and sources enter runtime. Verdict
oracles remain in the generated test-only fixture pack.
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import re
import zipfile
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
DEFAULT_ZIP_PATH = ROOT / "docs" / "fable_handoff" / "sigurscan_op_impersonare_atlas_2026.zip"
DEFAULT_REPORT_PATH = ROOT / "docs" / "fable_handoff" / "raport-cercetare-aprofundată (2).md"
DEFAULT_SEED_PATH = ROOT / "backend" / "data" / "scam_atlas_impersonation_seed.json"
DEFAULT_FIXTURES_PATH = ROOT / "backend" / "testdata" / "impersonation_research_fixtures_2026.json"

FORBIDDEN_RUNTIME_FIELDS = {
    "expected_final_verdict",
    "max_solo",
    "severity_baseline",
    "suggested_expected_verdict",
    "verdict",
    "verdict_effect",
}

# Sources which are valuable for a family but are not referenced consistently
# by the two research schemas. The routing is evidence metadata, not a verdict.
SOURCE_FAMILY_ROUTES = {
    "IMP-01": {"src-anaf", "src-ghiseul"},
    "IMP-02": {"bnr_warning", "src-bnr-registre", "src-bcr-phishing", "src-raiffeisen-sec-online"},
    "IMP-03": {"fan_smishing", "src-posta-phishing-sms"},
    "IMP-04": {"apple_social_engineering"},
    "IMP-05": {"src-meta-scams", "whatsapp_security"},
    "IMP-07": {"ing_investment_fraud"},
    "IMP-09": {"altex_campaign", "altex_support", "emag_phishing"},
    "IMP-10": {"europol_charity_scams"},
    "IMP-11": {"igpr_romance_scam"},
}

# Verification sources describe independent ways to validate an identity.
# They enrich evidence but never override the final verdict.
VERIFICATION_SOURCE_FAMILY_ROUTES = {
    "IMP-01": {"ANAF", "DNSC", "Ghiseul.ro", "Politia Romana", "Poliția/MAI/IGPR"},
    "IMP-02": {
        "ANCOM", "ASF", "BT", "Banca Transilvania", "BCR", "BNR", "ING", "Raiffeisen", "Revolut",
    },
    "IMP-03": {"DHL", "FAN Courier", "Posta Romana", "Poșta Română", "Sameday"},
    "IMP-04": {"Apple", "Microsoft"},
    "IMP-05": {"WhatsApp"},
    "IMP-07": {"ASF", "BNR"},
    "IMP-08": {"OLX"},
    "IMP-09": {"eMAG/Altex retail"},
    "IMP-13": {
        "Digi", "E.ON", "Electrica Furnizare", "Hidroelectrica", "Orange", "PPC Energie", "Vodafone",
    },
}

# Cross-family research signals are attached only to relevant families. This
# makes them active runtime match material without creating a second scorer.
GLOBAL_SIGNAL_FAMILY_ROUTES = {
    "state_brand_on_wrong_channel_asks_payment": {"IMP-01"},
    "safe_account_request": {"IMP-02"},
    "otp_requested_by_human": {"IMP-02", "IMP-03", "IMP-05"},
    "remote_access_requested": {"IMP-02", "IMP-04", "IMP-07"},
    "gift_card_or_crypto_payment": {"IMP-01", "IMP-02", "IMP-04", "IMP-10", "IMP-11", "IMP-12"},
    "courier_tiny_fee_card_request": {"IMP-03"},
    "lookalike_or_non_official_domain": {
        "IMP-01", "IMP-02", "IMP-03", "IMP-04", "IMP-07", "IMP-08", "IMP-09", "IMP-13",
    },
    "bec_supplier_iban_change": {"IMP-06"},
    "marketplace_payment_link": {"IMP-08"},
    "deepfake_investment_with_lead_form": {"IMP-07"},
    "utility_disconnect_link": {"IMP-13"},
    "marketing_only_or_hidden_link_only": {"IMP-09", "IMP-13"},
}

MERGED_FAMILY_LIST_FIELDS = {
    "attack_goal",
    "common_channels",
    "false_positive_guards",
    "high_risk_conditions",
    "official_verification_paths",
    "source_refs",
    "typical_user_action_requested",
}

# These are generalized patterns distilled from dangerous fixtures which were
# still below the semantic match threshold. They are not verdict rules.
DANGEROUS_RUNTIME_PATTERN_ENRICHMENTS = {
    "IMP-04": [
        "Windows Defender alert dispozitiv compromis sunați numărul afișat",
    ],
    "IMP-07": [
        "guvernator BNR video dubla investiția formular consultant",
    ],
    "IMP-12": [
        "avocat internațional materiale intime carduri cadou",
        "filmări cameră BTC wallet amenințare contacte",
    ],
}

RUNTIME_SCAN_RULE_ENRICHMENTS = [
    {
        "rule_id": "SR-UTILITY-DISCONNECT",
        "applies_to": ["IMP-13"],
        "description": "Presiune pe factură utilități/telco: deconectare, plată rapidă sau actualizare date prin canal nesigur.",
        "regex": "(deconect|suspend|factur[ăa]|abonament|contract).{0,80}(pl[ăa]te[șs]te|achit[ăa]|actualizeaz[ăa]|confirm[ăa]|link|card)",
        "flags": "i",
        "weight": "contextual",
    }
]


def _dedupe(values: list[Any], *, key=None) -> list[Any]:
    output: list[Any] = []
    seen = set()
    for value in values:
        marker = key(value) if key else json.dumps(value, ensure_ascii=False, sort_keys=True)
        if marker in seen:
            continue
        seen.add(marker)
        output.append(value)
    return output


def _strip_runtime_oracles(value: Any) -> Any:
    if isinstance(value, dict):
        return {
            field: _strip_runtime_oracles(item)
            for field, item in value.items()
            if field not in FORBIDDEN_RUNTIME_FIELDS
        }
    if isinstance(value, list):
        return [_strip_runtime_oracles(item) for item in value]
    return value


def _extract_report_json(report_path: Path) -> dict:
    content = report_path.read_text(encoding="utf-8")
    match = re.search(r"```json\s*(\{.*?\})\s*```", content, re.DOTALL)
    if not match:
        raise ValueError(f"No JSON research block found in {report_path}")
    payload = json.loads(match.group(1))
    if not isinstance(payload, dict):
        raise ValueError(f"Research JSON block in {report_path} is not an object")
    return payload


def _load_zip_json(zip_path: Path) -> dict:
    with zipfile.ZipFile(zip_path) as archive:
        candidates = [
            name
            for name in archive.namelist()
            if name.endswith("sigurscan_op_impersonare_atlas_2026.json")
        ]
        if len(candidates) != 1:
            raise ValueError(f"Expected one full impersonation atlas JSON in {zip_path}")
        return json.loads(archive.read(candidates[0]))


def _source_id(source: dict) -> str:
    return str(source.get("source_id") or source.get("id") or "").strip()


def _verification_source_name(source: dict) -> str:
    return str(source.get("entity") or source.get("name") or source.get("brand") or "").strip()


def _guard_id(guard: Any) -> str:
    if isinstance(guard, dict):
        return str(guard.get("guard_slug") or guard.get("id") or guard.get("text") or "").strip()
    return str(guard or "").strip()


def _family_id(family: dict) -> str:
    return str(family.get("id") or family.get("code") or "").strip()


def _as_list(value: Any) -> list[Any]:
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def _merge_research_families(packs: list[dict]) -> list[dict]:
    merged: dict[str, dict] = {}
    for pack in packs:
        for incoming in pack.get("families", []):
            family_id = _family_id(incoming)
            if not family_id:
                continue
            if family_id not in merged:
                merged[family_id] = copy.deepcopy(incoming)
                merged[family_id]["name_aliases"] = _as_list(incoming.get("name"))
                merged[family_id]["research_descriptions"] = _as_list(incoming.get("description"))
                merged[family_id]["impersonated_identities"] = _as_list(
                    incoming.get("impersonated_identity")
                )
                continue

            family = merged[family_id]
            family["name_aliases"] = _dedupe(
                [*family.get("name_aliases", []), *_as_list(incoming.get("name"))]
            )
            family["research_descriptions"] = _dedupe(
                [*family.get("research_descriptions", []), *_as_list(incoming.get("description"))]
            )
            family["impersonated_identities"] = _dedupe(
                [
                    *family.get("impersonated_identities", []),
                    *_as_list(incoming.get("impersonated_identity")),
                ]
            )
            for field in MERGED_FAMILY_LIST_FIELDS:
                family[field] = _dedupe(
                    [*_as_list(family.get(field)), *_as_list(incoming.get(field))]
                )
    return list(merged.values())


def load_research_inputs(zip_path: Path = DEFAULT_ZIP_PATH, report_path: Path = DEFAULT_REPORT_PATH) -> dict:
    packs = [_load_zip_json(zip_path), _extract_report_json(report_path)]

    families = _merge_research_families(packs)
    signals = _dedupe(
        [signal for pack in packs for signal in pack.get("signals", []) if signal.get("signal_slug")],
        key=lambda signal: str(signal["signal_slug"]),
    )
    fixtures = _dedupe(
        [fixture for pack in packs for fixture in pack.get("fixtures", []) if fixture.get("id")],
        key=lambda fixture: str(fixture["id"]),
    )
    sources = _dedupe(
        [source for pack in packs for source in pack.get("source_index", []) if _source_id(source)],
        key=_source_id,
    )
    verification_sources = _dedupe(
        [
            source
            for pack in packs
            for source in pack.get("verification_sources", [])
            if _verification_source_name(source)
        ],
        key=lambda source: _verification_source_name(source).lower(),
    )
    false_positive_guards = _dedupe(
        [guard for pack in packs for guard in pack.get("false_positive_guards", []) if _guard_id(guard)],
        key=_guard_id,
    )

    return {
        "families": families,
        "signals": signals,
        "fixtures": fixtures,
        "source_index": sources,
        "verification_sources": verification_sources,
        "false_positive_guards": false_positive_guards,
    }


def _source_ref(source: dict) -> dict:
    url = str(source.get("url") or "").strip() or None
    source_id = _source_id(source)
    if not source_id and url:
        source_id = f"source-url-{hashlib.sha256(url.encode('utf-8')).hexdigest()[:16]}"
    return {
        "source_id": source_id,
        "url": url,
        "publisher": source.get("publisher"),
        "source_type": source.get("source_type"),
        "confidence": source.get("confidence"),
    }


def _resolve_source_refs(values: list[Any], source_map: dict[str, dict]) -> list[dict]:
    source_by_url = {
        str(source.get("url") or "").strip(): source
        for source in source_map.values()
        if str(source.get("url") or "").strip()
    }
    refs: list[dict] = []
    for value in values or []:
        if isinstance(value, str):
            source = source_map.get(value)
            if source:
                refs.append(_source_ref(source))
            elif value.startswith(("https://", "http://")):
                refs.append(_source_ref(source_by_url.get(value, {"url": value})))
            elif value.strip():
                refs.append(_source_ref({"source_id": value.strip()}))
        elif isinstance(value, dict):
            source_id = _source_id(value)
            url = str(value.get("url") or "").strip()
            source = source_map.get(source_id) or source_by_url.get(url)
            normalized = _source_ref(source or value)
            if normalized["source_id"]:
                refs.append(normalized)
    return _dedupe(refs, key=lambda source: _source_id(source) or str(source.get("url") or ""))


def _merge_strings(existing: list[Any], incoming: list[Any]) -> list[str]:
    values = [str(value).strip() for value in [*(existing or []), *(incoming or [])] if str(value).strip()]
    return _dedupe(values, key=lambda value: value.lower())


def _normalize_verification_source(source: dict, source_map: dict[str, dict]) -> dict:
    normalized = _strip_runtime_oracles(copy.deepcopy(source))
    normalized["name"] = _verification_source_name(source)
    normalized["official_domains"] = _merge_strings([], normalized.get("official_domains", []))
    normalized["official_apps_or_deeplink_domains"] = _merge_strings(
        [],
        normalized.get("official_apps_or_deeplink_domains", [])
        or normalized.get("official_apps_or_deeplinks", []),
    )
    normalized.pop("entity", None)
    normalized.pop("brand", None)
    normalized.pop("official_apps_or_deeplinks", None)

    never_ask_for = normalized.get("never_ask_for")
    if isinstance(never_ask_for, str):
        normalized["never_ask_for"] = [{"item": never_ask_for, "source_refs": []}]
    elif isinstance(never_ask_for, list):
        normalized_items = []
        for item in never_ask_for:
            if isinstance(item, dict):
                normalized_item = copy.deepcopy(item)
                normalized_item["source_refs"] = _resolve_source_refs(
                    normalized_item.get("source_refs", []),
                    source_map,
                )
                normalized_items.append(normalized_item)
            elif str(item).strip():
                normalized_items.append({"item": str(item).strip(), "source_refs": []})
        normalized["never_ask_for"] = normalized_items
    else:
        normalized["never_ask_for"] = []
    return normalized


def _new_runtime_family(research_family: dict) -> dict:
    family_id = _family_id(research_family)
    name = str(research_family.get("name") or family_id)
    description = str(research_family.get("description") or name)
    return {
        "id": family_id,
        "title": name,
        "family": name,
        "hook": description,
        "asks_for": list(research_family.get("typical_user_action_requested") or []),
        "safe_actions": list(research_family.get("official_verification_paths") or []),
        "channels": list(research_family.get("common_channels") or []),
        "claimed_brand_or_role": research_family.get("impersonated_identity"),
        "requested_asset": list(research_family.get("attack_goal") or []),
        "signals": [],
        "sources": [],
        "examples": [],
        "structured_signals": [],
        "verification_sources": [],
        "source_refs": [],
        "scan_rule_ids": [],
    }


def _rule_id(rule: dict) -> str:
    return str(rule.get("rule_id") or rule.get("id") or "").strip()


def _ensure_runtime_scan_rule_enrichments(runtime_seed: dict) -> None:
    scan_rules = runtime_seed.setdefault("scan_rules", [])
    existing_rule_ids = {_rule_id(rule) for rule in scan_rules if isinstance(rule, dict)}
    for rule in RUNTIME_SCAN_RULE_ENRICHMENTS:
        if rule["rule_id"] not in existing_rule_ids:
            scan_rules.append(copy.deepcopy(rule))
            existing_rule_ids.add(rule["rule_id"])


def _refresh_family_scan_rule_ids(runtime_seed: dict, families: dict[str, dict]) -> None:
    rule_ids_by_family: dict[str, set[str]] = {
        family_id: set(family.get("scan_rule_ids") or [])
        for family_id, family in families.items()
    }
    for rule in runtime_seed.get("scan_rules", []):
        if not isinstance(rule, dict):
            continue
        rule_id = _rule_id(rule)
        if not rule_id:
            continue
        for family_id in _as_list(rule.get("applies_to")):
            family_key = str(family_id or "").strip()
            if family_key in rule_ids_by_family:
                rule_ids_by_family[family_key].add(rule_id)

    for family_id, family in families.items():
        family["scan_rule_ids"] = sorted(rule_ids_by_family.get(family_id, set()))


def build_impersonation_knowledge(seed: dict, research: dict) -> dict:
    runtime_seed = copy.deepcopy(seed)
    _ensure_runtime_scan_rule_enrichments(runtime_seed)
    source_map = {_source_id(source): source for source in research["source_index"]}
    verification_sources = {
        _verification_source_name(source): _normalize_verification_source(source, source_map)
        for source in research["verification_sources"]
        if _verification_source_name(source)
    }
    safe_fixture_texts = {
        str(fixture.get("input_text") or "").strip()
        for fixture in research["fixtures"]
        if fixture.get("expected_final_verdict") == "SAFE"
    }
    families = {
        _family_id(family): family
        for family in runtime_seed.get("scam_families", [])
        if _family_id(family)
    }

    for research_family in research["families"]:
        family_id = _family_id(research_family)
        family = families.setdefault(family_id, _new_runtime_family(research_family))
        family["channels"] = _merge_strings(
            family.get("channels", []),
            research_family.get("common_channels", []),
        )
        family["asks_for"] = _merge_strings(
            family.get("asks_for", []),
            research_family.get("typical_user_action_requested", []),
        )
        family["requested_asset"] = _merge_strings(
            family.get("requested_asset", []),
            research_family.get("attack_goal", []),
        )
        family["safe_actions"] = _merge_strings(
            family.get("safe_actions", []),
            research_family.get("official_verification_paths", []),
        )
        family["signals"] = _merge_strings(
            family.get("signals", []),
            [
                *research_family.get("name_aliases", []),
                *research_family.get("research_descriptions", []),
                *research_family.get("high_risk_conditions", []),
                *research_family.get("impersonated_identities", []),
            ],
        )
        family["research_descriptions"] = _merge_strings(
            family.get("research_descriptions", []),
            research_family.get("research_descriptions", []),
        )
        family["impersonated_identities"] = _merge_strings(
            family.get("impersonated_identities", []),
            research_family.get("impersonated_identities", []),
        )
        family["false_positive_guards"] = _dedupe(
            [
                *(family.get("false_positive_guards") or []),
                *(research_family.get("false_positive_guards") or []),
            ]
        )
        family["verification_sources"] = _dedupe(
            [
                *[
                    _normalize_verification_source(source, source_map)
                    for source in family.get("verification_sources", [])
                    if _verification_source_name(source)
                ],
                *[
                    verification_sources[name]
                    for name in sorted(VERIFICATION_SOURCE_FAMILY_ROUTES.get(family_id, set()))
                    if name in verification_sources
                ],
            ],
            key=lambda source: _verification_source_name(source).lower(),
        )
        family["source_refs"] = _dedupe(
            [
                *_resolve_source_refs(family.get("source_refs", []), source_map),
                *_resolve_source_refs(research_family.get("source_refs", []), source_map),
                *_resolve_source_refs(sorted(SOURCE_FAMILY_ROUTES.get(family_id, set())), source_map),
            ],
            key=lambda source: _source_id(source) or str(source.get("url") or ""),
        )

    for signal in research["signals"]:
        signal_slug = str(signal.get("signal_slug") or "").strip()
        explicit_family = str(signal.get("family") or "").strip()
        target_families = (
            {explicit_family}
            if explicit_family
            else GLOBAL_SIGNAL_FAMILY_ROUTES.get(signal_slug, set())
        )
        for family_id in target_families:
            family = families.get(family_id)
            if not family:
                continue
            normalized_signal = _strip_runtime_oracles(copy.deepcopy(signal))
            normalized_signal["family"] = family_id
            if not explicit_family:
                normalized_signal["origin_scope"] = "cross_family"
                normalized_signal["applies_to_families"] = sorted(target_families)
            normalized_signal["source_refs"] = _resolve_source_refs(signal.get("source_refs", []), source_map)
            existing_signals = {
                str(item.get("signal_slug") or ""): item
                for item in family.get("structured_signals", [])
                if isinstance(item, dict)
            }
            existing_signals[signal_slug] = normalized_signal
            family["structured_signals"] = list(existing_signals.values())
            family["signals"] = _merge_strings(
                family.get("signals", []),
                [signal_slug, normalized_signal.get("text")],
            )
            family["source_refs"] = _dedupe(
                [*(family.get("source_refs") or []), *normalized_signal["source_refs"]],
                key=lambda source: _source_id(source) or str(source.get("url") or ""),
            )

    for family_id, patterns in DANGEROUS_RUNTIME_PATTERN_ENRICHMENTS.items():
        if family_id in families:
            families[family_id]["signals"] = _merge_strings(families[family_id].get("signals", []), patterns)

    for family in families.values():
        family["signals"] = [
            value for value in family.get("signals", []) if value not in safe_fixture_texts
        ]
        family["examples"] = [
            value for value in family.get("examples", []) if value not in safe_fixture_texts
        ]

    _refresh_family_scan_rule_ids(runtime_seed, families)
    runtime_seed["scam_families"] = sorted(families.values(), key=lambda family: _family_id(family))
    runtime_seed["source_index"] = [_source_ref(source) for source in research["source_index"]]
    runtime_seed["false_positive_guards"] = research["false_positive_guards"]
    runtime_seed.setdefault("metadata", {}).update(
        {
            "generator": "backend/tools/build_impersonation_knowledge.py",
            "research_fixture_count": len(research["fixtures"]),
            "research_false_positive_guard_count": len(research["false_positive_guards"]),
            "research_signal_count": len(research["signals"]),
            "research_source_count": len(research["source_index"]),
            "research_verification_source_count": len(research["verification_sources"]),
            "cross_family_signal_count": sum(
                1 for signal in research["signals"] if not signal.get("family")
            ),
        }
    )
    runtime_seed = _strip_runtime_oracles(runtime_seed)

    fixtures = {
        "runtime_role": "test_oracle_only",
        "purpose": "Research fixtures for recall, false-positive guards and gate evaluation.",
        "sources": [
            str(DEFAULT_ZIP_PATH.relative_to(ROOT)),
            str(DEFAULT_REPORT_PATH.relative_to(ROOT)),
        ],
        "fixtures": research["fixtures"],
    }
    return {"runtime_seed": runtime_seed, "fixtures": fixtures}


def _write_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--zip", type=Path, default=DEFAULT_ZIP_PATH)
    parser.add_argument("--report", type=Path, default=DEFAULT_REPORT_PATH)
    parser.add_argument("--seed", type=Path, default=DEFAULT_SEED_PATH)
    parser.add_argument("--seed-output", type=Path, default=DEFAULT_SEED_PATH)
    parser.add_argument("--fixtures-output", type=Path, default=DEFAULT_FIXTURES_PATH)
    args = parser.parse_args()

    seed = json.loads(args.seed.read_text(encoding="utf-8"))
    result = build_impersonation_knowledge(seed, load_research_inputs(args.zip, args.report))
    _write_json(args.seed_output, result["runtime_seed"])
    _write_json(args.fixtures_output, result["fixtures"])
    print(
        f"Wrote {args.seed_output} with {len(result['runtime_seed']['scam_families'])} families "
        f"and {len(result['fixtures']['fixtures'])} test fixtures"
    )


if __name__ == "__main__":
    main()
