import importlib.util
import json
import sys
import zipfile
from pathlib import Path


BACKEND_DIR = Path(__file__).resolve().parent


def _load_importer():
    path = BACKEND_DIR / "tools" / "import_official_domain_registry_pack.py"
    spec = importlib.util.spec_from_file_location("official_registry_import_tool_test", path)
    module = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    sys.modules["official_registry_import_tool_test"] = module
    spec.loader.exec_module(module)
    return module


def test_official_registry_importer_preserves_policy_scopes_and_removes_corrections():
    importer = _load_importer()
    brand_pack = {
        "metadata": {},
        "brand_registry": {
            "Wrong IKEA": ["ike.com"],
        },
        "trusted_base_names": {
            "ike": "Wrong IKEA",
        },
        "official_registry_updates": [],
    }
    payload = {
        "metadata": {"pack_id": "test-pack"},
        "critical_corrections": [
            {
                "existing_value": "ike.com",
                "action": "remove_and_replace",
                "replacement": "ikea.com",
            }
        ],
        "entities": [
            {
                "brand_id": "prefectura_alba",
                "display_name": "Instituția Prefectului – Județul Alba",
                "exact_hosts": ["ab.prefectura.mai.gov.ro"],
                "match_policy": "exact_host",
                "can_contribute_to_safe": True,
            },
            {
                "brand_id": "itm_alba",
                "display_name": "Inspectoratul Teritorial de Muncă Alba",
                "official_domains": ["itmalba.ro"],
                "match_policy": "registrable_domain_suffix",
                "can_contribute_to_safe": True,
            },
            {
                "brand_id": "dsp_alba",
                "display_name": "Direcția de Sănătate Publică Alba",
                "official_domains": ["ms.ro"],
                "exact_hosts": ["www.ms.ro"],
                "path_prefixes": ["/ro/directiile-de-sanatate-publica/dsp-alba/"],
                "match_policy": "shared_host_plus_path_prefix",
                "shared_host": True,
                "can_contribute_to_safe": True,
            },
        ],
    }

    imported, summary = importer.import_pack_payload(
        brand_pack,
        payload,
        source_label="test-pack.zip",
    )

    updates = {entry["brand_id"]: entry for entry in imported["official_registry_updates"]}
    assert set(updates) == {"prefectura_alba", "itm_alba", "dsp_alba"}
    assert imported["brand_registry"]["Inspectoratul Teritorial de Muncă Alba"] == ["itmalba.ro"]
    assert "Instituția Prefectului – Județul Alba" not in imported["brand_registry"]
    assert "Direcția de Sănătate Publică Alba" not in imported["brand_registry"]
    assert imported["brand_registry"]["Wrong IKEA"] == []
    assert "ike" not in imported["trusted_base_names"]
    assert summary["updates_added"] == 3
    assert summary["legacy_registry_domains_added"] == 1
    assert summary["policy_only_entities"] == 2


def test_official_registry_importer_is_idempotent_for_same_pack():
    importer = _load_importer()
    brand_pack = {"metadata": {}, "brand_registry": {}, "trusted_base_names": {}, "official_registry_updates": []}
    payload = {
        "metadata": {"pack_id": "test-pack"},
        "entities": [
            {
                "brand_id": "itm_alba",
                "display_name": "Inspectoratul Teritorial de Muncă Alba",
                "official_domains": ["itmalba.ro"],
                "match_policy": "registrable_domain_suffix",
                "can_contribute_to_safe": True,
            }
        ],
    }

    imported_once, _ = importer.import_pack_payload(brand_pack, payload, source_label="test-pack.zip")
    imported_twice, summary = importer.import_pack_payload(imported_once, payload, source_label="test-pack.zip")

    assert len(imported_twice["official_registry_updates"]) == 1
    assert imported_twice["brand_registry"]["Inspectoratul Teritorial de Muncă Alba"] == ["itmalba.ro"]
    assert summary["updates_added"] == 0
    assert summary["legacy_registry_domains_added"] == 0


def test_official_registry_importer_does_not_promote_corrected_domains():
    importer = _load_importer()
    brand_pack = {"metadata": {}, "brand_registry": {}, "trusted_base_names": {}, "official_registry_updates": []}
    payload = {
        "metadata": {"pack_id": "test-pack"},
        "critical_corrections": [
            {
                "existing_value": "aep.ro",
                "action": "do_not_whitelist",
            }
        ],
        "entities": [
            {
                "brand_id": "aep_example",
                "display_name": "Autoritate Exemplu",
                "official_domains": ["aep.ro"],
                "match_policy": "registrable_domain_suffix",
                "can_contribute_to_safe": True,
            }
        ],
    }

    imported, summary = importer.import_pack_payload(brand_pack, payload, source_label="test-pack.zip")

    assert imported["official_registry_updates"][0]["brand_id"] == "aep_example"
    assert "Autoritate Exemplu" not in imported["brand_registry"]
    assert "aep" not in imported["trusted_base_names"]
    assert summary["updates_added"] == 1
    assert summary["legacy_registry_domains_added"] == 0
    assert summary["legacy_registry_domain_removals"] == 0


def test_official_registry_importer_dedupes_alias_display_names_by_technical_scope():
    importer = _load_importer()
    brand_pack = {
        "metadata": {},
        "brand_registry": {},
        "trusted_base_names": {},
        "official_registry_updates": [
            {
                "brand_id": "prefectura_alba",
                "display_name": "Instituția Prefectului – Județul Alba",
                "exact_hosts": ["ab.prefectura.mai.gov.ro"],
                "match_policy": "exact_host",
                "can_contribute_to_safe": True,
            }
        ],
    }
    payload = {
        "metadata": {"pack_id": "test-pack"},
        "entities": [
            {
                "display_name": "Prefectura Alba",
                "official_domains": ["ab.prefectura.mai.gov.ro"],
                "exact_hosts": ["www.ab.prefectura.mai.gov.ro"],
                "match_policy": "exact_host",
                "shared_host": True,
                "can_contribute_to_safe": True,
            }
        ],
    }

    imported, summary = importer.import_pack_payload(brand_pack, payload, source_label="test-pack.zip")

    assert len(imported["official_registry_updates"]) == 1
    assert summary["updates_added"] == 0


def test_official_registry_importer_selects_full_registry_json_from_zip(tmp_path):
    importer = _load_importer()
    pack_path = tmp_path / "brand_pack.json"
    pack_path.write_text(
        json.dumps({"metadata": {}, "brand_registry": {}, "trusted_base_names": {}, "official_registry_updates": []}),
        encoding="utf-8",
    )
    zip_path = tmp_path / "registry.zip"
    with zipfile.ZipFile(zip_path, "w") as archive:
        archive.writestr(
            "high_confidence.json",
            json.dumps({"entities": [{"brand_id": "one", "display_name": "One", "official_domains": ["one.ro"]}]}),
        )
        archive.writestr(
            "full.json",
            json.dumps(
                {
                    "metadata": {"pack_id": "full-pack"},
                    "entities": [
                        {"brand_id": "one", "display_name": "One", "official_domains": ["one.ro"]},
                        {"brand_id": "two", "display_name": "Two", "official_domains": ["two.ro"]},
                    ],
                }
            ),
        )

    result = importer.import_pack_file(pack_path, zip_path, write=False)

    assert result["selected_json"] == "full.json"
    assert result["entities_read"] == 2
    assert result["write"] is False


def test_official_registry_importer_accepts_list_shaped_extra_corrections_from_zip(tmp_path):
    importer = _load_importer()
    pack_path = tmp_path / "brand_pack.json"
    pack_path.write_text(
        json.dumps({"metadata": {}, "brand_registry": {}, "trusted_base_names": {}, "official_registry_updates": []}),
        encoding="utf-8",
    )
    zip_path = tmp_path / "registry.zip"
    with zipfile.ZipFile(zip_path, "w") as archive:
        archive.writestr(
            "full.json",
            json.dumps(
                {
                    "metadata": {"pack_id": "full-pack"},
                    "entities": [
                        {"brand_id": "bad", "display_name": "Bad", "official_domains": ["bad.ro"]},
                    ],
                }
            ),
        )
        archive.writestr(
            "critical_corrections.json",
            json.dumps([{"existing_value": "bad.ro", "action": "do_not_whitelist"}]),
        )

    result = importer.import_pack_file(pack_path, zip_path, write=False)

    assert result["entities_read"] == 1
    assert result["legacy_registry_domains_added"] == 0
    assert result["domains_removed_by_corrections"] == ["bad.ro"]


def test_official_registry_importer_accepts_standalone_high_confidence_json(tmp_path):
    importer = _load_importer()
    pack_path = tmp_path / "brand_pack.json"
    pack_path.write_text(
        json.dumps({"metadata": {}, "brand_registry": {}, "trusted_base_names": {}, "official_registry_updates": []}),
        encoding="utf-8",
    )
    registry_path = tmp_path / "registry.json"
    registry_path.write_text(
        json.dumps(
            {
                "version": "2026-06-18",
                "research_scope": "official_domain_registry_ro",
                "high_confidence": [
                    {
                        "display_name": "Example Official",
                        "official_domains": ["example.gov.ro"],
                        "match_policy": "registrable_domain_suffix",
                        "can_contribute_to_safe": True,
                    }
                ],
                "review_queue": [
                    {
                        "display_name": "Defunct Example",
                        "candidate_domains": ["defunct.ro"],
                        "can_contribute_to_safe": False,
                    }
                ],
            }
        ),
        encoding="utf-8",
    )

    result = importer.import_pack_file(pack_path, registry_path, write=False)

    assert result["selected_json"] == str(registry_path)
    assert result["entities_read"] == 1
    assert result["legacy_registry_domains_added"] == 1
