import json
from pathlib import Path


ROOT = Path(__file__).resolve().parent
PACK_PATH = ROOT / "data" / "brand_knowledge_pack.json"


def _brand_pack() -> dict:
    return json.loads(PACK_PATH.read_text(encoding="utf-8"))


def test_official_domain_registry_high_confidence_packs_are_merged():
    pack = _brand_pack()
    registry = pack.get("brand_registry", {})
    updates = pack.get("official_registry_updates", [])

    assert "Exim Banca Românească" in registry
    assert "eximbank.ro" in registry["Exim Banca Românească"]
    assert "Inspectoratul Școlar Alba" in registry
    assert "isjalba.ro" in registry["Inspectoratul Școlar Alba"]
    assert "Autoritatea Electorală Permanentă" in registry
    assert "roaep.ro" in registry["Autoritatea Electorală Permanentă"]
    assert "Inspectoratul Teritorial de Muncă Alba" in registry
    assert "itmalba.ro" in registry["Inspectoratul Teritorial de Muncă Alba"]

    prefecture = next(entry for entry in updates if entry.get("brand_id") == "prefectura_alba")
    assert prefecture["match_policy"] == "exact_host"
    assert "ab.prefectura.mai.gov.ro" in prefecture["exact_hosts"]

    dsp = next(entry for entry in updates if entry.get("brand_id") == "dsp_alba")
    assert dsp["match_policy"] == "shared_host_plus_path_prefix"
    assert dsp["shared_host"] is True
    assert "/ro/directiile-de-sanatate-publica/dsp-alba/" in dsp["path_prefixes"]
    assert "Direcția de Sănătate Publică Alba" not in registry


def test_official_registry_exports_specific_lookalike_tokens():
    from services import scam_atlas

    tokens = scam_atlas.OFFICIAL_REGISTRY_LOOKALIKE_TOKENS

    assert tokens["prefecturaalba"] == "Instituția Prefectului – Județul Alba"
    assert tokens["dspalba"] == "Direcția de Sănătate Publică Alba"
    assert tokens["itmalba"] == "Inspectoratul Teritorial de Muncă Alba"
    assert "prefectura" not in tokens


def test_official_domain_registry_critical_corrections_are_enforced():
    pack = _brand_pack()
    all_domains = {
        str(domain).lower()
        for domains in pack.get("brand_registry", {}).values()
        for domain in domains
    }

    assert "aep.ro" not in all_domains
    assert "ike.com" not in all_domains
    assert "rovinieta.ro" not in all_domains
