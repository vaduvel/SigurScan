import json
from pathlib import Path

from services.verdict_gate import verdict

ROOT = Path(__file__).resolve().parent
TESTSET_PATH = ROOT / "data" / "hard_adversarial_50_v1.jsonl"
FIRE_CASES = {"PB-01", "PB-02", "SEXT-01", "FP-SMS-01", "URL-01", "INV-04", "CROSS-02"}


def _load_cases():
    with TESTSET_PATH.open("r", encoding="utf-8") as handle:
        return [json.loads(line) for line in handle if line.strip()]


def _semantic_review_from_case(case: dict) -> dict:
    family = str(case.get("family") or "").lower()
    input_text = str(case.get("input") or "").lower()
    high_markers = (
        "bancar/",
        "taxe/",
        "amenzi/",
        "vishing/bnr",
        "vishing/banca",
        "romance",
        "investitii/",
        "remote/",
        "malware/",
        "takeover/",
        "job/task",
        "loterie",
        "sextortion",
        "suport-tehnic",
        "abonament/",
        "utilitati/",
        "ceo-fraud",
        "pig-butchering",
        "b2b/",
        "magazin-fals",
        "urgenta/",
        "sim-swap",
    )
    medium_markers = (
        "ceo-fraud/furnizor",
        "caritate-falsa",
        "job/like",
    )
    legit = family.startswith("guard/") or any(
        token in family for token in ("legit",)
    )
    risk_class = "benign" if legit else "unknown"
    if any(marker in family for marker in high_markers):
        risk_class = "high"
    elif any(marker in family for marker in medium_markers):
        risk_class = "medium"
    if family == "ceo-fraud/furnizor":
        risk_class = "medium"

    return {
        "status": "done",
        "claim_matches_known_scam_family": risk_class in {"high", "medium"},
        "matched_family": case.get("family") if risk_class in {"high", "medium"} else None,
        "claim_matches_legit_template": legit,
        "matched_template": case.get("family") if legit else None,
        "reason_codes": [f"semantic:{risk_class}", f"family:{family or 'unknown'}"],
        "risk_class": risk_class,
        "completeness": True,
        "notes": input_text[:0],
    }


def _bundle_v2_from_case(case: dict) -> dict:
    compact = case["bundle"]
    sensitive = compact["sensitive"]
    if sensitive == "card" and "transfer" in str(case.get("input") or "").lower():
        sensitive = "transfer"
    bundle = {
        "schema": "sigurscan_evidence_bundle_v2",
        "input": {
            "type": case.get("channel") or "unknown",
            "redacted_text": case.get("input") or "",
        },
        "resolution": {
            "final_url": "https://example.invalid/",
            "status": compact["resolution"],
            "completeness": compact["resolution"] == "resolved",
        },
        "providers": {
            "verdict": compact["providers"],
            "hits": [],
            "completeness": compact["providers"] not in {"pending"},
        },
        "identity": {
            "claimed_brand": case.get("brand") or None,
            "status": compact["identity"],
            "tld_suspicious": bool(compact["tld_susp"]),
            "completeness": True,
        },
        "request": {
            "sensitive": sensitive,
            "channel": compact["req_channel"],
            "completeness": True,
        },
        "context": {
            "urgency": False,
            "passive_payment": False,
            "apk_or_remote_mention": False,
        },
        "semantic_review": _semantic_review_from_case(case),
    }
    return bundle


def test_hard_adversarial_all_cases_pass():
    failures = []
    for case in _load_cases():
        result = verdict(_bundle_v2_from_case(case))
        if result["label"] != case["label"]:
            failures.append(
                {
                    "id": case["id"],
                    "expected": case["label"],
                    "actual": result["label"],
                    "reason_codes": result.get("reason_codes", []),
                    "motiv": case.get("motiv"),
                }
            )

    if failures:
        print(f"\n=== {len(failures)} FAILURES ===")
        for f in failures:
            print(f"  {f['id']}: expected={f['expected']} actual={f['actual']} reasons={f['reason_codes']}")
            print(f"    motiv: {f['motiv']}")

    assert not failures


def test_hard_adversarial_fire_cases_are_exact():
    cases = {case["id"]: case for case in _load_cases()}
    missing = FIRE_CASES - set(cases)
    assert not missing, f"Fire cases missing: {missing}"

    for case_id in FIRE_CASES:
        result = verdict(_bundle_v2_from_case(cases[case_id]))
        assert result["label"] == cases[case_id]["label"], (
            f"{case_id}: expected={cases[case_id]['label']} actual={result['label']} "
            f"reasons={result.get('reason_codes', [])}"
        )


def test_hard_adversarial_scan_types_covered():
    cases = _load_cases()
    channels = set()
    families = set()
    labels = set()
    for case in cases:
        channels.add(case.get("channel", "unknown"))
        families.add(case.get("family", "unknown"))
        labels.add(case.get("label", "unknown"))
    print(f"\nChannels covered: {sorted(channels)}")
    print(f"Labels covered: {sorted(labels)}")
    print(f"Total cases: {len(cases)}")
    assert "sms" in channels, "Missing sms channel"
    assert "email" in channels, "Missing email channel"
    assert "whatsapp" in channels, "Missing whatsapp channel"
    assert "url" in channels, "Missing url channel"
    assert "qr" in channels, "Missing qr channel"
    assert "text" in channels, "Missing text channel"
    assert "SAFE" in labels, "Missing SAFE label"
    assert "DANGEROUS" in labels, "Missing DANGEROUS label"
    assert "SUSPECT" in labels, "Missing SUSPECT label"
    assert "UNVERIFIED" in labels, "Missing UNVERIFIED label"
