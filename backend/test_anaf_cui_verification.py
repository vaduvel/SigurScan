"""Offline, deterministic tests for the ANAF CUI verification tool (R4).

The real ANAF cross-check runs as a scheduled workflow (needs network). These
tests exercise the tool's LOGIC without any network so the checker itself is
regression-guarded in normal CI:

- the registry reader collects CUIs from both `entries` and `brands` shapes
  (batch15 OSIM uses `brands` — reading only `entries` would silently skip it),
- classify_row maps an ANAF record to the right status,
- `--fail-on-discrepancy` makes the tool exit non-zero on a bad CUI (the CI gate).
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

import tools.verify_registry_cui_anaf as anaf


# --- registry reader --------------------------------------------------------

def test_iter_entries_reads_both_entries_and_brands():
    from_entries = list(anaf.iter_entries({"entries": [{"cui": "1"}, {"cui": "2"}]}))
    from_brands = list(anaf.iter_entries({"brands": [{"cui": "3"}]}))
    assert [e["cui"] for e in from_entries] == ["1", "2"]
    assert [e["cui"] for e in from_brands] == ["3"]  # brands-key files not skipped


def test_collect_registry_cuis_picks_up_brands_key(tmp_path: Path):
    (tmp_path / "a_entries.json").write_text(
        json.dumps({"entries": [{"brand_id": "x", "cui": "123", "legal_name": "X SRL"}]}),
        encoding="utf-8",
    )
    (tmp_path / "b_brands.json").write_text(
        json.dumps({"brands": [{"brand_id": "osim", "cui": "4266081", "legal_name": "OSIM"}]}),
        encoding="utf-8",
    )
    rows = anaf.collect_registry_cuis(tmp_path)
    cuis = {r["cui"] for r in rows}
    assert cuis == {"123", "4266081"}


def test_norm_cui_strips_prefix_and_nondigits():
    assert anaf.norm_cui("RO 013831166") == "13831166"
    assert anaf.norm_cui("2864518") == "2864518"
    assert anaf.norm_cui(None) is None
    assert anaf.norm_cui("abc") is None


# --- name matching ----------------------------------------------------------

def test_names_match_positive_and_negative():
    assert anaf.names_match("ANCA SILVER GOLD SRL", "ANCA SILVER GOLD S.R.L.")
    assert anaf.names_match("Altex Romania", "ALTEX ROMANIA SRL")
    assert not anaf.names_match("ANCA SILVER GOLD SRL", "POLTERGEIST SRL")


# --- classify_row (pure comparison) ----------------------------------------

def _anaf_rec(*, cui="123", denumire="X SRL", inactive=False):
    rec = {"date_generale": {"cui": int(cui), "denumire": denumire}}
    if inactive:
        rec["date_generale"]["statusInactivi"] = True
    return rec


def test_classify_row_ok():
    row = {"cui": "123", "legal_name": "X SRL", "display_name": "X"}
    out = anaf.classify_row(row, _anaf_rec(denumire="X SRL"))
    assert out["status"] == anaf.STATUS_OK


def test_classify_row_cui_not_found():
    row = {"cui": "999", "legal_name": "X SRL", "display_name": "X"}
    out = anaf.classify_row(row, None)
    assert out["status"] == anaf.STATUS_CUI_NOT_FOUND


def test_classify_row_inactive():
    row = {"cui": "123", "legal_name": "X SRL", "display_name": "X"}
    out = anaf.classify_row(row, _anaf_rec(inactive=True))
    assert out["status"] == anaf.STATUS_INACTIVE


def test_classify_row_name_mismatch():
    row = {"cui": "123", "legal_name": "X SRL", "display_name": "X"}
    out = anaf.classify_row(row, _anaf_rec(denumire="COMPLET ALTCEVA SA"))
    assert out["status"] == anaf.STATUS_NAME_MISMATCH


# --- end-to-end main() with mocked ANAF (the CI gate) -----------------------

def _write_registry(directory: Path, cui: str, legal_name: str = "GOOD CO SRL"):
    (directory / "reg.json").write_text(
        json.dumps({"entries": [{"brand_id": "good", "display_name": "Good",
                                 "legal_name": legal_name, "cui": cui}]}),
        encoding="utf-8",
    )


def test_main_passes_on_matching_cui(tmp_path, monkeypatch):
    reg = tmp_path / "reg"; reg.mkdir()
    _write_registry(reg, "123", "GOOD CO SRL")
    monkeypatch.setattr(anaf, "query_anaf",
                        lambda cuis, as_of: {"123": _anaf_rec(cui="123", denumire="GOOD CO SRL")})
    rc = anaf.main([
        "--dir", str(reg),
        "--out-json", str(tmp_path / "out.json"),
        "--out-csv", str(tmp_path / "out.csv"),
        "--fail-on-discrepancy",
    ])
    assert rc == 0


def test_main_fails_on_broken_cui_fixture(tmp_path, monkeypatch):
    """DoD: a deliberately wrong CUI must make the CI gate exit non-zero."""
    reg = tmp_path / "reg"; reg.mkdir()
    _write_registry(reg, "13831166", "ALTEX ROMANIA SRL")  # the historical wrong Altex CUI
    # ANAF does not return that CUI (as if invalid/typo).
    monkeypatch.setattr(anaf, "query_anaf", lambda cuis, as_of: {})
    rc = anaf.main([
        "--dir", str(reg),
        "--out-json", str(tmp_path / "out.json"),
        "--out-csv", str(tmp_path / "out.csv"),
        "--fail-on-discrepancy",
    ])
    assert rc == 1
    report = json.loads((tmp_path / "out.json").read_text(encoding="utf-8"))
    assert report["summary"]["discrepancies"] == 1
    assert report["results"][0]["status"] == anaf.STATUS_CUI_NOT_FOUND


def test_main_offline_extract_only_never_calls_anaf(tmp_path, monkeypatch):
    reg = tmp_path / "reg"; reg.mkdir()
    _write_registry(reg, "123")

    def _boom(*a, **k):
        raise AssertionError("query_anaf must not be called in offline-extract mode")

    monkeypatch.setattr(anaf, "query_anaf", _boom)
    rc = anaf.main([
        "--dir", str(reg),
        "--offline-extract-only",
        "--out-json", str(tmp_path / "extract.json"),
    ])
    assert rc == 0
    extract = json.loads((tmp_path / "extract.json").read_text(encoding="utf-8"))
    assert extract["unique_cuis"] == ["123"]


def test_real_registry_parses_and_yields_cuis():
    """Guards against a new registry file using an unrecognised shape."""
    reg = Path(__file__).resolve().parent / "data" / "payment_destination_registry"
    rows = anaf.collect_registry_cuis(reg)
    assert len(rows) > 300  # sanity: the bulk of the registry carries CUIs
    # the OSIM entry (brands-key file) must be present
    assert any(r["cui"] == "4266081" for r in rows)
