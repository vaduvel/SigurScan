#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import re
import subprocess
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


ROUND3_SIGNALS = [
    ("osim_trademark_fee_unofficial_sender", ["OSIM_TRADEMARK_FEE_UNOFFICIAL_SENDER"], "covered"),
    ("legal_demand_payment_to_new_iban", ["LEGAL_DEMAND_PAYMENT_TO_NEW_IBAN"], "covered"),
    ("domain_renewal_invoice_no_existing_vendor", ["DOMAIN_RENEWAL_INVOICE_NO_EXISTING_VENDOR"], "covered"),
    ("grant_consulting_fee_before_contract", ["GRANT_CONSULTING_FEE_BEFORE_CONTRACT"], "covered"),
    ("saas_license_audit_urgent_payment", ["SAAS_LICENSE_AUDIT_URGENT_PAYMENT"], "covered"),
    ("po_or_overpayment_return_request", ["PO_OR_OVERPAYMENT_RETURN_REQUEST"], "covered"),
    ("new_vendor_public_procurement_fee", ["NEW_VENDOR_PUBLIC_PROCUREMENT_FEE"], "covered"),
    (
        "payroll_or_employee_data_request_via_invoice_thread",
        ["PAYROLL_OR_EMPLOYEE_DATA_REQUEST_VIA_INVOICE_THREAD"],
        "covered",
    ),
    ("official_registry_claim_but_no_provenance", ["OFFICIAL_REGISTRY_CLAIM_BUT_NO_PROVENANCE"], "covered"),
    (
        "invoice_attachment_has_payment_link_mismatch",
        ["PHISHING_LINK_IN_INVOICE_EMAIL", "PAYMENT_LINK_UNKNOWN_PSP"],
        "covered_by_generic_payment_link_logic",
    ),
    ("urgent_payment_override_no_ticket", ["URGENT_PAYMENT_OVERRIDE_NO_TICKET"], "covered"),
    (
        "efactura_or_official_document_mismatch",
        ["EFACTURA_CLAIM_WITHOUT_DOCUMENT"],
        "partial_no_xml_diff_engine_yet",
    ),
]


PAYMENT_PASS1_BRANDS = [
    ("ppc_energy", "positive_registry"),
    ("eon_energie_romania", "positive_registry"),
    ("hidroelectrica", "positive_registry"),
    ("engie_romania", "positive_registry"),
    ("electrica_furnizare", "positive_registry"),
    ("digi_romania", "positive_registry"),
    ("orange_romania", "positive_registry"),
    ("vodafone_romania", "positive_registry"),
    ("aquatim", "positive_registry"),
    ("apavital_iasi", "positive_registry"),
    ("compania_apa_brasov", "positive_registry"),
    ("ghiseul_ro", "advisory_never_asks"),
    ("fan_courier", "advisory_never_asks"),
    ("olx", "advisory_never_asks"),
    ("banca_transilvania", "advisory_never_asks"),
    ("bcr", "advisory_never_asks"),
    ("ing", "advisory_never_asks"),
]


RDAP_FILES = [
    "backend/services/whois_ssl_signals.py",
    "backend/services/redirect_resolver.py",
]


def _read(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


def _git_head() -> str:
    try:
        return subprocess.check_output(
            ["git", "rev-parse", "--short", "HEAD"],
            cwd=ROOT,
            text=True,
            stderr=subprocess.DEVNULL,
        ).strip()
    except Exception:
        return "unknown"


def _implemented_flags() -> set[str]:
    code = _read("backend/services/b2b_invoice_signals.py")
    return set(re.findall(r'"([A-Z0-9_]{6,})"', code))


def _payment_registry_ids() -> set[str]:
    ids: set[str] = set()
    registry_dir = ROOT / "backend/data/payment_destination_registry"
    for path in registry_dir.glob("*.json"):
        data = json.loads(path.read_text(encoding="utf-8"))
        entries = []
        if isinstance(data, dict):
            for key in ("entries", "payment_destinations", "vendors", "brands"):
                value = data.get(key)
                if isinstance(value, list):
                    entries.extend(value)
            batches = data.get("batches")
            if isinstance(batches, list):
                for batch in batches:
                    if isinstance(batch, dict) and isinstance(batch.get("entries"), list):
                        entries.extend(batch["entries"])
        for entry in entries:
            if isinstance(entry, dict):
                brand_id = (
                    entry.get("brand_id")
                    or entry.get("vendor_id")
                    or entry.get("id")
                    or entry.get("canonical_id")
                )
                if brand_id:
                    ids.add(str(brand_id))
    return ids


def _never_asks_ids() -> set[str]:
    data = json.loads(_read("backend/data/brand_never_asks_v1.json"))
    return {
        str(item.get("brand_id"))
        for item in data.get("brands", [])
        if isinstance(item, dict) and item.get("brand_id")
    }


def _rdap_brace_status() -> tuple[str, list[str]]:
    issues: list[str] = []
    for rel in RDAP_FILES:
        text = _read(rel)
        if "{https://" in text or "{http://" in text:
            issues.append(f"{rel}: literal URL braces")
        if "rdap.org/domain/{domain}" in text and 'f"https://rdap.org/domain/{domain}"' not in text:
            issues.append(f"{rel}: suspicious RDAP template")
        if "cloudflare-dns.com/dns-query?name={domain}&type=MX" in text and (
            'f"https://cloudflare-dns.com/dns-query?name={domain}&type=MX"' not in text
        ):
            issues.append(f"{rel}: suspicious Cloudflare MX template")
    return ("fixed" if not issues else "needs_fix", issues)


def _status_icon(status: str) -> str:
    if status in {"covered", "present", "fixed", "covered_by_generic_payment_link_logic"}:
        return "OK"
    if status.startswith("partial"):
        return "PARTIAL"
    if status in {"intentionally_not_payment_registry", "advisory_present"}:
        return "ADVISORY"
    return "MISSING"


def build_report() -> str:
    flags = _implemented_flags()
    registry_ids = _payment_registry_ids()
    never_asks_ids = _never_asks_ids()
    rdap_status, rdap_issues = _rdap_brace_status()

    round3_rows = []
    for signal, expected_flags, policy in ROUND3_SIGNALS:
        missing = [flag for flag in expected_flags if flag not in flags]
        if missing:
            status = "missing"
        else:
            status = policy
        round3_rows.append((signal, ", ".join(expected_flags), status))

    payment_rows = []
    for brand_id, expected_layer in PAYMENT_PASS1_BRANDS:
        if expected_layer == "positive_registry":
            status = "present" if brand_id in registry_ids else "missing"
            note = "positive payment destination registry"
        else:
            status = "advisory_present" if brand_id in never_asks_ids else "missing"
            note = "advisory/never-asks, not safe-contributing IBAN registry"
        payment_rows.append((brand_id, expected_layer, status, note))

    represented_round3 = sum(1 for _, _, status in round3_rows if status != "missing")
    partial_round3 = sum(1 for _, _, status in round3_rows if status.startswith("partial"))
    full_round3 = represented_round3 - partial_round3
    full_payment = sum(1 for _, _, status, _ in payment_rows if status != "missing")

    lines = [
        "# SigurScan Research Coverage Audit - 2026-06-15",
        "",
        f"Generated from repo state: `{_git_head()}`.",
        "",
        "Scope:",
        "- `sigurscan_imm_b2b_invoice_fraud_round3_2026_06_15.zip`",
        "- `payment_destination_registry_ro_deepresearch_pass1_2026_06_15.zip`",
        "- RDAP / Cloudflare MX brace-bug note from the handoff",
        "",
        "Policy:",
        "- Official complete IBANs go into the positive payment destination registry.",
        "- Brand safety statements without complete official IBANs go into advisory / never-asks knowledge.",
        "- Research signals must be evidence contributors, not separate verdict engines.",
        "",
        "## Summary",
        "",
        f"- B2B Round3 signals represented: `{represented_round3}/{len(round3_rows)}` (`{full_round3}` full, `{partial_round3}` partial).",
        f"- Payment pass1 entities represented: `{full_payment}/{len(payment_rows)}`.",
        f"- RDAP / Cloudflare MX brace bug: `{rdap_status}`.",
        "",
        "## B2B Round3 Signals",
        "",
        "| Signal | Implemented evidence flags | Status |",
        "| --- | --- | --- |",
    ]
    for signal, implemented, status in round3_rows:
        lines.append(f"| `{signal}` | `{implemented}` | {_status_icon(status)} `{status}` |")

    lines.extend(
        [
            "",
            "Notes:",
            "- `efactura_or_official_document_mismatch` is intentionally marked partial: the backend detects missing e-Factura proof, but does not yet compare official XML/PDF content against an email PDF field-by-field.",
            "- `invoice_attachment_has_payment_link_mismatch` is covered by the generic payment-link / anchor-mismatch evidence, not a dedicated one-off flag.",
            "",
            "## Payment Destination Pass1",
            "",
            "| Entity | Expected layer | Status | Note |",
            "| --- | --- | --- | --- |",
        ]
    )
    for brand_id, layer, status, note in payment_rows:
        lines.append(f"| `{brand_id}` | `{layer}` | {_status_icon(status)} `{status}` | {note} |")

    lines.extend(
        [
            "",
            "Rejected from positive payment registry:",
            "- `ghiseul_ro`, `fan_courier`, `olx`, `banca_transilvania`, `bcr`, `ing`: pass1 did not provide complete official payment IBANs for these entities. They are intentionally treated as advisory / never-asks knowledge, not as SAFE-contributing destination accounts.",
            "",
            "## RDAP / MX Brace Bug",
            "",
            f"Status: {_status_icon(rdap_status)} `{rdap_status}`.",
        ]
    )
    if rdap_issues:
        lines.append("")
        lines.append("Issues:")
        lines.extend(f"- {issue}" for issue in rdap_issues)
    else:
        lines.extend(
            [
                "",
                "Verified files:",
                "- `backend/services/whois_ssl_signals.py`: RDAP URL is `f\"https://rdap.org/domain/{domain}\"`.",
                "- `backend/services/redirect_resolver.py`: RDAP and Cloudflare MX URLs are formatted without literal braces.",
            ]
        )

    lines.extend(
        [
            "",
            "## Next Coverage Work",
            "",
            "1. Add an official XML/PDF e-Factura diff path before marking `efactura_or_official_document_mismatch` as fully covered.",
            "2. Expand pass1 `needs_confirmation` entities only when official complete IBANs or official never-asks statements are available.",
            "3. Keep this audit updated when new research packs are imported.",
            "",
        ]
    )
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description="Audit SigurScan research-pack coverage in repo code/data.")
    parser.add_argument("--write", type=Path, help="Write Markdown report to this path.")
    args = parser.parse_args()

    report = build_report()
    if args.write:
        output = args.write if args.write.is_absolute() else ROOT / args.write
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(report, encoding="utf-8")
    else:
        print(report)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
