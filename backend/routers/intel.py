"""Threat-intel, campaigns, reporting and provenance routes.

Covers /v1/verify/provenance, /v1/intel/*, /v1/campaign/*, /v1/urechea/*,
/v1/radar/hot-iocs, /v1/report, /v1/btr/sync, /v1/legal/action-plan. Depends only
on the shared app_stores singletons, services and api_models. Extracted from main.py.
"""

import re
import json
import time
import logging
from datetime import datetime, timedelta, timezone
from typing import Optional, List, Dict, Any

from fastapi import APIRouter, HTTPException, Request

from services import supabase_store
from services.cfx_engine import extract_fingerprint, CampaignFingerprint, FingerprintMatch
from app_stores import brand_truth_registry, campaign_store, urechea_ingester, cfx_store
from api_models import *  # noqa: F401,F403 (request schemas)

router = APIRouter()
logger = logging.getLogger("sigurscan.intel")


@router.post("/v1/verify/provenance")
async def verify_provenance(payload: ProvenanceRequest):
    result = brand_truth_registry.provenance_check(
        claimed_brand=payload.claimed_brand,
        observed_channel=payload.observed_channel,
        observed_domain=payload.observed_domain,
        observed_phone_e164=payload.observed_phone_e164,
        observed_shortcode=payload.observed_shortcode,
        sensitive_asks=payload.sensitive_asks,
        payment_method=payload.payment_method,
        final_url=payload.final_url,
    )
    return {
        "manifest_id": result.manifest_id,
        "provenance": result.provenance,
        "identity_status": result.identity_status,
        "official_match": result.official_match,
        "violated_never_asks": result.violated_never_asks,
        "violated_never_does": result.violated_never_does,
        "safe_requires_failed": result.safe_requires_failed,
        "evidence_power": result.evidence_power,
        "reason_codes": result.reason_codes,
        "max_effect": result.max_effect,
        "btr_version": brand_truth_registry.version,
    }










@router.post("/v1/intel/ingest")
async def ingest_intel(payload: IntelIngestRequest):
    regions = payload.regions_hint or ["national"]
    result = urechea_ingester.ingest_raw(
        title=payload.title,
        body=payload.body,
        source_url=payload.source_url,
        source_kind=payload.source_kind,
        claimed_identity=payload.claimed_identity,
        evidence_quality=payload.evidence_quality,
        regions_hint=regions,
    )
    return result.to_dict()


@router.post("/v1/intel/moderate")
async def moderate_intel(payload: IntelModerateRequest):
    if payload.action not in ("approve", "reject"):
        raise HTTPException(status_code=400, detail="actiunea trebuie sa fie 'approve' sau 'reject'")
    if payload.action == "approve":
        ok = urechea_ingester.approve_intel(payload.intel_id, payload.approved_by or "moderator")
    else:
        ok = urechea_ingester.reject_intel(payload.intel_id)
    if not ok:
        raise HTTPException(status_code=404, detail="Intel ID negasit")
    return {"status": "ok"}


@router.get("/v1/campaign/active")
async def active_campaigns(since: Optional[float] = None):
    now = time.time()
    since_ts = since if since is not None else (now - 7 * 86400)
    results = campaign_store.active(since=since_ts)
    return {
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now)),
        "btr_version": brand_truth_registry.version,
        "count": len(results),
        "campaigns": [r.to_dict() for r in results],
    }


@router.get("/v1/radar/hot-iocs")
async def radar_hot_iocs(since: Optional[float] = None):
    """PR-5 — Radarul: payload sincronizat de device pentru CallScreening offline.
    Campanii active + reputație numere pe buckets (zero număr brut server-side).
    """
    from services.radar_hot_cache import build_hot_cache
    from services.reputation_graph import ReputationGraph

    reports: List[Dict[str, Any]] = []
    number_reputation_items: List[Dict[str, Any]] = []
    if supabase_store.is_supabase_enabled():
        try:
            rows = supabase_store._get_json(
                "community_reports",
                {"select": "hash,target_type,report_count,family,risk_level", "limit": "500",
                 "order": "report_count.desc"},
            )
            reports = rows if isinstance(rows, list) else []
        except Exception:
            reports = []
        try:
            graph_rows = supabase_store.load_reputation_graph_rows(limit=1000)
            graph = ReputationGraph.from_rows(
                observations=graph_rows.get("observations", []),
                edges=graph_rows.get("edges", []),
                allowlist=graph_rows.get("allowlist", []),
            )
            graph_report_counts: Dict[Tuple[str, str], int] = {}
            for row in graph_rows.get("observations", []):
                key = (
                    str(row.get("target_type") or "unknown").strip().lower(),
                    str(row.get("target_hash") or row.get("hash") or "").strip().lower(),
                )
                try:
                    report_count = max(1, int(row.get("report_count") or 1))
                except (TypeError, ValueError):
                    report_count = 1
                graph_report_counts[key] = graph_report_counts.get(key, 0) + report_count

            community_backfill: List[Dict[str, Any]] = []
            for row in reports:
                key = (
                    str(row.get("target_type") or "unknown").strip().lower(),
                    str(row.get("hash") or row.get("target_hash") or "").strip().lower(),
                )
                try:
                    community_count = max(1, int(row.get("report_count") or 1))
                except (TypeError, ValueError):
                    community_count = 1
                missing_count = community_count - graph_report_counts.get(key, 0)
                if missing_count > 0:
                    adjusted = dict(row)
                    adjusted["report_count"] = missing_count
                    community_backfill.append(adjusted)
            graph.load_community_reports(community_backfill)
            number_reputation_items = graph.radar_number_reputation()
        except Exception:
            number_reputation_items = []
    return build_hot_cache(
        campaign_store,
        reports=[] if number_reputation_items else reports,
        number_reputation_items=number_reputation_items,
        since=since,
    )


@router.post("/v1/report")
async def one_tap_report(payload: OneTapReportRequest):
    """PR-5 — raport 1-tap precompletat (DNSC/1911, PNRISC, ANPC, bancă).
    Pregătește pachetul; userul trimite. Fără PII brut, doar ținta redactată.
    """
    from services.report_builder import build_report_package

    return build_report_package(
        target={"type": payload.target_type, "value_redacted": payload.target_redacted},
        family=payload.family or "UNKNOWN",
        verdict=payload.verdict or "SUSPECT",
        redacted_summary=payload.redacted_summary,
    )


# ─── PR-6 — Cercul (out-of-band verification) + Guardian second opinion ──────
# §6: protocol semnat, NU trece prin verdict_gate. Privacy: ping metadata-only,
# second-opinion default metadata_only, revocare doar de protejat.














# ─── PR-7 (Faza 2) — Inboxul Protejat: BTR sync pentru match on-device ──────
# Linia roșie §8: ZERO conținut SMS către server. Singurul trafic e manifestele
# BTR care COBOARĂ pe device (version-gated), pentru proveniență on-device.
# NU există endpoint care primește SMS — verdictul se calculează pe telefon
# (services/inbox_provenance.build_inbox_verdict e logica de referință portată în app).
@router.get("/v1/btr/sync")
async def btr_sync(client_version: Optional[str] = None):
    """PR-7 — device pull al Brand Truth Registry (delta version-gated)."""
    from services.inbox_provenance import btr_sync_payload

    return btr_sync_payload(brand_truth_registry, client_version=client_version)


@router.get("/v1/rules/sync")
async def rules_sync(client_version: Optional[str] = None):
    """P-RULES Felia 2 — device/backend pull al manifestului de reguli semantice
    (delta version-gated, BTR-style). Doar reguli, zero conținut de mesaj."""
    from services.rules_manifest import rules_sync_payload

    return rules_sync_payload(client_version=client_version)


# ─── PR-8 — Jurist Dinamic Lvl 2 (M6): plan de acțiune post-incident ─────────


@router.post("/v1/legal/action-plan")
async def legal_action_plan(payload: LegalActionPlanRequest):
    """PR-8 — TriageScreen: pași de remediere ordonați pe urgență + raport + carduri
    legale verbatim. NU schimbă verdictul; pașii sunt operaționali, articolele vin din KB."""
    from services.legal_action_plan import build_action_plan

    target = None
    if payload.target_type or payload.target_redacted:
        target = {"type": payload.target_type or "unknown",
                  "value_redacted": payload.target_redacted or "[redactat]"}
    return build_action_plan(
        verdict=payload.verdict,
        family=payload.family,
        impacts=payload.impacts,
        target=target,
        document_type=payload.document_type,
    )


@router.get("/v1/campaign/families")
async def campaign_families():
    from services.campaign_intel import FAMILY_TAXONOMY
    return {"families": FAMILY_TAXONOMY}






_INTEL_STATUS: IntelStatusData = IntelStatusData()


def _update_intel_status(**kwargs) -> None:
    for k, v in kwargs.items():
        if hasattr(_INTEL_STATUS, k):
            setattr(_INTEL_STATUS, k, v)


@router.get("/v1/urechea/status")
async def urechea_status():
    sources = urechea_ingester.sources
    return {
        "last_run_at": _INTEL_STATUS.last_run_at,
        "entries_ingested": _INTEL_STATUS.entries_ingested,
        "sources_configured": len(sources),
        "sources_with_rss": sum(1 for s in sources.values() if s.feed_url is not None),
        "sources_enabled": sum(1 for s in sources.values() if s.enabled),
        "moderation_queue_length": len(urechea_ingester.moderation_queue),
        "campaign_count": len(campaign_store.all()),
    }


@router.post("/v1/urechea/run")
async def urechea_run(payload: UrecheaRunRequest):
    sources = urechea_ingester.sources
    requested = [
        str(name or "").strip()
        for name in (payload.sources or [])
        if str(name or "").strip()
    ]
    if not requested:
        requested = [
            name for name, src in sources.items()
            if src.enabled and src.feed_url and src.fetch_strategy == "rss"
        ]
    max_entries = max(1, min(int(payload.max_entries_per_source or 5), 20))
    source_results = []
    total_ingested = 0
    for name in requested:
        src = sources.get(name)
        if src is None or not src.enabled:
            source_results.append({"source": name, "status": "skipped", "reason": "source_disabled_or_missing", "ingested": 0})
            continue
        entries = urechea_ingester.fetch_source(name)[:max_entries]
        ingested = 0
        for entry in entries:
            intel = urechea_ingester.ingest_raw(
                title=entry.get("title", ""),
                body=entry.get("body", ""),
                source_url=entry.get("link", ""),
                source_kind=src.kind,
                evidence_quality=src.confidence,
            )
            supabase_store.save_campaign_intel(intel.to_dict())
            ingested += 1
        total_ingested += ingested
        source_results.append({"source": name, "status": "ok", "entries": len(entries), "ingested": ingested})
    _update_intel_status(
        last_run_at=time.time(),
        entries_ingested=_INTEL_STATUS.entries_ingested + total_ingested,
        sources_configured=len(sources),
        sources_with_rss=sum(1 for src in sources.values() if src.feed_url is not None),
        sources_enabled=sum(1 for src in sources.values() if src.enabled),
    )
    return {
        "status": "ok",
        "sources_attempted": len(requested),
        "entries_ingested": total_ingested,
        "source_results": source_results,
        "last_run_at": _INTEL_STATUS.last_run_at,
    }


@router.post("/v1/campaign/match")
async def match_campaign(payload: CampaignMatchRequest):
    fp = extract_fingerprint(
        payload.text,
        channel=payload.channel,
        claimed_identity=payload.claimed_identity,
        urls=payload.urls,
    )
    matches = cfx_store.match(fp)
    matched_any = any(m.matched for m in matches)
    best = matches[0] if matches else None
    return {
        "fingerprint_id": fp.fingerprint_id,
        "fingerprint": fp.to_dict(),
        "matches": [
            {
                "fingerprint_id": m.fingerprint_id,
                "arc_family": m.arc_family,
                "similarity": round(m.similarity, 4),
                "matched": m.matched,
            }
            for m in matches[:10]
        ],
        "match_count": len(matches),
        "best_similarity": round(best.similarity, 4) if best else 0.0,
        "matched": matched_any,
    }


@router.get("/v1/intel/moderation-queue")
async def moderation_queue():
    return {
        "count": len(urechea_ingester.moderation_queue),
        "items": [i.to_dict() for i in urechea_ingester.moderation_queue],
    }


@router.get("/v1/intel/sources")
async def intel_sources():
    sources = []
    for name, src in urechea_ingester.sources.items():
        sources.append({"name": name, "kind": src.kind, "enabled": src.enabled, "fetch_strategy": src.fetch_strategy})
    return {"sources": sources}
