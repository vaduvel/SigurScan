"""Feedback, evaluation, telemetry and HTML dashboard routes."""

import json
import importlib
import time
from collections import Counter
from typing import Optional, List, Dict, Any

from config import RISK_THRESHOLD
from core.scan_context import _feedback_sample_payload, _resolve_eval_dataset_path
from services.url_reputation import get_reputation_cache_stats
from services.telemetry import (
    _build_feedback_quality_payload,
    _build_orchestration_telemetry_payload,
    _build_readiness_payload,
    _build_shadow_adjudication_payload,
    build_feedback_evaluation_rows,
    find_scan_record_by_id,
    load_feedback_records,
    load_scan_records,
    log_feedback_event,
    summarize_feedback_records,
    summarize_feedback_trend,
)

from fastapi import APIRouter, HTTPException
from fastapi.responses import HTMLResponse
from api_models import FeedbackRequest


router = APIRouter()


@router.post("/v1/feedback")
async def submit_feedback(payload: FeedbackRequest):
    normalized = (payload.feedback or "").strip().lower()
    if normalized not in {"correct", "false_positive", "false_negative", "uncertain"}:
        raise HTTPException(
            status_code=400,
            detail="feedback trebuie sa fie: correct, false_positive, false_negative sau uncertain.",
        )

    scan_record = find_scan_record_by_id(payload.scan_id)
    predicted_is_scam = payload.predicted_is_scam
    predicted_risk_score = payload.predicted_risk_score
    risk_level = payload.risk_level
    signal_ids = payload.signal_ids
    actual_is_scam = payload.actual_is_scam

    if scan_record:
        if predicted_is_scam is None:
            scan_predicted = scan_record.get("predicted_is_scam")
            if isinstance(scan_predicted, bool):
                predicted_is_scam = scan_predicted
        if predicted_risk_score is None:
            predicted_risk_score = scan_record.get("risk_score")
        if risk_level is None:
            risk_level = scan_record.get("risk_level")
        if not signal_ids:
            signal_ids = scan_record.get("signal_ids")

    if actual_is_scam is None:
        if normalized == "false_positive":
            actual_is_scam = False
        elif normalized == "false_negative":
            actual_is_scam = True
        elif normalized == "correct" and isinstance(predicted_is_scam, bool):
            actual_is_scam = predicted_is_scam

    log_feedback_event(
        {
            "scan_id": payload.scan_id,
            "feedback": normalized,
            "actual_is_scam": actual_is_scam,
            "predicted_is_scam": predicted_is_scam,
            "predicted_risk_score": predicted_risk_score,
            "risk_level": risk_level,
            "signal_ids": signal_ids or [],
            "source_channel": scan_record.get("source_channel") if scan_record else None,
            "notes": payload.notes,
        }
    )
    return {
        "status": "ok",
        "scan_id": payload.scan_id,
        "feedback": normalized,
    }


@router.get("/v1/feedback/summary")
def feedback_summary(
    source_channel: Optional[str] = None,
    since_ts: Optional[int] = None,
    until_ts: Optional[int] = None,
    include_examples: bool = False,
    max_examples_per_type: int = 20,
):
    rows = load_feedback_records()
    summary = summarize_feedback_records(
        rows,
        source_channel=source_channel,
        since_ts=since_ts,
        until_ts=until_ts,
        include_examples=include_examples,
        max_examples_per_type=max_examples_per_type,
    )
    return {"summary": summary}


@router.get("/v1/reputation/cache/stats")
def reputation_cache_stats() -> Dict[str, Any]:
    return {"cache": get_reputation_cache_stats()}


@router.get("/v1/orchestration/telemetry")
def orchestration_telemetry(
    limit: int = 1000,
    urlscan_timeout_rate_alert: float = 0.15,
) -> Dict[str, Any]:
    if limit <= 0:
        raise HTTPException(status_code=400, detail="limit trebuie sa fie strict pozitiv.")
    if limit > 10000:
        raise HTTPException(status_code=400, detail="limit maxim este 10000.")
    if urlscan_timeout_rate_alert < 0 or urlscan_timeout_rate_alert > 1:
        raise HTTPException(status_code=400, detail="urlscan_timeout_rate_alert trebuie sa fie intre 0 si 1.")
    builder = _build_orchestration_telemetry_payload
    return {"orchestration": builder(
        limit=limit,
        urlscan_timeout_rate_alert=urlscan_timeout_rate_alert,
    )}


def _html_escape(value: Any) -> str:
    return (
        str(value if value is not None else "")
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
        .replace("'", "&#x27;")
    )


@router.get("/v1/orchestration/dashboard", response_class=HTMLResponse)
def orchestration_dashboard(
    limit: int = 1000,
    urlscan_timeout_rate_alert: float = 0.15,
) -> HTMLResponse:
    if limit <= 0:
        raise HTTPException(status_code=400, detail="limit trebuie sa fie strict pozitiv.")
    if limit > 10000:
        raise HTTPException(status_code=400, detail="limit maxim este 10000.")
    payload = _build_orchestration_telemetry_payload(
        limit=limit,
        urlscan_timeout_rate_alert=urlscan_timeout_rate_alert,
    )
    alerts = payload.get("alerts") if isinstance(payload.get("alerts"), list) else []
    stage_latency = payload.get("stage_latency_ms") if isinstance(payload.get("stage_latency_ms"), dict) else {}
    by_event = payload.get("by_event_type") if isinstance(payload.get("by_event_type"), dict) else {}

    def card(title: str, value: Any, hint: str = "") -> str:
        return (
            "<section class='card'>"
            f"<span>{_html_escape(title)}</span>"
            f"<strong>{_html_escape(value)}</strong>"
            f"<small>{_html_escape(hint)}</small>"
            "</section>"
        )

    alert_html = "".join(
        f"<li class='{_html_escape(alert.get('severity', 'watch'))}'>"
        f"<strong>{_html_escape(alert.get('code'))}</strong> - {_html_escape(alert.get('message'))}"
        "</li>"
        for alert in alerts
    ) or "<li class='ok'>Nu există alerte pe fereastra curentă.</li>"

    latency_rows = "".join(
        "<tr>"
        f"<td>{_html_escape(stage)}</td>"
        f"<td>{_html_escape(values.get('avg'))}</td>"
        f"<td>{_html_escape(values.get('max'))}</td>"
        f"<td>{_html_escape(values.get('samples'))}</td>"
        "</tr>"
        for stage, values in stage_latency.items()
    ) or "<tr><td colspan='4'>Nu există încă date de latență pe stage.</td></tr>"

    event_rows = "".join(
        f"<tr><td>{_html_escape(event)}</td><td>{_html_escape(count)}</td></tr>"
        for event, count in sorted(by_event.items())
    ) or "<tr><td colspan='2'>Nu există evenimente orchestrated.</td></tr>"

    urlscan = payload.get("urlscan", {}) if isinstance(payload.get("urlscan"), dict) else {}
    conflicts = payload.get("conflicts", {}) if isinstance(payload.get("conflicts"), dict) else {}
    polls = payload.get("polls_to_final", {}) if isinstance(payload.get("polls_to_final"), dict) else {}
    time_to_final = payload.get("time_to_final_ms", {}) if isinstance(payload.get("time_to_final_ms"), dict) else {}

    html = f"""
<!doctype html>
<html lang="ro">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>SigurScan Orchestration Dashboard</title>
  <style>
    :root {{
      color-scheme: light;
      --bg: #f6f8fc;
      --card: #ffffff;
      --ink: #172033;
      --muted: #62708a;
      --line: #dde5f1;
      --blue: #316bff;
      --red: #c7332f;
      --amber: #ad6500;
      --green: #087f5b;
    }}
    body {{
      margin: 0;
      padding: 32px;
      background: var(--bg);
      color: var(--ink);
      font: 15px/1.5 -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
    }}
    header {{ margin-bottom: 24px; }}
    h1 {{ margin: 0 0 6px; font-size: 28px; }}
    p {{ margin: 0; color: var(--muted); }}
    .grid {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
      gap: 14px;
      margin: 24px 0;
    }}
    .card {{
      background: var(--card);
      border: 1px solid var(--line);
      border-radius: 18px;
      padding: 18px;
      box-shadow: 0 12px 30px rgba(24, 39, 75, .06);
    }}
    .card span, small {{ color: var(--muted); display: block; }}
    .card strong {{ display: block; font-size: 30px; margin: 8px 0; }}
    section.panel {{
      background: var(--card);
      border: 1px solid var(--line);
      border-radius: 18px;
      padding: 20px;
      margin: 16px 0;
    }}
    table {{ width: 100%; border-collapse: collapse; }}
    th, td {{ border-bottom: 1px solid var(--line); padding: 10px; text-align: left; }}
    th {{ color: var(--muted); font-weight: 700; }}
    li {{ margin: 8px 0; }}
    .high {{ color: var(--red); }}
    .watch {{ color: var(--amber); }}
    .ok {{ color: var(--green); }}
    code {{ background: #eef3ff; color: var(--blue); padding: 2px 6px; border-radius: 8px; }}
  </style>
</head>
<body>
  <header>
    <h1>SigurScan Orchestration Dashboard</h1>
    <p>Dashboard minimal peste <code>scan_events</code>. Nu expune secrete și nu rulează providerii.</p>
  </header>
  <div class="grid">
    {card("Scanări urmărite", payload.get("scan_count"), f"limit={limit} evenimente")}
    {card("Evenimente", payload.get("events_considered"), "orchestrated_*")}
    {card("Poll-uri până la verdict", polls.get("avg"), f"max={polls.get('max')}")}
    {card("Timp până la verdict", time_to_final.get("avg"), f"max={time_to_final.get('max')} ms")}
    {card("urlscan timeout rate", urlscan.get("pending_timeout_rate"), f"events={urlscan.get('pending_timeout_events')}")}
    {card("Conflict merge", conflicts.get("merge_events"), f"retry failures={conflicts.get('retry_failures')}")}
  </div>
  <section class="panel">
    <h2>Alerte</h2>
    <ul>{alert_html}</ul>
  </section>
  <section class="panel">
    <h2>Latențe pe stage</h2>
    <table><thead><tr><th>Stage</th><th>Avg ms</th><th>Max ms</th><th>Samples</th></tr></thead><tbody>{latency_rows}</tbody></table>
  </section>
  <section class="panel">
    <h2>Evenimente</h2>
    <table><thead><tr><th>Event</th><th>Count</th></tr></thead><tbody>{event_rows}</tbody></table>
  </section>
</body>
</html>
"""
    return HTMLResponse(content=html)


@router.get("/v1/adjudication/shadow")
def shadow_adjudication_telemetry(
    limit: int = 1000,
    fallback_rate_alert: float = 0.05,
    disagreement_rate_alert: float = 0.25,
    latency_p95_alert_ms: int = 2500,
) -> Dict[str, Any]:
    if limit <= 0:
        raise HTTPException(status_code=400, detail="limit trebuie sa fie strict pozitiv.")
    if limit > 10000:
        raise HTTPException(status_code=400, detail="limit maxim este 10000.")
    if fallback_rate_alert < 0 or fallback_rate_alert > 1:
        raise HTTPException(status_code=400, detail="fallback_rate_alert trebuie sa fie intre 0 si 1.")
    if disagreement_rate_alert < 0 or disagreement_rate_alert > 1:
        raise HTTPException(status_code=400, detail="disagreement_rate_alert trebuie sa fie intre 0 si 1.")
    if latency_p95_alert_ms <= 0:
        raise HTTPException(status_code=400, detail="latency_p95_alert_ms trebuie sa fie strict pozitiv.")
    builder = _build_shadow_adjudication_payload
    return {
        "shadow_adjudication": builder(
            limit=limit,
            fallback_rate_alert=fallback_rate_alert,
            disagreement_rate_alert=disagreement_rate_alert,
            latency_p95_alert_ms=latency_p95_alert_ms,
        )
    }


@router.get("/v1/adjudication/dashboard", response_class=HTMLResponse)
def shadow_adjudication_dashboard(
    limit: int = 1000,
    fallback_rate_alert: float = 0.05,
    disagreement_rate_alert: float = 0.25,
    latency_p95_alert_ms: int = 2500,
) -> HTMLResponse:
    if limit <= 0:
        raise HTTPException(status_code=400, detail="limit trebuie sa fie strict pozitiv.")
    if limit > 10000:
        raise HTTPException(status_code=400, detail="limit maxim este 10000.")
    payload = _build_shadow_adjudication_payload(
        limit=limit,
        fallback_rate_alert=fallback_rate_alert,
        disagreement_rate_alert=disagreement_rate_alert,
        latency_p95_alert_ms=latency_p95_alert_ms,
    )
    agreement = payload.get("agreement", {}) if isinstance(payload.get("agreement"), dict) else {}
    latency = payload.get("latency_ms", {}) if isinstance(payload.get("latency_ms"), dict) else {}
    cache = payload.get("cache", {}) if isinstance(payload.get("cache"), dict) else {}
    feedback = payload.get("feedback_comparison", {}) if isinstance(payload.get("feedback_comparison"), dict) else {}
    promotion = payload.get("promotion_gate", {}) if isinstance(payload.get("promotion_gate"), dict) else {}
    alerts = payload.get("alerts") if isinstance(payload.get("alerts"), list) else []
    examples = payload.get("examples", {}) if isinstance(payload.get("examples"), dict) else {}

    def card(title: str, value: Any, hint: str = "") -> str:
        return (
            "<section class='card'>"
            f"<span>{_html_escape(title)}</span>"
            f"<strong>{_html_escape(value)}</strong>"
            f"<small>{_html_escape(hint)}</small>"
            "</section>"
        )

    alert_html = "".join(
        f"<li class='{_html_escape(alert.get('severity', 'watch'))}'>"
        f"<strong>{_html_escape(alert.get('code'))}</strong> - {_html_escape(alert.get('message'))}"
        "</li>"
        for alert in alerts
    ) or "<li class='ok'>Nu există alerte pe fereastra curentă.</li>"

    disagreement_rows = "".join(
        "<tr>"
        f"<td>{_html_escape(item.get('scan_id'))}</td>"
        f"<td>{_html_escape(item.get('gate_label'))}</td>"
        f"<td>{_html_escape(item.get('shadow_label'))}</td>"
        f"<td>{_html_escape(item.get('confidence'))}</td>"
        f"<td>{_html_escape(item.get('reason'))}</td>"
        "</tr>"
        for item in examples.get("disagreements", [])
        if isinstance(item, dict)
    ) or "<tr><td colspan='5'>Nu există dezacorduri validate.</td></tr>"

    fallback_rows = "".join(
        "<tr>"
        f"<td>{_html_escape(item.get('scan_id'))}</td>"
        f"<td>{_html_escape(item.get('gate_label'))}</td>"
        f"<td>{_html_escape(item.get('fallback_reason'))}</td>"
        "</tr>"
        for item in examples.get("fallbacks", [])
        if isinstance(item, dict)
    ) or "<tr><td colspan='3'>Nu există fallback-uri.</td></tr>"

    html = f"""
<!doctype html>
<html lang="ro">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>SigurScan Shadow Adjudication</title>
  <style>
    :root {{
      color-scheme: light;
      --bg: #f6f8fc;
      --card: #ffffff;
      --ink: #172033;
      --muted: #62708a;
      --line: #dde5f1;
      --blue: #316bff;
      --red: #c7332f;
      --amber: #ad6500;
      --green: #087f5b;
    }}
    body {{
      margin: 0;
      padding: 32px;
      background: var(--bg);
      color: var(--ink);
      font: 15px/1.5 -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
    }}
    header {{ margin-bottom: 24px; }}
    h1 {{ margin: 0 0 6px; font-size: 28px; }}
    p {{ margin: 0; color: var(--muted); }}
    .grid {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
      gap: 14px;
      margin: 24px 0;
    }}
    .card, section.panel {{
      background: var(--card);
      border: 1px solid var(--line);
      border-radius: 18px;
      box-shadow: 0 12px 30px rgba(24, 39, 75, .06);
    }}
    .card {{ padding: 18px; }}
    section.panel {{ padding: 20px; margin: 16px 0; }}
    .card span, small {{ color: var(--muted); display: block; }}
    .card strong {{ display: block; font-size: 30px; margin: 8px 0; }}
    table {{ width: 100%; border-collapse: collapse; }}
    th, td {{ border-bottom: 1px solid var(--line); padding: 10px; text-align: left; vertical-align: top; }}
    th {{ color: var(--muted); font-weight: 700; }}
    li {{ margin: 8px 0; }}
    .high {{ color: var(--red); }}
    .watch {{ color: var(--amber); }}
    .ok {{ color: var(--green); }}
    code {{ background: #eef3ff; color: var(--blue); padding: 2px 6px; border-radius: 8px; }}
  </style>
</head>
<body>
  <header>
    <h1>SigurScan Shadow Adjudication</h1>
    <p>Compară gate-ul determinist cu Mistral shadow. Nu schimbă verdictul userului și nu rulează providerii.</p>
  </header>
  <div class="grid">
    {card("Evenimente shadow", payload.get("events_considered"), f"limit={limit}")}
    {card("Validate", payload.get("valid"), f"fallback={payload.get('fallback')}")}
    {card("Dezacorduri", agreement.get("disagreements"), f"rate={agreement.get('disagreement_rate')}")}
    {card("Fallback rate", payload.get("fallback_rate"), "validator reject / timeout")}
    {card("Latență p95", latency.get("p95"), f"avg={latency.get('avg')} ms")}
    {card("Cache hit rate", cache.get("hit_rate"), f"hits={cache.get('hits')}")}
    {card("Feedback etichetat", feedback.get("labeled"), f"improve={feedback.get('shadow_would_improve')} regress={feedback.get('shadow_would_regress')}")}
    {card("Promovabil", promotion.get("can_promote"), f"{promotion.get('current_labeled_real_messages')}/{promotion.get('min_labeled_real_messages')} mesaje")}
  </div>
  <section class="panel">
    <h2>Alerte</h2>
    <ul>{alert_html}</ul>
  </section>
  <section class="panel">
    <h2>Dezacorduri validate</h2>
    <table><thead><tr><th>Scan</th><th>Gate</th><th>Mistral</th><th>Confidence</th><th>Motiv</th></tr></thead><tbody>{disagreement_rows}</tbody></table>
  </section>
  <section class="panel">
    <h2>Fallback / Validator Reject</h2>
    <table><thead><tr><th>Scan</th><th>Gate</th><th>Motiv fallback</th></tr></thead><tbody>{fallback_rows}</tbody></table>
  </section>
</body>
</html>
"""
    return HTMLResponse(content=html)


@router.get("/v1/evaluation/feedback")
def feedback_evaluation_quality(
    source_channel: Optional[str] = None,
    since_ts: Optional[int] = None,
    until_ts: Optional[int] = None,
    include_uncertain: bool = False,
    include_examples: bool = True,
    max_examples_per_type: int = 50,
    run_sweep: bool = True,
    sweep_start: int = 0,
    sweep_end: int = 100,
    sweep_step: int = 5,
    sweep_metric: str = "f1",
):
    return _build_feedback_quality_payload(
        source_channel=source_channel,
        since_ts=since_ts,
        until_ts=until_ts,
        include_uncertain=include_uncertain,
        include_examples=include_examples,
        max_examples_per_type=max_examples_per_type,
        run_sweep=run_sweep,
        sweep_start=sweep_start,
        sweep_end=sweep_end,
        sweep_step=sweep_step,
        sweep_metric=sweep_metric,
    )


@router.get("/v1/evaluation/run")
def run_evaluation_endpoint(
    dataset_path: Optional[str] = None,
    risk_threshold: Optional[int] = None,
    max_rows: Optional[int] = None,
    disable_redirects: bool = False,
    disable_reputation: bool = False,
    run_sweep: bool = False,
    sweep_start: int = 0,
    sweep_end: int = 100,
    sweep_step: int = 5,
    sweep_metric: str = "f1",
):
    if risk_threshold is None:
        risk_threshold = int(RISK_THRESHOLD)
    if max_rows is not None and max_rows <= 0:
        raise HTTPException(status_code=400, detail="max_rows trebuie sa fie strict pozitiv.")
    if sweep_step <= 0:
        raise HTTPException(status_code=400, detail="sweep_step trebuie sa fie strict pozitiv.")
    if sweep_end < sweep_start:
        raise HTTPException(status_code=400, detail="sweep_end trebuie sa fie mai mare sau egal cu sweep_start.")

    path = _resolve_eval_dataset_path(dataset_path)
    evaluate_module = importlib.import_module("eval.evaluate")
    run_evaluation = getattr(evaluate_module, "run_evaluation")
    run_threshold_sweep = getattr(evaluate_module, "run_threshold_sweep")

    baseline = run_evaluation(
        path,
        risk_threshold=risk_threshold,
        max_rows=max_rows,
        disable_redirects=disable_redirects,
        disable_reputation=disable_reputation,
    )

    response = {
        "dataset_path": str(path),
        "generated_at": int(time.time()),
        "run_options": {
            "risk_threshold": risk_threshold,
            "max_rows": max_rows,
            "disable_redirects": disable_redirects,
            "disable_reputation": disable_reputation,
        },
        "baseline": baseline,
    }

    if run_sweep:
        sweep = run_threshold_sweep(
            path,
            disable_redirects=disable_redirects,
            disable_reputation=disable_reputation,
            sweep_start=sweep_start,
            sweep_end=sweep_end,
            sweep_step=sweep_step,
            optimize_metric=sweep_metric,
            max_rows=max_rows,
        )
        response["threshold_sweep"] = sweep
        response["recommended_threshold"] = sweep["best"]["risk_threshold"]

        best_threshold = sweep["best"].get("risk_threshold")
        if isinstance(best_threshold, int):
            response["best_eval"] = run_evaluation(
                path,
                risk_threshold=best_threshold,
                max_rows=max_rows,
                disable_redirects=disable_redirects,
                disable_reputation=disable_reputation,
            )

    return response


@router.get("/v1/feedback/samples")
def feedback_samples(
    source_channel: Optional[str] = None,
    since_ts: Optional[int] = None,
    until_ts: Optional[int] = None,
    include_uncertain: bool = False,
    include_examples: bool = True,
    max_examples_per_type: int = 50,
    error_category: Optional[str] = None,
):
    feedback_rows = load_feedback_records()
    scan_rows = load_scan_records()
    dataset_rows = build_feedback_evaluation_rows(
        feedback_rows,
        scan_rows,
        source_channel=source_channel,
        since_ts=since_ts,
        until_ts=until_ts,
        include_uncertain=include_uncertain,
        fallback_threshold=RISK_THRESHOLD,
    )

    normalized_error_category = (error_category or "").strip().lower() or None
    if normalized_error_category and normalized_error_category not in {
        "correct",
        "false_positive",
        "false_negative",
        "uncertain",
    }:
        raise HTTPException(status_code=400, detail="error_category trebuie sa fie: correct, false_positive, false_negative sau uncertain.")

    sample_buckets: Dict[str, List[Dict[str, Any]]] = {
        "correct": [],
        "false_positive": [],
        "false_negative": [],
        "uncertain": [],
    }
    category_counts: Counter[str] = Counter()

    if max_examples_per_type < 0:
        max_examples_per_type = 0

    for row in dataset_rows:
        if not isinstance(row, dict):
            continue

        category = row.get("error_category") or "uncertain"
        if category not in sample_buckets:
            continue

        if normalized_error_category is not None and category != normalized_error_category:
            continue

        category_counts[category] += 1
        if not include_examples:
            continue
        bucket = sample_buckets[category]
        if len(bucket) >= max_examples_per_type:
            continue

        bucket.append(_feedback_sample_payload(row))

    samples: Dict[str, Any] = {}
    if normalized_error_category is not None:
        samples[normalized_error_category] = sample_buckets[normalized_error_category]
    else:
        for category_name, bucket in sample_buckets.items():
            if bucket:
                samples[category_name] = bucket

    response = {
        "items_evaluated": len(dataset_rows),
        "source_channel": source_channel,
        "category_counts": dict(category_counts),
        "samples": samples,
    }
    if normalized_error_category is not None:
        response["error_category"] = normalized_error_category
    return response


@router.get("/v1/feedback/quality")
def feedback_quality(
    source_channel: Optional[str] = None,
    since_ts: Optional[int] = None,
    until_ts: Optional[int] = None,
    include_uncertain: bool = False,
    include_examples: bool = True,
    max_examples_per_type: int = 50,
    run_sweep: bool = True,
    sweep_start: int = 0,
    sweep_end: int = 100,
    sweep_step: int = 5,
    sweep_metric: str = "f1",
    ):
    return _build_feedback_quality_payload(
        source_channel=source_channel,
        since_ts=since_ts,
        until_ts=until_ts,
        include_uncertain=include_uncertain,
        include_examples=include_examples,
        max_examples_per_type=max_examples_per_type,
        run_sweep=run_sweep,
        sweep_start=sweep_start,
        sweep_end=sweep_end,
        sweep_step=sweep_step,
        sweep_metric=sweep_metric,
    )


@router.get("/v1/evaluation/feedback/trend")
def feedback_trend(
    source_channel: Optional[str] = None,
    since_ts: Optional[int] = None,
    until_ts: Optional[int] = None,
    include_uncertain: bool = False,
    bucket_size_days: int = 1,
    min_bucket_support: int = 1,
    top_signals: int = 10,
    min_signal_support: int = 1,
):
    if bucket_size_days <= 0:
        raise HTTPException(status_code=400, detail="bucket_size_days trebuie sa fie mai mare ca 0.")
    if min_bucket_support < 0:
        raise HTTPException(status_code=400, detail="min_bucket_support trebuie sa fie >= 0.")
    if top_signals < 0:
        raise HTTPException(status_code=400, detail="top_signals trebuie sa fie >= 0.")
    if min_signal_support < 0:
        raise HTTPException(status_code=400, detail="min_signal_support trebuie sa fie >= 0.")

    feedback_rows = load_feedback_records()
    scan_rows = load_scan_records()
    dataset_rows = build_feedback_evaluation_rows(
        feedback_rows,
        scan_rows,
        source_channel=source_channel,
        since_ts=since_ts,
        until_ts=until_ts,
        include_uncertain=include_uncertain,
        fallback_threshold=RISK_THRESHOLD,
    )

    trend = summarize_feedback_trend(
        dataset_rows,
        source_channel=source_channel,
        since_ts=None,
        until_ts=None,
        bucket_size_days=bucket_size_days,
        include_uncertain=include_uncertain,
        min_bucket_support=min_bucket_support,
        top_signals=top_signals,
        min_signal_support=min_signal_support,
    )

    return {
        "source_channel": source_channel,
        "query": {
            "since_ts": since_ts,
            "until_ts": until_ts,
            "include_uncertain": include_uncertain,
            "bucket_size_days": bucket_size_days,
            "min_bucket_support": min_bucket_support,
            "top_signals": top_signals,
            "min_signal_support": min_signal_support,
        },
        "items_evaluated": len(dataset_rows),
        "trend": trend,
    }


@router.get("/v1/evaluation/readiness")
def evaluation_readiness(
    source_channel: Optional[str] = None,
    since_ts: Optional[int] = None,
    until_ts: Optional[int] = None,
    include_uncertain: bool = False,
    bucket_size_days: int = 1,
    trend_top_signals: int = 10,
    trend_min_bucket_support: int = 1,
    trend_min_signal_support: int = 1,
):
    if bucket_size_days <= 0:
        raise HTTPException(status_code=400, detail="bucket_size_days trebuie sa fie mai mare ca 0.")
    if trend_top_signals < 0:
        raise HTTPException(status_code=400, detail="trend_top_signals trebuie sa fie >= 0.")
    if trend_min_bucket_support < 0:
        raise HTTPException(status_code=400, detail="trend_min_bucket_support trebuie sa fie >= 0.")
    if trend_min_signal_support < 0:
        raise HTTPException(status_code=400, detail="trend_min_signal_support trebuie sa fie >= 0.")

    return _build_readiness_payload(
        source_channel=source_channel,
        since_ts=since_ts,
        until_ts=until_ts,
        include_uncertain=include_uncertain,
        bucket_size_days=bucket_size_days,
        trend_top_signals=trend_top_signals,
        trend_min_bucket_support=trend_min_bucket_support,
        trend_min_signal_support=trend_min_signal_support,
    )


# ---------------------------------------------------------------------------
# Community endpoints (for iOS app)
# ---------------------------------------------------------------------------
