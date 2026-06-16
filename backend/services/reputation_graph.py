"""Reputation Graph v1 — cross-surface intel, privacy-first.

Graph-ul coreleaza phone/domain/url/iban/email/wallet doar prin identificatori
hash-uiti/canonici. Nu este verdict_gate si nu face un link/factura "sigur" sau
"periculos" singur; produce dovezi consumabile de Radar, facturi si pipeline.
"""
from __future__ import annotations

import re
import time
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional, Tuple


TARGET_TYPES = {"phone", "domain", "url", "iban", "email", "wallet", "text", "unknown"}
EDGE_RELATIONS = {"pays_to", "co_occurred_in_case", "same_campaign", "claimed_by", "redirects_to"}
_SHA256_HEX_RE = re.compile(r"^[0-9a-f]{64}$", re.IGNORECASE)

_RISK_RANK = {
    "clean": 0,
    "low": 1,
    "info": 1,
    "watch": 2,
    "medium": 3,
    "suspect": 3,
    "high": 4,
    "critical": 5,
    "dangerous": 5,
    "blocked": 6,
}
_AUTHORITATIVE_BLOCK_SOURCES = {
    "dnsc",
    "police",
    "law_enforcement",
    "google_web_risk",
    "urlhaus",
    "phishing_database",
    "manual_blocklist",
}


@dataclass
class ReputationObservation:
    target_type: str
    target_hash: str
    source: str
    risk_level: str = "medium"
    family: Optional[str] = None
    report_count: int = 1
    evidence_quality: str = "medium"
    observed_at: float = field(default_factory=time.time)


@dataclass
class ReputationEdge:
    source_type: str
    source_hash: str
    target_type: str
    target_hash: str
    relation: str
    evidence_quality: str = "medium"
    source: str = "case_correlation"
    family: Optional[str] = None
    observed_at: float = field(default_factory=time.time)


@dataclass
class AllowlistEntry:
    target_type: str
    target_hash: str
    source: str
    reason: str
    observed_at: float = field(default_factory=time.time)


def _normalize_type(value: str) -> str:
    normalized = str(value or "").strip().lower()
    if normalized not in TARGET_TYPES:
        raise ValueError(f"invalid reputation target_type: {value!r}")
    return normalized


def _normalize_hash(value: str) -> str:
    normalized = str(value or "").strip().lower()
    if not _SHA256_HEX_RE.fullmatch(normalized):
        raise ValueError("reputation graph identifiers must be SHA256 hex digests, not raw values")
    return normalized


def _normalize_risk(value: str) -> str:
    normalized = str(value or "medium").strip().lower()
    return normalized if normalized in _RISK_RANK else "medium"


def reputation_bucket(report_count: int) -> str:
    try:
        n = int(report_count)
    except (TypeError, ValueError):
        n = 0
    if n <= 0:
        return "0"
    if n <= 4:
        return "1-4"
    if n <= 24:
        return "5-24"
    if n <= 99:
        return "25-99"
    return "100+"


def _riskier(left: str, right: str) -> str:
    l = _normalize_risk(left)
    r = _normalize_risk(right)
    return r if _RISK_RANK[r] > _RISK_RANK[l] else l


class ReputationGraph:
    def __init__(self) -> None:
        self._observations: Dict[Tuple[str, str], List[ReputationObservation]] = {}
        self._edges: List[ReputationEdge] = []
        self._allowlist: Dict[Tuple[str, str], AllowlistEntry] = {}

    @classmethod
    def from_rows(
        cls,
        *,
        observations: Iterable[Dict[str, Any]],
        edges: Iterable[Dict[str, Any]],
        allowlist: Iterable[Dict[str, Any]],
    ) -> "ReputationGraph":
        graph = cls()
        for row in allowlist or []:
            try:
                graph.mark_allowlisted(
                    target_type=str(row.get("target_type") or "unknown"),
                    target_hash=str(row.get("target_hash") or row.get("hash") or ""),
                    source=str(row.get("source") or "unknown"),
                    reason=str(row.get("reason") or "official"),
                )
            except ValueError:
                continue
        for row in observations or []:
            try:
                graph.add_observation(
                    target_type=str(row.get("target_type") or "unknown"),
                    target_hash=str(row.get("target_hash") or row.get("hash") or ""),
                    source=str(row.get("source") or "unknown"),
                    risk_level=str(row.get("risk_level") or "medium"),
                    family=row.get("family"),
                    report_count=int(row.get("report_count") or 1),
                    evidence_quality=str(row.get("evidence_quality") or "medium"),
                )
            except (TypeError, ValueError):
                continue
        for row in edges or []:
            try:
                graph.add_edge(
                    source_type=str(row.get("source_type") or "unknown"),
                    source_hash=str(row.get("source_hash") or ""),
                    target_type=str(row.get("target_type") or "unknown"),
                    target_hash=str(row.get("target_hash") or ""),
                    relation=str(row.get("relation") or ""),
                    evidence_quality=str(row.get("evidence_quality") or "medium"),
                    source=str(row.get("source") or "case_correlation"),
                    family=row.get("family"),
                )
            except ValueError:
                continue
        return graph

    def add_observation(
        self,
        *,
        target_type: str,
        target_hash: str,
        source: str,
        risk_level: str = "medium",
        family: Optional[str] = None,
        report_count: int = 1,
        evidence_quality: str = "medium",
        observed_at: Optional[float] = None,
    ) -> ReputationObservation:
        t = _normalize_type(target_type)
        h = _normalize_hash(target_hash)
        obs = ReputationObservation(
            target_type=t,
            target_hash=h,
            source=str(source or "unknown").strip().lower() or "unknown",
            risk_level=_normalize_risk(risk_level),
            family=family,
            report_count=max(1, int(report_count or 1)),
            evidence_quality=str(evidence_quality or "medium").strip().lower() or "medium",
            observed_at=float(observed_at if observed_at is not None else time.time()),
        )
        self._observations.setdefault((t, h), []).append(obs)
        return obs

    def add_edge(
        self,
        *,
        source_type: str,
        source_hash: str,
        target_type: str,
        target_hash: str,
        relation: str,
        evidence_quality: str = "medium",
        source: str = "case_correlation",
        family: Optional[str] = None,
        observed_at: Optional[float] = None,
    ) -> ReputationEdge:
        st = _normalize_type(source_type)
        sh = _normalize_hash(source_hash)
        tt = _normalize_type(target_type)
        th = _normalize_hash(target_hash)
        rel = str(relation or "").strip().lower()
        if rel not in EDGE_RELATIONS:
            raise ValueError(f"invalid reputation edge relation: {relation!r}")
        edge = ReputationEdge(
            source_type=st,
            source_hash=sh,
            target_type=tt,
            target_hash=th,
            relation=rel,
            evidence_quality=str(evidence_quality or "medium").strip().lower() or "medium",
            source=str(source or "case_correlation").strip().lower() or "case_correlation",
            family=family,
            observed_at=float(observed_at if observed_at is not None else time.time()),
        )
        self._edges.append(edge)
        return edge

    def mark_allowlisted(
        self,
        *,
        target_type: str,
        target_hash: str,
        source: str,
        reason: str,
        observed_at: Optional[float] = None,
    ) -> AllowlistEntry:
        t = _normalize_type(target_type)
        h = _normalize_hash(target_hash)
        entry = AllowlistEntry(
            target_type=t,
            target_hash=h,
            source=str(source or "unknown").strip().lower() or "unknown",
            reason=str(reason or "official").strip().lower() or "official",
            observed_at=float(observed_at if observed_at is not None else time.time()),
        )
        self._allowlist[(t, h)] = entry
        return entry

    def evaluate(self, target_type: str, target_hash: str) -> Dict[str, Any]:
        t = _normalize_type(target_type)
        h = _normalize_hash(target_hash)
        direct = self._direct_evidence(t, h)
        allowlisted = (t, h) in self._allowlist
        linked = self._linked_evidence(t, h)

        reason_codes: List[str] = []
        if allowlisted:
            reason_codes.append("GRAPH_ALLOWLIST_MATCH")

        if direct["report_count"] > 0:
            reason_codes.extend(direct["reason_codes"])
        if linked:
            reason_codes.extend(linked["reason_codes"])

        authoritative_block = any(
            obs.source in _AUTHORITATIVE_BLOCK_SOURCES and _RISK_RANK[obs.risk_level] >= _RISK_RANK["dangerous"]
            for obs in self._observations.get((t, h), [])
        )

        if allowlisted and not authoritative_block:
            if direct["report_count"] > 0 or linked:
                return self._result(
                    status="allowlisted_watch",
                    action="allow_with_watch",
                    can_block=False,
                    risk_level="low",
                    family=direct["family"] or (linked or {}).get("family"),
                    report_count=direct["report_count"],
                    reason_codes=reason_codes + ["GRAPH_ALLOWLIST_PROTECTED"],
                )
            return self._result(
                status="allowlisted",
                action="allow",
                can_block=False,
                risk_level="clean",
                family=None,
                report_count=0,
                reason_codes=reason_codes,
            )

        if direct["can_block"]:
            return self._result(
                status="blocked",
                action="block",
                can_block=True,
                risk_level=direct["risk_level"],
                family=direct["family"],
                report_count=direct["report_count"],
                reason_codes=reason_codes,
            )

        if linked:
            return self._result(
                status="suspicious",
                action="raise_risk",
                can_block=False,
                risk_level=linked["risk_level"],
                family=linked["family"] or direct["family"],
                report_count=direct["report_count"],
                reason_codes=reason_codes,
            )

        if direct["report_count"] > 0:
            return self._result(
                status="reported",
                action="warn",
                can_block=False,
                risk_level=direct["risk_level"],
                family=direct["family"],
                report_count=direct["report_count"],
                reason_codes=reason_codes,
            )

        return self._result(
            status="unknown",
            action="none",
            can_block=False,
            risk_level="unknown",
            family=None,
            report_count=0,
            reason_codes=[],
        )

    def radar_number_reputation(self) -> List[Dict[str, Any]]:
        items: List[Dict[str, Any]] = []
        for (target_type, target_hash), observations in self._observations.items():
            if target_type != "phone" or not observations:
                continue
            verdict = self.evaluate(target_type, target_hash)
            if verdict["status"] not in {"reported", "blocked", "allowlisted_watch"}:
                continue
            status = "blocked" if verdict["can_block"] else "reported"
            items.append(
                {
                    "phone_hash": target_hash,
                    "status": status,
                    "family": verdict.get("family"),
                    "bucket_count": verdict["bucket_count"],
                }
            )
        return items

    def load_community_reports(self, reports: Iterable[Dict[str, Any]]) -> None:
        for row in reports or []:
            target_type = str(row.get("target_type") or "unknown").strip().lower()
            target_hash = str(row.get("hash") or row.get("target_hash") or "").strip().lower()
            if target_type not in TARGET_TYPES or not _SHA256_HEX_RE.fullmatch(target_hash):
                continue
            self.add_observation(
                target_type=target_type,
                target_hash=target_hash,
                source=str(row.get("source") or "community").strip().lower() or "community",
                risk_level=str(row.get("risk_level") or "medium"),
                family=row.get("family"),
                report_count=int(row.get("report_count") or 1),
                evidence_quality=str(row.get("evidence_quality") or "medium"),
            )

    def _direct_evidence(self, target_type: str, target_hash: str) -> Dict[str, Any]:
        observations = self._observations.get((target_type, target_hash), [])
        report_count = sum(max(1, int(obs.report_count or 1)) for obs in observations)
        risk_level = "low"
        family = None
        for obs in observations:
            risk_level = _riskier(risk_level, obs.risk_level)
            if not family and obs.family:
                family = obs.family
        can_block = self._can_block_direct(target_type, report_count, risk_level, observations)
        reason_codes: List[str] = []
        if report_count == 1:
            reason_codes.append("GRAPH_SINGLE_REPORT_NON_BLOCKING")
        if target_type == "phone" and can_block:
            reason_codes.append("GRAPH_HIGH_VOLUME_PHONE_REPORTS")
        elif report_count > 0:
            reason_codes.append("GRAPH_COMMUNITY_REPORTS")
        return {
            "report_count": report_count,
            "risk_level": risk_level,
            "family": family,
            "can_block": can_block,
            "reason_codes": reason_codes,
        }

    def _can_block_direct(
        self,
        target_type: str,
        report_count: int,
        risk_level: str,
        observations: List[ReputationObservation],
    ) -> bool:
        if target_type != "phone":
            return False
        if any(obs.source in _AUTHORITATIVE_BLOCK_SOURCES and obs.risk_level in {"dangerous", "blocked"} for obs in observations):
            return True
        if report_count >= 100:
            return True
        return report_count >= 25 and risk_level in {"high", "critical", "dangerous", "blocked"}

    def _linked_evidence(self, target_type: str, target_hash: str) -> Optional[Dict[str, Any]]:
        for edge in self._edges:
            if edge.target_type != target_type or edge.target_hash != target_hash:
                continue
            source_direct = self._direct_evidence(edge.source_type, edge.source_hash)
            source_high = source_direct["can_block"] or (
                source_direct["report_count"] >= 25
                and source_direct["risk_level"] in {"high", "critical", "dangerous", "blocked"}
            )
            if not source_high:
                continue
            if target_type == "iban" and edge.source_type == "phone" and edge.relation == "pays_to":
                return {
                    "risk_level": "high",
                    "family": edge.family or source_direct["family"],
                    "reason_codes": ["GRAPH_LINKED_TO_HIGH_RISK_PHONE"],
                }
            return {
                "risk_level": "medium",
                "family": edge.family or source_direct["family"],
                "reason_codes": ["GRAPH_LINKED_TO_SUSPICIOUS_INFRA"],
            }
        return None

    def _result(
        self,
        *,
        status: str,
        action: str,
        can_block: bool,
        risk_level: str,
        family: Optional[str],
        report_count: int,
        reason_codes: List[str],
    ) -> Dict[str, Any]:
        deduped_reasons = list(dict.fromkeys(reason_codes))
        return {
            "status": status,
            "action": action,
            "can_block": bool(can_block),
            "risk_level": risk_level,
            "family": family,
            "report_count": int(report_count or 0),
            "bucket_count": reputation_bucket(report_count),
            "reason_codes": deduped_reasons,
        }
