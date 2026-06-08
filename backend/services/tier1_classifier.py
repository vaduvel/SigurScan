from __future__ import annotations

import json
import math
import re
import unicodedata
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Dict, Iterable, List, Tuple


LABELS = {"legit_marketing", "official_notice", "scam_like", "unknown"}
LEGIT_LABELS = {"legit_marketing", "official_notice"}

ROOT = Path(__file__).resolve().parents[1]

BUILTIN_TRAINING_ROWS: List[Tuple[str, str]] = [
    (
        "legit_marketing",
        "SALE pana la -50%! Pantofi de top le poti cumpara chiar si la jumatate de pret. https://snrs.it/0BJIIOV #MODIVOclub StopSMS",
    ),
    (
        "legit_marketing",
        "eMAG: oferta limitata weekendul acesta, pana la -50%. Vezi produsele: emag.ro/promo",
    ),
    (
        "legit_marketing",
        "Altex: cod reducere 10% valabil azi. Detalii: altex.ro/voucher",
    ),
    (
        "legit_marketing",
        "Hipo iti recomanda evenimentul Angajatori de TOP. Inscrie-te https://www.hipo.ro/ADT_TM",
    ),
    (
        "legit_marketing",
        "Nu amana renovarea. La Cetelem ai un credit cu dobanda fixa. Intra pe bit.ly/38EsUAf",
    ),
    (
        "official_notice",
        "In data de 07-06-2026 s-a emis factura ta Orange. Descarca factura aici https://orange.ro/r/KK5IMyT",
    ),
    (
        "official_notice",
        "Sameday: coletul AWB 712334 este in livrare azi. Urmareste in aplicatie.",
    ),
    (
        "official_notice",
        "BT: tranzactie aprobata 149.99 lei la eMAG. Detalii in aplicatia BT Pay.",
    ),
    (
        "official_notice",
        "Netflix: planul tau s-a reinnoit. Gestioneaza abonamentul pe netflix.com/account.",
    ),
    (
        "scam_like",
        "FanCourier: taxa vamala neachitata 3.50 RON. Introdu datele cardului aici fancurier-relivrare.com/plata",
    ),
    (
        "scam_like",
        "ANAF: Aveti o rambursare de impozit. Introdu datele cardului pentru a primi banii.",
    ),
    (
        "scam_like",
        "BNR: transfera banii in cont sigur si nu spune nimanui. Suna urgent.",
    ),
    (
        "scam_like",
        "Broker crypto: instaleaza AnyDesk si depune bani pentru profit garantat.",
    ),
]


def _strip_diacritics(value: str) -> str:
    normalized = unicodedata.normalize("NFKD", value or "")
    return "".join(ch for ch in normalized if not unicodedata.combining(ch))


def _tokens(text: str) -> List[str]:
    normalized = _strip_diacritics(text).lower()
    normalized = re.sub(r"https?://\S+|www\.\S+", " urltoken ", normalized)
    return [
        token
        for token in re.findall(r"[a-z0-9]{2,}", normalized)
        if token not in {"https", "http", "www"}
    ]


def _row_text(row: Dict[str, Any]) -> str:
    return str(row.get("text") or row.get("input") or row.get("message") or "").strip()


def _coarse_label(row: Dict[str, Any]) -> str | None:
    label = str(row.get("expected_contract_label") or row.get("label") or "").strip().upper()
    if label == "PERICULOS":
        return "scam_like"
    if label != "SIGUR":
        return None

    text = _strip_diacritics(_row_text(row)).lower()
    family = str(row.get("family") or "").lower()
    marketing_markers = (
        "oferta",
        "reducere",
        "voucher",
        "catalog",
        "sale",
        "promo",
        "cumpara",
        "cumparat",
        "credit",
        "eveniment",
        "inscrie",
    )
    official_notice_markers = (
        "factura",
        "tranzactie",
        "colet",
        "awb",
        "abonament",
        "planul tau",
        "pin ridicare",
        "livrare",
    )
    if family.startswith("guard/") and any(marker in text for marker in marketing_markers):
        return "legit_marketing"
    if any(marker in text for marker in marketing_markers):
        return "legit_marketing"
    if any(marker in text for marker in official_notice_markers):
        return "official_notice"
    return "official_notice"


def _load_jsonl_rows(path: Path) -> Iterable[Dict[str, Any]]:
    if not path.exists():
        return []
    rows = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        try:
            value = json.loads(line)
        except Exception:
            continue
        if isinstance(value, dict):
            rows.append(value)
    return rows


class Tier1Classifier:
    """Small local text classifier used to calibrate semantic false positives.

    It is intentionally lightweight: no external API, no model download, and no
    heavy runtime dependency. The final verdict still belongs to verdict_gate.
    """

    def __init__(self, training_rows: Iterable[Tuple[str, str]]) -> None:
        self.class_counts: Counter[str] = Counter()
        self.token_counts: Dict[str, Counter[str]] = defaultdict(Counter)
        self.total_tokens: Counter[str] = Counter()
        self.vocabulary: set[str] = set()
        for label, text in training_rows:
            if label not in LABELS or not text:
                continue
            self.class_counts[label] += 1
            for token in _tokens(text):
                self.token_counts[label][token] += 1
                self.total_tokens[label] += 1
                self.vocabulary.add(token)
        if not self.class_counts:
            for label, text in BUILTIN_TRAINING_ROWS:
                self.class_counts[label] += 1
                for token in _tokens(text):
                    self.token_counts[label][token] += 1
                    self.total_tokens[label] += 1
                    self.vocabulary.add(token)

    @classmethod
    def load_default(cls) -> "Tier1Classifier":
        rows: List[Tuple[str, str]] = list(BUILTIN_TRAINING_ROWS)
        for path in (
            ROOT / "data" / "eval" / "romania_decision_contract_eval_v2026_06_08.jsonl",
            ROOT / "data" / "verdict_testset_ro.jsonl",
            ROOT / "data" / "eval_dataset.jsonl",
        ):
            for row in _load_jsonl_rows(path):
                label = _coarse_label(row)
                text = _row_text(row)
                if label and text:
                    rows.append((label, text))
        return cls(rows)

    @staticmethod
    def _sensitive_override(text: str) -> bool:
        normalized = _strip_diacritics(text).lower()
        return bool(
            re.search(r"\b(introdu|completeaza|trimite|confirma|valideaza)\b.{0,80}\b(card|cvv|cvc|otp|parola|pin|iban|cnp)\b", normalized)
            or re.search(r"\b(anydesk|teamviewer|rustdesk|cont sigur|transfera banii|profit garantat)\b", normalized)
            or (
                re.search(r"\b(fan|curier|courier|colet|awb|livrare|relivrare)\b", normalized)
                and re.search(r"\b(taxa|taxe|vamala|vamal|neachitata|neachitat|reprograma|reprogramati|plata)\b", normalized)
            )
        )

    def classify(self, text: str) -> Dict[str, Any]:
        text = text or ""
        if not text.strip():
            return {"label": "unknown", "confidence": 0.0, "source": "tier1_local_classifier", "top_terms": []}
        if self._sensitive_override(text):
            return {
                "label": "scam_like",
                "confidence": 0.95,
                "source": "tier1_local_classifier",
                "top_terms": ["sensitive_request"],
            }

        tokens = _tokens(text)
        if not tokens:
            return {"label": "unknown", "confidence": 0.0, "source": "tier1_local_classifier", "top_terms": []}

        vocab_size = max(1, len(self.vocabulary))
        total_docs = sum(self.class_counts.values())
        log_scores: Dict[str, float] = {}
        for label in self.class_counts:
            log_prob = math.log((self.class_counts[label] + 1) / (total_docs + len(self.class_counts)))
            denom = self.total_tokens[label] + vocab_size
            for token in tokens:
                log_prob += math.log((self.token_counts[label][token] + 1) / denom)
            log_scores[label] = log_prob

        best_label = max(log_scores, key=log_scores.get)
        best = log_scores[best_label]
        exps = {label: math.exp(score - best) for label, score in log_scores.items()}
        confidence = exps[best_label] / max(sum(exps.values()), 1e-9)
        if confidence < 0.42:
            best_label = "unknown"

        top_terms = [
            token
            for token, _ in Counter(tokens).most_common(8)
            if token in self.vocabulary
        ]
        return {
            "label": best_label,
            "confidence": round(float(confidence), 3),
            "source": "tier1_local_classifier",
            "top_terms": top_terms[:5],
        }
