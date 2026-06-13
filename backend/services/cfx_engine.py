from __future__ import annotations

import hashlib
import json
import re
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple


SIMHASH_BITS = 64
MATCH_THRESHOLD = 0.82


@dataclass
class CampaignFingerprint:
    fingerprint_id: str
    locale: str = "ro-RO"
    channel_class: str = "sms"
    arc_family: str = ""
    ask_sequence_sig: str = ""
    cta_pattern_sig: str = ""
    identity_claim_sig: str = ""
    payment_rail_sig: str = ""
    sensitive_request_sig: List[str] = field(default_factory=list)
    text_skeleton_hash: str = ""
    url_shape_sig: str = "no-url"
    no_raw_iocs: bool = True
    created_at: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "fingerprint_id": self.fingerprint_id,
            "locale": self.locale,
            "channel_class": self.channel_class,
            "arc_family": self.arc_family,
            "ask_sequence_sig": self.ask_sequence_sig,
            "cta_pattern_sig": self.cta_pattern_sig,
            "identity_claim_sig": self.identity_claim_sig,
            "payment_rail_sig": self.payment_rail_sig,
            "sensitive_request_sig": self.sensitive_request_sig,
            "text_skeleton_hash": self.text_skeleton_hash,
            "url_shape_sig": self.url_shape_sig,
            "no_raw_iocs": self.no_raw_iocs,
            "created_at": self.created_at,
        }

    @staticmethod
    def from_dict(d: Dict[str, Any]) -> CampaignFingerprint:
        return CampaignFingerprint(
            fingerprint_id=d["fingerprint_id"],
            locale=d.get("locale", "ro-RO"),
            channel_class=d.get("channel_class", "sms"),
            arc_family=d.get("arc_family", ""),
            ask_sequence_sig=d.get("ask_sequence_sig", ""),
            cta_pattern_sig=d.get("cta_pattern_sig", ""),
            identity_claim_sig=d.get("identity_claim_sig", ""),
            payment_rail_sig=d.get("payment_rail_sig", ""),
            sensitive_request_sig=d.get("sensitive_request_sig", []),
            text_skeleton_hash=d.get("text_skeleton_hash", ""),
            url_shape_sig=d.get("url_shape_sig", "no-url"),
            no_raw_iocs=d.get("no_raw_iocs", True),
            created_at=d.get("created_at", 0.0),
        )


@dataclass
class FingerprintMatch:
    fingerprint_id: str
    arc_family: str
    similarity: float
    matched: bool


_ROMANIAN_NORM = str.maketrans({"ș": "s", "ș": "s", "ț": "t", "ț": "t", "â": "a", "î": "i", "ă": "a", "Â": "A", "Î": "I", "Ă": "A"})


def _normalize(text: str) -> str:
    text = text.translate(_ROMANIAN_NORM)
    return re.sub(r"[^a-z0-9\s]", " ", text.lower()).strip()


PII_PATTERNS = re.compile(
    r"\b\d{10,}\b"              # phone / numeric PII
    r"|RO[a-zA-Z0-9]{1,24}\b"   # IBAN
    r"|\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"  # email
    r"|\bhttps?://\S+\b"        # URL
    , re.IGNORECASE
)


def _clean_skeleton_text(raw: str) -> str:
    cleaned = PII_PATTERNS.sub(" ", raw)
    cleaned = _normalize(cleaned)
    cleaned = re.sub(r"\s+", " ", cleaned).strip()
    return cleaned


def _tokenize(text: str) -> List[str]:
    return [t for t in text.split() if len(t) > 2]


_RO_STOP = frozenset({
    "pentru", "acesta", "acest", "aceasta", "aceste", "acei",
    "sunt", "este", "fost", "mai", "prin", "cat", "catre",
    "dupa", "incepand", "pentru", "catre", "multe", "niste",
    "peste", "chiar", "atunci", "toate", "fara", "nici",
    "foarte", "putin", "unele", "cand", "cum", "unde",
    "asta", "ale", "din", "pe", "la", "cu", "ca", "sa",
    "nu", "de", "se", "si", "in", "un", "o", "au", "ma",
})


def _filter_stop(tokens: List[str]) -> List[str]:
    return [t for t in tokens if t not in _RO_STOP]


def _simhash(tokens: List[str], bits: int = SIMHASH_BITS) -> int:
    v = [0] * bits
    for token in tokens:
        h = int(hashlib.sha256(token.encode("utf-8")).hexdigest()[:16], 16)
        for i in range(bits):
            if (h >> i) & 1:
                v[i] += 1
            else:
                v[i] -= 1
    fingerprint = 0
    for i in range(bits):
        if v[i] > 0:
            fingerprint |= (1 << i)
    return fingerprint


def _hamming_distance(a: int, b: int) -> int:
    return bin(a ^ b).count("1")


def _simhash_similarity(a: int, b: int, bits: int = SIMHASH_BITS) -> float:
    return 1.0 - (_hamming_distance(a, b) / bits)


_ARC_SIGNALS: Dict[str, List[str]] = {
    "authority_claim": ["politia", "poliție", "dnsc", "anaf", "bnr", "banca", "bcr", "ing", "bt", "brd", "ofițer", "comisar", "procuror"],
    "threat": ["arest", "proces", "amendă", "amenda", "blocare", "suspendare", "pericl", "penal", "investigat", "periculo"],
    "move_money": ["transfer", "cont sigur", "contul sigur", "mută", "muta", "trimite", "depune", "virează"],
    "urgency": ["urgent", "imediat", "astăzi", "acum", "termen limită", "ultima zi", "expiră"],
    "verify_identity": ["verifica", "confirmă", "confirmati", "validare", "autentificare"],
    "read_otp": ["cod", "otp", "parolă", "parola", "sms", "whatsapp", "spune-mi"],
    "install_app": ["anydesk", "teamviewer", "quick support", "aplicație", "remote", "aplicatia"],
    "personal_info": ["cnp", "ci", "buletin", "pașaport", "pasaport", "date personale", "serie", "număr act"],
}

_CTA_SIGNALS: Dict[str, List[str]] = {
    "transfer_safe_account": ["cont sigur", "contul sigur", "cont protejat", "cont seif"],
    "read_otp": ["cod", "otp", "spune codul", "citeste codul", "cod primit"],
    "install_remote_access": ["anydesk", "teamviewer", "quick support", "descărcați", "instalează"],
    "card_details": ["card", "cvv", "număr card", "data expirării", "pin card"],
    "advance_payment": ["avans", "plată înainte", "taxă", "comision", "garantare"],
    "click_link": ["click", "accesează", "link", "intră pe", "apasă"],
}

_IDENTITY_SIGNALS: Dict[str, List[str]] = {
    "bank": ["banca", "bcr", "bt", "ing", "brd", "transilvania", "bank"],
    "bnr": ["bnr", "banca nationala", "banca națională"],
    "police": ["politia", "poliție", "mai", "polițist", "comisar", "ofițer"],
    "anaf": ["anaf", "finanțe", "fisc"],
    "dnsc": ["dnsc", "siguranta online"],
    "courier": ["curier", "fan courier", "sameday", "cargus", "posta romana", "colet"],
    "marketplace": ["olx", "emag", "altex", "vanzare", "cumperi"],
    "telco": ["orange", "vodafone", "digi", "telekom"],
}

_PAYMENT_SIGNALS: Dict[str, List[str]] = {
    "bank_transfer": ["transfer bancar", "cont", "iban", "virează"],
    "crypto": ["crypto", "bitcoin", "btc", "ethereum", "wallet", "coin"],
    "gift_card": ["gift card", "card cadou", "voucher", "steam card"],
    "card_form": ["card", "cardul", "cvv", "număr card", "plata card"],
}

_SENSITIVE_SIGNALS: Dict[str, List[str]] = {
    "otp": ["cod", "otp", "parolă", "parola", "whatsapp", "spune-mi codul"],
    "remote_access": ["anydesk", "teamviewer", "quick support", "remote"],
    "card": ["card", "cvv", "card_number", "număr card", "data card"],
    "password": ["password", "parolă", "parola cont"],
    "id_document": ["cnp", "ci", "buletin", "pașaport", "pasaport", "carte identitate"],
}


def _extract_signals(text_lower: str, claimed_identity: Optional[str] = None) -> Dict[str, Any]:
    ask_sequence = []
    cta_pattern = ""
    identity_claim = ""
    payment_rail = ""
    sensitive = []

    for sig_name, keywords in _ARC_SIGNALS.items():
        if any(k in text_lower for k in keywords):
            ask_sequence.append(sig_name)

    cta_matches = []
    for sig_name, keywords in _CTA_SIGNALS.items():
        if any(k in text_lower for k in keywords):
            cta_matches.append(sig_name)
    if cta_matches:
        cta_pattern = cta_matches[0]

    identity_matches = []
    for sig_name, keywords in _IDENTITY_SIGNALS.items():
        if any(k in text_lower for k in keywords):
            identity_matches.append(sig_name)
    if claimed_identity:
        identity_lower = claimed_identity.lower()
        for sig_name, keywords in _IDENTITY_SIGNALS.items():
            if any(k in identity_lower for k in keywords):
                if sig_name not in identity_matches:
                    identity_matches.append(sig_name)
    if identity_matches:
        identity_claim = identity_matches[0]

    payment_matches = []
    for sig_name, keywords in _PAYMENT_SIGNALS.items():
        if any(k in text_lower for k in keywords):
            payment_matches.append(sig_name)
    if payment_matches:
        payment_rail = payment_matches[0]

    for sig_name, keywords in _SENSITIVE_SIGNALS.items():
        if any(k in text_lower for k in keywords):
            sensitive.append(sig_name)

    return {
        "ask_sequence": "->".join(ask_sequence) if ask_sequence else "",
        "cta_pattern": cta_pattern,
        "identity_claim": identity_claim,
        "payment_rail": payment_rail,
        "sensitive": sensitive,
    }


def _classify_channel(channel: str) -> str:
    m = {
        "sms": "sms", "whatsapp": "im", "messenger": "im",
        "email": "email", "browser": "email",
        "phone_call": "phone_transcript",
        "pdf": "pdf", "qr": "qr",
    }
    return m.get(channel, "sms")


def _url_shape(urls: List[str]) -> str:
    if not urls:
        return "no-url"
    combined = " ".join(urls).lower()
    if any(k in combined for k in ["bit.ly", "tinyurl", "tiny.cc", "shorturl", "short", "t.co"]):
        return "shortener"
    brand_patterns = [r"([a-z]+[-\s]*[a-z]*)[.\-]?(livrare|tracking|plat[ei]|pay|secure|verificare|confirmare)\.(ro|com|xyz|info|top|online|site)"]
    for pat in brand_patterns:
        if re.search(pat, combined, re.IGNORECASE):
            return "brand-lookalike-domain"
    return "direct-url"


def extract_fingerprint(
    raw_text: str,
    *,
    channel: str = "sms",
    claimed_identity: Optional[str] = None,
    urls: Optional[List[str]] = None,
    arc_family: Optional[str] = None,
) -> CampaignFingerprint:
    text_lower = _normalize(raw_text)
    cleaned = _clean_skeleton_text(raw_text)
    tokens = _filter_stop(_tokenize(cleaned))
    simhash_val = _simhash(tokens)
    simhash_hex = format(simhash_val, "016x")

    signals = _extract_signals(text_lower, claimed_identity)
    now = time.time()
    fp_id = f"cf_{int(now)}_{hashlib.md5(raw_text.encode()).hexdigest()[:8]}"

    return CampaignFingerprint(
        fingerprint_id=fp_id,
        locale="ro-RO",
        channel_class=_classify_channel(channel),
        arc_family=arc_family or signals["identity_claim"],
        ask_sequence_sig=signals["ask_sequence"],
        cta_pattern_sig=signals["cta_pattern"],
        identity_claim_sig=signals["identity_claim"],
        payment_rail_sig=signals["payment_rail"],
        sensitive_request_sig=signals["sensitive"],
        text_skeleton_hash=simhash_hex,
        url_shape_sig=_url_shape(urls or []),
        no_raw_iocs=True,
        created_at=now,
    )


def compute_similarity(a: CampaignFingerprint, b: CampaignFingerprint) -> float:
    hash_score = 0.0
    if a.text_skeleton_hash and b.text_skeleton_hash and len(a.text_skeleton_hash) == 16 and len(b.text_skeleton_hash) == 16:
        hash_a = int(a.text_skeleton_hash, 16)
        hash_b = int(b.text_skeleton_hash, 16)
        hash_score = _simhash_similarity(hash_a, hash_b)

    struct_score = 0.0
    struct_matches = 0
    total_checks = 0

    if a.arc_family and b.arc_family:
        total_checks += 1
        if a.arc_family == b.arc_family:
            struct_matches += 1

    if a.cta_pattern_sig and b.cta_pattern_sig:
        total_checks += 1
        if a.cta_pattern_sig == b.cta_pattern_sig:
            struct_matches += 1

    if a.identity_claim_sig and b.identity_claim_sig:
        total_checks += 1
        if a.identity_claim_sig == b.identity_claim_sig:
            struct_matches += 1

    if a.payment_rail_sig and b.payment_rail_sig:
        total_checks += 1
        if a.payment_rail_sig == b.payment_rail_sig:
            struct_matches += 1

    if a.sensitive_request_sig and b.sensitive_request_sig:
        total_checks += 1
        a_set = set(a.sensitive_request_sig)
        b_set = set(b.sensitive_request_sig)
        if a_set & b_set:
            struct_matches += 1

    if total_checks > 0:
        struct_score = struct_matches / total_checks

    combined = hash_score * 0.5 + struct_score * 0.5
    return combined


class CfxStore:
    def __init__(self):
        self._fingerprints: Dict[str, CampaignFingerprint] = {}

    def put(self, fp: CampaignFingerprint) -> None:
        self._fingerprints[fp.fingerprint_id] = fp

    def get(self, fp_id: str) -> Optional[CampaignFingerprint]:
        return self._fingerprints.get(fp_id)

    def all(self) -> List[CampaignFingerprint]:
        return list(self._fingerprints.values())

    def match(self, query: CampaignFingerprint, threshold: float = MATCH_THRESHOLD) -> List[FingerprintMatch]:
        results = []
        for fp in self._fingerprints.values():
            sim = compute_similarity(query, fp)
            results.append(FingerprintMatch(
                fingerprint_id=fp.fingerprint_id,
                arc_family=fp.arc_family,
                similarity=sim,
                matched=sim >= threshold,
            ))
        results.sort(key=lambda r: r.similarity, reverse=True)
        return results

    def seed_from_campaigns(self, intels: List[Any]) -> None:
        for intel in intels:
            if intel.status != "active":
                continue
            skeleton = intel.skeleton or {}
            text_parts = [
                skeleton.get("claimed_identity", ""),
                skeleton.get("ask", ""),
                str(skeleton.get("channel", "sms")),
            ]
            raw_text = " ".join(text_parts)
            fp_id = f"cf_{intel.intel_id}"
            fp = extract_fingerprint(
                raw_text,
                channel=intel.skeleton.get("channel", "sms") if intel.skeleton else "sms",
                claimed_identity=skeleton.get("claimed_identity") if skeleton else None,
                arc_family=FAMILY_TAXONOMY.get(intel.family, intel.family),
            )
            fp.fingerprint_id = fp_id
            self.put(fp)


from services.campaign_intel import FAMILY_TAXONOMY
