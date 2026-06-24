"""Shared scan helpers extracted from runtime.py."""

from __future__ import annotations

from typing import Any, Callable, Dict, Optional, Set, Tuple

from fastapi import HTTPException
from starlette.concurrency import run_in_threadpool

from config import ALLOWED_MOCK_OCR, PRIVACY_SAFE_MODE
from services.google_vision_ocr import has_vision_key


def _validate_text_input(field_name: str, value: str, max_chars: int) -> None:
    if not value or not value.strip():
        raise HTTPException(status_code=400, detail=f"{field_name} nu poate fi gol.")
    if len(value) > max_chars:
        raise HTTPException(
            status_code=413,
            detail=f"{field_name} depășește limita de {max_chars} caractere.",
        )


def _validate_file_upload(
    filename: str,
    content_type: str | None,
    file_bytes: bytes,
    *,
    max_bytes: int,
    allowed_exts: Set[str],
    allowed_mime_types: Set[str],
    magic_validator: Optional[Callable[[bytes], bool]] = None,
) -> None:
    if len(file_bytes) > max_bytes:
        raise HTTPException(
            status_code=413,
            detail=f"Fisierul este prea mare. Limita maxima este {max_bytes // 1024 // 1024} MB.",
        )

    ext = filename.lower().rsplit(".", 1)
    ext = f".{ext[-1]}" if len(ext) == 2 else ""
    if ext not in allowed_exts and (not content_type or content_type.lower() not in allowed_mime_types):
        raise HTTPException(
            status_code=400,
            detail=(
                "Tipul fisierului nu este acceptat. "
                f"Extensii permise: {', '.join(sorted(allowed_exts))}"
            ),
        )
    if magic_validator is not None and not magic_validator(file_bytes):
        raise HTTPException(
            status_code=400,
            detail="Fișierul nu pare să fie un format valid pentru tipul declarat.",
        )


def _is_allowed_image_bytes(file_bytes: bytes) -> bool:
    if file_bytes.startswith(b"\xff\xd8\xff"):
        return True
    if file_bytes.startswith(b"\x89PNG\r\n\x1a\n"):
        return True
    return len(file_bytes) >= 12 and file_bytes[:4] == b"RIFF" and file_bytes[8:12] == b"WEBP"


def mock_ocr_text_by_filename(filename: str) -> str:
    """
    Fallback text used when OCR cloud is unavailable.
    Kept for deterministic demo/test behavior on common scam themes.
    """
    filename_lower = filename.lower()

    if "anaf" in filename_lower or "spv" in filename_lower:
        return (
            "ANAF: Notificare de plata urgenta. Aveti o obligatie fiscala neachitata in valoare de 450 RON. "
            "Neplata va atrage penalizări. Conectati-va in SPV si platiti aici: http://anaf-spv-plati.info/login"
        )
    if "posta" in filename_lower:
        return (
            "Posta Romana: Pachetul dvs. a sosit in depozit dar adresa este incompleta. "
            "Va rugam completati adresa corecta si achitati taxa de 2.45 RON: http://posta-romana-taxe.top"
        )
    if "revolut" in filename_lower:
        return (
            "Revolut: Contul tau a fost blocat temporar din motive de securitate. "
            "Va rugam confirmati identitatea si deblocati aplicatia accesand link-ul: http://revolut-security.net/verify"
        )
    if "olx" in filename_lower:
        return (
            "Buna ziua, am efectuat plata prin OLX. Pentru a incasa banii de pe produs, va rugam faceti click pe link "
            "si introduceti datele cardului dvs.: http://olx-ro-tranzactii.online/payment"
        )
    if "whatsapp" in filename_lower:
        return (
            "WhatsApp: Codul tau de verificare este [492-385]. Nu distribui acest cod cu nimeni."
        )

    return (
        "Stimate client, coletul tau nr. RO-5829-X9 nu a putut fi livrat din cauza adresei incomplete. "
        "Va rugam actualizati adresa si alegeti lockerul de ridicare aici: http://fan-locker-ridicare.ru/awb"
    )


async def extract_text_for_scan(
    filename: str,
    file_bytes: bytes,
    extract_fn: Callable[[bytes], str],
) -> tuple[str, Optional[str]]:
    """
    Runs OCR through Google Vision when configured, with deterministic fallback.
    Returns extracted text and an OCR warning if OCR was unavailable or partial.
    """
    ocr_warning: Optional[str] = None
    ocr_text = ""

    if PRIVACY_SAFE_MODE:
        ocr_warning = "Mod sigur activ: OCR cloud dezactivat."
    elif has_vision_key():
        try:
            ocr_text = await run_in_threadpool(extract_fn, file_bytes)
            if not ocr_text.strip():
                ocr_warning = "OCR cloud nu a extras text din fișier."
        except Exception as exc:
            ocr_warning = f"Fallback OCR pe nume fișier: {str(exc)}"
    else:
        ocr_warning = (
            "Lipsește GOOGLE_CLOUD_VISION_API_KEY. Se folosește scenariu mock pe nume fișier."
        )

    if not ocr_text.strip() and ALLOWED_MOCK_OCR:
        ocr_text = mock_ocr_text_by_filename(filename)
    if not ocr_text.strip():
        if ocr_warning is None:
            ocr_warning = "OCR-ul nu a returnat niciun text din acest fisier."
        raise HTTPException(status_code=503, detail=ocr_warning)

    return ocr_text, ocr_warning


def _invoice_payment_destination_for_client(
    result: Any,
    invoice_gate: Optional[Dict[str, Any]] = None,
) -> Optional[Dict[str, Any]]:
    raw = getattr(result, "payment_destination", None) if result else None
    payload = dict(raw) if isinstance(raw, dict) else None
    bundle = invoice_gate.get("bundle") if isinstance(invoice_gate, dict) else None
    providers = bundle.get("providers") if isinstance(bundle, dict) else {}
    evidence_payment = providers.get("payment_destination") if isinstance(providers, dict) else None
    if isinstance(evidence_payment, dict):
        promotes_destination = bool(
            evidence_payment.get("matched") is True
            or evidence_payment.get("can_contribute_to_safe") is True
            or evidence_payment.get("trust_tier") == "T2_OFFICIAL_DOCUMENT_CHAIN"
        )
        if promotes_destination or payload is None:
            payload = {**(payload or {}), **evidence_payment}
    if not isinstance(payload, dict):
        return None

    trust_tier = str(payload.get("trust_tier") or "")
    if not payload.get("display"):
        if payload.get("can_contribute_to_safe") is True:
            if trust_tier == "T2_OFFICIAL_DOCUMENT_CHAIN":
                payload["display"] = "IBAN confirmat prin document oficial"
            elif trust_tier in {"T0_PARTNER_SIGNED", "T1_PUBLIC_OFFICIAL"}:
                payload["display"] = "IBAN publicat de furnizor într-o sursă oficială"
            else:
                payload["display"] = "Destinație de plată confirmată"
        elif payload.get("cui_matches") is False or (
            payload.get("brand_matches") is False
            and payload.get("cui_matches") is not True
        ):
            # cui_matches=True => same legal entity; don't claim the IBAN belongs
            # to someone else just because the brand-name string differed.
            payload["display"] = "IBAN asociat altei entități"
        elif payload.get("matched") is False:
            payload["display"] = "IBAN valid, dar destinație neconfirmată"
        else:
            payload["display"] = "Destinație verificată parțial"
    return payload

