import base64
import os
from typing import Any

import requests

GOOGLE_CLOUD_VISION_API_KEY = os.environ.get("GOOGLE_CLOUD_VISION_API_KEY")
GOOGLE_CLOUD_VISION_LOCATION = os.environ.get("GOOGLE_CLOUD_VISION_LOCATION", "eu")


def _get_vision_host() -> str:
    """Return Google Vision host based on configured region."""
    return (
        f"{GOOGLE_CLOUD_VISION_LOCATION}-vision.googleapis.com"
        if GOOGLE_CLOUD_VISION_LOCATION
        else "vision.googleapis.com"
    )


def has_vision_key() -> bool:
    return bool(GOOGLE_CLOUD_VISION_API_KEY)


def extract_text_with_vision(image_bytes: bytes) -> str:
    """Extract text from image bytes using Google Cloud Vision DOCUMENT_TEXT_DETECTION."""
    if not GOOGLE_CLOUD_VISION_API_KEY:
        raise RuntimeError("Lipsește GOOGLE_CLOUD_VISION_API_KEY.")

    # Cost guard (#82): stop paid OCR calls once the monthly budget is spent.
    # Same failure path callers already handle for a missing key/timeouts.
    from services.paid_provider_budgets import consume_google_vision

    if not consume_google_vision():
        raise RuntimeError("Google Vision monthly budget exhausted.")

    image_b64 = base64.b64encode(image_bytes).decode("utf-8")
    host = _get_vision_host()
    endpoint = f"https://{host}/v1/images:annotate?key={GOOGLE_CLOUD_VISION_API_KEY}"
    payload: dict[str, Any] = {
        "requests": [
            {
                "image": {"content": image_b64},
                "features": [
                    {
                        "type": "DOCUMENT_TEXT_DETECTION",
                        "model": "builtin/stable",
                    }
                ],
                "imageContext": {"languageHints": ["ro", "en"]},
            }
        ]
    }

    try:
        response = requests.post(endpoint, json=payload, timeout=15)
        response.raise_for_status()
        data = response.json()
    except requests.Timeout as exc:
        raise RuntimeError("Vision API request timeout.") from exc
    except requests.RequestException as exc:
        raise RuntimeError(f"Vision API request failed: {exc}") from exc
    except ValueError as exc:
        raise RuntimeError("Vision API response invalid JSON.") from exc

    responses = data.get("responses", []) if isinstance(data, dict) else []
    if not responses:
        return ""

    first = responses[0]
    if not isinstance(first, dict):
        return ""

    if first.get("error"):
        message = first["error"].get("message", "Unknown Vision API error") if isinstance(first["error"], dict) else "Unknown Vision API error"
        raise RuntimeError(message)

    text = (first.get("fullTextAnnotation") or {}).get("text", "")
    if isinstance(text, str) and text.strip():
        return text.strip()

    annotations = first.get("textAnnotations", [])
    if annotations and isinstance(annotations, list):
        first_annotation = annotations[0]
        description = first_annotation.get("description") if isinstance(first_annotation, dict) else None
        if isinstance(description, str):
            return description.strip()

    return ""


def extract_text_from_pdf_with_vision(pdf_bytes: bytes) -> str:
    """Extract text from PDF bytes using Google Cloud Vision DOCUMENT_TEXT_DETECTION."""
    if not GOOGLE_CLOUD_VISION_API_KEY:
        raise RuntimeError("Lipsește GOOGLE_CLOUD_VISION_API_KEY.")

    # Cost guard (#82): same paid Vision quota as the image OCR path.
    from services.paid_provider_budgets import consume_google_vision

    if not consume_google_vision():
        raise RuntimeError("Google Vision monthly budget exhausted.")

    pdf_b64 = base64.b64encode(pdf_bytes).decode("utf-8")
    host = _get_vision_host()
    endpoint = f"https://{host}/v1/files:annotate?key={GOOGLE_CLOUD_VISION_API_KEY}"
    payload: dict[str, Any] = {
        "requests": [
            {
                "inputConfig": {
                    "mimeType": "application/pdf",
                    "content": pdf_b64,
                },
                "features": [{"type": "DOCUMENT_TEXT_DETECTION"}],
                "pages": [1, 2, 3, 4, 5],
            }
        ]
    }

    try:
        response = requests.post(endpoint, json=payload, timeout=20)
        response.raise_for_status()
        data = response.json()
    except requests.Timeout as exc:
        raise RuntimeError("Vision API request timeout.") from exc
    except requests.RequestException as exc:
        raise RuntimeError(f"Vision API request failed: {exc}") from exc
    except ValueError as exc:
        raise RuntimeError("Vision API response invalid JSON.") from exc

    responses = data.get("responses", []) if isinstance(data, dict) else []
    if not responses:
        return ""

    file_response = responses[0]
    if not isinstance(file_response, dict):
        return ""

    if file_response.get("error"):
        message = (
            file_response["error"].get("message", "Unknown Vision API error")
            if isinstance(file_response["error"], dict)
            else "Unknown Vision API error"
        )
        raise RuntimeError(message)

    page_responses = file_response.get("responses", [])
    page_texts: list[str] = []

    for page in page_responses if isinstance(page_responses, list) else []:
        if page.get("error"):
            message = (
                page["error"].get("message", "Unknown Vision API error")
                if isinstance(page.get("error"), dict)
                else "Unknown Vision API error"
            )
            raise RuntimeError(message)

        text = (page.get("fullTextAnnotation") or {}).get("text", "")
        if isinstance(text, str) and text.strip():
            page_texts.append(text.strip())
            continue

        annotations = page.get("textAnnotations", [])
        if annotations and isinstance(annotations, list):
            first_annotation = annotations[0]
            description = first_annotation.get("description") if isinstance(first_annotation, dict) else None
            if isinstance(description, str) and description.strip():
                page_texts.append(description.strip())

    return "\n\n".join(page_texts).strip()
