from __future__ import annotations

import re
import urllib.parse
from typing import Any, Dict, List, Optional

import html
from bs4 import BeautifulSoup, Comment

from core.text_utils import _normalise_obfuscated_text
from core.url_intelligence import _canonicalize_url, extract_urls


_BUTTON_TYPES = {"button", "submit", "image"}
_INLINE_CLICK_URL_RE = re.compile(r"https?://[^\s\"'<>]+|//[^\s\"'<>]+")
_RE_LINK_TOKEN = re.compile(r"[\"']([^\"']+)[\"']")
_JS_QUOTED_VALUE_RE = re.compile(r"'(?:[^'\\]|\\.)*'|\"(?:[^\"\\]|\\.)*\"|`(?:[^`\\]|\\.)*`")
_JS_VARIABLE_RE = re.compile(
    r"\b(?:var|let|const)\s+([A-Za-z_$][A-Za-z0-9_$]*)\s*=\s*("
    r"'(?:[^'\\]|\\.)*'|\"(?:[^\"]|\\.)*\"|`(?:[^`\\\\]|\\\\.)*`"
    r")"
)
_JS_NAV_ASSIGN_RE = re.compile(
    r"""
    (?:(?:window|top|self)\s*
      (?:\.\s*location|\[\s*['\"]location['\"]\s*\])
      |
      document\s*
      (?:\.\s*location|\[\s*['\"]location['\"]\s*\])
      |
      location
      |
      document\.location
    )
    (?:\s*(?:\.\s*href|\[\s*['\"]href['\"]\s*\]))?\s*
    =\s*([^;]+)
    """,
    re.IGNORECASE | re.VERBOSE,
)
_JS_NAV_ASSIGN_ALT_RE = re.compile(
    r"(?:window\.|top\.|self\.)?(?:location\.(?:assign|replace)|open)\s*\(\s*([^,\)]+)",
    re.IGNORECASE,
)
_JS_CLICK_LIKE_RE = re.compile(
    r"""
    \b(?:javascript:|window|document|top|self)\b
    |
    (?:^|\s)(?:var|let|const)\s+location\s*=
    |
    (?:^|\s)location\s*(?:=|\.|\[)
    |
    \b(?:open|assign|replace)\s*\(
    """,
    re.IGNORECASE | re.MULTILINE | re.VERBOSE,
)
_CLICKABLE_ROLES = {"button", "link"}
_GENERIC_CLICK_ATTRS = ("onclick", "data-href", "data-url", "data-action", "data-link", "data-target")


def _extract_button_text(node: Any) -> str:
    """
    Extract an actionable label for a clickable node, using the most likely
    human-visible text.
    """
    if node is None:
        return ""
    if getattr(node, "name", "").lower() == "input":
        return (
            (node.get("value") or "").strip()
            or (node.get("alt") or "").strip()
            or (node.get("aria-label") or "").strip()
            or (node.get("title") or "").strip()
        )

    text = (node.get("aria-label") or node.get("title") or "").strip()
    if text:
        return text
    return (node.get_text(separator=" ", strip=True) or "").strip()


def _decode_js_string_literal(raw: str) -> str:
    """
    Decode a quoted JS string literal into a raw string.
    """
    if not raw:
        return ""
    quote = raw[0]
    if quote not in {"'", '"', "`"} or len(raw) < 2:
        return ""
    body = raw[1:-1]
    if quote == "`":
        body = re.sub(r"\$\{[^}]*\}", "", body)
    try:
        return bytes(body, "utf-8").decode("unicode_escape")
    except Exception:
        return body


def _split_js_plus_expression(expression: str) -> List[str]:
    """
    Best-effort split for JS concatenations around +, respecting quoted strings.
    """
    parts: List[str] = []
    current = []
    in_quote: str | None = None
    escape = False
    for ch in expression:
        if escape:
            current.append(ch)
            escape = False
            continue
        if ch == "\\" and in_quote:
            current.append(ch)
            escape = True
            continue
        if in_quote:
            current.append(ch)
            if ch == in_quote:
                in_quote = None
            continue
        if ch in {"'", '"', "`"}:
            in_quote = ch
            current.append(ch)
            continue
        if ch == "+":
            segment = "".join(current).strip()
            if segment:
                parts.append(segment)
            current = []
            continue
        current.append(ch)

    segment = "".join(current).strip()
    if segment:
        parts.append(segment)
    return parts


def _resolve_js_concat_expression(expression: str, var_values: Dict[str, str]) -> List[str]:
    """
    Resolve simple JS concat expressions into concrete URL strings.
    """
    if not expression:
        return []
    normalized_expression = expression.strip().strip("()")
    parts = _split_js_plus_expression(normalized_expression)
    if not parts:
        return []

    resolved_parts: List[str] = []
    has_unresolved = False
    for part in parts:
        token = part.strip().strip("()")
        if not token:
            continue
        if token[0] in {"'", '"', "`"} and token[-1] == token[0]:
            resolved_parts.append(_decode_js_string_literal(token))
            continue
        if token in var_values:
            resolved_parts.append(var_values[token])
            continue
        # Ignore bare `window.location` or placeholder values we cannot evaluate
        if token.lower().replace(" ", "") in {
            "window.location",
            "location",
            "document.location",
            "window.location.href",
            "location.href",
            "self.location",
            "top.location",
        }:
            continue
        has_unresolved = True

    if has_unresolved:
        return []
    if not resolved_parts:
        return []
    return ["".join(resolved_parts)]


def _is_relative_click_url(raw_url: str) -> bool:
    normalized = (raw_url or "").strip()
    return normalized.startswith(("/", "./", "../", "?"))


def _is_likely_js_url_token(token: str) -> bool:
    """
    Best-effort gate for string tokens extracted from JS snippets.
    """
    normalized = (token or "").strip().strip("`'\"")
    if not normalized:
        return False
    lowered = normalized.lower()
    if lowered.startswith(("http://", "https://", "//", "/", "./", "../", "?")):
        return True
    if any(char.isspace() for char in normalized):
        return False
    if "://" in lowered:
        return True
    return "." in normalized


def _normalize_click_target_url(raw_url: str, base_url: str | None = None) -> Optional[str]:
    """
    Normalize click targets without dropping relative URLs.

    If a relative target (like /verify) is found and no base is available, keep it
    as-is so it can still be treated as a risky unresolved destination.
    """
    normalized = (raw_url or "").strip().strip(" ;\")'`")
    if not normalized:
        return None

    if normalized.lower().startswith("javascript:"):
        normalized = normalized[len("javascript:") :].strip()

    if normalized.startswith("//"):
        normalized = f"https:{normalized}"

    if base_url and _is_relative_click_url(normalized):
        normalized = urllib.parse.urljoin(base_url, normalized)

    if _is_relative_click_url(normalized):
        return normalized

    return _canonicalize_url(normalized)


def _extract_urls_from_js_code(raw_js: str, base_url: str | None = None) -> List[str]:
    """
    Extract URLs from JS snippets used in event handlers.
    """
    normalized = _normalise_obfuscated_text(html.unescape(raw_js or ""))
    if not normalized:
        return []

    normalized = normalized.strip()
    if normalized.lower().startswith("javascript:"):
        normalized = normalized[len("javascript:") :].strip()

    if normalized.startswith("(") and normalized.endswith(")"):
        normalized = normalized[1:-1].strip()

    variable_values: Dict[str, str] = {}
    for match in _JS_VARIABLE_RE.finditer(normalized):
        var_name = match.group(1)
        raw_value = match.group(2)
        if not raw_value:
            continue
        variable_values[var_name] = _decode_js_string_literal(raw_value)

    expressions: List[str] = []
    for match in _JS_NAV_ASSIGN_RE.finditer(normalized):
        lhs = normalized[match.start():match.end()].split("=")[0].strip()
        if re.search(r"\b(?:var|let|const)\s+location\s*=", lhs, re.IGNORECASE):
            continue
        expressions.append(match.group(1).strip())
    expressions.extend(match.group(1).strip() for match in _JS_NAV_ASSIGN_ALT_RE.finditer(normalized))

    url_candidates: List[str] = []
    if not expressions:
        # Fall back to quoted URLs inside function args or inline snippets.
        for token in _RE_LINK_TOKEN.findall(normalized):
            if not _is_likely_js_url_token(token):
                continue
            url_candidates.append(token)

    for expr in expressions:
        expr = expr.strip().strip(" ;")
        if not expr:
            continue
        resolved = _resolve_js_concat_expression(expr, var_values)
        for resolved_expr in resolved:
            candidate = _normalize_click_target_url(resolved_expr, base_url=base_url)
            if candidate:
                url_candidates.append(candidate)

    seen_urls: set[str] = set()
    urls: List[str] = []
    for raw_url in url_candidates:
        url = _normalize_click_target_url(raw_url, base_url=base_url)
        if not url or url in seen_urls:
            continue
        seen_urls.add(url)
        urls.append(url)
    return urls


def _extract_urls_from_click_attr(raw_value: str, base_url: str | None = None) -> List[str]:
    normalized = _normalise_obfuscated_text(html.unescape(raw_value or ""))
    if _is_relative_click_url(normalized):
        resolved = _normalize_click_target_url(normalized, base_url=base_url)
        if resolved:
            return [resolved]

    if normalized.lower().startswith("javascript:"):
        normalized = normalized[len("javascript:") :].strip()

    direct_urls = _extract_urls_from_js_code(raw_value, base_url=base_url)
    is_inline_like = _JS_CLICK_LIKE_RE.search(normalized) is None
    if not direct_urls and is_inline_like:
        direct_urls = _INLINE_CLICK_URL_RE.findall(normalized)
    if base_url and is_inline_like:
        if normalized.startswith(("/", "./", "../", "?")):
            direct_urls.append(urllib.parse.urljoin(base_url, normalized))

    if base_url and is_inline_like:
        for token in _RE_LINK_TOKEN.findall(normalized):
            token = token.strip()
            if not token:
                continue
            token = _normalise_obfuscated_text(token)
            if token.lower().startswith(("http://", "https://")):
                direct_urls.append(token)
            elif token.startswith(("/", "./", "../", "?")):
                direct_urls.append(urllib.parse.urljoin(base_url, token))

    if direct_urls:
        urls: List[str] = []
        seen = set()
        for raw_url in direct_urls:
            url = _normalize_click_target_url(raw_url, base_url=base_url)
            if not url or url in seen:
                continue
            seen.add(url)
            urls.append(url)
        return urls
    return extract_urls(normalized)


def _collect_click_targets_from_html(soup: BeautifulSoup) -> list[Dict[str, Any]]:
    """
    Extract actionable links hidden in HTML call-to-action elements, not only `<a href>`.
    """
    targets: list[Dict[str, Any]] = []
    base_url = None
    base_tag = soup.find("base", href=True)
    if base_tag:
        base_url = _canonicalize_url(base_tag.get("href") or "")
        if base_url:
            parsed_base = urllib.parse.urlparse(base_url)
            if not parsed_base.scheme or not parsed_base.netloc:
                base_url = None
    seen_urls = set()

    def append_target(button_text: str, raw_url: str, source_tag: str, source_attr: str) -> None:
        for url in _extract_urls_from_click_attr(raw_url, base_url=base_url):
            if url in seen_urls:
                continue
            seen_urls.add(url)
            targets.append(
                {
                    "button_text": button_text,
                    "original_url": url,
                    "source_tag": source_tag,
                    "source_attr": source_attr,
                }
            )

    # Standard links
    for link in soup.find_all("a"):
        button_text = _extract_button_text(link) or "[Buton/Imagine fără text]"
        href = link.get("href") or link.get("xlink:href")
        if href:
            style = str(link.get("style") or "").lower()
            is_overlay = bool(
                re.search(r"position\s*:\s*absolute|inset\s*:\s*0|color\s*:\s*transparent", style)
            )
            attr_name = "href" if link.get("href") else "xlink:href"
            append_target(button_text, href, "a", "href_overlay" if is_overlay else attr_name)
        for attr in ("data-href", "data-url", "data-action", "data-link", "data-target", "onclick"):
            value = link.get(attr)
            if value:
                append_target(button_text, value, "a", attr)

    # <button> and CTA-like input controls
    for btn in soup.find_all("button"):
        button_text = _extract_button_text(btn) or "[Buton/Imagine fără text]"
        if btn.get("formaction"):
            append_target(button_text, btn.get("formaction"), "button", "formaction")
        if btn.get("onclick"):
            append_target(button_text, btn.get("onclick"), "button", "onclick")
        for attr in ("data-href", "data-url", "data-action", "data-link", "data-target"):
            value = btn.get(attr)
            if value:
                append_target(button_text, value, "button", attr)

    for inp in soup.find_all("input"):
        input_type = (inp.get("type") or "").lower().strip()
        if input_type and input_type not in _BUTTON_TYPES:
            continue
        button_text = _extract_button_text(inp) or "[Buton/Imagine fără text]"
        if inp.get("formaction"):
            append_target(button_text, inp.get("formaction"), "input", "formaction")
        if inp.get("onclick"):
            append_target(button_text, inp.get("onclick"), "input", "onclick")
        for attr in ("data-href", "data-url", "data-action", "data-link", "data-target"):
            value = inp.get(attr)
            if value:
                append_target(button_text, value, "input", attr)

    # Clickable image maps and other semantic areas
    for area in soup.find_all("area"):
        button_text = _extract_button_text(area) or "[Buton/Imagine fără text]"
        if area.get("href"):
            append_target(button_text, area.get("href"), "area", "href")
        if area.get("onclick"):
            append_target(button_text, area.get("onclick"), "area", "onclick")

    # Outlook/VML "bulletproof" buttons used by most branded HTML emails. The
    # generic loop below skips them because they carry no role/onclick, only href.
    for vml in soup.find_all(["v:roundrect", "v:rect", "v:shape", "v:oval"]):
        href = vml.get("href")
        if href:
            button_text = _extract_button_text(vml) or "[Buton/Imagine fără text]"
            append_target(button_text, href, vml.name, "href")

    # Outlook conditional comments (<!--[if mso]> ... <![endif]-->) hide the
    # VML button markup from html.parser as plain comments, so the linkable
    # content inside them is parsed separately.
    for comment in soup.find_all(string=lambda text: isinstance(text, Comment)):
        raw = str(comment)
        lowered = raw.lower()
        if "href" not in lowered or ("[if" not in lowered and "<v:" not in lowered):
            continue
        fragment = BeautifulSoup(raw, "html.parser")
        for node in fragment.find_all(["v:roundrect", "v:rect", "v:shape", "v:oval", "a", "area"]):
            href = node.get("href")
            if href:
                button_text = _extract_button_text(node) or "[Buton/Imagine fără text]"
                append_target(button_text, href, f"mso-comment:{node.name}", "href")

    # Generic click-capable elements commonly used in branded phishing templates
    for tag in soup.find_all(True):
        tag_name = tag.name.lower()
        if tag_name in {"a", "button", "input", "area", "form"}:
            continue

        role = (tag.get("role") or "").lower().strip()
        has_interaction_attr = tag.has_attr("onclick") or any(tag.get(attr) for attr in _GENERIC_CLICK_ATTRS)
        if role not in _CLICKABLE_ROLES and not has_interaction_attr:
            continue

        button_text = _extract_button_text(tag) or "[Buton/Imagine fără text]"
        href = tag.get("href") or tag.get("xlink:href")
        if href:
            append_target(button_text, href, tag_name, "href" if tag.get("href") else "xlink:href")
        if tag.get("onclick"):
            append_target(button_text, tag.get("onclick"), tag_name, "onclick")
        for attr in _GENERIC_CLICK_ATTRS:
            value = tag.get(attr)
            if value:
                append_target(button_text, value, tag_name, attr)

    # Fallback for form actions when no direct button action was found
    for form in soup.find_all("form"):
        if not form.get("action"):
            continue
        submit_like = form.find_all(["button", "input"], recursive=True)
        button_text = "[Buton/Imagine fără text]"
        for node in submit_like:
            node_type = (node.get("type") or "").lower()
            if not node_type or node_type in _BUTTON_TYPES or node.name == "button":
                extracted = _extract_button_text(node)
                if extracted:
                    button_text = extracted
                    break
        append_target(button_text, form.get("action"), "form", "action")

    return targets


def _collect_form_context_from_html(soup: BeautifulSoup) -> list[str]:
    contexts: list[str] = []
    for form in soup.find_all("form"):
        raw_action = str(form.get("action") or "").strip()
        action_urls = _extract_urls_from_click_attr(raw_action) if raw_action else []
        field_tokens: list[str] = []
        for field in form.find_all(["input", "textarea", "select"], recursive=True):
            field_bits = [
                field.name,
                field.get("type"),
                field.get("name"),
                field.get("id"),
                field.get("autocomplete"),
                field.get("placeholder"),
            ]
            compact = ":".join(str(bit).strip() for bit in field_bits if str(bit or "").strip())
            if compact and compact not in field_tokens:
                field_tokens.append(compact)
        submit_texts: list[str] = []
        for node in form.find_all(["button", "input"], recursive=True):
            node_type = (node.get("type") or "").lower()
            if node.name == "button" or not node_type or node_type in _BUTTON_TYPES:
                label = _extract_button_text(node)
                if label and label not in submit_texts:
                    submit_texts.append(label)
        if not raw_action and not field_tokens and not submit_texts:
            continue
        contexts.append(
            "FORM action: "
            + (", ".join(action_urls) if action_urls else raw_action or "[no-action]")
            + " fields: "
            + (", ".join(field_tokens) if field_tokens else "[none]")
            + " submit: "
            + (", ".join(submit_texts) if submit_texts else "[none]")
        )
    return contexts
