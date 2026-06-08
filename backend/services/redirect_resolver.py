import requests
import tldextract
import re
from typing import List, Dict, Any, Tuple, Optional
import urllib.parse
import ipaddress
import socket
import datetime
from concurrent.futures import ThreadPoolExecutor

try:
    import certifi
except Exception:  # pragma: no cover - optional dependency
    certifi = None

# Common executable/binary MIME types or extensions we want to avoid downloading
DANGEROUS_MIMES = [
    "application/octet-stream",
    "application/x-msdownload",  # .exe, .dll
    "application/x-sh",
    "application/x-ms-shortcut", # .lnk
    "application/zip",
    "application/x-tar",
    "application/x-rar-compressed",
    "application/x-debian-package",
    "application/vnd.android.package-archive" # .apk
]

# Known URL shortener domains — any link through these is suspicious in a cold message
KNOWN_SHORTENERS = {
    "bit.ly", "bitly.com", "tinyurl.com", "t.ly", "shorturl.at", "is.gd",
    "goo.gl", "ow.ly", "cutt.ly", "rebrand.ly", "bl.ink", "short.io",
    "tiny.cc", "lnkd.in", "buff.ly", "clck.ru", "rb.gy", "v.gd",
    "qr.ae", "adf.ly", "bc.vc", "j.mp", "surl.li", "s.id", "postis.io", "t.postis.io",
    "rotf.lol", "1url.com", "hyperurl.co", "urlzs.com", "u.to",
    "shrtco.de", "lmy.de", "shorturl.asia", "link.ac"
}

# Regex to extract meta-refresh redirect URLs from HTML
# Matches: <meta http-equiv="refresh" content="0; url=https://example.com">
META_REFRESH_RE = re.compile(
    r'<meta\s+[^>]*?http-equiv\s*=\s*["\']?refresh["\']?\s+[^>]*?content\s*=\s*["\']?\d+\s*;\s*url\s*=\s*([^"\'\s>]+)',
    re.IGNORECASE
)

# Regex to detect JavaScript-based redirects in HTML body
# Matches: window.location = "...", window.location.href = "...",
# location.replace("..."), document.location = "..."
JS_REDIRECT_PATTERNS = [
    re.compile(r'(?:window\.)?location(?:\.href)?\s*=\s*["\']([^"\']+)["\']', re.IGNORECASE),
    re.compile(r'(?:window\.)?location\.replace\s*\(\s*["\']([^"\']+)["\']', re.IGNORECASE),
    re.compile(r'document\.location\s*=\s*["\']([^"\']+)["\']', re.IGNORECASE),
    re.compile(r'window\.open\s*\(\s*["\']([^"\']+)["\']', re.IGNORECASE),
]

# Maximum bytes of HTML body to read when scanning for meta/JS redirects
# Keeps things safe — we only look at the first 32KB of text/html responses
MAX_HTML_SCAN_BYTES = 32 * 1024

LOCAL_HOST_BLOCKLIST = {
    "localhost",
    "localhost.localdomain",
    "local",
    "localdomain",
}

CF_DNS_API_URL = "https://cloudflare-dns.com/dns-query"


def _get_registrable_domain(extracted: "tldextract.ExtractResult") -> str:
    domain = getattr(extracted, "top_domain_under_public_suffix", "")
    if isinstance(domain, str) and domain.strip():
        return domain.strip().lower()
    return ""


def _is_scan_target_blocked(url: str) -> str | None:
    """
    Detects scan targets that should be rejected to prevent SSRF-like behavior.
    Returns a short reason string when blocked, otherwise None.
    """
    parsed = urllib.parse.urlparse(url)
    scheme = (parsed.scheme or "").lower()
    if not scheme:
        return "Scheme missing"
    if scheme not in {"http", "https"}:
        return f"Unsupported scheme '{scheme}'"

    hostname = (parsed.hostname or "").lower()
    if not hostname:
        return "Hostname missing"

    if hostname in LOCAL_HOST_BLOCKLIST:
        return "Internal hostname blocked"
    if hostname.endswith(".local") or hostname.endswith(".internal") or hostname.endswith(".localhost"):
        return "Internal domain blocked"

    try:
        ip = ipaddress.ip_address(hostname)
        if (
            ip.is_private
            or ip.is_loopback
            or ip.is_link_local
            or ip.is_multicast
            or ip.is_reserved
            or ip.is_unspecified
        ):
            return "Private/reserved IP blocked"
    except ValueError:
        # Not a direct IP address. Keep scanning on hostname.
        pass

    return None


def get_domain_info(url: str) -> Tuple[str, str]:
    """
    Extracts the hostname and registered domain (e.g., brand.ro) from a URL.
    Returns (hostname, registered_domain).
    """
    try:
        parsed = urllib.parse.urlparse(url)
        hostname = parsed.hostname or ""
        extracted = tldextract.extract(url)
        registered_domain = _get_registrable_domain(extracted) or hostname
        return hostname, registered_domain
    except Exception:
        return "", ""


def is_known_shortener(url: str) -> bool:
    """Checks if a URL belongs to a known shortener service."""
    try:
        _, reg_domain = get_domain_info(url)
        hostname = urllib.parse.urlparse(url).hostname or ""
        return (
            reg_domain.lower() in KNOWN_SHORTENERS or
            hostname.lower() in KNOWN_SHORTENERS
        )
    except Exception:
        return False


def query_rotld_whois(domain: str) -> str:
    """
    Sends a query to whois.rotld.ro on port 43 and returns the response string.
    """
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(2.0)
        s.connect(('whois.rotld.ro', 43))
        s.sendall(f"{domain}\r\n".encode('utf-8'))
        response = b""
        while True:
            chunk = s.recv(4096)
            if not chunk:
                break
            response += chunk
        s.close()
        return response.decode('utf-8', errors='ignore')
    except Exception:
        return ""


def check_domain_age(domain: str) -> Tuple[Optional[int], Optional[str]]:
    """
    Tries to find the creation date/age in days for the given registered domain.
    Returns (age_days, creation_date_str).
    """
    if not domain:
        return None, None
        
    domain = domain.lower().strip()
    
    # 1. Handle .ro domains specifically using ROTLD WHOIS
    if domain.endswith(".ro"):
        response = query_rotld_whois(domain)
        if not response:
            return None, None
            
        # Parse "Registered On: Before 2001" or "Registered On: YYYY-MM-DD"
        match = re.search(r'Registered On:\s*(Before 2001|\d{4}-\d{2}-\d{2})', response, re.IGNORECASE)
        if match:
            date_val = match.group(1).strip()
            if date_val.lower() == "before 2001":
                created_date = "2000-01-01"
            else:
                created_date = date_val
            
            try:
                dt = datetime.datetime.strptime(created_date, "%Y-%m-%d").date()
                today = datetime.date.today()
                delta = today - dt
                return max(0, delta.days), created_date
            except Exception:
                return None, None
        return None, None
        
    # 2. Handle generic TLDs using RDAP
    headers = {
        "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
    }
    try:
        r = requests.get(f"https://rdap.org/domain/{domain}", headers=headers, timeout=3.0)
        if r.status_code == 200:
            data = r.json()
            events = data.get("events", [])
            created_date_raw = None
            
            # Find the registration or creation event
            for event in events:
                action = event.get("eventAction", "").lower()
                if action in ("registration", "creation", "registration date", "creation date"):
                    created_date_raw = event.get("eventDate")
                    break
            if not created_date_raw:
                for event in events:
                    action = event.get("eventAction", "").lower()
                    if "reg" in action or "creat" in action:
                        created_date_raw = event.get("eventDate")
                        break
                        
            if created_date_raw:
                created_date = created_date_raw[:10]  # Get YYYY-MM-DD
                dt = datetime.datetime.strptime(created_date, "%Y-%m-%d").date()
                today = datetime.date.today()
                delta = today - dt
                return max(0, delta.days), created_date
    except Exception:
        pass
        
    return None, None


def check_mx_records(domain: str) -> Optional[bool]:
    """
    Checks if the domain has configured MX (Mail Exchanger) records using Cloudflare DoH.
    Returns:
        - True if MX records are found
        - False if no MX records are found
        - None if an error occurs (network timeout, invalid response, etc.)
    """
    if not domain:
        return None
    domain = domain.lower().strip()
    try:
        r = requests.get(
            f"https://cloudflare-dns.com/dns-query?name={domain}&type=MX",
            headers={"Accept": "application/dns-json"},
            timeout=3.0
        )
        if r.status_code == 200:
            data = r.json()
            # Look for type 15 (MX) record in Answer section
            answers = data.get("Answer", [])
            has_mx = any(ans.get("type") == 15 for ans in answers)
            return has_mx
        return None
    except Exception:
        return None


def query_dns_txt_records(domain: str, record_type: str = "TXT") -> list[str]:
    """
    Retrieves TXT-like DNS answers using Cloudflare DoH.
    Returns cleaned payload strings.
    """
    if not domain:
        return []
    try:
        response = requests.get(
            f"{CF_DNS_API_URL}?name={urllib.parse.quote(domain)}&type={record_type}",
            headers={"Accept": "application/dns-json"},
            timeout=3.0,
        )
        if response.status_code != 200:
            return []
        data = response.json()
        answers = data.get("Answer", [])
        values: list[str] = []
        for answer in answers:
            if not isinstance(answer, dict):
                continue
            value = str(answer.get("data", ""))
            if record_type.upper() == "TXT":
                value = value.strip().strip('"')
            values.append(value)
        return values
    except Exception:
        return []


def get_spf_dns_record(domain: str) -> str | None:
    """
    Returns the SPF TXT record if available.
    """
    records = query_dns_txt_records(domain, record_type="TXT")
    for record in records:
        if "v=spf1" in (record or "").lower():
            return record
    return None


def get_dmarc_policy(domain: str) -> Optional[Dict[str, str]]:
    """
    Returns a normalized DMARC policy dictionary, if published.
    """
    if not domain:
        return None
    dmarc_domain = f"_dmarc.{domain.lower()}"
    records = query_dns_txt_records(dmarc_domain, record_type="TXT")
    if not records:
        return None

    for record in records:
        text = (record or "").strip().lower()
        if not text.startswith("v=dmarc1"):
            continue
        policy: Dict[str, str] = {"raw": record}
        for part in [piece.strip() for piece in text.split(";")]:
            if not part or "=" not in part:
                continue
            key, value = [x.strip() for x in part.split("=", 1)]
            if key in {"p", "sp", "adkim", "aspf", "pct", "rua", "ruf"}:
                policy[key] = value
        return policy
    return None


def check_dkim_dns_record(selector: str, domain: str) -> str | None:
    """
    Checks DNS for DKIM public key record at selector._domainkey.domain.
    """
    if not selector or not domain:
        return None
    key_domain = f"{selector}._domainkey.{domain}".strip(".")
    records = query_dns_txt_records(key_domain, record_type="TXT")
    for record in records:
        if "v=dkim1" in (record or "").lower():
            return record
    return None


def _extract_soft_redirect(html_snippet: str, base_url: str) -> str | None:
    """
    Scans a limited HTML snippet for meta-refresh and JS-based redirects.
    Does NOT execute JS — only uses regex pattern matching on the raw HTML source.
    Returns the target URL if found, or None.
    """
    # 1. Try meta-refresh
    match = META_REFRESH_RE.search(html_snippet)
    if match:
        target = match.group(1).strip()
        if target.startswith(("http://", "https://")):
            return target
        else:
            return urllib.parse.urljoin(base_url, target)

    # 2. Try JS redirect patterns (regex scan, no execution)
    for pattern in JS_REDIRECT_PATTERNS:
        match = pattern.search(html_snippet)
        if match:
            target = match.group(1).strip()
            if target.startswith(("http://", "https://")):
                return target
            elif target.startswith("/"):
                return urllib.parse.urljoin(base_url, target)

    return None


def resolve_redirects_safely(
    url: str,
    max_redirects: int = 15,
    timeout_seconds: float = 4.0
) -> Dict[str, Any]:
    """
    Follows a URL's redirect chain safely in a sandbox-like manner:

    Security guarantees:
    - No JavaScript execution (pure HTTP + regex scanning).
    - No file downloads — uses stream=True and reads at most 32KB of HTML.
    - Blocks dangerous MIME types (APK, EXE, ZIP, etc.).
    - Blocks large responses (>2MB content-length header).
    - Short timeout per hop (4 seconds).
    - Max 15 hops to handle multi-shortener chains (bit.ly → tinyurl → t.ly → ... → phishing.ru).
    - Loop detection — stops if the same URL appears twice.
    - Detects meta-refresh and JS-based redirects by scanning the first 32KB of HTML.

    Returns a dict with:
    - original_url, final_url, final_hostname, final_registered_domain
    - redirect_chain: list of each hop with url, hostname, registered_domain, status_code, is_shortener
    - redirect_count, shortener_count
    - detected_soft_redirects: list of meta/JS redirect URLs found
    - success, error_message
    """
    chain: List[Dict[str, Any]] = []
    current_url = url
    shortener_count = 0
    detected_soft_redirects: List[str] = []
    blocked_reason = _is_scan_target_blocked(current_url)
    if blocked_reason:
        return {
            "original_url": url,
            "final_url": current_url,
            "final_hostname": urllib.parse.urlparse(current_url).hostname,
            "final_registered_domain": get_domain_info(current_url)[1],
            "domain_age_days": None,
            "domain_created_date": None,
            "has_mx_records": None,
            "redirect_chain": [{
                "url": current_url,
                "hostname": urllib.parse.urlparse(current_url).hostname or "",
                "registered_domain": get_domain_info(current_url)[1] or (urllib.parse.urlparse(current_url).hostname or ""),
                "status_code": "BLOCKED",
                "is_shortener": False,
                "redirect_type": "initial",
            }],
            "redirect_count": 0,
            "shortener_count": 0,
            "uses_shortener": False,
            "detected_soft_redirects": [],
            "success": False,
            "error_message": blocked_reason,
        }
    
    # Standard User-Agent to avoid immediate block, but keeps it recognizable
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                       "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 SigurScan/1.0"
    }

    error_msg = None
    
    # Add initial URL to chain
    hostname, reg_domain = get_domain_info(current_url)
    is_short = is_known_shortener(current_url)
    if is_short:
        shortener_count += 1

    chain.append({
        "url": current_url,
        "hostname": hostname,
        "registered_domain": reg_domain,
        "status_code": "0",
        "is_shortener": is_short,
        "redirect_type": "initial"
    })

    session = requests.Session()
    # allow_redirects=False keeps redirect handling manual, but requests still
    # consults Session.max_redirects internally. A zero value raises
    # TooManyRedirects before shorteners such as bit.ly can expose the first hop.
    session.max_redirects = max_redirects + 5
    verify_candidates: List[Any] = [True]
    if certifi is not None:
        verify_candidates.append(certifi.where())

    for i in range(max_redirects):
        try:
            blocked_reason = _is_scan_target_blocked(current_url)
            if blocked_reason:
                error_msg = f"Scan stopped: {blocked_reason}"
                chain[-1]["status_code"] = "BLOCKED"
                break

            # We use stream=True so we can inspect headers before downloading content
            # allow_redirects=False so we record each step manually
            response = None
            last_ssl_error = None
            for verify in verify_candidates:
                try:
                    response = session.get(
                        current_url,
                        headers=headers,
                        timeout=timeout_seconds,
                        allow_redirects=False,
                        stream=True,
                        verify=verify,
                    )
                    break
                except requests.exceptions.SSLError as exc:
                    last_ssl_error = exc
                    response = None
                    continue

            if response is None:
                raise requests.exceptions.SSLError(last_ssl_error)
            
            # Update status code of the current step (last element in chain)
            chain[-1]["status_code"] = str(response.status_code)

            # Inspect headers for size and MIME types
            content_length = response.headers.get("Content-Length")
            content_type = response.headers.get("Content-Type", "")

            if content_length and int(content_length) > 2 * 1024 * 1024:  # 2 MB limit
                chain[-1]["body_scan_skipped_reason"] = f"Content length too large ({content_length} bytes)"
                response.close()
                break

            if any(dangerous in content_type.lower() for dangerous in DANGEROUS_MIMES):
                error_msg = f"Scan stopped: Dangerous or binary content type ({content_type})"
                response.close()
                break
            
            # ─────────────────────────────────────────────────────────────
            # CASE A: HTTP redirect (301, 302, 303, 307, 308)
            # ─────────────────────────────────────────────────────────────
            if response.status_code in (301, 302, 303, 307, 308):
                redirect_url = response.headers.get("Location")
                response.close()  # close connection stream
                
                if not redirect_url:
                    break

                # Resolve relative redirects
                redirect_url = urllib.parse.urljoin(current_url, redirect_url)
                
                # Check for loop
                if any(step["url"] == redirect_url for step in chain):
                    error_msg = "Redirect loop detected"
                    break

                current_url = redirect_url
                hostname, reg_domain = get_domain_info(current_url)
                is_short = is_known_shortener(current_url)
                if is_short:
                    shortener_count += 1

                chain.append({
                    "url": current_url,
                    "hostname": hostname,
                    "registered_domain": reg_domain,
                    "status_code": "0",
                    "is_shortener": is_short,
                    "redirect_type": "http"
                })

            # ─────────────────────────────────────────────────────────────
            # CASE B: 200 OK — check for soft redirects in HTML body
            # ─────────────────────────────────────────────────────────────
            elif response.status_code == 200 and "text/html" in content_type.lower():
                # Read only first 32KB to scan for meta-refresh / JS redirects
                html_snippet = response.raw.read(MAX_HTML_SCAN_BYTES).decode("utf-8", errors="ignore")
                response.close()

                soft_target = _extract_soft_redirect(html_snippet, current_url)
                if soft_target:
                    # Check for loop
                    if any(step["url"] == soft_target for step in chain):
                        error_msg = "Soft-redirect loop detected (meta/JS)"
                        break

                    detected_soft_redirects.append(soft_target)
                    current_url = soft_target
                    hostname, reg_domain = get_domain_info(current_url)
                    is_short = is_known_shortener(current_url)
                    if is_short:
                        shortener_count += 1

                    chain.append({
                        "url": current_url,
                        "hostname": hostname,
                        "registered_domain": reg_domain,
                        "status_code": "0",
                        "is_shortener": is_short,
                        "redirect_type": "meta_refresh" if META_REFRESH_RE.search(html_snippet) else "js_redirect"
                    })
                else:
                    # Final destination reached — HTML page with no further redirects
                    break
            else:
                # Not a redirect and not scannable HTML — final destination
                response.close()
                break

        except requests.exceptions.Timeout:
            error_msg = f"Connection timed out at hop #{i + 1}"
            chain[-1]["status_code"] = "TIMEOUT"
            break
        except requests.exceptions.TooManyRedirects:
            error_msg = "Too many redirects (library-level)"
            chain[-1]["status_code"] = "TOO_MANY_REDIRECTS"
            break
        except requests.exceptions.RequestException as e:
            error_msg = f"Connection error at hop #{i + 1}: {str(e)}"
            chain[-1]["status_code"] = "ERROR"
            break

    # Extract final information
    final_step = chain[-1]
    final_reg_domain = final_step["registered_domain"]
    
    domain_age_days = None
    domain_created_date = None
    has_mx_records = None
    
    if final_reg_domain:
        # WHOIS/RDAP and MX are independent reputation signals; running them together
        # keeps the resolver inside the serverless poll budget.
        with ThreadPoolExecutor(max_workers=2) as executor:
            age_future = executor.submit(check_domain_age, final_reg_domain)
            mx_future = executor.submit(check_mx_records, final_reg_domain)
            domain_age_days, domain_created_date = age_future.result()
            has_mx_records = mx_future.result()
    
    return {
        "original_url": url,
        "final_url": final_step["url"],
        "final_hostname": final_step["hostname"],
        "final_registered_domain": final_reg_domain,
        "domain_age_days": domain_age_days,
        "domain_created_date": domain_created_date,
        "has_mx_records": has_mx_records,
        "redirect_chain": chain,
        "redirect_count": len(chain) - 1,
        "shortener_count": shortener_count,
        "uses_shortener": shortener_count > 0,
        "detected_soft_redirects": detected_soft_redirects,
        "success": error_msg is None,
        "error_message": error_msg
    }
