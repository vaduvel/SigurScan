import asyncio
import logging
import os
import socket
import ssl
from datetime import datetime, timezone
from typing import Any, Dict, Optional

import httpx

logger = logging.getLogger("whois_ssl_signals")

SSL_CERT_DATE_FMT = "%b %d %H:%M:%S %Y %Z"
RDAP_TIMEOUT_SECONDS = float(os.getenv("RDAP_TIMEOUT_SECONDS", "2.0"))
SSL_TIMEOUT_SECONDS = float(os.getenv("SSL_TIMEOUT_SECONDS", "2.0"))
RO_DOMAIN_SUFFIXES = (".ro",)


def check_ssl(hostname: str, timeout: Optional[float] = None) -> Dict[str, Any]:
    if not hostname or not isinstance(hostname, str):
        return {"valid": None, "reason": "no_hostname"}
    timeout = timeout if timeout is not None else SSL_TIMEOUT_SECONDS
    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((hostname, 443), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
    except ssl.SSLCertVerificationError:
        return {"valid": False, "reason": "cert_verification_failed"}
    except (socket.timeout, ConnectionError, OSError, ssl.SSLError) as exc:
        return {"valid": None, "reason": "unreachable", "detail": str(exc)}
    if not cert:
        return {"valid": None, "reason": "no_cert_returned"}
    try:
        not_before = datetime.strptime(cert["notBefore"], SSL_CERT_DATE_FMT).replace(tzinfo=timezone.utc)
        not_after = datetime.strptime(cert["notAfter"], SSL_CERT_DATE_FMT).replace(tzinfo=timezone.utc)
    except (KeyError, ValueError) as exc:
        return {"valid": None, "reason": "parse_error", "detail": str(exc)}
    now = datetime.now(timezone.utc)
    issuer = {}
    if "issuer" in cert:
        try:
            issuer = dict(x[0] for x in cert["issuer"])
        except (IndexError, ValueError, TypeError):
            issuer = {}
    issuer_org = issuer.get("organizationName")
    return {
        "valid": not_before <= now <= not_after,
        "cert_age_days": (now - not_before).days,
        "issuer_org": issuer_org,
        "not_before": not_before.isoformat(),
        "not_after": not_after.isoformat(),
    }


async def check_rdap(domain: str, timeout: Optional[float] = None) -> Dict[str, Any]:
    if not domain or not isinstance(domain, str):
        return {"age_days": None, "reason": "no_domain"}
    timeout = timeout if timeout is not None else RDAP_TIMEOUT_SECONDS
    url = f"https://rdap.org/domain/{domain}"
    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            r = await client.get(url, headers={"Accept": "application/rdap+json"})
    except (httpx.TimeoutException, httpx.HTTPError):
        return {"age_days": None, "reason": "timeout"}
    if r.status_code == 404:
        return {"age_days": None, "registered": False, "reason": "inexistent_domain"}
    if r.status_code != 200:
        return {"age_days": None, "reason": f"http_{r.status_code}"}
    try:
        data = r.json()
    except Exception:
        return {"age_days": None, "reason": "parse_error"}
    events = data.get("events", [])
    if not isinstance(events, list):
        return {"age_days": None, "reason": "no_events"}
    reg_date = None
    for event in events:
        if isinstance(event, dict) and event.get("eventAction") == "registration":
            reg_date = event.get("eventDate")
            break
    if not reg_date:
        return {"age_days": None, "reason": "no_registration_event"}
    try:
        reg_dt = datetime.fromisoformat(reg_date.replace("Z", "+00:00"))
    except (ValueError, AttributeError):
        return {"age_days": None, "reason": "parse_registration_date"}
    age = (datetime.now(timezone.utc) - reg_dt).days
    return {"age_days": age, "registered": True, "registration_date": reg_dt.isoformat()}


async def check_domain_ssl_parallel(domain: str) -> Dict[str, Any]:
    ssl_task = asyncio.to_thread(check_ssl, domain)
    rdap_task = check_rdap(domain)
    ssl_result, rdap_result = await asyncio.gather(ssl_task, rdap_task, return_exceptions=True)
    if isinstance(ssl_result, Exception):
        logger.warning("SSL check failed for %s: %s", domain, ssl_result)
        ssl_result = {"valid": None, "reason": "error", "detail": str(ssl_result)}
    if isinstance(rdap_result, Exception):
        logger.warning("RDAP check failed for %s: %s", domain, rdap_result)
        rdap_result = {"age_days": None, "reason": "error", "detail": str(rdap_result)}
    return {"ssl": ssl_result, "rdap": rdap_result}


def domain_risk_from_signals(ssl_result: Dict[str, Any], rdap_result: Dict[str, Any], domain: str) -> Dict[str, Any]:
    signals: Dict[str, Any] = {
        "rdap_404": False,
        "domain_age_days": None,
        "domain_young": False,
        "ssl_valid": None,
        "cert_age_days": None,
        "cert_young": False,
        "unreachable": False,
    }
    rdap_404 = rdap_result.get("reason") == "inexistent_domain"
    signals["rdap_404"] = bool(rdap_404)
    if rdap_404:
        signals["domain_age_days"] = None
        signals["domain_young"] = False
    else:
        age_days = rdap_result.get("age_days")
        if age_days is not None:
            try:
                signals["domain_age_days"] = int(age_days)
                signals["domain_young"] = signals["domain_age_days"] < 30
            except (ValueError, TypeError):
                signals["domain_age_days"] = None
                signals["domain_young"] = False
        else:
            signals["domain_age_days"] = None
            signals["domain_young"] = False
    ssl_valid = ssl_result.get("valid")
    if ssl_valid is True:
        signals["ssl_valid"] = True
    elif ssl_valid is False:
        signals["ssl_valid"] = False
    else:
        signals["ssl_valid"] = None
    cert_age = ssl_result.get("cert_age_days")
    if cert_age is not None:
        try:
            signals["cert_age_days"] = int(cert_age)
            signals["cert_young"] = signals["cert_age_days"] < 14
        except (ValueError, TypeError):
            signals["cert_age_days"] = None
            signals["cert_young"] = False
    else:
        signals["cert_age_days"] = None
        signals["cert_young"] = False
    unreachable_reasons = {"unreachable", "timeout", "error"}
    signals["unreachable"] = (
        ssl_result.get("reason", "") in unreachable_reasons
        or rdap_result.get("reason", "") in unreachable_reasons
    )
    risk_score = 0
    risk_flags: list[str] = []
    if rdap_404:
        risk_score += 60
        risk_flags.append("rdap_inexistent_domain")
    if signals["domain_young"] and signals["domain_age_days"] is not None and signals["domain_age_days"] >= 0:
        risk_score += 45
        risk_flags.append("domain_very_young")
    elif signals["domain_age_days"] is not None and 30 <= signals["domain_age_days"] <= 90:
        risk_score += 20
        risk_flags.append("domain_recent")
    elif signals["domain_age_days"] is not None and signals["domain_age_days"] > 365:
        risk_score -= 15
        risk_flags.append("domain_established")
    if ssl_valid is False:
        risk_score += 50
        risk_flags.append("invalid_ssl")
    if signals["cert_young"] and signals["cert_age_days"] is not None and signals["cert_age_days"] >= 0:
        risk_score += 15
        risk_flags.append("cert_very_young")
    if signals["unreachable"]:
        risk_score += 20
        risk_flags.append("host_unreachable")
    issuer = ssl_result.get("issuer_org")
    if issuer is not None and str(issuer).strip().lower() in {"let's encrypt", "zerossl", "lets encrypt"}:
        risk_score += 0
        risk_flags.append("auto_issuer")
    return {"signal_score": risk_score, "flags": risk_flags, **signals}
