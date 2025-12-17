import whois
import dns.resolver
import requests
import tldextract
from datetime import datetime, timezone
from typing import Optional, Dict, Any, List
from urllib.parse import urlparse


# ----------------------------
# URL SYNTAX VALIDATION
# ----------------------------
def is_valid_url_syntax(url: str) -> bool:
    if not url or " " in url:
        return False

    if "://" not in url:
        url = "http://" + url

    parsed = urlparse(url)
    return bool(parsed.hostname and "." in parsed.hostname)


# ----------------------------
# CANONICAL DOMAIN EXTRACTION
# ----------------------------
def extract_domain(url: str) -> str:
    """
    cnn.com
    www.cnn.com
    https://www.cnn.com/news
    → cnn.com
    """
    if not url:
        return ""

    if "://" not in url:
        url = "http://" + url

    parsed = urlparse(url)
    ext = tldextract.extract(parsed.hostname or "")

    if not ext.domain or not ext.suffix:
        return ""

    return f"{ext.domain}.{ext.suffix}"


# ----------------------------
# DNS LOOKUP (SOFT)
# ----------------------------
def dns_lookup(domain: str) -> Dict[str, Any]:
    out = {"A": None, "MX": None, "NS": None}
    resolver = dns.resolver.Resolver()
    resolver.lifetime = 5

    try:
        answers = resolver.resolve(domain, "A")
        out["A"] = [{"address": a.address} for a in answers]
    except Exception:
        pass

    try:
        answers = resolver.resolve(domain, "MX")
        out["MX"] = [{"exchange": str(r.exchange), "priority": r.preference} for r in answers]
    except Exception:
        pass

    try:
        answers = resolver.resolve(domain, "NS")
        out["NS"] = [{"target": str(r.target)} for r in answers]
    except Exception:
        pass

    return out


# ----------------------------
# HTTP ACCESSIBILITY (SOFT)
# ----------------------------
def is_http_accessible(url: str) -> bool:
    try:
        if "://" not in url:
            url = "http://" + url

        r = requests.head(
            url,
            allow_redirects=True,
            timeout=5,
            headers={"User-Agent": "CyberSentinelAI/1.0"},
        )
        return r.status_code < 500
    except Exception:
        return False


# ----------------------------
# WHOIS + RDAP FALLBACK
# ----------------------------
def _safe_date(x):
    if isinstance(x, list):
        x = x[0]
    if isinstance(x, str):
        try:
            return datetime.fromisoformat(x)
        except Exception:
            return None
    return x


def get_whois_info(domain: str) -> Dict[str, Any]:
    try:
        w = whois.whois(domain)
        return {
            "domain_name": domain,
            "registrar": getattr(w, "registrar", None),
            "creation_date": _safe_date(getattr(w, "creation_date", None)),
        }
    except Exception:
        return {"error": "WHOIS lookup failed"}


# ----------------------------
# DOMAIN AGE
# ----------------------------
def calculate_domain_age_days(creation_date):
    if not creation_date:
        return None

    if creation_date.tzinfo:
        creation_date = creation_date.astimezone(timezone.utc).replace(tzinfo=None)

    return (datetime.utcnow() - creation_date).days


# ----------------------------
# FORMATTERS
# ----------------------------
def explain_whois(whois_data: Dict[str, Any], age_days: Optional[int]) -> str:
    if "error" in whois_data:
        return "WHOIS lookup failed or not available."

    if age_days is None:
        return "Domain age information unavailable."

    if age_days < 30:
        return f"Domain is very new ({age_days} days) — higher risk."
    if age_days < 365:
        return f"Domain is moderately new ({age_days} days)."

    return f"Domain is well-established ({age_days} days old)."


def format_dns_readable(dns_data: Dict[str, Any]) -> str:
    lines = []

    for record in ["A", "MX", "NS"]:
        lines.append(f"{record} Records:")
        if not dns_data.get(record):
            lines.append(" - ❌ None found")
        else:
            for r in dns_data[record]:
                lines.append(f" - {r}")
        lines.append("")

    return "\n".join(lines)
