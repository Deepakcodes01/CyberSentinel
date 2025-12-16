import whois
import dns.resolver
import requests
import socket
from datetime import datetime, timezone
from typing import Optional, Dict, Any, List
from urllib.parse import urlparse


# =====================================================
# Helpers
# =====================================================

def _safe_date(x):
    if x is None:
        return None
    if isinstance(x, list):
        x = x[0]
    if isinstance(x, str):
        try:
            return datetime.fromisoformat(x)
        except Exception:
            return None
    if isinstance(x, datetime):
        return x
    return None


# =====================================================
# URL VALIDATION (WHAT YOUR BOSS ASKED FOR)
# =====================================================

def is_valid_url_syntax(url: str) -> bool:
    if not url or " " in url:
        return False
    parsed = urlparse(url if "://" in url else "http://" + url)
    return bool(parsed.netloc and "." in parsed.netloc)


def extract_domain(url: str) -> str:
    parsed = urlparse(url if "://" in url else "http://" + url)
    return parsed.hostname.lower() if parsed.hostname else ""


def domain_exists(domain: str) -> bool:
    try:
        socket.gethostbyname(domain)
        return True
    except Exception:
        return False


def is_http_accessible(url: str) -> bool:
    if not urlparse(url).scheme:
        url = "http://" + url
    try:
        r = requests.head(
            url,
            allow_redirects=True,
            timeout=5,
            headers={"User-Agent": "CyberSentinelAI/1.0"}
        )
        return r.status_code < 500
    except requests.RequestException:
        return False


# =====================================================
# WHOIS + RDAP
# =====================================================

def rdap_lookup(domain: str) -> Dict[str, Any]:
    try:
        r = requests.get(f"https://rdap.org/domain/{domain}", timeout=8)
        if r.status_code != 200:
            return {"error": "RDAP lookup failed"}
        j = r.json()
        return {
            "domain_name": j.get("ldhName"),
            "creation_date": _safe_date(j.get("events", [{}])[0].get("eventDate")),
            "registrar": None,
            "owner": None,
            "name_servers": [n.get("ldhName") for n in j.get("nameservers", [])],
        }
    except Exception as e:
        return {"error": str(e)}


def get_whois_info(domain: str) -> Dict[str, Any]:
    try:
        w = whois.whois(domain)
        return {
            "domain_name": getattr(w, "domain_name", domain),
            "registrar": getattr(w, "registrar", None),
            "owner": getattr(w, "org", None),
            "creation_date": _safe_date(getattr(w, "creation_date", None)),
            "expiration_date": _safe_date(getattr(w, "expiration_date", None)),
            "updated_date": _safe_date(getattr(w, "updated_date", None)),
            "name_servers": getattr(w, "name_servers", None),
        }
    except Exception:
        return rdap_lookup(domain)


# =====================================================
# DNS
# =====================================================

def dns_lookup(domain: str) -> Dict[str, Optional[List[Dict[str, Any]]]]:
    out = {"A": None, "MX": None, "NS": None}
    resolver = dns.resolver.Resolver()
    resolver.timeout = 3
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


# =====================================================
# ANALYSIS
# =====================================================

def calculate_domain_age_days(creation_date):
    if not creation_date:
        return None
    if creation_date.tzinfo:
        creation_date = creation_date.astimezone(timezone.utc).replace(tzinfo=None)
    return (datetime.utcnow() - creation_date).days


def calculate_risk_score(model_prob: float, domain_age_days: Optional[int], dns_data: Dict[str, Any]) -> float:
    risk = model_prob
    if domain_age_days is not None and domain_age_days < 30:
        risk += 0.2
    if not dns_data.get("MX"):
        risk += 0.1
    return min(risk, 1.0)


# =====================================================
# FORMATTING
# =====================================================

def explain_whois(whois_data: Dict[str, Any], age_days: Optional[int]) -> str:
    if not whois_data or "error" in whois_data:
        return "WHOIS lookup unavailable."
    return f"Domain {whois_data.get('domain_name')} | Age: {age_days} days"


def format_dns_readable(dns_data: Dict[str, Any]) -> str:
    lines = []
    for k in ["A", "MX", "NS"]:
        lines.append(f"{k} Records:")
        if not dns_data.get(k):
            lines.append(" - ❌ None found")
        else:
            for r in dns_data[k]:
                lines.append(f" - {r}")
    return "\n".join(lines)
