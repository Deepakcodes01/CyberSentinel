import dns.resolver
import requests
import whois
from urllib.parse import urlparse
from datetime import datetime, timezone


# ----------------------------
# URL HELPERS
# ----------------------------
def extract_domain(url: str) -> str:
    if not url.startswith("http"):
        url = "http://" + url
    parsed = urlparse(url)
    return parsed.netloc.lower()


def is_valid_url_syntax(url: str) -> bool:
    try:
        parsed = urlparse(url if url.startswith("http") else "http://" + url)
        return bool(parsed.netloc)
    except Exception:
        return False
        
def normalize_domain(domain: str) -> str:
    return domain[4:] if domain.startswith("www.") else domain


# ----------------------------
# DNS
# ----------------------------
def dns_lookup(domain: str) -> dict:
    records = {"A": [], "MX": [], "NS": []}
    try:
        records["A"] = [str(r) for r in dns.resolver.resolve(domain, "A")]
    except Exception:
        pass

    try:
        records["MX"] = [str(r.exchange) for r in dns.resolver.resolve(domain, "MX")]
    except Exception:
        pass

    try:
        records["NS"] = [str(r) for r in dns.resolver.resolve(domain, "NS")]
    except Exception:
        pass

    return records


# ----------------------------
# HTTP
# ----------------------------
def is_http_accessible(url: str, timeout: int = 5) -> bool:
    try:
        if not url.startswith("http"):
            url = "http://" + url
        r = requests.head(url, allow_redirects=True, timeout=timeout)
        return r.status_code < 500
    except Exception:
        return False


# ----------------------------
# WHOIS
# ----------------------------
def get_whois_info(domain: str) -> dict:
    try:
        return whois.whois(domain)
    except Exception:
        return {}




def calculate_domain_age_days(creation_date):
    if not creation_date:
        return None

    # WHOIS sometimes returns a list
    if isinstance(creation_date, list):
        creation_date = creation_date[0]

    if not isinstance(creation_date, datetime):
        return None

    # Convert creation_date to UTC if timezone-aware
    if creation_date.tzinfo is not None:
        creation_date = creation_date.astimezone(timezone.utc)
    else:
        creation_date = creation_date.replace(tzinfo=timezone.utc)

    now = datetime.now(timezone.utc)

    return (now - creation_date).days



def explain_whois(whois_data: dict, age_days: int | None) -> str:
    if not whois_data:
        return "WHOIS information not available."
    if age_days is None:
        return "Domain age could not be determined."
    return f"Domain registered {age_days} days ago."


# ----------------------------
# FORMATTERS
# ----------------------------
def format_dns_readable(dns_data: dict) -> str:
    if not dns_data:
        return "DNS Information:\nNo DNS records found."

    lines = ["DNS Information:\n"]

    # A Records
    if dns_data.get("A"):
        lines.append("A Records:")
        for a in dns_data["A"]:
            lines.append(f"- {{'address': '{a}'}}")
        lines.append("")

    # MX Records
    if dns_data.get("MX"):
        lines.append("MX Records:")
        for mx in dns_data["MX"]:
            if isinstance(mx, dict):
                exchange = mx.get("exchange")
                priority = mx.get("priority")
                lines.append(
                    f"- {{'exchange': '{exchange}', 'priority': {priority}}}"
                )
            else:
                lines.append(f"- {mx}")
        lines.append("")

    # NS Records
    if dns_data.get("NS"):
        lines.append("NS Records:")
        for ns in dns_data["NS"]:
            lines.append(f"- {{'target': '{ns}'}}")
        lines.append("")

    return "\n".join(lines).strip()

