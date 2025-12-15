import whois
import dns.resolver
import requests
from datetime import datetime, timezone
from typing import Optional, Dict, Any, List


def _safe_date(x):
    """Normalize whois date fields (lists/None/str/datetime) -> datetime or None"""
    if x is None:
        return None
    if isinstance(x, list) and len(x) > 0:
        x = x[0]
    if isinstance(x, datetime):
        return x
    if isinstance(x, str):
        try:
            # try ISO first
            return datetime.fromisoformat(x)
        except:
            # try common formats
            for fmt in ("%Y-%m-%d", "%d-%b-%Y", "%Y%m%d"):
                try:
                    return datetime.strptime(x, fmt)
                except:
                    pass
    return None


def rdap_lookup(domain: str) -> Dict[str, Any]:
    """RDAP fallback via rdap.org (public). Returns dict with keys similar to whois."""
    try:
        r = requests.get(f"https://rdap.org/domain/{domain}", timeout=8)
        if r.status_code != 200:
            return {"error": f"RDAP status {r.status_code}"}
        j = r.json()
        out = {
            "domain_name": j.get("ldhName") or j.get("handle"),
            "registrar": None,
            "owner": None,
            "creation_date": None,
            "expiration_date": None,
            "updated_date": None,
            "name_servers": None,
            "status": None,
        }
        # events: creation/expiry/update
        events = j.get("events", [])
        for e in events:
            event_action = e.get("eventAction")
            when = e.get("eventDate")
            if event_action == "registration":
                out["creation_date"] = _safe_date(when)
            elif event_action == "expiration":
                out["expiration_date"] = _safe_date(when)
            elif event_action == "last changed":
                out["updated_date"] = _safe_date(when)
        # registrar/owner: try entities
        ents = j.get("entities", [])
        for ent in ents:
            roles = ent.get("roles", [])
            v = ent.get("vcardArray")
            if v and isinstance(v, list) and len(v) >= 2:
                # extract org or fn
                fn = None
                for item in v[1]:
                    if item and isinstance(item, list) and len(item) >= 3:
                        if item[0] == "fn":
                            fn = item[3]
                            break
                if fn and "registrar" in roles:
                    out["registrar"] = fn
                if fn and ("registrant" in roles or "registrar" not in roles):
                    out["owner"] = fn if out.get("owner") is None else out.get("owner")
        # nameservers
        ns = j.get("nameservers")
        if ns:
            out["name_servers"] = [n.get("ldhName") or n.get("handle") for n in ns]
        return out
    except Exception as e:
        return {"error": f"RDAP error: {e}"}


def get_whois_info(domain: str) -> Dict[str, Any]:
    """
    Try python-whois, then RDAP fallback.
    Returns a dictionary of fields or {'error': '...'}.
    """
    try:
        w = whois.whois(domain)
        creation = _safe_date(getattr(w, "creation_date", None))
        expiry = _safe_date(getattr(w, "expiration_date", None))
        updated = _safe_date(getattr(w, "updated_date", None))
        ns = getattr(w, "name_servers", None)
        if isinstance(ns, str):
            ns = [ns]
        return {
            "domain_name": getattr(w, "domain_name", domain),
            "registrar": getattr(w, "registrar", None),
            "owner": getattr(w, "org", getattr(w, "name", None)),
            "creation_date": creation,
            "expiration_date": expiry,
            "updated_date": updated,
            "name_servers": ns,
            "status": getattr(w, "status", None),
        }
    except Exception:
        # fallback to RDAP
        return rdap_lookup(domain)


def dns_lookup(domain: str) -> Dict[str, Optional[List[Dict[str, Any]]]]:
    """
    Return structured DNS records. Each record list contains dicts with additional metadata where possible.
    Example:
      { "A": [{"address":"1.2.3.4", "ttl": 300}, ... ],
        "MX": [{"exchange":"mx1.example.com", "priority": 10, "ttl":300}, ... ],
        "NS": [{"target":"ns1.example.com", "ttl":300}, ...] }
    TTL availability depends on resolver response object.
    """
    out = {"A": None, "MX": None, "NS": None}
    resolver = dns.resolver.Resolver()
    resolver.lifetime = 5.0
    resolver.timeout = 3.0

    # A
    try:
        answers = resolver.resolve(domain, "A")
        out["A"] = [{"address": a.address, "ttl": int(answers.rrset.ttl) if getattr(answers.rrset, "ttl", None) else None} for a in answers]
    except Exception:
        out["A"] = None

    # MX
    try:
        answers = resolver.resolve(domain, "MX")
        mxs = []
        for r in answers:
            # r.exchange is a Name object; r.preference is priority
            mxs.append({
                "exchange": str(r.exchange).rstrip("."),
                "priority": int(r.preference) if hasattr(r, "preference") else None,
                "ttl": int(answers.rrset.ttl) if getattr(answers.rrset, "ttl", None) else None
            })
        out["MX"] = mxs
    except Exception:
        out["MX"] = None

    # NS
    try:
        answers = resolver.resolve(domain, "NS")
        out["NS"] = [{"target": str(r.target).rstrip("."), "ttl": int(answers.rrset.ttl) if getattr(answers.rrset, "ttl", None) else None} for r in answers]
    except Exception:
        out["NS"] = None

    return out




def calculate_domain_age_days(creation_date):
    if not creation_date:
        return None

    # Handle list values
    if isinstance(creation_date, list):
        creation_date = creation_date[0]

    # Convert string to datetime
    if isinstance(creation_date, str):
        try:
            creation_date = datetime.fromisoformat(creation_date)
        except:
            return None

    # If WHOIS datetime is timezone-aware, convert to naive UTC
    if creation_date.tzinfo is not None:
        creation_date = creation_date.astimezone(timezone.utc).replace(tzinfo=None)

    # Convert now() to naive UTC for fair comparison
    now = datetime.utcnow()

    return (now - creation_date).days

def _safe_date(dt):
    try:
        if isinstance(dt, list):
            dt = dt[0]
        if isinstance(dt, str):
            return datetime.fromisoformat(dt)
        return dt
    except:
        return None



def calculate_risk_score(model_prob: float, domain_age_days: Optional[int], dns_data: Dict[str, Any]) -> float:
    """
    Hybrid score in [0..1]. Base = model_prob (0..1).
    Additive heuristics:
      - domain_age < 30 days -> +0.18
      - missing MX -> +0.06
      - missing A -> +0.10
      - NS points if uses suspicious provider? (not implemented here)
    """
    risk = float(model_prob)
    if domain_age_days is not None:
        if domain_age_days < 30:
            risk += 0.18
        elif domain_age_days < 365:
            risk += 0.05

    if not dns_data.get("MX"):
        risk += 0.06
    if not dns_data.get("A"):
        risk += 0.10

    return min(risk, 1.0)


# ---------- Formatting helpers for UI ----------

def format_whois_nic_style(w: Dict[str, Any]) -> str:
    if not w or "error" in w:
        return "WHOIS lookup failed or not available."

    lines = []
    def add(label, value):
        if value:
            lines.append(f"{label:<12} {value}")

    add("domain:", w.get("domain_name"))
    add("owner:", w.get("owner"))
    add("registrar:", w.get("registrar"))
    ns = w.get("name_servers")
    if isinstance(ns, list):
        for n in ns:
            add("nserver:", n)
    def fdate(d):
        if isinstance(d, datetime):
            return d.strftime("%Y-%m-%d")
        return d
    add("created:", fdate(w.get("creation_date")))
    add("changed:", fdate(w.get("updated_date")))
    add("expires:", fdate(w.get("expiration_date")))
    status = w.get("status")
    if isinstance(status, list):
        status = ", ".join(map(str, status))
    add("status:", status)
    return "\n".join(lines)


def explain_whois(whois_data: Dict[str, Any], age_days: Optional[int]) -> str:
    if not whois_data or "error" in whois_data:
        return "WHOIS lookup failed or not available."

    parts = []
    parts.append(f"Domain: {whois_data.get('domain_name')}")
    registrar = whois_data.get("registrar")
    if registrar:
        parts.append(f"Registrar: {registrar}")
    if age_days is not None:
        if age_days < 30:
            parts.append(f"Age: {age_days} days (very new — higher risk)")
        elif age_days < 365:
            parts.append(f"Age: {age_days} days (moderately new)")
        else:
            parts.append(f"Age: {age_days} days (established)")
    return " • ".join(parts)


def format_dns_readable(dns_data: Dict[str, Any]) -> str:
    lines = []
    def section(title, items):
        lines.append(f"{title}:")
        if not items:
            lines.append(" - ❌ No records found")
            lines.append("")
            return
        for rec in items:
            if title == "A Records":
                lines.append(f" - {rec.get('address')} (ttl={rec.get('ttl')})")
            elif title == "MX Records":
                lines.append(f" - {rec.get('exchange')} (priority={rec.get('priority')}, ttl={rec.get('ttl')})")
            elif title == "NS Records":
                lines.append(f" - {rec.get('target')} (ttl={rec.get('ttl')})")
        lines.append("")
    section("A Records", dns_data.get("A"))
    section("MX Records", dns_data.get("MX"))
    section("NS Records", dns_data.get("NS"))
    return "\n".join(lines)
