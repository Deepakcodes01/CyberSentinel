import tldextract
from urllib.parse import urlparse
from src.db.supabase_client import supabase

from src.model_loader import predict_url
from src.utils import (
    get_whois_info,
    dns_lookup,
    calculate_domain_age_days,
    explain_whois,
    format_dns_readable,
    is_valid_url_syntax,
    extract_domain,
    domain_exists,
    is_http_accessible,
)

     def save_scan(url: str, result: dict):
            try:
                supabase.table("url_scans").insert({
                    "url": url,
                    "domain": result.get("domain"),
                    "risk_score": result.get("risk_score"),
                    "trust_status": result.get("trust_status"),
                    "url_type": result.get("url_type"),
                }).execute()
            except Exception as e:
                print("⚠️ Failed to save scan:", e)

class URLScannerService:
    def __init__(self, popular_domains: set):
        self.popular_domains = popular_domains

    def scan(self, url: str) -> dict:

        # -------- Normalize --------
        if "://" not in url:
            url = "http://" + url

        # -------- Validate --------
        if not is_valid_url_syntax(url):
            return {"error": "Invalid URL format."}

        domain = extract_domain(url)

        if not domain_exists(domain):
            return {"error": "Domain does not exist."}

        if not is_http_accessible(url):
            return {"error": "URL is not reachable."}

        # -------- Trusted Shortcut --------
        if domain in self.popular_domains:
            return {
                "domain": domain,
                "trust_status": "Trusted",
                "url_type": "benign",
                "risk_level": "LOW",
                "risk_score": 0.0,
                "verdict": "Trusted domain.",
                "whois_summary": "Well-known trusted domain.",
                "dns_summary": "Standard DNS records found.",
            }

        # -------- WHOIS + DNS --------
        whois_data = get_whois_info(domain)
        dns_data = dns_lookup(domain)
        age_days = calculate_domain_age_days(whois_data.get("creation_date"))

        # -------- AI Prediction --------
        url_type, confidence = predict_url(url)

        # -------- Risk Mapping --------
        if url_type == "benign":
            risk_level, risk_score = "LOW", 0.1
            verdict = "This URL appears safe."
            trust_status = "Trusted"
        elif url_type == "phishing":
            risk_level, risk_score = "HIGH", 0.8
            verdict = "Likely phishing attempt."
            trust_status = "Untrusted"
        elif url_type == "defacement":
            risk_level, risk_score = "MEDIUM", 0.6
            verdict = "Possible defacement."
            trust_status = "Untrusted"
        else:
            risk_level, risk_score = "HIGH", 0.9
            verdict = "Possible malware distribution."
            trust_status = "Untrusted"
            

   

        return {
            "domain": domain,
            "trust_status": trust_status,
            "url_type": url_type,
            "risk_level": risk_level,
            "risk_score": risk_score,
            "verdict": verdict,
            "whois_summary": explain_whois(whois_data, age_days),
            "dns_summary": format_dns_readable(dns_data),
        }
