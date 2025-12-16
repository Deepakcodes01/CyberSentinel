import torch
import tldextract
from urllib.parse import urlparse
from transformers import AutoTokenizer, AutoModelForSequenceClassification

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

from src.db.supabase_client import supabase


# =========================================================
# Load MULTI-CLASS URLBERT MODEL (ONCE AT STARTUP)
# =========================================================
MODEL_PATH = "models/urlbert-multiclass"

print("🔄 Loading URLBERT model...")
tokenizer = AutoTokenizer.from_pretrained(MODEL_PATH)
model = AutoModelForSequenceClassification.from_pretrained(MODEL_PATH)
model.eval()
print("✅ Model loaded successfully")

id2label = {
    0: "benign",
    1: "phishing",
    2: "defacement",
    3: "malware",
}


# =========================================================
# URL SCANNER SERVICE
# =========================================================
class URLScannerService:
    def __init__(self, popular_domains: set):
        self.popular_domains = popular_domains

    def scan(self, url: str) -> dict:
        # ----------------------------
        # Normalize URL
        # ----------------------------
        if not url:
            return {"error": "URL is required"}

        if "://" not in url:
            url = "http://" + url

        # ----------------------------
        # URL SYNTAX VALIDATION
        # ----------------------------
        if not is_valid_url_syntax(url):
            return {
                "error": "Invalid URL format. Please enter a valid URL."
            }

        domain = extract_domain(url)

        if not domain:
            return {"error": "Unable to extract domain from URL"}

        # ----------------------------
        # DOMAIN EXISTENCE CHECK
        # ----------------------------
        if not domain_exists(domain):
            return {
                "error": "Domain does not exist or DNS resolution failed."
            }

        # ----------------------------
        # HTTP ACCESSIBILITY CHECK (SOFT)
        # ----------------------------
        http_reachable = is_http_accessible(url)
        if not http_reachable:
            return {
                "error": "URL is not reachable over HTTP/HTTPS."
            }

        # ----------------------------
        # TRUSTED DOMAIN SHORTCUT
        # ----------------------------
        if domain in self.popular_domains:
            return {
                "domain": domain,
                "trust_status": "Trusted",
                "url_type": "benign",
                "risk_level": "LOW",
                "risk_score": 0.0,
                "verdict": "This is a trusted and well-established domain.",
                "whois_summary": "This domain belongs to a widely trusted organization.",
                "dns_summary": "Standard DNS records found.",
            }

        # ----------------------------
        # WHOIS + DNS ANALYSIS
        # ----------------------------
        whois_data = get_whois_info(domain)
        dns_data = dns_lookup(domain)
        age_days = calculate_domain_age_days(whois_data.get("creation_date"))

        # ----------------------------
        # AI MULTI-CLASS PREDICTION
        # ----------------------------
        inputs = tokenizer(url, return_tensors="pt", truncation=True)
        with torch.no_grad():
            outputs = model(**inputs)

        logits = outputs.logits
        pred_class_id = torch.argmax(logits, dim=1).item()
        url_type = id2label[pred_class_id]

        confidence = torch.softmax(logits, dim=1)[0][pred_class_id].item()

        # ----------------------------
        # RISK MAPPING
        # ----------------------------
        if url_type == "benign":
            trust_status = "Trusted"
            risk_level = "LOW"
            risk_score = 0.1
            verdict = "This URL appears to be safe."

        elif url_type == "phishing":
            trust_status = "Untrusted"
            risk_level = "HIGH"
            risk_score = 0.8
            verdict = "This URL is likely a phishing attempt impersonating a trusted brand."

        elif url_type == "defacement":
            trust_status = "Untrusted"
            risk_level = "MEDIUM"
            risk_score = 0.6
            verdict = "This URL may be associated with website defacement."

        else:  # malware
            trust_status = "Untrusted"
            risk_level = "HIGH"
            risk_score = 0.9
            verdict = "This URL may distribute malware and should be avoided."

        # ----------------------------
        # FINAL RESPONSE
        # ----------------------------
        return {
            "domain": domain,
            "trust_status": trust_status,
            "url_type": url_type,
            "risk_level": risk_level,
            "risk_score": round(risk_score, 2),
            "verdict": verdict,
            "whois_summary": explain_whois(whois_data, age_days),
            "dns_summary": format_dns_readable(dns_data),
        }


# =========================================================
# SAVE SCAN RESULT (SUPABASE)
# =========================================================
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
