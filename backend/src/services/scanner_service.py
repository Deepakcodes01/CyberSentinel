import torch
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
# Load MULTI-CLASS URLBERT MODEL (once at startup)
# =========================================================
MODEL_PATH = "models/urlbert-multiclass"

tokenizer = AutoTokenizer.from_pretrained(MODEL_PATH)
model = AutoModelForSequenceClassification.from_pretrained(MODEL_PATH)
model.eval()

id2label = {
    0: "benign",
    1: "phishing",
    2: "defacement",
    3: "malware",
}


# =========================================================
# URL Scanner Service
# =========================================================
class URLScannerService:
    def __init__(self, popular_domains: set):
        self.popular_domains = popular_domains

    def scan(self, url: str) -> dict:
        # ---------------------------
        # 1. Normalize URL
        # ---------------------------
        if "://" not in url:
            url = "http://" + url

        # ---------------------------
        # 2. URL syntax validation
        # ---------------------------
        if not is_valid_url_syntax(url):
            return {
                "error": "Invalid URL format. Please enter a valid URL."
            }

        # ---------------------------
        # 3. Extract domain
        # ---------------------------
        domain = extract_domain(url)

        # ---------------------------
        # 4. DNS existence validation
        # ---------------------------
        if not domain_exists(domain):
            return {
                "error": "Domain does not exist or is not reachable."
            }

        # ---------------------------
        # 5. HTTP accessibility (soft check)
        # ---------------------------
        http_reachable = is_http_accessible(url)

        # ---------------------------
        # 6. Trusted domain shortcut
        # ---------------------------
        if domain in self.popular_domains:
            return {
                "domain": domain,
                "trust_status": "Trusted",
                "url_type": "benign",
                "risk_level": "LOW",
                "risk_score": 0.0,
                "reachable": http_reachable,
                "verdict": "This is a trusted and well-established domain.",
                "whois_summary": "Trusted domain. WHOIS lookup skipped.",
                "dns_summary": "Standard DNS records detected.",
            }

        # ---------------------------
        # 7. WHOIS + DNS analysis
        # ---------------------------
        whois_data = get_whois_info(domain)
        dns_data = dns_lookup(domain)
        age_days = calculate_domain_age_days(whois_data.get("creation_date"))

        # ---------------------------
        # 8. AI MULTI-CLASS PREDICTION
        # ---------------------------
        inputs = tokenizer(url, return_tensors="pt", truncation=True)
        with torch.no_grad():
            outputs = model(**inputs)

        logits = outputs.logits
        pred_class_id = torch.argmax(logits, dim=1).item()
        url_type = id2label[pred_class_id]

        confidence = torch.softmax(logits, dim=1)[0][pred_class_id].item()

        # ---------------------------
        # 9. Risk mapping
        # ---------------------------
        trust_status = "Untrusted"

        if url_type == "benign":
            risk_level = "LOW"
            risk_score = 0.1
            verdict = "This URL appears to be safe."

        elif url_type == "phishing":
            risk_level = "HIGH"
            risk_score = 0.8
            verdict = "This URL is likely a phishing attempt impersonating a trusted brand."

        elif url_type == "defacement":
            risk_level = "MEDIUM"
            risk_score = 0.6
            verdict = "This URL may be associated with website defacement."

        else:  # malware
            risk_level = "HIGH"
            risk_score = 0.9
            verdict = "This URL may distribute malware and should be avoided."

        # ---------------------------
        # DEBUG / DEMO OUTPUT
        # ---------------------------
        print("\n🤖 AI MODEL OUTPUT")
        print("-" * 40)
        print(f"URL        : {url}")
        print(f"Domain     : {domain}")
        print(f"Prediction : {url_type}")
        print(f"Confidence : {confidence:.4f}")
        print(f"Reachable  : {http_reachable}")
        print(f"Risk Level : {risk_level}")
        print("-" * 40)

        # ---------------------------
        # Final response
        # ---------------------------
        return {
            "domain": domain,
            "trust_status": trust_status,
            "url_type": url_type,
            "risk_level": risk_level,
            "risk_score": round(risk_score, 2),
            "reachable": http_reachable,
            "verdict": verdict,
            "whois_summary": explain_whois(whois_data, age_days),
            "dns_summary": format_dns_readable(dns_data),
        }


# =========================================================
# Save scan result to Supabase
# =========================================================
def save_scan(url: str, result: dict):
    supabase.table("url_scans").insert({
        "url": url,
        "domain": result.get("domain"),
        "risk_score": result.get("risk_score"),
        "trust_status": result.get("trust_status"),
        "url_type": result.get("url_type"),
    }).execute()
