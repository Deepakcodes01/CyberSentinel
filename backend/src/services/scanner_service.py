import torch
from transformers import AutoTokenizer, AutoModelForSequenceClassification

from src.utils import (
    get_whois_info,
    dns_lookup,
    calculate_domain_age_days,
    explain_whois,
    format_dns_readable,
    is_valid_url_syntax,
    extract_domain,
    is_http_accessible,
)

from src.db.supabase_client import supabase


# ----------------------------
# LOAD MODEL ONCE
# ----------------------------
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


# ----------------------------
# URL SCANNER SERVICE
# ----------------------------
class URLScannerService:
    def __init__(self, popular_domains: set):
        self.popular_domains = popular_domains

    def scan(self, url: str) -> dict:
        if not url:
            return {"error": "URL is required"}

        if not is_valid_url_syntax(url):
            return {"error": "Invalid URL format"}

        domain = extract_domain(url)
        is_trusted = domain in self.popular_domains

        # Soft checks
        dns_data = dns_lookup(domain)
        http_reachable = is_http_accessible(url)

        # WHOIS
        whois_data = get_whois_info(domain)
        age_days = calculate_domain_age_days(whois_data.get("creation_date"))

        # AI prediction
        inputs = tokenizer(url, return_tensors="pt", truncation=True)
        with torch.no_grad():
            outputs = model(**inputs)

        logits = outputs.logits
        pred = torch.argmax(logits, dim=1).item()
        url_type = id2label[pred]
        confidence = torch.softmax(logits, dim=1)[0][pred].item()

        # ----------------------------
        # WEIGHTED RISK SCORING
        # ----------------------------
        risk_score = 0.0

        # ML contribution
        if url_type != "benign":
            risk_score += min(0.4, confidence)

        # Domain age
        if age_days is not None:
            if age_days < 30:
                risk_score += 0.3
            elif age_days < 365:
                risk_score += 0.15
            else:
                risk_score -= 0.3

        # DNS stability
        if dns_data.get("A"):
            risk_score -= 0.15
        if dns_data.get("MX"):
            risk_score -= 0.1
        if dns_data.get("NS"):
            risk_score -= 0.1

        # HTTP reachability
        if http_reachable:
            risk_score -= 0.1

        # Popular domain bonus
        if is_trusted:
            risk_score -= 0.2

        # Clamp
        risk_score = max(0.0, min(1.0, risk_score))

        # Risk level
        if risk_score >= 0.7:
            risk_level = "HIGH"
        elif risk_score >= 0.4:
            risk_level = "MEDIUM"
        else:
            risk_level = "LOW"

        trust_status = "Trusted" if risk_score < 0.4 else "Untrusted"

        verdict = (
            "This is a trusted and well-established domain."
            if trust_status == "Trusted"
            else "This URL may pose a security risk."
        )

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


# ----------------------------
# SAVE RESULT (OPTIONAL)
# ----------------------------
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
