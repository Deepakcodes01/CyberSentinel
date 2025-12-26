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
    normalize_domain,         
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

        # ----------------------------
        # DOMAIN EXTRACTION + NORMALIZATION (⭐ FIX)
        # ----------------------------
        domain = extract_domain(url)
        root_domain = normalize_domain(domain)   # ⭐ IMPORTANT FIX
        is_trusted = root_domain in self.popular_domains

        # ----------------------------
        # 1️⃣ INTERNET EXISTENCE CHECK
        # ----------------------------
        dns_data = dns_lookup(root_domain)        # ⭐ USE ROOT DOMAIN
        http_reachable = is_http_accessible(url)

        exists_on_internet = bool(dns_data) and http_reachable

        if not exists_on_internet:
            return {
                "domain": root_domain,
                "trust_status": "Untrusted",
                "url_type": "non-existent",
                "risk_level": "HIGH",
                "risk_score": 1.0,
                "reachable": False,
                "verdict": "This URL does not exist on the internet.",
                "whois_summary": "WHOIS data not available.",
                "dns_summary": format_dns_readable(dns_data),
            }

        # ----------------------------
        # 2️⃣ WHOIS
        # ----------------------------
        whois_data = get_whois_info(root_domain)
        age_days = calculate_domain_age_days(whois_data.get("creation_date"))

        # ----------------------------
        # 3️⃣ ML PREDICTION
        # ----------------------------
        inputs = tokenizer(url, return_tensors="pt", truncation=True)
        with torch.no_grad():
            outputs = model(**inputs)

        logits = outputs.logits
        pred = torch.argmax(logits, dim=1).item()
        ml_label = id2label[pred]
        confidence = torch.softmax(logits, dim=1)[0][pred].item()

        # ----------------------------
        # 4️⃣ TRUST OVERRIDE
        # ----------------------------
        url_type = "benign" if is_trusted else ml_label

        # ----------------------------
        # 5️⃣ WEIGHTED RISK SCORE
        # ----------------------------
        risk_score = 0.0

        if url_type != "benign" and not is_trusted:
            risk_score += min(0.4, confidence)

        if age_days is not None:
            if age_days < 30:
                risk_score += 0.3
            elif age_days < 365:
                risk_score += 0.15
            else:
                risk_score -= 0.3

        if dns_data.get("A"):
            risk_score -= 0.15
        if dns_data.get("MX"):
            risk_score -= 0.1
        if dns_data.get("NS"):
            risk_score -= 0.1

        if http_reachable:
            risk_score -= 0.1

        if is_trusted:
            risk_score -= 0.4

        risk_score = max(0.0, min(1.0, risk_score))

        # ----------------------------
        # 6️⃣ FINAL RISK LEVEL
        # ----------------------------
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

        result = {
            "domain": root_domain,
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
        # 7️⃣ SAVE RESULT (NON-BLOCKING)
        # ----------------------------
        try:
            supabase.table("url_scans").insert({
                "url": url,
                "domain": root_domain,
                "risk_score": result["risk_score"],
                "trust_status": trust_status,
                "url_type": url_type,
            }).execute()
        except Exception as e:
            print("⚠️ Failed to save scan:", e)

        return result
