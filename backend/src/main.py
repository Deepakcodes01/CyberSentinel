from fastapi import FastAPI, Query
from fastapi.middleware.cors import CORSMiddleware

from src.services.scanner_service import URLScannerService, save_scan
from src.repositories.popular_repo import PopularDomainRepository

# =========================================================
# FastAPI App Configuration
# =========================================================
app = FastAPI(
    title="CyberSentinel AI",
    description="AI-powered malicious URL detection and threat intelligence system",
    version="1.0.0",
)

# =========================================================
# CORS Configuration (Frontend access)
# =========================================================
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Safe for demo; restrict in production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# =========================================================
# Initialize Services (RUNS ONCE)
# =========================================================
repo = PopularDomainRepository()
scanner = URLScannerService(repo.domains)

# =========================================================
# Health Check Endpoint
# =========================================================
@app.get("/")
def root():
    return {
        "status": "running",
        "message": "CyberSentinel AI backend is live",
        "usage": "/scan?url=https://example.com"
    }

# =========================================================
# Scan Endpoint
# =========================================================
@app.get("/scan")
def scan(
    url: str = Query(..., description="URL to analyze for malicious behavior")
):
    """
    Scans a URL using:
    - Syntax validation
    - DNS + WHOIS checks
    - AI (URLBERT multi-class model)
    """

    result = scanner.scan(url)

    # -----------------------------------------------------
    # If validation failed, DO NOT save to database
    # -----------------------------------------------------
    if "error" in result:
        return result

    # -----------------------------------------------------
    # Save only valid scans
    # -----------------------------------------------------
    try:
        save_scan(url, result)
    except Exception as e:
        # Do NOT crash API if DB fails
        print("⚠️ Supabase save failed:", e)

    return result
