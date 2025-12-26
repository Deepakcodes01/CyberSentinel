from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from src.services.scanner_service import URLScannerService, save_scan
from src.repositories.popular_repo import PopularDomainRepository

app = FastAPI(
    title="CyberSentinel AI",
    description="AI-powered malicious URL detection and threat intelligence system",
    version="1.0.0",
)

# ----------------------------
# CORS CONFIGURATION
# ----------------------------
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], 
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ----------------------------
# INITIALIZE SERVICES
# ----------------------------
repo = PopularDomainRepository()
scanner = URLScannerService(repo.domains)

# ----------------------------
# ROOT ENDPOINT
# ----------------------------
@app.get("/")
def root():
    return {
        "status": "running",
        "message": "AI Malicious URL Detector API is live",
        "usage": "/scan?url=https://example.com"
    }

# ----------------------------
# SCAN ENDPOINT
# ----------------------------
@app.get("/scan")
def scan(url: str):
    result = scanner.scan(url)

    # Save only valid scan results
    if "error" not in result:
        save_scan(url, result)

    return result
