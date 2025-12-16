from fastapi import FastAPI, Query
from fastapi.middleware.cors import CORSMiddleware
from src.services.scanner_service import URLScannerService, save_scan
from src.repositories.popular_repo import PopularDomainRepository

app = FastAPI(
    title="CyberSentinel AI",
    description="AI-powered malicious URL detection and threat intelligence system",
    version="1.0.0",
)

@app.get("/")
def root():
    return {"status": "CyberSentinel AI backend is running"}

#CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], 
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

repo = PopularDomainRepository()
scanner = URLScannerService(repo.domains)


@app.get("/")
def root():
    return {
        "status": "running",
        "message": "AI Malicious URL Detector API is live",
        "usage": "/scan?url=https://example.com"
    }


@app.get("/scan")
def scan(url: str):
    result = scanner.scan(url)
    save_scan(url, result)
    return result
