# backend/main.py

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any
from phishing_detector import PhishingDetector
import os

app = FastAPI(
    title="URL Phishing Detector API",
    description="Hopefully Advanced URL phishing detection",
    version="1.0.0"
)

# CORS - Allow Angular frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:4200",
        "http://127.0.0.1:4200",
        "http://localhost:3000",
        "https://serin-cyro.github.io"
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class AnalyzeRequest(BaseModel):
    url: str = Field(..., min_length=1, max_length=2048)
    deep_scan: bool = False


class BatchAnalyzeRequest(BaseModel):
    urls: List[str] = Field(..., max_length=20)
    deep_scan: bool = False


class Finding(BaseModel):
    level: str
    category: str
    message: str
    score_impact: int
    details: Optional[str] = None


class URLFeatures(BaseModel):
    url_length: int
    hostname_length: int
    path_length: int
    query_length: int
    num_dots: int
    num_hyphens: int
    num_underscores: int
    num_slashes: int
    num_digits: int
    num_params: int
    num_fragments: int
    num_subdomains: int
    has_ip: bool
    has_port: bool
    has_https: bool
    has_at_symbol: bool
    has_double_slash: bool
    has_punycode: bool
    domain_entropy: float
    path_entropy: float
    digit_letter_ratio: float
    special_char_ratio: float
    is_shortened: bool
    tld_length: int
    longest_word_length: int
    avg_word_length: float


class AnalysisResult(BaseModel):
    url: str
    normalized_url: str
    hostname: str
    is_trusted: bool
    risk_score: int
    risk_level: str
    findings: List[Finding]
    features: URLFeatures
    analysis_time_ms: float
    threat_type: Optional[str] = None
    target_brand: Optional[str] = None
    error: Optional[str] = None


# Endpoints

@app.post("/api/analyze", response_model=AnalysisResult)
async def analyze_url(request: AnalyzeRequest):
    """Analyze a URL for phishing indicators."""
    
    if not request.url or not request.url.strip():
        raise HTTPException(status_code=400, detail="URL is required")
    
    # Run analysis
    detector = PhishingDetector(request.url, deep_scan=request.deep_scan)
    result = detector.analyze()
    
    if 'error' in result and result.get('hostname') == '':
        raise HTTPException(status_code=400, detail=result['error'])
    
    return AnalysisResult(
        url=result['url'],
        normalized_url=result['normalized_url'],
        hostname=result['hostname'],
        is_trusted=result['is_trusted'],
        risk_score=result['risk_score'],
        risk_level=result['risk_level'],
        findings=[Finding(**f) for f in result['findings']],
        features=URLFeatures(**result['features']),
        analysis_time_ms=result['analysis_time_ms'],
        threat_type=result.get('threat_type'),
        target_brand=result.get('target_brand')
    )


@app.post("/api/analyze/batch")
async def analyze_batch(request: BatchAnalyzeRequest):
    """Analyze multiple URLs in batch."""
    
    if len(request.urls) > 20:
        raise HTTPException(status_code=400, detail="Maximum 20 URLs per batch")
    
    results = []
    for url in request.urls:
        try:
            detector = PhishingDetector(url, deep_scan=request.deep_scan)
            result = detector.analyze()
            results.append(AnalysisResult(
                url=result['url'],
                normalized_url=result['normalized_url'],
                hostname=result['hostname'],
                is_trusted=result['is_trusted'],
                risk_score=result['risk_score'],
                risk_level=result['risk_level'],
                findings=[Finding(**f) for f in result['findings']],
                features=URLFeatures(**result['features']),
                analysis_time_ms=result['analysis_time_ms'],
                threat_type=result.get('threat_type'),
                target_brand=result.get('target_brand')
            ))
        except Exception as e:
            results.append({"url": url, "error": str(e)})
    
    return results


@app.get("/api/trusted-domains")
async def get_trusted_domains():
    """Get list of trusted domains."""
    return {
        "domains": list(PhishingDetector.TRUSTED_DOMAINS.keys()),
        "count": len(PhishingDetector.TRUSTED_DOMAINS)
    }


@app.get("/api/suspicious-tlds")
async def get_suspicious_tlds():
    """Get list of suspicious TLDs with risk scores."""
    return {
        "tlds": PhishingDetector.SUSPICIOUS_TLDS,
        "count": len(PhishingDetector.SUSPICIOUS_TLDS)
    }


@app.get("/health")
async def health_check():
    """Health check endpoint."""
    return {
        "status": "healthy",
        "version": "2.0.0"
    }


@app.get("/")
async def root():
    """Root endpoint."""
    return {
        "name": "URL Phishing Detector API",
        "version": "2.0.0",
        "docs": "/docs",
        "endpoints": {
            "analyze": "POST /api/analyze",
            "batch": "POST /api/analyze/batch",
            "health": "GET /health"
        }
    }


if __name__ == "__main__":
    import uvicorn
    port = int(os.environ.get("PORT", 8000))
    is_production = os.environ.get("RENDER", "false").lower() == "true"
    
    if is_production:
        print(f" Starting URL Phishing Detector API (Production)...")
        print(f"Running on port {port}")
        uvicorn.run("main:app", host="0.0.0.0", port=port, reload=False)
    else:
        print("Starting URL Phishing Detector API (Development)...")
        print(f"API Docs: http://localhost:{port}/docs")
        print(f"Analyze: POST http://localhost:{port}/api/analyze")
        print("Hot reload enabled")
        uvicorn.run("main:app", host="0.0.0.0", port=port, reload=True)