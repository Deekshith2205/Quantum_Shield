"""QuantumShield - Quantum Readiness / Post-Quantum Cryptography Assessment Platform.
Main FastAPI application entry point.
"""

import logging
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.api.routes import router as api_router

# Configure clean logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)
logger = logging.getLogger("quantumshield")

app = FastAPI(
    title="QuantumShield API",
    description="Banking Security Audit & Zero-Trust Readiness Platform with Quantum-Safe Cryptographic Assessment",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
)

# Configure CORS for local development and production deployments
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Allows all origins for local hackathon development
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Register API routes
app.include_router(api_router, prefix="/api")


@app.get("/")
def root():
    return {
        "platform": "QuantumShield",
        "tagline": "Know your cryptographic exposure before quantum computers do.",
        "api_docs": "/docs",
        "health_check": "/api/health",
        "scan_endpoint": "POST /api/scan",
        "audit_endpoint": "POST /api/audit",
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app.main:app", host="0.0.0.0", port=8000, reload=True)

