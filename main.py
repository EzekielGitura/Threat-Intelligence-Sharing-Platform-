# Threat Intelligence Sharing Platform
# Main application structure

import asyncio
import uuid
from typing import List, Dict, Any, Optional
from pydantic import BaseModel, Field, validator
from fastapi import FastAPI, HTTPException, Depends, BackgroundTasks
from fastapi.security import APIKeyHeader
from sqlalchemy import create_engine, Column, Integer, String, JSON, DateTime
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session
from datetime import datetime, timedelta
import httpx
import logging
import hashlib
import json

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Database Configuration
DATABASE_URL = "sqlite:///./threat_intel.db"
engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# Models
class ThreatIndicator(Base):
    """
    Database model for storing threat indicators
    """
    __tablename__ = "threat_indicators"
    
    id = Column(Integer, primary_key=True, index=True)
    uid = Column(String, unique=True, index=True)
    type = Column(String)
    value = Column(String)
    confidence = Column(Integer)
    severity = Column(String)
    tags = Column(JSON)
    sources = Column(JSON)
    first_seen = Column(DateTime, default=datetime.utcnow)
    last_seen = Column(DateTime, default=datetime.utcnow)

# Create database tables
Base.metadata.create_all(bind=engine)

# Pydantic Models for API
class ThreatIndicatorCreate(BaseModel):
    """
    Input model for creating threat indicators
    """
    type: str = Field(..., description="Type of threat indicator (IP, Domain, Hash)")
    value: str = Field(..., description="Actual indicator value")
    confidence: int = Field(default=50, ge=0, le=100, description="Confidence score")
    severity: str = Field(default="medium", description="Threat severity")
    tags: Optional[List[str]] = None
    sources: Optional[List[str]] = None

    @validator('type')
    def validate_type(cls, v):
        valid_types = ['ip', 'domain', 'hash', 'email', 'url']
        if v.lower() not in valid_types:
            raise ValueError(f'Invalid type. Must be one of {valid_types}')
        return v.lower()

class ThreatIndicatorResponse(ThreatIndicatorCreate):
    """
    Response model for threat indicators
    """
    uid: str
    first_seen: datetime
    last_seen: datetime

# External Threat Intelligence Services (Simulated)
class ThreatIntelService:
    """
    External threat intelligence service aggregation
    """
    async def fetch_external_intel(self, indicator: str) -> Dict[str, Any]:
        """
        Simulate fetching intelligence from multiple sources
        """
        async with httpx.AsyncClient() as client:
            try:
                # Mock external API calls
                responses = await asyncio.gather(
                    self._virustotal_lookup(client, indicator),
                    self._abuseipdb_lookup(client, indicator)
                )
                return self._merge_intel_responses(responses)
            except Exception as e:
                logger.error(f"External intel fetch error: {e}")
                return {}

    async def _virustotal_lookup(self, client, indicator):
        # Simulated VirusTotal-like lookup
        return {
            "source": "VirusTotal",
            "malicious_votes": 3,
            "total_votes": 10
        }

    async def _abuseipdb_lookup(self, client, indicator):
        # Simulated AbuseIPDB-like lookup
        return {
            "source": "AbuseIPDB",
            "abuse_confidence": 75
        }

    def _merge_intel_responses(self, responses):
        """
        Merge and normalize responses from multiple sources
        """
        merged = {"sources": []}
        for resp in responses:
            if resp:
                merged["sources"].append(resp["source"])
        return merged

# Main Application
app = FastAPI(
    title="Threat Intelligence Sharing Platform",
    description="Aggregate, normalize, and share threat intelligence"
)

# Dependency for database session
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# Threat Intelligence Service
threat_intel_service = ThreatIntelService()

@app.post("/indicators/", response_model=ThreatIndicatorResponse)
async def create_threat_indicator(
    indicator: ThreatIndicatorCreate, 
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db)
):
    """
    Create and enrich a new threat indicator
    """
    # Generate unique identifier
    uid = str(uuid.uuid4())
    
    # Enrich with external intelligence
    background_tasks.add_task(
        _enrich_indicator, 
        indicator.dict(), 
        uid, 
        db
    )

    # Create base indicator record
    db_indicator = ThreatIndicator(
        uid=uid,
        type=indicator.type,
        value=indicator.value,
        confidence=indicator.confidence,
        severity=indicator.severity,
        tags=indicator.tags or [],
        sources=indicator.sources or []
    )
    
    db.add(db_indicator)
    db.commit()
    db.refresh(db_indicator)

    return ThreatIndicatorResponse(
        uid=uid,
        **indicator.dict(),
        first_seen=db_indicator.first_seen,
        last_seen=db_indicator.last_seen
    )

async def _enrich_indicator(indicator_data: dict, uid: str, db: Session):
    """
    Background task for enriching threat indicators
    """
    try:
        # Fetch external intelligence
        external_intel = await threat_intel_service.fetch_external_intel(
            indicator_data['value']
        )

        # Update indicator with enriched data
        db_indicator = db.query(ThreatIndicator).filter(
            ThreatIndicator.uid == uid
        ).first()

        if db_indicator and external_intel:
            # Update sources and confidence
            current_sources = db_indicator.sources or []
            current_sources.extend(external_intel.get('sources', []))
            
            db_indicator.sources = list(set(current_sources))
            db_indicator.last_seen = datetime.utcnow()
            
            db.commit()
    except Exception as e:
        logger.error(f"Enrichment error for {uid}: {e}")

# Utility Endpoints
@app.get("/indicators/", response_model=List[ThreatIndicatorResponse])
def list_indicators(
    skip: int = 0, 
    limit: int = 100, 
    db: Session = Depends(get_db)
):
    """
    List threat indicators with pagination
    """
    indicators = db.query(ThreatIndicator).offset(skip).limit(limit).all()
    return [
        ThreatIndicatorResponse(
            uid=ind.uid,
            type=ind.type,
            value=ind.value,
            confidence=ind.confidence,
            severity=ind.severity,
            tags=ind.tags,
            sources=ind.sources,
            first_seen=ind.first_seen,
            last_seen=ind.last_seen
        ) for ind in indicators
    ]

# Optional: Simple Rate Limiting and Authentication
API_KEYS = {
    "demo_key": {
        "rate_limit": 100,  # requests per hour
        "permissions": ["read", "write"]
    }
}

api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)

def validate_api_key(api_key: str):
    """
    Validate and check API key permissions
    """
    if api_key not in API_KEYS:
        raise HTTPException(status_code=403, detail="Invalid API Key")
    return API_KEYS[api_key]

# Run Configuration
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
  
