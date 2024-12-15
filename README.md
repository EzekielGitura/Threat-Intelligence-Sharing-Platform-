# Threat Intelligence Sharing Platform

## Overview
This platform provides a robust solution for aggregating, normalizing, and sharing threat intelligence. It offers a flexible API for creating, enriching, and retrieving threat indicators.

## Features
- Threat Indicator Creation
- External Intelligence Enrichment
- Persistent Storage
- API-based Interaction
- Background Processing
- Basic Authentication

## Prerequisites
- Python 3.8+
- pip (Python Package Manager)

## Installation

### 1. Clone the Repository
```bash
git clone https://github.com/yourusername/threat-intel-platform.git
cd threat-intel-platform
```

### 2. Create Virtual Environment
```bash
python -m venv venv
source venv/bin/activate  # On Windows use `venv\Scripts\activate`
```

### 3. Install Dependencies
```bash
pip install -r requirements.txt
```

### Requirements File (requirements.txt)
```
fastapi
uvicorn
sqlalchemy
pydantic
httpx
asyncio
```

## Running the Application
```bash
uvicorn main:app --reload
```

## API Endpoints

### Create Threat Indicator
`POST /indicators/`
- Payload: Threat Indicator Details
- Background enrichment from external sources
- Generates unique identifier

### List Threat Indicators
`GET /indicators/`
- Supports pagination
- Returns list of threat indicators

## Usage Examples

### Create Indicator
```python
import requests

url = "http://localhost:8000/indicators/"
payload = {
    "type": "ip",
    "value": "8.8.8.8",
    "confidence": 75,
    "severity": "high",
    "tags": ["malware", "c2"]
}

response = requests.post(url, json=payload)
print(response.json())
```

## Security Considerations
- Uses SQLite for lightweight database
- Basic API key authentication
- Async processing for external intelligence
- Input validation

## Possible Improvements
1. Add more external threat intel sources
2. Implement more robust authentication
3. Create web dashboard
4. Add advanced filtering capabilities

## Deployment Notes
- Use production WSGI server (Gunicorn)
- Configure proper database (PostgreSQL)
- Implement proper secret management
- Set up logging and monitoring
```
