# Sentinel Pulse Deployment & Operational Playbook

This document describes the instructions required to deploy Sentinel Pulse with the Mobile Protection module to production environments.

## Deployment Checklist

1. **Environment Configuration:**
   - Configure Python 3.12+ virtual environment.
   - Install dependencies using `pip install -r requirements.txt`.
   - Set environment variables inside `.env`:
     ```env
     SECRET_KEY=your_production_secret_key
     VIRUSTOTAL_API_KEY=your_vt_api_key
     ABUSEIPDB_API_KEY=your_abuseipdb_key
     FLASK_APP=run.py
     FLASK_ENV=production
     ```

2. **Database Initialization:**
   - On startup, the application factory will automatically create the database models, including the new tables `mobile_submission` and `threat_intel` using SQLAlchemy.

3. **Running the Application Server:**
   - For local development: `python run.py`.
   - For production environments: Use Gunicorn as the WSGI server:
     ```bash
     gunicorn -w 4 -b 0.0.0.0:5000 run:app
     ```

## Verification Scenarios
- Visit the dashboard at `/mobile/dashboard`.
- Verify System Health heartbeat states on `/health` shows Nominal heartbeats for "Mobile Ingestion Endpoint" and "AI Decision heuristics".
- Execute automated unit and integration tests using `pytest`.
