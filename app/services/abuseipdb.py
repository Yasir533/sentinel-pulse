import ipaddress
from datetime import datetime
import requests
from flask import current_app
from app.extensions import db
from app.models.threat import Threat, AbuseIPDBEnrichment

def get_abuseipdb_api_key() -> str:
    """Retrieve the AbuseIPDB API key from current app configuration."""
    return current_app.config.get('ABUSEIPDB_API_KEY', '').strip()

def lookup_ip(ip_address: str) -> dict:
    """
    Lookup an IP address on AbuseIPDB API v2.
    Validates the structure and range of the IP before querying.
    Returns the parsed JSON response dict.
    """
    api_key = get_abuseipdb_api_key()
    if not api_key:
        raise ValueError("AbuseIPDB API Key is not configured.")

    val = ip_address.strip()

    # Structure validation: Verify it's a valid IP address
    try:
        ip_obj = ipaddress.ip_address(val)
    except ValueError:
        raise ValueError("Invalid IP address format.")

    # Private IP validation: Skip calling remote API for private IPs
    if ip_obj.is_private:
        raise ValueError("Private IP addresses cannot be checked.")

    headers = {
        "Key": api_key,
        "Accept": "application/json"
    }
    params = {
        "ipAddress": val,
        "maxAgeInDays": 90
    }

    url = "https://api.abuseipdb.com/api/v2/check"
    
    try:
        response = requests.get(url, headers=headers, params=params, timeout=10)
    except requests.exceptions.Timeout:
        raise TimeoutError("AbuseIPDB API request timed out.")
    except requests.exceptions.RequestException as e:
        raise ConnectionError(f"Network error communicating with AbuseIPDB: {e}")

    if response.status_code == 200:
        return response.json()
    elif response.status_code == 401:
        raise PermissionError("Invalid AbuseIPDB API Key.")
    elif response.status_code == 404:
        raise FileNotFoundError("IP address not found in AbuseIPDB database.")
    elif response.status_code == 429:
        raise ConnectionRefusedError("AbuseIPDB API rate limit exceeded.")
    else:
        raise ConnectionError(f"AbuseIPDB API returned error {response.status_code}: {response.text}")

def enrich_ip(threat: Threat) -> AbuseIPDBEnrichment:
    """
    Queries AbuseIPDB and stores/updates the AbuseIPDBEnrichment record for the Threat.
    Self-recovers and records failures/skips in the database.
    """
    # Fetch or instantiate the enrichment record
    enrichment = AbuseIPDBEnrichment.query.filter_by(threat_id=threat.id).first()
    if not enrichment:
        enrichment = AbuseIPDBEnrichment(threat_id=threat.id)
        db.session.add(enrichment)

    # Check if API Key is configured
    api_key = get_abuseipdb_api_key()
    if not api_key:
        enrichment.status = 'failed'
        enrichment.error_message = "API Key Missing"
        db.session.commit()
        return enrichment

    enrichment.status = 'pending'
    db.session.commit()

    try:
        data = lookup_ip(threat.ioc_value)
        
        ip_data = data.get('data', {})
        
        enrichment.status = 'success'
        enrichment.abuse_confidence_score = ip_data.get('abuseConfidenceScore', 0)
        enrichment.country_code = ip_data.get('countryCode')
        enrichment.country_name = ip_data.get('countryName')
        enrichment.isp = ip_data.get('isp')
        enrichment.domain = ip_data.get('domain')
        enrichment.usage_type = ip_data.get('usageType')
        enrichment.total_reports = ip_data.get('totalReports', 0)
        
        # Parse lastReportedAt safely
        last_reported_str = ip_data.get('lastReportedAt')
        last_reported_at = None
        if last_reported_str:
            try:
                # normalize Z representation to timezone offset
                if last_reported_str.endswith('Z'):
                    last_reported_str = last_reported_str[:-1] + '+00:00'
                dt = datetime.fromisoformat(last_reported_str)
                # Keep it naive UTC
                if dt.tzinfo is not None:
                    dt = dt.astimezone().replace(tzinfo=None)
                last_reported_at = dt
            except Exception:
                pass
                
        enrichment.last_reported_at = last_reported_at
        enrichment.raw_data = data
        enrichment.error_message = None
        
        db.session.commit()
        return enrichment
        
    except Exception as e:
        current_app.logger.error(f"AbuseIPDB ERROR: {e}")
        enrichment.status = 'failed'
        # Map specific exceptions to standard user facing error messages
        error_msg = str(e)
        if isinstance(e, PermissionError):
            error_msg = "API Key Missing" if "missing" in str(e).lower() else "Invalid AbuseIPDB API Key."
        elif isinstance(e, ConnectionRefusedError):
            error_msg = "Rate Limit Exceeded"
        elif isinstance(e, (TimeoutError, ConnectionError)):
            error_msg = "Network Error"
        
        enrichment.error_message = error_msg
        db.session.commit()
        return enrichment


def calculate_abuse_risk(score: int) -> dict:
    """
    Calculate the Risk Level dynamically based on Abuse Confidence Score.
    
    0-20   -> Low Risk (Green, Shield Check)
    21-60  -> Medium Risk (Yellow/Orange, Exclamation Triangle)
    61-100 -> High Risk (Red, Shield Exclamation)
    """
    if score is None:
        score = 0
        
    if score <= 20:
        return {
            "label": "Low Risk",
            "badge": "success",
            "icon": "bi-shield-check",
            "color": "#22c55e",
            "recommendation": "No immediate action required. Continue monitoring."
        }
    elif score <= 60:
        return {
            "label": "Medium Risk",
            "badge": "warning",
            "icon": "bi-exclamation-triangle",
            "color": "#f59e0b",
            "recommendation": "Further investigation recommended. Monitor network activity."
        }
    else:
        return {
            "label": "High Risk",
            "badge": "danger",
            "icon": "bi-shield-exclamation",
            "color": "#ef4444",
            "recommendation": "Immediate investigation required. Consider blocking this IP and initiating an incident response."
        }
