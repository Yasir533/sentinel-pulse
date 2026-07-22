import base64
from datetime import datetime
import requests
from flask import current_app
from app.extensions import db
from app.models.threat import Threat, VTEnrichment

def get_virustotal_api_key() -> str:
    """Retrieve the VirusTotal API key from current app configuration."""
    return current_app.config.get('VIRUSTOTAL_API_KEY', '').strip()

def lookup_ioc_on_vt(ioc_type: str, ioc_value: str) -> dict:
    """
    Lookup an IOC on VirusTotal API v3.
    Supported types: IP Address, Domain, URL, MD5, SHA256.
    Returns the parsed JSON response dict.
    """
    api_key = get_virustotal_api_key()
    if not api_key:
        raise ValueError("VirusTotal API Key is not configured.")

    headers = {
        "x-apikey": api_key,
        "accept": "application/json"
    }

    normalized_type = ioc_type.lower().strip()
    val = ioc_value.strip()

    if 'ip' in normalized_type:
        endpoint = f"ip_addresses/{val}"
    elif 'domain' in normalized_type:
        endpoint = f"domains/{val}"
    elif 'url' in normalized_type:
        # Base64 encode the URL, safe, strip padding '='
        url_id = base64.urlsafe_b64encode(val.encode()).decode().strip("=")
        endpoint = f"urls/{url_id}"
    elif 'md5' in normalized_type or 'sha256' in normalized_type or 'sha-256' in normalized_type or 'sha1' in normalized_type or 'hash' in normalized_type:
        endpoint = f"files/{val}"
    else:
        # Generic heuristic: if it matches MD5 or SHA256 formats
        clean_val = val.lower()
        if len(clean_val) in (32, 40, 64) and all(c in '0123456789abcdef' for c in clean_val):
            endpoint = f"files/{val}"
        else:
            raise ValueError(f"Unsupported IOC type for VirusTotal lookup: {ioc_type}")

    url = f"https://www.virustotal.com/api/v3/{endpoint}"
    
    try:
        response = requests.get(url, headers=headers, timeout=10)
    except requests.exceptions.Timeout:
        raise TimeoutError("VirusTotal API request timed out.")
    except requests.exceptions.RequestException as e:
        raise ConnectionError(f"Network error communicating with VirusTotal: {e}")

    if response.status_code == 200:
        return response.json()
    elif response.status_code == 404:
        raise FileNotFoundError("IOC not found in VirusTotal database.")
    elif response.status_code == 429:
        raise ConnectionRefusedError("VirusTotal API rate limit exceeded.")
    elif response.status_code == 401:
        raise PermissionError("Invalid VirusTotal API Key.")
    else:
        raise ConnectionError(f"VirusTotal API returned error {response.status_code}: {response.text}")

def enrich_threat(threat: Threat) -> VTEnrichment:
    """
    Queries VirusTotal and stores/updates the VTEnrichment record for the Threat.
    Self-recovers and records failures/skips in the database.
    """
    # Fetch or instantiate the enrichment record
    enrichment = VTEnrichment.query.filter_by(threat_id=threat.id).first()
    if not enrichment:
        enrichment = VTEnrichment(threat_id=threat.id)
        db.session.add(enrichment)

    # Check if API Key is configured
    api_key = get_virustotal_api_key()
    if not api_key:
        enrichment.status = 'failed'
        enrichment.error_message = "VirusTotal API Key is not configured."
        db.session.commit()
        return enrichment

    # 24-Hour Cache Check: Reuse recent successful enrichment for identical IOC
    from datetime import timedelta
    cached = VTEnrichment.query.join(Threat).filter(
        Threat.ioc_value == threat.ioc_value,
        VTEnrichment.status == 'success',
        VTEnrichment.updated_at >= datetime.utcnow() - timedelta(hours=24)
    ).first()

    if cached:
        enrichment.status = 'success'
        enrichment.malicious_count = cached.malicious_count
        enrichment.suspicious_count = cached.suspicious_count
        enrichment.harmless_count = cached.harmless_count
        enrichment.undetected_count = cached.undetected_count
        enrichment.reputation = cached.reputation
        enrichment.raw_data = cached.raw_data
        enrichment.error_message = None
        db.session.commit()
        return enrichment

    enrichment.status = 'pending'
    db.session.commit()

    try:
        data = lookup_ioc_on_vt(threat.ioc_type, threat.ioc_value)
        
        attributes = data.get('data', {}).get('attributes', {})
        stats = attributes.get('last_analysis_stats', {})
        
        enrichment.status = 'success'
        enrichment.malicious_count = stats.get('malicious', 0)
        enrichment.suspicious_count = stats.get('suspicious', 0)
        enrichment.harmless_count = stats.get('harmless', 0)
        enrichment.undetected_count = stats.get('undetected', 0)
        enrichment.reputation = attributes.get('reputation', 0)
        enrichment.raw_data = data
        enrichment.error_message = None
        
        db.session.commit()
        return enrichment
        
    except Exception as e:
        current_app.logger.error(f"VirusTotal ERROR: {e}")
        enrichment.status = 'failed'
        enrichment.error_message = str(e)
        db.session.commit()
        return enrichment
