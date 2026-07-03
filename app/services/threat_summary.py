from app.models.threat import Threat

def calculate_overall_risk(threat: Threat) -> dict:
    """
    Calculate the Overall Risk dynamically based on VirusTotal and AbuseIPDB telemetry.
    Returns a dict with overall risk properties: label, badge, and color.
    """
    malicious_count = 0
    if threat.vt_enrichment and threat.vt_enrichment.status == 'success':
        malicious_count = threat.vt_enrichment.malicious_count or 0

    abuse_confidence_score = 0
    if threat.abuseipdb_enrichment and threat.abuseipdb_enrichment.status == 'success':
        abuse_confidence_score = threat.abuseipdb_enrichment.abuse_confidence_score or 0

    if malicious_count >= 20 or abuse_confidence_score > 80:
        return {
            "label": "HIGH",
            "badge": "danger",
            "color": "#ef4444"
        }
    elif (5 <= malicious_count <= 19) or (21 <= abuse_confidence_score <= 80):
        return {
            "label": "MEDIUM",
            "badge": "warning",
            "color": "#f59e0b"
        }
    else:
        return {
            "label": "LOW",
            "badge": "success",
            "color": "#22c55e"
        }

def generate_summary(threat: Threat) -> str:
    """
    Generate the AI threat summary description based on the calculated overall risk.
    """
    risk_info = calculate_overall_risk(threat)
    risk_label = risk_info["label"]
    
    if risk_label == "HIGH":
        return "This IOC is strongly associated with malicious activity across multiple intelligence sources."
    elif risk_label == "MEDIUM":
        return "This IOC has mixed intelligence results. Further investigation is recommended before taking action."
    else:
        return "This IOC appears to be safe based on current threat intelligence. No major security vendors detected malicious behaviour."

def generate_recommendation(threat: Threat) -> list[str]:
    """
    Generate analyst recommendations based on the calculated overall risk.
    """
    risk_info = calculate_overall_risk(threat)
    risk_label = risk_info["label"]
    
    if risk_label == "HIGH":
        return [
            "Block the IOC",
            "Initiate incident response",
            "Investigate affected assets",
            "Continue monitoring"
        ]
    elif risk_label == "MEDIUM":
        return [
            "Investigate related systems",
            "Monitor network activity",
            "Review firewall logs"
        ]
    else:
        return [
            "Continue monitoring",
            "No immediate action"
        ]
