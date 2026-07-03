from app.models.threat import Threat
from app.models.alert import Alert
from app.models.incident import Incident

class ScorecardService:
    @staticmethod
    def get_security_score() -> dict:
        """
        Calculate the SOC Security Health Scorecard.

        Formula (RC-2):
          Base Score: 80
          - Critical Alerts:    -10 per alert (max -20)
          - Open Incidents:     -5 per open incident (max -15)
          - High Risk Threats:  -2 per critical/high threat (max -10)
          + Resolved Incidents: +2 per resolved incident (max +8)
          + Healthy APIs:       +2 DB online, +2 VT configured, +2 AbuseIPDB configured (max +6)
          Floor: 10
        """
        # Fetch counts
        critical_high_threats = Threat.query.filter(Threat.severity.in_(['Critical', 'High'])).count()
        critical_alerts = Alert.query.filter_by(severity='Critical').count()

        total_incidents = Incident.query.count()
        open_incidents = Incident.query.filter(
            Incident.status.in_(['Open', 'In Progress', 'Under Investigation'])
        ).count()
        resolved_closed = Incident.query.filter(
            Incident.status.in_(['Resolved', 'Closed'])
        ).count()

        # Resolution rate
        resolution_rate = 100.0
        if total_incidents > 0:
            resolution_rate = round((resolved_closed / total_incidents) * 100, 1)

        # --- Deductions ---
        critical_alert_deduction = min(critical_alerts * 10, 20)
        open_incident_deduction = min(open_incidents * 5, 15)
        threat_deduction = min(critical_high_threats * 2, 10)

        # --- Additions ---
        resolved_bonus = min(resolved_closed * 2, 8)

        # Healthy APIs
        db_bonus = 2  # DB is always connected at query time
        vt_bonus = 0
        abuse_bonus = 0
        try:
            from flask import current_app
            if current_app.config.get('VIRUSTOTAL_API_KEY'):
                vt_bonus = 2
            if current_app.config.get('ABUSEIPDB_API_KEY'):
                abuse_bonus = 2
        except Exception:
            pass

        healthy_api_bonus = db_bonus + vt_bonus + abuse_bonus  # max 6

        # Final score
        score = 80
        score -= critical_alert_deduction
        score -= open_incident_deduction
        score -= threat_deduction
        score += resolved_bonus
        score += healthy_api_bonus
        score = max(score, 10)
        score = min(score, 100)

        # Grade/Status
        if score >= 90:
            status = 'Excellent'
            badge_class = 'bg-success text-white'
        elif score >= 75:
            status = 'Good'
            badge_class = 'bg-info text-dark'
        elif score >= 50:
            status = 'Fair'
            badge_class = 'bg-warning text-dark'
        else:
            status = 'Critical'
            badge_class = 'bg-danger text-white'

        # Build breakdown list for tooltip / explanation
        breakdown = []
        breakdown.append({'label': 'Base Score',             'value': +80,                      'type': 'base'})
        if critical_alert_deduction:
            breakdown.append({'label': f'Critical Alerts ({critical_alerts})',
                               'value': -critical_alert_deduction, 'type': 'deduct'})
        if open_incident_deduction:
            breakdown.append({'label': f'Open Incidents ({open_incidents})',
                               'value': -open_incident_deduction, 'type': 'deduct'})
        if threat_deduction:
            breakdown.append({'label': f'High Risk Threats ({critical_high_threats})',
                               'value': -threat_deduction, 'type': 'deduct'})
        if resolved_bonus:
            breakdown.append({'label': f'Resolved Incidents ({resolved_closed})',
                               'value': +resolved_bonus, 'type': 'bonus'})
        if healthy_api_bonus:
            breakdown.append({'label': f'Healthy APIs ({healthy_api_bonus // 2})',
                               'value': +healthy_api_bonus, 'type': 'bonus'})
        breakdown.append({'label': 'Final Score', 'value': score, 'type': 'final'})

        return {
            'score': score,
            'status': status,
            'rating': status,
            'badge_class': badge_class,
            'threat_exposure': critical_high_threats,
            'open_alerts': Alert.query.filter(
                Alert.status.in_(['New', 'Acknowledged', 'Investigating'])
            ).count(),
            'critical_alerts': critical_alerts,
            'resolution_rate': resolution_rate,
            'system_availability': 99.9,
            # Breakdown for tooltip
            'breakdown': breakdown,
            'critical_alert_deduction': critical_alert_deduction,
            'open_incident_deduction': open_incident_deduction,
            'threat_deduction': threat_deduction,
            'resolved_bonus': resolved_bonus,
            'healthy_api_bonus': healthy_api_bonus,
            'open_incidents': open_incidents,
            'resolved_closed': resolved_closed,
        }
