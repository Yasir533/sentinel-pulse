from app.models.threat import Threat
from app.models.alert import Alert
from app.models.incident import Incident

class ScorecardService:
    @staticmethod
    def get_security_score() -> dict:
        """
        Calculate the SOC Security Health Scorecard.
        Returns a dictionary containing raw metrics, the overall score, and a grade rating.
        """
        # Fetch counts
        total_threats = Threat.query.count()
        critical_high_threats = Threat.query.filter(Threat.severity.in_(['Critical', 'High'])).count()

        total_alerts = Alert.query.count()
        open_alerts = Alert.query.filter(Alert.status.in_(['New', 'Acknowledged', 'Investigating'])).count()
        critical_alerts = Alert.query.filter_by(severity='Critical').count()

        total_incidents = Incident.query.count()
        open_incidents = Incident.query.filter(Incident.status.in_(['Open', 'In Progress', 'Under Investigation'])).count()
        resolved_closed = Incident.query.filter(Incident.status.in_(['Resolved', 'Closed'])).count()
        
        # Calculate resolution percentage
        resolution_rate = 100.0
        if total_incidents > 0:
            resolution_rate = round((resolved_closed / total_incidents) * 100, 1)

        # Base Score calculation
        score = 100
        
        # Deduct for open incidents (max 25 deduction)
        incident_deduction = min(open_incidents * 5, 25)
        # Deduct for critical alerts (max 30 deduction)
        critical_alert_deduction = min(critical_alerts * 10, 30)
        # Deduct for unresolved alerts (max 20 deduction)
        unresolved_alert_deduction = min(open_alerts * 2, 20)
        # Deduct for high exposure threats (max 15 deduction)
        threat_deduction = min(critical_high_threats * 3, 15)

        score = score - incident_deduction - critical_alert_deduction - unresolved_alert_deduction - threat_deduction
        # Minimum score floor
        score = max(score, 10)

        # Grade/Status categorization
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

        return {
            'score': score,
            'status': status,
            'badge_class': badge_class,
            'threat_exposure': critical_high_threats,
            'open_alerts': open_alerts,
            'critical_alerts': critical_alerts,
            'resolution_rate': resolution_rate,
            'system_availability': 99.9  # Constant mock availability
        }
