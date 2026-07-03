from datetime import datetime
from flask import current_app
from app.extensions import db
from app.models.alert import Alert
from app.models.threat import Threat
from app.services.activity import log_activity
from app.services.threat_summary import calculate_overall_risk

class AlertService:
    @staticmethod
    def generate_next_alert_number() -> str:
        """
        Generate an auto-incrementing alert number in format: ALT-YYYY-XXXX.
        Ensures uniqueness.
        """
        year = datetime.utcnow().year
        prefix = f"ALT-{year}-"
        # Find the maximum sequence number for the current year
        max_alert = db.session.query(Alert).filter(Alert.alert_number.like(f"{prefix}%")).order_by(Alert.alert_number.desc()).first()
        if max_alert:
            try:
                last_seq = int(max_alert.alert_number.split('-')[-1])
                next_seq = last_seq + 1
            except ValueError:
                next_seq = 1
        else:
            next_seq = 1
        return f"{prefix}{next_seq:04d}"

    @classmethod
    def generate_alert(cls, threat: Threat) -> Alert | None:
        """
        Evaluate threat telemetry and risk summary. If rules match, automatically create an Alert.
        Ensures no duplicate alert is generated for the same threat (unless existing alerts are Archived).
        """
        # 1. Prevent duplicate alerts (only block if there is a non-Archived alert for this threat)
        active_alert = Alert.query.filter(
            Alert.threat_id == threat.id,
            Alert.status != 'Archived'
        ).first()
        if active_alert:
            return active_alert

        # 2. Get AI Overall Risk
        risk_info = calculate_overall_risk(threat)
        ai_risk_label = risk_info.get("label", "LOW").upper()

        # Rule validation checks
        is_critical_vt = False
        is_critical_ai = False
        is_high_abuse = False
        is_high_ai = False

        # Rule 1: AI Risk = HIGH -> High Alert
        if ai_risk_label == 'HIGH':
            is_high_ai = True

        # Rule 2: AI Risk = CRITICAL -> Critical Alert
        if ai_risk_label == 'CRITICAL':
            is_critical_ai = True

        # Rule 3: VirusTotal malicious detections >= 20 -> Critical Alert
        if threat.vt_enrichment and threat.vt_enrichment.status == 'success':
            if (threat.vt_enrichment.malicious_count or 0) >= 20:
                is_critical_vt = True

        # Rule 4: AbuseIPDB confidence >= 80 -> High Alert
        if threat.abuseipdb_enrichment and threat.abuseipdb_enrichment.status == 'success':
            if (threat.abuseipdb_enrichment.abuse_confidence_score or 0) >= 80:
                is_high_abuse = True

        # Rule 5: AI Risk = LOW -> Do NOT create Alert based on AI Risk
        # (Note: VT or AbuseIPDB rules can still trigger alert creation even if AI Risk is LOW)

        # Determine final severity and construct message
        severity = None
        message = ""

        if is_critical_vt or is_critical_ai:
            severity = 'Critical'
            if is_critical_vt:
                message = "Critical malware identified by VirusTotal."
            else:
                message = "High-risk indicator requires analyst investigation."
        elif is_high_abuse or is_high_ai:
            severity = 'High'
            if is_high_abuse:
                message = "Malicious IP exceeds AbuseIPDB confidence threshold."
            else:
                message = "High Risk IOC detected."

        # If severity matches, create the alert
        if severity:
            alert_number = cls.generate_next_alert_number()
            
            # If no specific message was set, use a fallback default message
            if not message:
                message = "High-risk indicator requires analyst investigation."

            alert = Alert(
                alert_number=alert_number,
                threat_id=threat.id,
                severity=severity,
                status='New',
                message=message,
                ai_risk=ai_risk_label
            )
            
            db.session.add(alert)
            db.session.commit()

            from app.services.audit import AuditService
            AuditService.log('Alert Generation', f"Alert {alert.alert_number}", after=f"Severity={alert.severity}, Message={alert.message}", status='Success')

            # Trigger notification
            try:
                from app.services.notification import NotificationService
                NotificationService.create_notification_for_alert(alert)
            except Exception:
                pass

            # Format log layout
            log_msg = (
                f"[Alert Engine]\n"
                f"Threat #{threat.id} evaluated\n"
                f"AI Risk {ai_risk_label}\n"
                f"Alert Generated\n"
                f"{alert_number}"
            )
            try:
                current_app.logger.info(log_msg)
            except Exception:
                pass

            # Log Activity
            log_activity(
                message=f"Alert Generated: {alert_number} ({severity}) for threat {threat.ioc_value}",
                icon="bi-bell-fill",
                badge_class="bg-danger-subtle text-danger"
            )
            
            return alert

        return None


def generate_next_alert_number() -> str:
    """Backwards compatible wrapper for generate_next_alert_number."""
    return AlertService.generate_next_alert_number()


def evaluate_and_create_alert(threat: Threat) -> Alert | None:
    """Backwards compatible wrapper for evaluate_and_create_alert."""
    return AlertService.generate_alert(threat)

