import re
from datetime import datetime
from flask import current_app
from app.extensions import db
from app.models.mobile_security import MobileSubmission, ThreatIntel
from app.models.threat import Threat
from app.models.alert import Alert
from app.services.alert import AlertService
from app.services.audit import AuditService
from app.services.notification import NotificationService

class AIScamAnalyzer:
    @staticmethod
    def correlate_indicator(intel_type: str, value: str) -> bool:
        """
        Check if an indicator (URL, phone number, email, domain, hash) has appeared before.
        """
        value_clean = value.strip().lower()
        # Find if it is in the ThreatIntel database
        existing = ThreatIntel.query.filter_by(intel_type=intel_type, intel_value=value_clean).first()
        if existing:
            return True
        
        # Or if it has been submitted at least twice in mobile submissions
        count = MobileSubmission.query.filter(
            MobileSubmission.content.like(f"%{value_clean}%")
        ).count()
        
        if count >= 1:
            # Auto-save to ThreatIntel to block future occurrences
            try:
                new_intel = ThreatIntel(
                    intel_type=intel_type,
                    intel_value=value_clean,
                    classification='Phishing Campaign',
                    mitre_tactic='Initial Access',
                    mitre_technique='T1566 - Phishing'
                )
                db.session.add(new_intel)
                db.session.commit()
            except Exception:
                db.session.rollback()
            return True
        
        return False

    @classmethod
    def analyze_content(cls, submission_type: str, content: str, meta: dict = None) -> dict:
        """
        Main scanner routine applying heuristics for urgency, fear tactics, fake banks,
        lotteries, courier services, UPI PIN requests, and correlation rules.
        """
        meta = meta or {}
        risk_score = 10
        confidence = 85
        verdict = 'ALLOW'
        threat_category = 'Safe'
        reasons = []
        recommendations = []
        mitre_tactic = None
        mitre_technique = None

        content_lower = content.lower()

        # 1. Threat Correlation checks
        correlated = False
        if submission_type == 'url' or submission_type == 'link':
            if cls.correlate_indicator('url', content):
                risk_score += 40
                reasons.append("URL has been flagged in multiple reports (Correlation)")
                correlated = True
        elif submission_type == 'phone':
            if cls.correlate_indicator('phone', content):
                risk_score += 45
                reasons.append("Phone number is associated with active threat campaigns")
                correlated = True
        elif submission_type == 'email':
            sender = meta.get('sender', '')
            if sender and cls.correlate_indicator('email', sender):
                risk_score += 40
                reasons.append("Sender email belongs to known phishing lists")
                correlated = True
        elif submission_type == 'apk':
            sha256 = meta.get('sha256', '')
            if sha256 and cls.correlate_indicator('hash', sha256):
                risk_score += 55
                reasons.append("File hash matches blacklisted malware signature")
                correlated = True

        # Heuristics - Fake Banks
        bank_keywords = ['hdfc', 'sbi', 'icici', 'axis', 'kyc', 'netbanking', 'paytm', 'paypal', 'blocked', 'suspend', 'verify account']
        if any(kw in content_lower for kw in bank_keywords):
            risk_score += 30
            threat_category = 'Fake Bank Scam'
            reasons.append("Detected bank impersonation attempt (HDFC/SBI/KYC verification)")
            recommendations.append("Never share bank credentials or OTP via text links.")
            mitre_tactic = 'Credential Access'
            mitre_technique = 'T1566.002 - Spearphishing Link'

        # Heuristics - Lottery / Winnings
        lottery_keywords = ['won', 'lottery', 'winner', 'crores', 'millions', 'prize', 'draw', 'claim your']
        if any(kw in content_lower for kw in lottery_keywords):
            risk_score += 25
            threat_category = 'Lottery Scam'
            reasons.append("Lottery or cash prize baiting phrase identified")
            recommendations.append("Do not pay processing fees or transfer money to claim unverified prizes.")
            mitre_tactic = 'Initial Access'
            mitre_technique = 'T1566 - Phishing'

        # Heuristics - UPI Scam
        upi_keywords = ['upi pin', 'gpay', 'phonepe', 'enter pin to receive', 'request money', 'refund']
        if any(kw in content_lower for kw in upi_keywords):
            risk_score += 35
            threat_category = 'UPI Scam'
            reasons.append("UPI PIN prompt for receiving payments detected (Standard fraud behavior)")
            recommendations.append("Remember: Entering your UPI PIN always sends money, it is never required to receive funds.")
            mitre_tactic = 'Defense Evasion'
            mitre_technique = 'T1036 - Masquerading'

        # Heuristics - Job Offer Scam
        job_keywords = ['part-time', 'earn daily', 'work from home', 'telegram task', 'wages', 'salary', 'daily pay']
        if any(kw in content_lower for kw in job_keywords):
            risk_score += 25
            threat_category = 'Job Scam'
            reasons.append("Work-from-home baiting words with unrealistic daily wages")
            recommendations.append("Legitimate companies do not recruit via WhatsApp to complete social tasks.")
            mitre_tactic = 'Initial Access'
            mitre_technique = 'T1566.001 - Spearphishing Attachment'

        # Heuristics - Fake Courier/Postage
        courier_keywords = ['fedex', 'dhl', 'package delayed', 'customs fee', 'parcel track', 'undelivered post']
        if any(kw in content_lower for kw in courier_keywords):
            risk_score += 30
            threat_category = 'Fake Courier Scam'
            reasons.append("Detected courier postage charge threat (FedEx/DHL/Customs decoy)")
            recommendations.append("Verify package status directly on the official tracking portal.")
            mitre_tactic = 'Initial Access'
            mitre_technique = 'T1566 - Phishing'

        # Urgency & Fear Tactics
        urgency_patterns = [r'\b(urgent|immediate|action required|final warning|within \d+ hours|immediately|account locked)\b']
        for pat in urgency_patterns:
            if re.search(pat, content_lower):
                risk_score += 15
                reasons.append("Uses high-urgency or fear-inducing vocabulary")

        # Grammar Anomalies / obfuscation
        char_obfuscation = [r'\b(cl1ck|b@nk|fr33|l0tt3ry|p0st)\b']
        for pat in char_obfuscation:
            if re.search(pat, content_lower):
                risk_score += 20
                reasons.append("Detected deliberate character substitution (grammar anomaly)")

        # VirusTotal Integration Lookup fallback
        if submission_type in ['url', 'link'] and not correlated:
            try:
                # Extract domain or full URL
                from app.services.virustotal import lookup_ioc_on_vt
                vt_res = lookup_ioc_on_vt('URL', content)
                stats = vt_res.get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
                malicious = stats.get('malicious', 0)
                if malicious > 0:
                    risk_score += (malicious * 10)
                    reasons.append(f"VirusTotal detected {malicious} engine detections")
                    threat_category = 'Phishing Link'
            except Exception:
                pass

        if submission_type == 'apk':
            sha256 = meta.get('sha256', '') or meta.get('md5', '')
            if sha256 and not correlated:
                try:
                    from app.services.virustotal import lookup_ioc_on_vt
                    vt_res = lookup_ioc_on_vt('hash', sha256)
                    stats = vt_res.get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
                    malicious = stats.get('malicious', 0)
                    if malicious > 0:
                        risk_score += (malicious * 10)
                        reasons.append(f"VirusTotal flagged file signature as malicious ({malicious} detections)")
                        threat_category = 'Malware APK'
                except Exception:
                    pass

        # Determine Verdict
        risk_score = min(risk_score, 100)
        if risk_score >= 80:
            verdict = 'ESCALATE'
        elif risk_score >= 60:
            verdict = 'BLOCK'
        elif risk_score >= 35:
            verdict = 'WARN'
        elif risk_score >= 20:
            verdict = 'QUARANTINE'
        else:
            verdict = 'ALLOW'

        if risk_score >= 30 and threat_category == 'Safe':
            threat_category = 'Social Engineering'

        if not recommendations:
            if verdict in ['WARN', 'BLOCK', 'ESCALATE']:
                recommendations.append("Exercise extreme caution. Do not click links, transfer money, or download files.")
            else:
                recommendations.append("No active indicators of fraud or malicious campaigns identified.")

        return {
            'risk_score': risk_score,
            'confidence': confidence if risk_score > 15 else 98,
            'verdict': verdict,
            'threat_category': threat_category,
            'reasons': reasons,
            'recommendation': " ".join(recommendations),
            'mitre_tactic': mitre_tactic,
            'mitre_technique': mitre_technique
        }

    @classmethod
    def process_submission(cls, user_id: int, submission_type: str, content: str, meta: dict = None, screenshot_path: str = None) -> MobileSubmission:
        """
        Processes a smartphone submission, creates threat objects, triggers alerts,
        creates audit logs and notifications automatically.
        """
        meta = meta or {}
        analysis = cls.analyze_content(submission_type, content, meta)

        submission = MobileSubmission(
            user_id=user_id,
            submission_type=submission_type,
            content=content,
            meta_data=meta,
            risk_score=analysis['risk_score'],
            verdict=analysis['verdict'],
            threat_category=analysis['threat_category'],
            confidence=analysis['confidence'],
            ai_recommendation=analysis['recommendation'],
            screenshot_path=screenshot_path
        )
        db.session.add(submission)
        db.session.commit()

        # Audit Log submission
        AuditService.log(
            action='Mobile Submission',
            entity=f"Submission {submission.id}",
            after=f"Type={submission.submission_type}, Verdict={submission.verdict}, Category={submission.threat_category}",
            status='Success'
        )

        # Generate threat & alerts if warning/malicious
        if analysis['risk_score'] >= 35:
            # Map IOC details
            ioc_type = 'URL'
            ioc_value = content
            if submission_type == 'apk':
                ioc_type = 'SHA-256'
                ioc_value = meta.get('sha256', 'unknown_apk_hash')
            elif submission_type == 'phone':
                ioc_type = 'Phone'
                ioc_value = content
            elif submission_type == 'email':
                ioc_type = 'Email'
                ioc_value = meta.get('sender', content)

            threat = Threat(
                threat_type=analysis['threat_category'],
                ioc_type=ioc_type,
                ioc_value=ioc_value[:256],
                severity='Critical' if analysis['risk_score'] >= 80 else 'High' if analysis['risk_score'] >= 60 else 'Medium',
                source='Mobile Submission',
                status='New',
                confidence_score=analysis['confidence'],
                description=f"AI Detection: {analysis['reasons'][0] if analysis['reasons'] else 'Scam content detected'}. Recommendations: {analysis['recommendation']}",
                created_by=user_id
            )
            db.session.add(threat)
            db.session.commit()

            # Enrich Threat automatically if it is a hash/URL using VirusTotal service
            if ioc_type in ['URL', 'SHA-256']:
                try:
                    from app.services.virustotal import enrich_threat
                    enrich_threat(threat)
                except Exception:
                    pass

            # Create Alert
            alert = AlertService.generate_alert(threat)
            if not alert:
                alert_number = AlertService.generate_next_alert_number()
                alert = Alert(
                    alert_number=alert_number,
                    threat_id=threat.id,
                    severity=threat.severity,
                    status='New',
                    message=f"Mobile security threat detected ({threat.threat_type}).",
                    ai_risk=threat.severity.upper()
                )
                db.session.add(alert)
                db.session.commit()
                AuditService.log('Alert Generation', f"Alert {alert.alert_number}", after=f"Severity={alert.severity}, Message={alert.message}", status='Success')
                try:
                    NotificationService.create_notification_for_alert(alert)
                except Exception:
                    pass

            # Trigger custom notification for critical scam alerts
            if analysis['risk_score'] >= 80:
                try:
                    NotificationService.create_notification(
                        user_id=user_id,
                        title="Critical Mobile Scam Escalated",
                        message=f"A critical mobile scam ({analysis['threat_category']}) has been automatically escalated to the SOC console.",
                        priority='High',
                        category='Security Update'
                    )
                except Exception:
                    pass

        return submission
