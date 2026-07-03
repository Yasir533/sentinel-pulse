from datetime import datetime
from app.extensions import db

class MobileSubmission(db.Model):
    """
    Database model representing smartphone threat submissions (SMS, WhatsApp, Email, URLs, APKs, etc.)
    and their corresponding scanning & AI analysis results.
    """
    __tablename__ = 'mobile_submissions'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='CASCADE'), nullable=False)
    submission_type = db.Column(db.String(50), nullable=False) # sms, whatsapp, email, url, phone, apk, qr, etc.
    content = db.Column(db.Text, nullable=False)
    meta_data = db.Column(db.JSON, nullable=True) # headers, sha256, filename, sender details, etc.
    
    # Analysis outputs
    risk_score = db.Column(db.Integer, nullable=False, default=0)
    verdict = db.Column(db.String(30), nullable=False, default='ALLOW') # ALLOW, WARN, BLOCK, QUARANTINE, ESCALATE
    threat_category = db.Column(db.String(100), nullable=False, default='Safe')
    confidence = db.Column(db.Integer, nullable=False, default=100)
    ai_recommendation = db.Column(db.Text, nullable=True)
    screenshot_path = db.Column(db.String(256), nullable=True)
    
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

    # Relationships
    user = db.relationship('User', backref=db.backref('mobile_submissions', lazy=True, cascade='all, delete-orphan'))

    def __repr__(self) -> str:
        return f'<MobileSubmission {self.submission_type} - Score: {self.risk_score} ({self.verdict})>'


class ThreatIntel(db.Model):
    """
    Database model representing mobile intelligence signatures (domains, IPs, phone numbers, hashes, emails).
    """
    __tablename__ = 'threat_intel'

    id = db.Column(db.Integer, primary_key=True)
    intel_type = db.Column(db.String(50), nullable=False) # domain, hash, url, phone, email, qr_destination
    intel_value = db.Column(db.String(256), nullable=False, unique=True)
    classification = db.Column(db.String(100), nullable=False, default='Scam')
    mitre_tactic = db.Column(db.String(100), nullable=True)
    mitre_technique = db.Column(db.String(100), nullable=True)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

    def __repr__(self) -> str:
        return f'<ThreatIntel {self.intel_type}: {self.intel_value}>'
