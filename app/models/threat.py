from datetime import datetime
from app.extensions import db

class Threat(db.Model):
    """
    Database model representing indicators of compromise (IOCs) and security threats.
    """
    __tablename__ = 'threats'

    # Valid Choices / Constraints
    THREAT_TYPES = [
        'Malware', 'Phishing', 'Intrusion', 'Ransomware', 
        'Suspicious Login', 'Malicious URL', 'Malicious IP', 
        'Malicious Domain', 'Other'
    ]
    SEVERITIES = ['Critical', 'High', 'Medium', 'Low']
    STATUSES = ['New', 'Investigating', 'Resolved', 'False Positive']

    id = db.Column(db.Integer, primary_key=True)
    threat_type = db.Column(db.String(50), nullable=False, default='Other')
    ioc_type = db.Column(db.String(50), nullable=False)
    ioc_value = db.Column(db.String(256), nullable=False)
    severity = db.Column(db.String(20), nullable=False, default='Medium')
    source = db.Column(db.String(100), nullable=False)
    status = db.Column(db.String(20), nullable=False, default='New')
    confidence_score = db.Column(db.Integer, nullable=False, default=0)
    description = db.Column(db.Text, nullable=True)
    
    # Relationships
    created_by = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='CASCADE'), nullable=False)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relationship to user model
    creator = db.relationship('User', backref=db.backref('threats', lazy=True))

    def __repr__(self) -> str:
        return f'<Threat {self.threat_type} - {self.ioc_value} ({self.severity})>'


class VTEnrichment(db.Model):
    """
    Database model representing VirusTotal analysis results for threat IOCs.
    """
    __tablename__ = 'vt_enrichments'

    id = db.Column(db.Integer, primary_key=True)
    threat_id = db.Column(db.Integer, db.ForeignKey('threats.id', ondelete='CASCADE'), nullable=False, unique=True)
    status = db.Column(db.String(20), nullable=False, default='pending') # pending, success, failed
    malicious_count = db.Column(db.Integer, nullable=False, default=0)
    suspicious_count = db.Column(db.Integer, nullable=False, default=0)
    harmless_count = db.Column(db.Integer, nullable=False, default=0)
    undetected_count = db.Column(db.Integer, nullable=False, default=0)
    reputation = db.Column(db.Integer, nullable=False, default=0)
    raw_data = db.Column(db.JSON, nullable=True)
    error_message = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relationship to Threat
    threat = db.relationship('Threat', backref=db.backref('vt_enrichment', uselist=False, cascade='all, delete-orphan'))

    def __repr__(self) -> str:
        return f'<VTEnrichment Threat {self.threat_id} ({self.status})>'


class AbuseIPDBEnrichment(db.Model):
    """
    Database model representing AbuseIPDB analysis results for IP Address IOCs.
    """
    __tablename__ = 'abuseipdb_enrichments'

    id = db.Column(db.Integer, primary_key=True)
    threat_id = db.Column(db.Integer, db.ForeignKey('threats.id', ondelete='CASCADE'), nullable=False, unique=True)
    status = db.Column(db.String(20), nullable=False, default='pending') # pending, success, failed
    abuse_confidence_score = db.Column(db.Integer, nullable=True)
    country_code = db.Column(db.String(10), nullable=True)
    country_name = db.Column(db.String(100), nullable=True)
    isp = db.Column(db.String(256), nullable=True)
    domain = db.Column(db.String(256), nullable=True)
    usage_type = db.Column(db.String(100), nullable=True)
    total_reports = db.Column(db.Integer, nullable=True)
    last_reported_at = db.Column(db.DateTime, nullable=True)
    raw_data = db.Column(db.JSON, nullable=True)
    error_message = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relationship to Threat
    threat = db.relationship('Threat', backref=db.backref('abuseipdb_enrichment', uselist=False, cascade='all, delete-orphan'))

    @property
    def risk_level(self) -> dict:
        """
        Dynamically calculate Risk Level properties based on the confidence score.
        """
        from app.services.abuseipdb import calculate_abuse_risk
        return calculate_abuse_risk(self.abuse_confidence_score or 0)

    def __repr__(self) -> str:
        return f'<AbuseIPDBEnrichment Threat {self.threat_id} ({self.status})>'
