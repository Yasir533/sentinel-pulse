from datetime import datetime
from app.extensions import db

class Alert(db.Model):
    """
    Database model representing security alerts generated from high-risk threats.
    """
    __tablename__ = 'alerts'

    STATUSES = ['New', 'Acknowledged', 'Investigating', 'Resolved', 'Archived']
    SEVERITIES = ['Low', 'Medium', 'High', 'Critical']

    id = db.Column(db.Integer, primary_key=True)
    alert_number = db.Column(db.String(20), unique=True, nullable=False, index=True)
    threat_id = db.Column(db.Integer, db.ForeignKey('threats.id', ondelete='CASCADE'), nullable=False)
    severity = db.Column(db.String(20), nullable=False, default='Medium')
    status = db.Column(db.String(20), nullable=False, default='New')
    message = db.Column(db.Text, nullable=True)
    ai_risk = db.Column(db.String(20), nullable=False, default='LOW')
    
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow, onupdate=datetime.utcnow)
    acknowledged_at = db.Column(db.DateTime, nullable=True)
    resolved_at = db.Column(db.DateTime, nullable=True)
    acknowledged_by = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='SET NULL'), nullable=True)

    # Relationships
    threat = db.relationship('Threat', backref=db.backref('alerts', lazy=True, cascade='all, delete-orphan'))
    acknowledged_by_user = db.relationship('User', foreign_keys=[acknowledged_by], backref=db.backref('acknowledged_alerts', lazy=True))

    def __repr__(self) -> str:
        return f'<Alert {self.alert_number} - {self.severity} ({self.status})>'
