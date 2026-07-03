from datetime import datetime
from app.extensions import db

class Incident(db.Model):
    """
    Database model representing security incidents linked to threat indicators.
    """
    __tablename__ = 'incidents'

    STATUSES = ['Open', 'In Progress', 'Under Investigation', 'Resolved', 'Closed']
    SEVERITIES = ['Low', 'Medium', 'High', 'Critical']

    id = db.Column(db.Integer, primary_key=True)
    incident_number = db.Column(db.String(20), unique=True, nullable=False, index=True)
    threat_id = db.Column(db.Integer, db.ForeignKey('threats.id', ondelete='CASCADE'), nullable=False)
    title = db.Column(db.String(128), nullable=False)
    description = db.Column(db.Text, nullable=True)
    severity = db.Column(db.String(20), nullable=False, default='Medium')
    status = db.Column(db.String(30), nullable=False, default='Open')
    
    assigned_to = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='SET NULL'), nullable=True)
    created_by = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='CASCADE'), nullable=False)
    
    resolution_notes = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow, onupdate=datetime.utcnow)
    resolved_at = db.Column(db.DateTime, nullable=True)

    # Relationships
    threat = db.relationship('Threat', backref=db.backref('incidents', lazy=True, cascade='all, delete-orphan'))
    assignee = db.relationship('User', foreign_keys=[assigned_to], backref=db.backref('assigned_incidents', lazy=True))
    creator = db.relationship('User', foreign_keys=[created_by], backref=db.backref('created_incidents', lazy=True))

    def __repr__(self) -> str:
        return f'<Incident {self.incident_number} - {self.title} ({self.status})>'
