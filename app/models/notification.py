from datetime import datetime
from app.extensions import db

class Notification(db.Model):
    """
    Database model representing platform notifications.
    """
    __tablename__ = 'notifications'

    id = db.Column(db.Integer, primary_key=True)
    notification_number = db.Column(db.String(20), unique=True, nullable=False, index=True)
    title = db.Column(db.String(128), nullable=False)
    message = db.Column(db.Text, nullable=False)
    type = db.Column(db.String(20), nullable=False)  # Threat, Alert, Incident, System
    priority = db.Column(db.String(20), nullable=False, default='Medium')  # Critical, High, Medium, Low
    status = db.Column(db.String(20), nullable=False, default='Unread')  # Unread, Read
    user_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='CASCADE'), nullable=False)
    related_alert_id = db.Column(db.Integer, db.ForeignKey('alerts.id', ondelete='SET NULL'), nullable=True)
    related_incident_id = db.Column(db.Integer, db.ForeignKey('incidents.id', ondelete='SET NULL'), nullable=True)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    read_at = db.Column(db.DateTime, nullable=True)

    # Relationships
    user = db.relationship('User', backref=db.backref('notifications', lazy=True, cascade='all, delete-orphan'))
    alert = db.relationship('Alert', backref=db.backref('notifications', lazy=True))
    incident = db.relationship('Incident', backref=db.backref('notifications', lazy=True))

    @property
    def relative_time(self) -> str:
        now = datetime.utcnow()
        delta = now - self.created_at
        if delta.days > 0:
            return f"{delta.days}d ago"
        hours = delta.seconds // 3600
        if hours > 0:
            return f"{hours}h ago"
        minutes = delta.seconds // 60
        if minutes > 0:
            return f"{minutes}m ago"
        return "just now"

    @property
    def color_class(self) -> str:
        if self.priority == 'Critical':
            return 'danger'
        elif self.priority == 'High':
            return 'warning'
        elif self.priority == 'Medium':
            return 'info'
        return 'secondary'

    @property
    def priority_class(self) -> str:
        if self.priority == 'Critical':
            return 'danger'
        elif self.priority == 'High':
            return 'warning'
        elif self.priority == 'Medium':
            return 'info'
        return 'secondary'

    @property
    def icon_class(self) -> str:
        if self.type == 'Threat':
            return 'bi-virus'
        elif self.type == 'Alert':
            return 'bi-alarm'
        elif self.type == 'Incident':
            return 'bi-exclamation-triangle'
        return 'bi-gear'

    @property
    def link_url(self) -> str:
        from flask import url_for
        if self.related_incident_id:
            try:
                return url_for('incidents.view_incident', incident_id=self.related_incident_id)
            except Exception:
                pass
        if self.related_alert_id:
            try:
                return url_for('alerts.view_alert', alert_id=self.related_alert_id)
            except Exception:
                pass
        try:
            return url_for('notifications.list_notifications')
        except Exception:
            return '/notifications/'

    def __repr__(self) -> str:
        return f'<Notification {self.notification_number} - {self.title} ({self.status})>'
