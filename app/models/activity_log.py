from datetime import datetime
from app.extensions import db

class ActivityLog(db.Model):
    """
    Database model representing platform activity log entries.
    """
    __tablename__ = 'activity_logs'

    id = db.Column(db.Integer, primary_key=True)
    message = db.Column(db.String(256), nullable=False)
    timestamp = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    icon = db.Column(db.String(50), nullable=False, default='bi-info-circle')
    badge_class = db.Column(db.String(50), nullable=False, default='bg-secondary-subtle text-muted')

    def __repr__(self) -> str:
        return f'<ActivityLog {self.id} - {self.message[:30]}...>'
