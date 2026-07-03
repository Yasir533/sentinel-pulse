from datetime import datetime
from app.extensions import db

class ReportSchedule(db.Model):
    """
    Database model representing report generation schedules.
    """
    __tablename__ = 'report_schedules'

    id = db.Column(db.Integer, primary_key=True)
    report_type = db.Column(db.String(50), nullable=False)
    frequency = db.Column(db.String(20), nullable=False) # 'Daily', 'Weekly', 'Monthly'
    email_recipient = db.Column(db.String(120), nullable=False)
    is_active = db.Column(db.Boolean, nullable=False, default=True)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    created_by_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='SET NULL'), nullable=True)

    # Relationships
    creator = db.relationship('User', backref=db.backref('schedules', lazy=True))

    def __repr__(self) -> str:
        return f"<ReportSchedule {self.report_type} - {self.frequency}>"
