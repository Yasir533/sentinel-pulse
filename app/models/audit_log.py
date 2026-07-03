from datetime import datetime
from app.extensions import db

class AuditLog(db.Model):
    """
    Database model representing enterprise-grade action logs for SOC compliance auditing.
    """
    __tablename__ = 'audit_logs'

    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    username = db.Column(db.String(64), nullable=False)
    role = db.Column(db.String(20), nullable=False)
    ip_address = db.Column(db.String(45), nullable=True)
    action = db.Column(db.String(100), nullable=False)
    entity = db.Column(db.String(100), nullable=False)
    
    # Store states before/after the action as serialized JSON/text
    before_state = db.Column(db.Text, nullable=True)
    after_state = db.Column(db.Text, nullable=True)
    
    status = db.Column(db.String(20), nullable=False, default='Success')

    def __repr__(self) -> str:
        return f"<AuditLog {self.id} - {self.action} by {self.username}>"
