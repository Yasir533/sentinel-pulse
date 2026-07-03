from datetime import datetime
from app.extensions import db

class Report(db.Model):
    """
    Database model representing generated security reports.
    """
    __tablename__ = 'reports'

    id = db.Column(db.Integer, primary_key=True)
    report_number = db.Column(db.String(30), unique=True, nullable=False)
    title = db.Column(db.String(100), nullable=False)
    report_type = db.Column(db.String(50), nullable=False)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    created_by_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='SET NULL'), nullable=True)

    # JSON payload holding stats, summary, recommendations, and chart structures
    payload = db.Column(db.JSON, nullable=False)

    # Relationship to user creator
    creator = db.relationship('User', backref=db.backref('reports', lazy=True))

    def __repr__(self) -> str:
        return f"<Report {self.report_number} - {self.title}>"
