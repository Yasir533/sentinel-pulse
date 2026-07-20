from datetime import datetime
from app.extensions import db

class AIDecision(db.Model):
    """
    Database model representing structured AI/ML and rule-based decision logs.
    Preserves auditability, explainability, and human-in-the-loop oversight.
    """
    __tablename__ = 'ai_decisions'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='SET NULL'), nullable=True, index=True)
    input_type = db.Column(db.String(50), nullable=False, index=True) # e.g. 'url', 'sms', 'apk', 'incident'
    input_value = db.Column(db.Text, nullable=False)
    engine_type = db.Column(db.String(50), nullable=False, default='Hybrid Rule & Threat Intel Engine')
    risk_score = db.Column(db.Integer, nullable=False, default=0)
    confidence = db.Column(db.Integer, nullable=False, default=0)
    severity = db.Column(db.String(20), nullable=False, default='Medium') # Low, Medium, High, Critical
    verdict = db.Column(db.String(20), nullable=False, default='ALLOW') # ALLOW, BLOCK, WARN
    reasoning_summary = db.Column(db.Text, nullable=True)
    mitre_tactic = db.Column(db.String(100), nullable=True)
    mitre_technique = db.Column(db.String(100), nullable=True)
    sources_consulted = db.Column(db.String(255), nullable=True)
    recommended_action = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow, index=True)

    # Relationships
    user = db.relationship('User', backref=db.backref('ai_decisions', lazy='dynamic'))

    def to_dict(self) -> dict:
        return {
            'id': self.id,
            'user_id': self.user_id,
            'username': self.user.username if self.user else 'System/Anonymous',
            'input_type': self.input_type,
            'input_value': self.input_value[:100] + ('...' if len(self.input_value) > 100 else ''),
            'engine_type': self.engine_type,
            'risk_score': self.risk_score,
            'confidence': self.confidence,
            'severity': self.severity,
            'verdict': self.verdict,
            'reasoning_summary': self.reasoning_summary,
            'mitre_tactic': self.mitre_tactic,
            'mitre_technique': self.mitre_technique,
            'sources_consulted': self.sources_consulted,
            'recommended_action': self.recommended_action,
            'created_at': self.created_at.strftime('%Y-%m-%d %H:%M:%S UTC')
        }

    def __repr__(self) -> str:
        return f'<AIDecision #{self.id} {self.input_type}:{self.verdict} Risk:{self.risk_score}>'
