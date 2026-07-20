from datetime import datetime
from flask import current_app
from app.extensions import db
from app.models.ai_decision import AIDecision

class AIDecisionService:
    @staticmethod
    def log_decision(
        input_type: str,
        input_value: str,
        risk_score: int,
        confidence: int,
        verdict: str,
        reasoning_summary: str,
        user_id: int = None,
        severity: str = 'Medium',
        engine_type: str = 'Hybrid-Rule-ML',
        mitre_tactic: str = None,
        mitre_technique: str = None,
        sources_consulted: str = None,
        recommended_action: str = None
    ) -> AIDecision:
        """
        Create and persist a structured AI/ML decision record for auditability.
        """
        try:
            decision = AIDecision(
                user_id=user_id,
                input_type=input_type,
                input_value=input_value,
                engine_type=engine_type,
                risk_score=risk_score,
                confidence=confidence,
                severity=severity,
                verdict=verdict,
                reasoning_summary=reasoning_summary,
                mitre_tactic=mitre_tactic,
                mitre_technique=mitre_technique,
                sources_consulted=sources_consulted,
                recommended_action=recommended_action,
                created_at=datetime.utcnow()
            )
            db.session.add(decision)
            db.session.commit()
            return decision
        except Exception as e:
            db.session.rollback()
            if current_app:
                current_app.logger.error(f"Failed to log AI decision: {e}")
            return None

    @staticmethod
    def get_decisions(page: int = 1, per_page: int = 20, severity: str = None, verdict: str = None, input_type: str = None):
        """
        Retrieve paginated AI decision logs with optional filters.
        """
        query = AIDecision.query

        if severity:
            query = query.filter_by(severity=severity)
        if verdict:
            query = query.filter_by(verdict=verdict)
        if input_type:
            query = query.filter_by(input_type=input_type)

        return query.order_by(AIDecision.created_at.desc()).paginate(page=page, per_page=per_page, error_out=False)

    @staticmethod
    def get_stats() -> dict:
        """
        Calculate aggregate statistics for the AI Decision Center.
        """
        total = AIDecision.query.count()
        blocks = AIDecision.query.filter_by(verdict='BLOCK').count()
        warns = AIDecision.query.filter_by(verdict='WARN').count()
        allows = AIDecision.query.filter_by(verdict='ALLOW').count()
        criticals = AIDecision.query.filter_by(severity='Critical').count()

        return {
            'total': total,
            'blocks': blocks,
            'warns': warns,
            'allows': allows,
            'criticals': criticals
        }
