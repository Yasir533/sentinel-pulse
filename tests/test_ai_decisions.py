from app.models.user import User
from app.services.ai_decision_service import AIDecisionService
from app.extensions import db

def test_log_ai_decision(app):
    """Test creating and persisting an AI Decision log."""
    with app.app_context():
        user = User(username='admin_test', email='admin_test@sentinelpulse.local', role='Admin')
        user.set_password('Password123!')
        db.session.add(user)
        db.session.commit()

        decision = AIDecisionService.log_decision(
            user_id=user.id,
            input_type='url',
            input_value='http://malicious-phish-bank.com',
            risk_score=85,
            confidence=90,
            verdict='BLOCK',
            severity='Critical',
            reasoning_summary='Bank impersonation detected',
            mitre_tactic='Initial Access',
            mitre_technique='T1566 - Phishing'
        )

        assert decision is not None
        assert decision.id is not None
        assert decision.verdict == 'BLOCK'
        assert decision.risk_score == 85
        assert decision.mitre_tactic == 'Initial Access'

        # Verify retrieval and stats
        stats = AIDecisionService.get_stats()
        assert stats['total'] >= 1
        assert stats['blocks'] >= 1

def test_ai_decision_center_access(client, app):
    """Verify Admin and Analyst access to AI Decision Center UI."""
    # 1. Unauthenticated -> Redirect to login
    res = client.get('/ai-decisions')
    assert res.status_code == 302

    # 2. Create Admin user & login
    with app.app_context():
        admin = User(username='admin_ui', email='admin_ui@sentinelpulse.local', role='Admin')
        admin.set_password('Password123!')
        db.session.add(admin)
        db.session.commit()

    login_res = client.post('/auth/login', data={
        'username_or_email': 'admin_ui',
        'password': 'Password123!'
    }, follow_redirects=True)
    assert login_res.status_code == 200

    res_admin = client.get('/ai-decisions')
    assert res_admin.status_code == 200
    assert b"AI Decision Center" in res_admin.data
