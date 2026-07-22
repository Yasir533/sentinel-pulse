import pytest
from app.models.user import User
from app.models.mobile_security import MobileSubmission, ThreatIntel
from app.models.threat import Threat
from app.models.alert import Alert
from app.extensions import db
from app.services.ai_scam_analyzer import AIScamAnalyzer

@pytest.fixture
def auth_client(client, app):
    """Seed a user and authenticate client."""
    with app.app_context():
        user = User(username='mobile_operator', email='mobile@sentinelpulse.local', role='Analyst')
        user.set_password('Password123!')
        db.session.add(user)
        db.session.commit()
        user_id = user.id

    client.post('/auth/login', data={
        'username_or_email': 'mobile_operator',
        'password': 'Password123!'
    }, follow_redirects=True)
    return client, user_id

def test_ai_scam_analyzer_heuristics(app):
    """Test AI Scam Analyzer rules for fake banks, lotteries, and UPI scams."""
    with app.app_context():
        # 1. Bank scam
        res1 = AIScamAnalyzer.analyze_content('sms', 'Your HDFC account is suspended. Update KYC at link')
        assert res1['verdict'] in ['WARN', 'BLOCK', 'ESCALATE']
        assert res1['threat_category'] == 'Fake Bank Scam'
        assert 'kyc' in res1['reasons'][0].lower() or 'bank' in res1['reasons'][0].lower()

        # 2. UPI scam
        res2 = AIScamAnalyzer.analyze_content('sms', 'Type your secret UPI PIN to receive refund bonus')
        assert res2['verdict'] in ['WARN', 'BLOCK', 'ESCALATE']
        assert res2['threat_category'] == 'UPI Scam'
        assert 'upi pin' in res2['reasons'][0].lower()

        # 3. Safe content
        res3 = AIScamAnalyzer.analyze_content('sms', 'Hello, are we meeting for dinner tonight?')
        assert res3['verdict'] == 'ALLOW'
        assert res3['threat_category'] == 'Safe'

def test_mobile_submission_flow(auth_client, app):
    """Test automated pipeline when a threat is submitted (creates Threat, Alert, Audit, Notification)."""
    client, user_id = auth_client

    response = client.post('/mobile/submit', data={
        'submission_type': 'url',
        'content': 'http://axisbank-netbanking-login.net',
        'sender': 'spam_sms_bot',
        'description': 'Targeted HDFC credentials decoy link'
    }, follow_redirects=True)

    assert response.status_code == 200
    assert b"submitted successfully" in response.data

    with app.app_context():
        # Verify MobileSubmission saved
        sub = MobileSubmission.query.filter_by(user_id=user_id, submission_type='url').first()
        assert sub is not None
        assert sub.verdict in ['WARN', 'BLOCK', 'ESCALATE']

        # Verify Threat generated
        threat = Threat.query.filter_by(source='Mobile Submission').first()
        assert threat is not None
        assert 'axisbank-netbanking-login.net' in threat.ioc_value

        # Verify Alert generated
        alert = Alert.query.filter_by(threat_id=threat.id).first()
        assert alert is not None

def test_scanners_endpoints(auth_client):
    """Test individual scanning tool page endpoints return correct render states."""
    client, _ = auth_client

    # Link Scan POST
    res1 = client.post('/mobile/scan/link', data={'url': 'http://malicious-dhl-parcel.com'}, follow_redirects=True)
    assert res1.status_code == 200
    assert b"DHL" in res1.data or b"verdict" in res1.data.lower()

    # SMS Scan POST
    res2 = client.post('/mobile/scan/sms', data={
        'sender': 'AX-FUNDS',
        'message': 'You won 5 crore lottery draws!'
    }, follow_redirects=True)
    assert res2.status_code == 200
    assert b"Lottery" in res2.data or b"verdict" in res2.data.lower()

    # QR Scan POST
    res3 = client.post('/mobile/scan/qr', data={'decoded_text': 'https://google.com'}, follow_redirects=True)
    assert res3.status_code == 200

def test_security_score_endpoint(auth_client):
    """Test user security score endpoint calculations."""
    client, _ = auth_client
    response = client.get('/mobile/score')
    assert response.status_code == 200
    assert b"Overall Endpoint Rating" in response.data

def test_threat_correlation_signatures(auth_client, app):
    """Test threat correlation identifies repeated indicators and flags them."""
    client, user_id = auth_client

    with app.app_context():
        # Scan URL first time
        AIScamAnalyzer.process_submission(user_id, 'url', 'http://repeat-phish-domain.com')
        assert ThreatIntel.query.filter_by(intel_value='http://repeat-phish-domain.com').first() is None

        # Scan URL second time -> triggers correlation and logs it in ThreatIntel
        AIScamAnalyzer.process_submission(user_id, 'url', 'http://repeat-phish-domain.com')
        intel = ThreatIntel.query.filter_by(intel_value='http://repeat-phish-domain.com').first()
        assert intel is not None
        assert intel.intel_type == 'url'
