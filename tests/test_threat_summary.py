import pytest
from app.models.user import User
from app.models.threat import Threat, VTEnrichment, AbuseIPDBEnrichment
from app.services.threat_summary import calculate_overall_risk, generate_summary, generate_recommendation
from app.extensions import db

@pytest.fixture
def seed_user(app):
    """Seed a test user with Analyst role for authentication."""
    with app.app_context():
        user = User(username='test_analyst_summary', email='analyst_summary@sentinelpulse.local', role='Analyst')
        user.set_password('AnalystPassword123')
        db.session.add(user)
        db.session.commit()
        return user.id

def test_threat_summary_logic_low(app, seed_user):
    """Test LOW risk calculation and generated text/recommendations."""
    with app.app_context():
        threat = Threat(
            threat_type='Malicious IP',
            ioc_type='IP Address',
            ioc_value='192.0.2.1',
            severity='Low',
            source='Unit Test',
            created_by=seed_user
        )
        db.session.add(threat)
        db.session.commit()

        # VT low, AbuseIPDB low
        vt = VTEnrichment(threat_id=threat.id, status='success', malicious_count=2, suspicious_count=0, harmless_count=50, undetected_count=2, reputation=5)
        ab = AbuseIPDBEnrichment(threat_id=threat.id, status='success', abuse_confidence_score=10, country_code='US', isp='Test ISP', total_reports=1)
        db.session.add_all([vt, ab])
        db.session.commit()

        risk = calculate_overall_risk(threat)
        summary = generate_summary(threat)
        recs = generate_recommendation(threat)

        assert risk["label"] == "LOW"
        assert risk["badge"] == "success"
        assert "appears to be safe" in summary
        assert "Continue monitoring" in recs
        assert "No immediate action" in recs

def test_threat_summary_logic_medium_vt(app, seed_user):
    """Test MEDIUM risk triggered by VirusTotal malicious count (5-19)."""
    with app.app_context():
        threat = Threat(
            threat_type='Malicious IP',
            ioc_type='IP Address',
            ioc_value='192.0.2.2',
            severity='Medium',
            source='Unit Test',
            created_by=seed_user
        )
        db.session.add(threat)
        db.session.commit()

        # VT medium (7 malicious), AbuseIPDB low (5 confidence)
        vt = VTEnrichment(threat_id=threat.id, status='success', malicious_count=7, suspicious_count=1, harmless_count=40, undetected_count=2, reputation=-2)
        ab = AbuseIPDBEnrichment(threat_id=threat.id, status='success', abuse_confidence_score=5, country_code='US', isp='Test ISP', total_reports=1)
        db.session.add_all([vt, ab])
        db.session.commit()

        risk = calculate_overall_risk(threat)
        summary = generate_summary(threat)
        recs = generate_recommendation(threat)

        assert risk["label"] == "MEDIUM"
        assert risk["badge"] == "warning"
        assert "mixed intelligence results" in summary
        assert "Investigate related systems" in recs

def test_threat_summary_logic_medium_abuse(app, seed_user):
    """Test MEDIUM risk triggered by AbuseIPDB confidence score (21-80)."""
    with app.app_context():
        threat = Threat(
            threat_type='Malicious IP',
            ioc_type='IP Address',
            ioc_value='192.0.2.3',
            severity='Medium',
            source='Unit Test',
            created_by=seed_user
        )
        db.session.add(threat)
        db.session.commit()

        # VT low (1 malicious), AbuseIPDB medium (50 confidence)
        vt = VTEnrichment(threat_id=threat.id, status='success', malicious_count=1, suspicious_count=0, harmless_count=50, undetected_count=2, reputation=0)
        ab = AbuseIPDBEnrichment(threat_id=threat.id, status='success', abuse_confidence_score=50, country_code='US', isp='Test ISP', total_reports=1)
        db.session.add_all([vt, ab])
        db.session.commit()

        risk = calculate_overall_risk(threat)
        summary = generate_summary(threat)
        recs = generate_recommendation(threat)

        assert risk["label"] == "MEDIUM"
        assert risk["badge"] == "warning"
        assert "mixed intelligence results" in summary

def test_threat_summary_logic_high_vt(app, seed_user):
    """Test HIGH risk triggered by VirusTotal malicious count >= 20."""
    with app.app_context():
        threat = Threat(
            threat_type='Malicious IP',
            ioc_type='IP Address',
            ioc_value='192.0.2.4',
            severity='High',
            source='Unit Test',
            created_by=seed_user
        )
        db.session.add(threat)
        db.session.commit()

        # VT high (25 malicious), AbuseIPDB low (10 confidence)
        vt = VTEnrichment(threat_id=threat.id, status='success', malicious_count=25, suspicious_count=5, harmless_count=20, undetected_count=0, reputation=-50)
        ab = AbuseIPDBEnrichment(threat_id=threat.id, status='success', abuse_confidence_score=10, country_code='US', isp='Test ISP', total_reports=10)
        db.session.add_all([vt, ab])
        db.session.commit()

        risk = calculate_overall_risk(threat)
        summary = generate_summary(threat)
        recs = generate_recommendation(threat)

        assert risk["label"] == "HIGH"
        assert risk["badge"] == "danger"
        assert "strongly associated with malicious activity" in summary
        assert "Block the IOC" in recs

def test_threat_summary_logic_high_abuse(app, seed_user):
    """Test HIGH risk triggered by AbuseIPDB confidence score > 80."""
    with app.app_context():
        threat = Threat(
            threat_type='Malicious IP',
            ioc_type='IP Address',
            ioc_value='192.0.2.5',
            severity='High',
            source='Unit Test',
            created_by=seed_user
        )
        db.session.add(threat)
        db.session.commit()

        # VT low (3 malicious), AbuseIPDB high (90 confidence)
        vt = VTEnrichment(threat_id=threat.id, status='success', malicious_count=3, suspicious_count=0, harmless_count=50, undetected_count=2, reputation=-5)
        ab = AbuseIPDBEnrichment(threat_id=threat.id, status='success', abuse_confidence_score=90, country_code='US', isp='Test ISP', total_reports=50)
        db.session.add_all([vt, ab])
        db.session.commit()

        risk = calculate_overall_risk(threat)
        summary = generate_summary(threat)
        recs = generate_recommendation(threat)

        assert risk["label"] == "HIGH"
        assert risk["badge"] == "danger"
        assert "strongly associated with malicious activity" in summary

def test_details_rendering_summary_card(client, app, seed_user):
    """Test threat details page renders AI Threat Summary card correctly."""
    # Authenticate user
    client.post('/auth/login', data={
        'username_or_email': 'test_analyst_summary',
        'password': 'AnalystPassword123'
    })

    with app.app_context():
        threat = Threat(
            threat_type='Malicious IP',
            ioc_type='IP Address',
            ioc_value='8.8.8.8',
            severity='High',
            source='Unit Test Web',
            created_by=seed_user
        )
        db.session.add(threat)
        db.session.commit()

        # Add enrichment to trigger MEDIUM risk
        vt = VTEnrichment(threat_id=threat.id, status='success', malicious_count=8, suspicious_count=0, harmless_count=50, undetected_count=2, reputation=0)
        db.session.add(vt)
        db.session.commit()
        threat_id = threat.id

    response = client.get(f'/threats/{threat_id}')
    assert response.status_code == 200
    assert b"AI Threat Summary" in response.data
    assert b"MEDIUM" in response.data
    assert b"This IOC has mixed intelligence results. Further investigation is recommended before taking action." in response.data
    assert b"Investigate related systems" in response.data
    assert b"Monitor network activity" in response.data
    assert b"Review firewall logs" in response.data
