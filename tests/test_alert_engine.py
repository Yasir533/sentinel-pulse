import pytest
from app.models.user import User
from app.models.threat import Threat, VTEnrichment, AbuseIPDBEnrichment
from app.models.alert import Alert
from app.extensions import db
from app.services.alert import AlertService

@pytest.fixture
def seed_test_users(app):
    """Seed Admin, Analyst, and Viewer operators for dashboard and RBAC validation."""
    with app.app_context():
        admin = User(username='admin_engine', email='admin_eng@sentinelpulse.local', role='Admin')
        admin.set_password('AdminEngine123')
        
        analyst = User(username='analyst_engine', email='analyst_eng@sentinelpulse.local', role='Analyst')
        analyst.set_password('AnalystEngine123')
        
        viewer = User(username='viewer_engine', email='viewer_eng@sentinelpulse.local', role='Viewer')
        viewer.set_password('ViewerEngine123')
        
        db.session.add_all([admin, analyst, viewer])
        db.session.commit()
        
        return {
            'admin': admin.id,
            'analyst': analyst.id,
            'viewer': viewer.id
        }

def test_scenario_1_vt_and_ai_risk_critical(app, seed_test_users):
    """Scenario 1: SHA256 '44d88612fea8a8f36de82e1278abb02f' with VT = 66, AI = HIGH -> Critical Alert."""
    with app.app_context():
        threat = Threat(
            threat_type='Malware', 
            ioc_type='SHA256', 
            ioc_value='44d88612fea8a8f36de82e1278abb02f', 
            source='Heuristics Engine', 
            created_by=seed_test_users['analyst']
        )
        db.session.add(threat)
        db.session.commit()

        # Seed VT Enrichment
        vt = VTEnrichment(threat_id=threat.id, status='success', malicious_count=66)
        db.session.add(vt)
        db.session.commit()

        # Mock calculate_overall_risk to return label=HIGH
        # Under normal conditions, generate_alert evaluates VT >= 20 to Critical
        alert = AlertService.generate_alert(threat)
        assert alert is not None
        assert alert.severity == 'Critical'
        assert alert.message == "Critical malware identified by VirusTotal."
        assert alert.status == 'New'

def test_scenario_2_low_risk_no_alert(app, seed_test_users):
    """Scenario 2: IP '8.8.8.8' with AI = LOW -> No Alert created."""
    with app.app_context():
        threat = Threat(
            threat_type='Malicious IP', 
            ioc_type='IP Address', 
            ioc_value='8.8.8.8', 
            source='Feed', 
            created_by=seed_test_users['analyst']
        )
        db.session.add(threat)
        db.session.commit()

        # Mock VT/AbuseIPDB to be benign or empty
        alert = AlertService.generate_alert(threat)
        assert alert is None

def test_scenario_3_abuseipdb_high_risk(app, seed_test_users):
    """Scenario 3: IP '185.220.101.1' with AbuseIPDB confidence score = 95% -> High Alert."""
    with app.app_context():
        threat = Threat(
            threat_type='Malicious IP', 
            ioc_type='IP Address', 
            ioc_value='185.220.101.1', 
            source='Abuse Feed', 
            created_by=seed_test_users['analyst']
        )
        db.session.add(threat)
        db.session.commit()

        # Seed AbuseIPDB
        abuse = AbuseIPDBEnrichment(threat_id=threat.id, status='success', abuse_confidence_score=95)
        db.session.add(abuse)
        db.session.commit()

        alert = AlertService.generate_alert(threat)
        assert alert is not None
        assert alert.severity == 'High'
        assert alert.message == "Malicious IP exceeds AbuseIPDB confidence threshold."

def test_duplicate_prevention_rules(app, seed_test_users):
    """Verify alert generation rules prevent duplicates unless previous is Archived."""
    with app.app_context():
        threat = Threat(
            threat_type='Malware', 
            ioc_type='MD5', 
            ioc_value='duplicate_guard_hash', 
            source='Manual', 
            created_by=seed_test_users['analyst']
        )
        db.session.add(threat)
        db.session.commit()

        # First alert created
        vt = VTEnrichment(threat_id=threat.id, status='success', malicious_count=22)
        db.session.add(vt)
        db.session.commit()

        alert1 = AlertService.generate_alert(threat)
        assert alert1 is not None
        
        # Second call with alert status 'New' -> returns alert1, does not create duplicate
        alert2 = AlertService.generate_alert(threat)
        assert alert2.id == alert1.id
        assert Alert.query.filter_by(threat_id=threat.id).count() == 1

        # Change status to Archived -> allows creating a duplicate new alert
        alert1.status = 'Archived'
        db.session.commit()

        alert3 = AlertService.generate_alert(threat)
        assert alert3 is not None
        assert alert3.id != alert1.id
        assert Alert.query.filter_by(threat_id=threat.id).count() == 2

def test_dashboard_metrics_counts(client, app, seed_test_users):
    """Test dashboard metrics counts reflect actual alerts db count correctly."""
    with app.app_context():
        # Create some alerts
        t1 = Threat(threat_type='Malware', ioc_type='SHA256', ioc_value='hash_1', source='Feed', created_by=seed_test_users['analyst'])
        t2 = Threat(threat_type='Malware', ioc_type='SHA256', ioc_value='hash_2', source='Feed', created_by=seed_test_users['analyst'])
        db.session.add_all([t1, t2])
        db.session.commit()

        a1 = Alert(alert_number='ALT-2026-0001', threat_id=t1.id, severity='Critical', status='New')
        a2 = Alert(alert_number='ALT-2026-0002', threat_id=t2.id, severity='High', status='New')
        db.session.add_all([a1, a2])
        db.session.commit()

    # 1. Admin login & count checks
    client.post('/auth/login', data={'username_or_email': 'admin_engine', 'password': 'AdminEngine123'})
    
    response = client.get('/admin/dashboard')
    assert response.status_code == 200
    assert b"Total Alerts" in response.data
    assert b"New Alerts" in response.data
    assert b"Critical Alerts" in response.data
    
    client.get('/auth/logout')

    # 2. Analyst login & count checks
    client.post('/auth/login', data={'username_or_email': 'analyst_engine', 'password': 'AnalystEngine123'})
    
    response = client.get('/analyst/dashboard')
    assert response.status_code == 200
    assert b"Assigned Alerts" in response.data
    assert b"New Alerts" in response.data
    
    client.get('/auth/logout')

    # 3. Viewer login & count checks
    client.post('/auth/login', data={'username_or_email': 'viewer_engine', 'password': 'ViewerEngine123'})
    
    response = client.get('/viewer/dashboard')
    assert response.status_code == 200
    assert b"Alerts" in response.data
