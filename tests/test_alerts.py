import pytest
from app.models.user import User
from app.models.threat import Threat, VTEnrichment, AbuseIPDBEnrichment
from app.models.alert import Alert
from app.models.activity_log import ActivityLog
from app.extensions import db
from app.services.alert import generate_next_alert_number, evaluate_and_create_alert

@pytest.fixture
def seed_users(app):
    """Seed three users with different roles (Admin, Analyst, Viewer)."""
    with app.app_context():
        admin = User(username='admin_op', email='admin@sentinelpulse.local', role='Admin')
        admin.set_password('AdminPassword123')
        
        analyst = User(username='analyst_op', email='analyst@sentinelpulse.local', role='Analyst')
        analyst.set_password('AnalystPassword123')
        
        viewer = User(username='viewer_op', email='viewer@sentinelpulse.local', role='Viewer')
        viewer.set_password('ViewerPassword123')
        
        db.session.add_all([admin, analyst, viewer])
        db.session.commit()
        
        return {
            'admin': admin.id,
            'analyst': analyst.id,
            'viewer': viewer.id
        }

def test_alert_number_generation(app):
    """Test auto-incrementing alert number sequence generation."""
    with app.app_context():
        # First alert number
        num1 = generate_next_alert_number()
        assert num1 == "ALT-2026-0001"

        # Save an alert
        alert1 = Alert(alert_number=num1, threat_id=1, severity='High', status='New')
        db.session.add(alert1)
        db.session.commit()

        # Second alert number
        num2 = generate_next_alert_number()
        assert num2 == "ALT-2026-0002"

def test_automatic_alert_rules(app, seed_users):
    """Test that threats trigger alerts with correct severity based on criteria."""
    with app.app_context():
        # Threat 1: VT malicious >= 20 -> Critical Alert
        threat1 = Threat(threat_type='Malware', ioc_type='SHA256', ioc_value='vt_crit_hash', source='Test', created_by=seed_users['analyst'])
        db.session.add(threat1)
        db.session.commit()
        
        vt = VTEnrichment(threat_id=threat1.id, status='success', malicious_count=20)
        db.session.add(vt)
        db.session.commit()

        alert1 = evaluate_and_create_alert(threat1)
        assert alert1 is not None
        assert alert1.severity == 'Critical'
        assert alert1.alert_number == 'ALT-2026-0001'

        # Threat 2: AbuseIPDB confidence >= 80 -> High Alert
        threat2 = Threat(threat_type='Malicious IP', ioc_type='IP Address', ioc_value='1.2.3.4', source='Test', created_by=seed_users['analyst'])
        db.session.add(threat2)
        db.session.commit()

        abuse = AbuseIPDBEnrichment(threat_id=threat2.id, status='success', abuse_confidence_score=85)
        db.session.add(abuse)
        db.session.commit()

        alert2 = evaluate_and_create_alert(threat2)
        assert alert2 is not None
        assert alert2.severity == 'High'
        assert alert2.alert_number == 'ALT-2026-0002'

        # Threat 3: Low overall risk -> No alert generated
        threat3 = Threat(threat_type='Malware', ioc_type='MD5', ioc_value='low_risk_hash', source='Test', created_by=seed_users['analyst'])
        db.session.add(threat3)
        db.session.commit()

        alert3 = evaluate_and_create_alert(threat3)
        assert alert3 is None

        # Verify duplicate prevention: calling again returns the same alert, doesn't duplicate
        dup_alert1 = evaluate_and_create_alert(threat1)
        assert dup_alert1.id == alert1.id
        assert Alert.query.filter_by(threat_id=threat1.id).count() == 1

def test_alert_routes_rbac(client, app, seed_users):
    """Test route visibility and access control for list, details, and acknowledge."""
    with app.app_context():
        # Setup an alert to view/acknowledge
        threat = Threat(threat_type='Malware', ioc_type='SHA256', ioc_value='some_hash', source='Test', created_by=seed_users['analyst'])
        db.session.add(threat)
        db.session.commit()
        alert = Alert(alert_number='ALT-2026-0001', threat_id=threat.id, severity='High', status='New')
        db.session.add(alert)
        db.session.commit()
        alert_id = alert.id

    # 1. Viewer role test: Can list and view, but cannot acknowledge
    client.post('/auth/login', data={
        'username_or_email': 'viewer_op',
        'password': 'ViewerPassword123'
    })
    
    # List alerts
    response = client.get('/alerts/')
    assert response.status_code == 200
    assert b"ALT-2026-0001" in response.data

    # Details page
    response = client.get(f'/alerts/{alert_id}')
    assert response.status_code == 200
    assert b"Security Alert Details" in response.data

    # Attempt to Acknowledge (should be blocked)
    response = client.post(f'/alerts/{alert_id}/acknowledge', follow_redirects=True)
    assert response.status_code == 403 # role required blocks Viewer

    client.get('/auth/logout')

    # 2. Analyst role test: Can list, view, and acknowledge
    client.post('/auth/login', data={
        'username_or_email': 'analyst_op',
        'password': 'AnalystPassword123'
    })

    # Acknowledge alert
    response = client.post(f'/alerts/{alert_id}/acknowledge', follow_redirects=True)
    assert response.status_code == 200
    assert b"acknowledged successfully" in response.data

    # Verify database update
    with app.app_context():
        updated_alert = db.session.get(Alert, alert_id)
        assert updated_alert.status == 'Acknowledged'
        assert updated_alert.acknowledged_by == seed_users['analyst']

        # Verify activity log entries (Alert Generated, Alert Viewed, Alert Acknowledged)
        log1 = ActivityLog.query.filter(ActivityLog.message.like("%viewed Alert ALT-2026-0001%")).first()
        assert log1 is not None
        log2 = ActivityLog.query.filter(ActivityLog.message.like("%acknowledged Alert ALT-2026-0001%")).first()
        assert log2 is not None

def test_alert_search_and_filters(client, app, seed_users):
    """Test searching by Alert Number, IOC Value, and filtering by severity, status, threat type."""
    with app.app_context():
        t1 = Threat(threat_type='Malware', ioc_type='SHA256', ioc_value='searchable_hash_1', source='Feed', created_by=seed_users['analyst'])
        t2 = Threat(threat_type='Phishing', ioc_type='Domain', ioc_value='phish_domain.com', source='Feed', created_by=seed_users['analyst'])
        db.session.add_all([t1, t2])
        db.session.commit()

        a1 = Alert(alert_number='ALT-2026-9001', threat_id=t1.id, severity='Critical', status='New')
        a2 = Alert(alert_number='ALT-2026-9002', threat_id=t2.id, severity='High', status='Acknowledged')
        db.session.add_all([a1, a2])
        db.session.commit()

    # Authenticate as Viewer
    client.post('/auth/login', data={'username_or_email': 'viewer_op', 'password': 'ViewerPassword123'})

    # 1. Search by Keyword (Alert Number)
    response = client.get('/alerts/?q=ALT-2026-9001')
    assert b'ALT-2026-9001' in response.data
    assert b'ALT-2026-9002' not in response.data

    # 2. Search by Keyword (IOC Value)
    response = client.get('/alerts/?q=phish_domain.com')
    assert b'ALT-2026-9002' in response.data
    assert b'ALT-2026-9001' not in response.data

    # 3. Filter by Severity
    response = client.get('/alerts/?severity=Critical')
    assert b'ALT-2026-9001' in response.data
    assert b'ALT-2026-9002' not in response.data

    # 4. Filter by Status
    response = client.get('/alerts/?status=Acknowledged')
    assert b'ALT-2026-9002' in response.data
    assert b'ALT-2026-9001' not in response.data

    # 5. Filter by Threat Type
    response = client.get('/alerts/?threat_type=Phishing')
    assert b'ALT-2026-9002' in response.data
    assert b'ALT-2026-9001' not in response.data

def test_alert_status_workflow_transitions(client, app, seed_users):
    """Test sequential transitions: New -> Acknowledged -> Investigating -> Resolved -> Archived."""
    with app.app_context():
        threat = Threat(threat_type='Malware', ioc_type='SHA256', ioc_value='workflow_hash', source='Test', created_by=seed_users['analyst'])
        db.session.add(threat)
        db.session.commit()
        alert = Alert(alert_number='ALT-2026-8001', threat_id=threat.id, severity='High', status='New')
        db.session.add(alert)
        db.session.commit()
        alert_id = alert.id

    # Login as Admin to perform all transitions
    client.post('/auth/login', data={'username_or_email': 'admin_op', 'password': 'AdminPassword123'})

    # 1. New -> Acknowledged (Acknowledge)
    response = client.post(f'/alerts/{alert_id}/acknowledge', follow_redirects=True)
    assert response.status_code == 200
    assert b"acknowledged successfully" in response.data
    with app.app_context():
        a = db.session.get(Alert, alert_id)
        assert a.status == 'Acknowledged'
        assert a.acknowledged_at is not None

    # Invalid: Acknowledge again should fail
    response = client.post(f'/alerts/{alert_id}/acknowledge', follow_redirects=True)
    assert b"Alert must be in New status to be acknowledged." in response.data

    # 2. Acknowledged -> Investigating (Investigate)
    response = client.post(f'/alerts/{alert_id}/investigate', follow_redirects=True)
    assert response.status_code == 200
    assert b"status changed to Investigating" in response.data
    with app.app_context():
        assert db.session.get(Alert, alert_id).status == 'Investigating'

    # Invalid: Investigating again should fail
    response = client.post(f'/alerts/{alert_id}/investigate', follow_redirects=True)
    assert b"Alert must be Acknowledged before starting investigation." in response.data

    # 3. Investigating -> Resolved (Resolve)
    response = client.post(f'/alerts/{alert_id}/resolve', follow_redirects=True)
    assert response.status_code == 200
    assert b"resolved successfully" in response.data
    with app.app_context():
        a = db.session.get(Alert, alert_id)
        assert a.status == 'Resolved'
        assert a.resolved_at is not None

    # 4. Resolved -> Archived (Archive)
    response = client.post(f'/alerts/{alert_id}/archive', follow_redirects=True)
    assert response.status_code == 200
    assert b"archived successfully" in response.data
    with app.app_context():
        assert db.session.get(Alert, alert_id).status == 'Archived'

def test_alert_workflow_rbac(client, app, seed_users):
    """Verify role checks: Analyst blocked from Resolve/Archive; Viewer blocked from all updates."""
    with app.app_context():
        threat = Threat(threat_type='Malware', ioc_type='SHA256', ioc_value='rbac_hash', source='Test', created_by=seed_users['analyst'])
        db.session.add(threat)
        db.session.commit()
        alert = Alert(alert_number='ALT-2026-7001', threat_id=threat.id, severity='High', status='Investigating')
        db.session.add(alert)
        db.session.commit()
        alert_id = alert.id

    # 1. Analyst login -> attempts to Resolve -> 403 Forbidden
    client.post('/auth/login', data={'username_or_email': 'analyst_op', 'password': 'AnalystPassword123'})
    response = client.post(f'/alerts/{alert_id}/resolve')
    assert response.status_code == 403

    # 2. Analyst attempts to Archive -> 403 Forbidden
    response = client.post(f'/alerts/{alert_id}/archive')
    assert response.status_code == 403

    # 3. Viewer login -> attempts to Investigate -> 403 Forbidden
    client.get('/auth/logout')
    client.post('/auth/login', data={'username_or_email': 'viewer_op', 'password': 'ViewerPassword123'})
    response = client.post(f'/alerts/{alert_id}/investigate')
    assert response.status_code == 403

def test_duplicate_incident_prevention(client, app, seed_users):
    """Verify that attempting to create duplicate incidents for the same threat is blocked."""
    with app.app_context():
        threat = Threat(threat_type='Malware', ioc_type='SHA256', ioc_value='incident_hash', source='Test', created_by=seed_users['analyst'])
        db.session.add(threat)
        db.session.commit()
        threat_id = threat.id

    # Login as Analyst
    client.post('/auth/login', data={'username_or_email': 'analyst_op', 'password': 'AnalystPassword123'})

    # 1. Create first incident successfully
    response = client.post(f'/incidents/new/{threat_id}', data={
        'title': 'First Incident',
        'description': 'Unique test incident description',
        'severity': 'High',
        'status': 'Open'
    }, follow_redirects=True)
    assert response.status_code == 200
    assert b"Incident Created Successfully" in response.data

    # 2. Try creating a second incident for the same threat_id -> redirects and shows warning
    response = client.post(f'/incidents/new/{threat_id}', data={
        'title': 'Duplicate Incident',
        'description': 'This should fail',
        'severity': 'High',
        'status': 'Open'
    }, follow_redirects=True)
    assert b"An Incident already exists for this Threat." in response.data

    # 3. Try access GET new route for the same threat_id -> redirects and shows warning
    response = client.get(f'/incidents/new/{threat_id}', follow_redirects=True)
    assert b"An Incident already exists for this Threat." in response.data

