import pytest
from app.models.user import User
from app.models.threat import Threat
from app.models.incident import Incident
from app.models.activity_log import ActivityLog
from app.extensions import db

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

@pytest.fixture
def seed_threat(app, seed_users):
    """Seed a test threat linked to the analyst user."""
    with app.app_context():
        threat = Threat(
            threat_type='Malware',
            ioc_type='IP Address',
            ioc_value='198.51.100.42',
            severity='High',
            source='External Feed',
            status='New',
            confidence_score=90,
            description='Test Malware IOC',
            created_by=seed_users['analyst']
        )
        db.session.add(threat)
        db.session.commit()
        return threat.id

def test_incident_creation_and_escalation(client, app, seed_users, seed_threat):
    """Test creating an incident escalates a threat successfully."""
    # Login as Admin
    client.post('/auth/login', data={
        'username_or_email': 'admin_op',
        'password': 'AdminPassword123'
    })

    # Create new incident escalation
    response = client.post(f'/incidents/new/{seed_threat}', data={
        'title': 'Test Incident Escalation',
        'description': 'Assessment of target malware intrusion',
        'severity': 'High',
        'status': 'Open',
        'assigned_to': str(seed_users['analyst']),
        'resolution_notes': 'Initial block completed'
    }, follow_redirects=True)

    assert response.status_code == 200
    assert b"Incident Created Successfully" in response.data

    with app.app_context():
        incident = Incident.query.first()
        assert incident is not None
        assert incident.title == 'Test Incident Escalation'
        assert incident.severity == 'High'
        assert incident.status == 'Open'
        assert incident.assigned_to == seed_users['analyst']
        assert incident.resolution_notes == 'Initial block completed'
        assert incident.threat_id == seed_threat
        assert incident.creator.username == 'admin_op'
        assert incident.incident_number.startswith('INC-')

        # Check Activity Log was populated
        logs = ActivityLog.query.order_by(ActivityLog.timestamp.desc()).limit(2).all()
        assert len(logs) > 0
        log_messages = [l.message for l in logs]
        assert any(incident.incident_number in msg for msg in log_messages)
        assert any("created" in msg for msg in log_messages)

def test_incident_list_and_filtering(client, app, seed_users, seed_threat):
    """Test listing incidents and applying filters."""
    # Create another threat with a different IOC Type
    with app.app_context():
        domain_threat = Threat(
            threat_type='Phishing',
            ioc_type='Domain',
            ioc_value='malicious-site.com',
            severity='Medium',
            source='External Feed',
            status='New',
            confidence_score=80,
            description='Phishing domain',
            created_by=seed_users['analyst']
        )
        db.session.add(domain_threat)
        db.session.commit()
        domain_threat_id = domain_threat.id

    # Create incidents via DB
    with app.app_context():
        inc1 = Incident(
            incident_number='INC-2026-0001',
            threat_id=seed_threat,
            title='Severe Attack',
            description='Desc 1',
            severity='Critical',
            status='In Progress',
            assigned_to=seed_users['analyst'],
            created_by=seed_users['admin']
        )
        inc2 = Incident(
            incident_number='INC-2026-0002',
            threat_id=domain_threat_id,
            title='Low Priority',
            description='Desc 2',
            severity='Low',
            status='Open',
            assigned_to=seed_users['admin'],
            created_by=seed_users['admin']
        )
        db.session.add_all([inc1, inc2])
        db.session.commit()

    # Login as Viewer (Viewers have read-only access to lists and details)
    client.post('/auth/login', data={
        'username_or_email': 'viewer_op',
        'password': 'ViewerPassword123'
    })

    # Test list page renders
    response = client.get('/incidents/')
    assert response.status_code == 200
    assert b'INC-2026-0001' in response.data
    assert b'INC-2026-0002' in response.data

    # Test filtering by severity
    response = client.get('/incidents/?severity=Critical')
    assert b'INC-2026-0001' in response.data
    assert b'INC-2026-0002' not in response.data

    # Test filtering by status
    response = client.get('/incidents/?status=Open')
    assert b'INC-2026-0001' not in response.data
    assert b'INC-2026-0002' in response.data

    # Test keyword search
    response = client.get('/incidents/?q=Severe')
    assert b'INC-2026-0001' in response.data
    assert b'INC-2026-0002' not in response.data

    # Test filtering by ioc_type
    response = client.get('/incidents/?ioc_type=IP Address')
    assert b'INC-2026-0001' in response.data
    assert b'INC-2026-0002' not in response.data

    response = client.get('/incidents/?ioc_type=Domain')
    assert b'INC-2026-0001' not in response.data
    assert b'INC-2026-0002' in response.data

def test_incident_rbac_and_workflow(client, app, seed_users, seed_threat):
    """Test role-based updates and workflows on incidents."""
    with app.app_context():
        incident = Incident(
            incident_number='INC-2026-0005',
            threat_id=seed_threat,
            title='Org Title',
            description='Org Desc',
            severity='Medium',
            status='Open',
            created_by=seed_users['admin']
        )
        db.session.add(incident)
        db.session.commit()
        incident_id = incident.id

    # 1. Viewer Role is read-only and cannot edit
    client.post('/auth/login', data={
        'username_or_email': 'viewer_op',
        'password': 'ViewerPassword123'
    })
    response = client.post(f'/incidents/{incident_id}/edit', data={
        'status': 'In Progress'
    })
    assert response.status_code == 403  # role_required aborts 403

    # 2. Analyst Role can only update Status and Resolution Notes
    client.get('/auth/logout')
    client.post('/auth/login', data={
        'username_or_email': 'analyst_op',
        'password': 'AnalystPassword123'
    })
    response = client.post(f'/incidents/{incident_id}/edit', data={
        'title': 'Hackers in System',  # restricted field
        'severity': 'Critical',         # restricted field
        'status': 'Resolved',           # allowed field
        'resolution_notes': 'Host isolated'  # allowed field
    }, follow_redirects=True)

    assert response.status_code == 200
    assert b'Incident Resolved Successfully' in response.data

    with app.app_context():
        inc = db.session.get(Incident, incident_id)
        # Verify allowed fields were updated
        assert inc.status == 'Resolved'
        assert inc.resolution_notes == 'Host isolated'
        assert inc.resolved_at is not None
        # Verify restricted fields were NOT changed
        assert inc.title == 'Org Title'
        assert inc.severity == 'Medium'

    # 3. Admin Role can update all fields (including closing a resolved incident)
    client.get('/auth/logout')
    client.post('/auth/login', data={
        'username_or_email': 'admin_op',
        'password': 'AdminPassword123'
    })
    response = client.post(f'/incidents/{incident_id}/edit', data={
        'title': 'New Title by Admin',
        'description': 'New Description',
        'severity': 'Critical',
        'status': 'Closed',
        'resolution_notes': 'Closed docket'
    }, follow_redirects=True)

    assert response.status_code == 200
    assert b'Incident Closed Successfully' in response.data or b'Incident Resolved Successfully' in response.data

    with app.app_context():
        inc = db.session.get(Incident, incident_id)
        assert inc.title == 'New Title by Admin'
        assert inc.description == 'New Description'
        assert inc.severity == 'Critical'
        assert inc.status == 'Closed'

def test_incident_deletion_restricted(client, app, seed_users, seed_threat):
    """Test incident deletion is restricted to Admins only."""
    with app.app_context():
        incident = Incident(
            incident_number='INC-2026-0009',
            threat_id=seed_threat,
            title='Delete Me',
            severity='Low',
            status='Open',
            created_by=seed_users['admin']
        )
        db.session.add(incident)
        db.session.commit()
        incident_id = incident.id

    # 1. Analyst cannot delete
    client.post('/auth/login', data={
        'username_or_email': 'analyst_op',
        'password': 'AnalystPassword123'
    })
    response = client.post(f'/incidents/{incident_id}/delete')
    assert response.status_code == 403

    # 2. Admin can delete
    client.get('/auth/logout')
    client.post('/auth/login', data={
        'username_or_email': 'admin_op',
        'password': 'AdminPassword123'
    })
    response = client.post(f'/incidents/{incident_id}/delete', follow_redirects=True)
    assert response.status_code == 200
    assert b'Incident Deleted Successfully' in response.data

    with app.app_context():
        inc = db.session.get(Incident, incident_id)
        assert inc is None

def test_incident_close_workflow_constraints(client, app, seed_users, seed_threat):
    """Test incident cannot be closed directly from an unresolved state."""
    with app.app_context():
        incident = Incident(
            incident_number='INC-2026-0010',
            threat_id=seed_threat,
            title='Close Constraint Test',
            severity='Low',
            status='Open',
            created_by=seed_users['admin']
        )
        db.session.add(incident)
        db.session.commit()
        incident_id = incident.id

    # Login as Admin
    client.post('/auth/login', data={
        'username_or_email': 'admin_op',
        'password': 'AdminPassword123'
    })

    # Try to close unresolved incident directly
    response = client.post(f'/incidents/{incident_id}/edit', data={
        'title': 'Close Constraint Test',
        'severity': 'Low',
        'status': 'Closed'
    }, follow_redirects=True)

    assert response.status_code == 200
    assert b"Incident can only be closed if it is resolved" in response.data

    with app.app_context():
        inc = db.session.get(Incident, incident_id)
        assert inc.status == 'Open'  # status is not changed to Closed

    # Resolve first
    response = client.post(f'/incidents/{incident_id}/edit', data={
        'title': 'Close Constraint Test',
        'severity': 'Low',
        'status': 'Resolved'
    }, follow_redirects=True)
    assert b"Incident Resolved Successfully" in response.data

    # Now close succeeds
    response = client.post(f'/incidents/{incident_id}/edit', data={
        'title': 'Close Constraint Test',
        'severity': 'Low',
        'status': 'Closed'
    }, follow_redirects=True)
    assert b"Incident Closed Successfully" in response.data

    with app.app_context():
        inc = db.session.get(Incident, incident_id)
        assert inc.status == 'Closed'

def test_ai_incident_assistant_vectors(app):
    """Test AIIncidentAssistant heuristics classify and recommend correctly across vectors."""
    from app.services.ai_incident_assistant import AIIncidentAssistant

    # 1. Malware / APK
    inc1 = Incident(title="Suspicious APK Downloaded", description="Malware signature matched on endpoint", severity="Critical", incident_number="INC-1")
    res1 = AIIncidentAssistant.generate_assistance(inc1)
    assert "Malware" in res1["summary"]
    assert "Isolate the affected mobile device" in res1["resolution_steps"][0]
    assert "MDM" in res1["prevention_suggestions"][0] or "sideloading" in res1["prevention_suggestions"][0]

    # 2. Ransomware
    inc2 = Incident(title="Critical server ransomware alert", description="Files encrypted with extension .locked", severity="Critical", incident_number="INC-2")
    res2 = AIIncidentAssistant.generate_assistance(inc2)
    assert "Ransomware" in res2["summary"]
    assert "Isolate the infected hosts" in res2["resolution_steps"][0]
    assert "backup" in res2["prevention_suggestions"][0].lower() or "immutable" in res2["prevention_suggestions"][0].lower()

    # 3. UPI Fraud
    inc3 = Incident(title="UPI transaction PIN bypass", description="Deceptive money collection request", severity="High", incident_number="INC-3")
    res3 = AIIncidentAssistant.generate_assistance(inc3)
    assert "UPI / Financial Fraud" in res3["summary"]
    assert "freeze affected accounts" in res3["resolution_steps"][0].lower()

    # 4. SMS Scam
    inc4 = Incident(title="SMS lottery scam broadcast", description="Smishing text lure received", severity="Medium", incident_number="INC-4")
    res4 = AIIncidentAssistant.generate_assistance(inc4)
    assert "SMS Scam" in res4["summary"]
    assert "cellular service providers" in res4["resolution_steps"][0].lower()

    # 5. Phishing Link
    inc5 = Incident(title="Phishing link domain accessed", description="User clicked url from WhatsApp", severity="High", incident_number="INC-5")
    res5 = AIIncidentAssistant.generate_assistance(inc5)
    assert "Phishing" in res5["summary"]
    assert "Block the malicious domain" in res5["resolution_steps"][0]

    # 6. Credential Access
    inc6 = Incident(title="Decoy login page auth failure", description="Suspected password spraying attack", severity="High", incident_number="INC-6")
    res6 = AIIncidentAssistant.generate_assistance(inc6)
    assert "Credential Access" in res6["summary"]
    assert "Force a global password reset" in res6["resolution_steps"][0]

    # 7. Default (Social Engineering)
    inc7 = Incident(title="Deceptive support call", description="Impression verification request", severity="Low", incident_number="INC-7")
    res7 = AIIncidentAssistant.generate_assistance(inc7)
    assert "Social Engineering" in res7["summary"]
    assert "verification of the user" in res7["resolution_steps"][0]

def test_ai_incident_assistant_dossier_integration(client, app, seed_users, seed_threat):
    """Test details route generates AI Incident Copilot Guidance and renders details dossier."""
    client.post('/auth/login', data={
        'username_or_email': 'admin_op',
        'password': 'AdminPassword123'
    })

    with app.app_context():
        incident = Incident(
            incident_number='INC-2026-0099',
            threat_id=seed_threat,
            title='Malware Ransomware Attack Triggered',
            description='Threat actor executed locker file extension payload',
            severity='Critical',
            status='Open',
            created_by=seed_users['admin']
        )
        db.session.add(incident)
        db.session.commit()
        incident_id = incident.id

    response = client.get(f'/incidents/{incident_id}')
    assert response.status_code == 200
    assert b"AI Incident Copilot Guidance" in response.data
    assert b"Executive Summary" in response.data
    assert b"Assessed Root Cause" in response.data
    assert b"Remediation Steps" in response.data
    assert b"Ransomware" in response.data or b"Malware" in response.data

